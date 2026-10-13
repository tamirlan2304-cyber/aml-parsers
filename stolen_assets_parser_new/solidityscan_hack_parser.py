"""Parse explicitly attributed malicious addresses from SolidityScan hack analyses.

The public WordPress REST API is used because it exposes the complete rendered
article body and reliable pagination metadata.  Only addresses attached to an
explicit attacker/exploiter/attack-contract/stolen-funds label are accepted.
Victim and vulnerable-contract addresses, transaction hashes and arbitrary
addresses from prose or source-code examples are intentionally omitted.
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import date, datetime
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, urlsplit

import pyarrow as pa
import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from defihacklabs_parser import FORBIDDEN_ADDRESSES
from telegram_investigations_parser import (
    ADDRESS_CANDIDATE_RE,
    EVM_RE,
    NETWORK_NAMES,
    canonical_address,
    network_for_address,
    network_hints,
    normalize_source_address,
    validated_network_codes,
)


LOGGER = logging.getLogger("solidityscan_hack_analysis")
CATEGORY_URL = "https://blog.solidityscan.com/category/hack-analysis/"
API_URL = "https://blog.solidityscan.com/wp-json/wp/v2/posts"
CATEGORY_ID = 39
S3_KEY = "stolen_assets/solidityscan_hack_analysis.parquet"
PER_PAGE = 100
MAX_PAGE_BYTES = 8 * 1024 * 1024
OUTPUT_SCHEMA = pa.schema([
    pa.field("address", pa.string(), nullable=False),
    pa.field("network", pa.string(), nullable=False),
    pa.field("incident_date", pa.date32(), nullable=False),
    pa.field("incident_name", pa.string(), nullable=False),
])

# Labels seen in the source include typographic apostrophes and singular/plural
# variants.  A bare use of the word "attacker" is deliberately insufficient.
POSITIVE_LABEL_RE = re.compile(
    r"\b(?:attacker(?:['’]s|s)?|exploiter(?:['’]s|s)?|hacker(?:['’]s|s)?)\s*"
    r"(?:exploit\s+)?(?:eoa|wallets?|address(?:es)?|contracts?|multi[- ]?sig\s+contracts?|"
    r"pre[- ]?compute(?:d)?\s+address(?:es)?)\b"
    r"|\b(?:helper\s+)?(?:attack|exploit|malicious)\s+contracts?(?:\s+address(?:es)?)?\b"
    r"|\b(?:stolen\s+funds?|stolen\s+fund|profits?)\s*"
    r"(?:wallets?|address(?:es)?|receivers?|held\s+by|parked\s+at|remain(?:s)?\s+(?:here|at))\b"
    r"|\bcurrently\s+stolen\s+funds\s+parked\s+at\b"
    r"|\b(?:final\s+)?consolidation\s+(?:wallet|address)\b"
    r"|\blaundering\s+(?:wallet|address)\b"
    r"|\bfrontrunner\s+address\b"
    r"|\breceivers?\b"
    r"|\brelated\s+address\s+chain\b",
    re.IGNORECASE,
)

# These labels terminate a positive field and can never start one.  In
# particular, funders are not treated as thieves merely because they funded an
# attacker, and transaction links are not address evidence.
EXCLUDED_LABEL_RE = re.compile(
    r"\b(?:victims?|vulnerable|affected|official)\b[^:\n]{0,80}:"
    r"|\b(?:attackers?|attacker['’]s?|attack|exploit)\s+(?:transactions?|txs?)\b"
    r"|\b(?:transactions?|txs?)\b[^:\n]{0,40}:"
    r"|\b(?:funders?|funded\s+from|returned\s+token)\b"
    r"|\b(?:tss\s+hot\s+signer|sender['’]s?\s+address|multi[- ]?sig\s+signers?)\b"
    r"|\b(?:token|pool|router|bridge|protocol|deployer|implementation|proxy)\b[^:\n]{0,80}:",
    re.IGNORECASE,
)

MONTH_PATTERN = (
    r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
    r"Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|"
    r"Nov(?:ember)?|Dec(?:ember)?"
)
TEXT_DATE_RE = re.compile(
    rf"\b(?:"
    rf"(?P<month>{MONTH_PATTERN})\.?\s+(?P<day>\d{{1,2}})(?:st|nd|rd|th)?\s*,?\s+(?P<year>20\d{{2}})"
    rf"|(?P<day_first>\d{{1,2}})(?:st|nd|rd|th)?\s+(?:of\s+)?"
    rf"(?P<month_after>{MONTH_PATTERN})\.?\s*,?\s+(?P<year_after>20\d{{2}})"
    rf")\b",
    re.IGNORECASE,
)
MONTHS = {
    name.casefold(): number
    for number, names in enumerate(
        (
            (),
            ("jan", "january"),
            ("feb", "february"),
            ("mar", "march"),
            ("apr", "april"),
            ("may",),
            ("jun", "june"),
            ("jul", "july"),
            ("aug", "august"),
            ("sep", "sept", "september"),
            ("oct", "october"),
            ("nov", "november"),
            ("dec", "december"),
        )
    )
    for name in names
}


@dataclass(frozen=True)
class HackPost:
    post_id: int
    published_date: date
    link: str
    title: str
    content: str


class _ArticleTextParser(HTMLParser):
    """Flatten article blocks while keeping full link targets beside labels."""

    BLOCK_TAGS = frozenset({
        "p", "li", "div", "section", "article", "tr", "td", "th",
        "h1", "h2", "h3", "h4", "h5", "h6", "br", "hr", "pre",
    })

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def _break(self) -> None:
        if self.parts and self.parts[-1] != "\n":
            self.parts.append("\n")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        if tag in self.BLOCK_TAGS:
            self._break()
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.parts.append(f" {unquote(href)} ")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in self.BLOCK_TAGS:
            self._break()

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def article_lines(content: str) -> list[str]:
    parser = _ArticleTextParser()
    parser.feed(content)
    parser.close()
    return [
        re.sub(r"\s+", " ", unescape(line)).strip()
        for line in "".join(parser.parts).splitlines()
        if line.strip()
    ]


def incident_name(title: str) -> str:
    value = re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", title))).strip()
    value = re.sub(
        r"\s*[-–—:]?\s*Hack\s+Analysis\b.*$",
        "",
        value,
        flags=re.IGNORECASE,
    ).strip()
    if not value:
        raise ValueError("SolidityScan post has an empty incident name")
    return value


def incident_date(content: str) -> date | None:
    """Return the first explicit prose date near the article overview."""
    text = " ".join(article_lines(content))
    # Incident summaries are at the beginning.  Avoid later transaction dates,
    # historical comparisons and remediation timelines.
    overview = text[:5000]
    marker = re.search(r"\bSmart\s+Contract\s+Hack\s+Overview\b", overview, re.IGNORECASE)
    if marker:
        overview = overview[: marker.start()]
    for match in TEXT_DATE_RE.finditer(overview):
        month_text = match.group("month") or match.group("month_after")
        day_text = match.group("day") or match.group("day_first")
        year_text = match.group("year") or match.group("year_after")
        month = MONTHS.get(month_text.rstrip(".").casefold())
        if month is None:
            continue
        try:
            parsed = date(int(year_text), month, int(day_text))
        except ValueError:
            continue
        if date(2015, 1, 1) <= parsed <= date.today():
            return parsed
    return None


def _valid_address(value: str, hints: set[str]) -> tuple[str, str] | None:
    address = normalize_source_address(value)
    if EVM_RE.fullmatch(address) and (
        int(address[2:], 16) <= 0xFFFFFFFF
        or len(set(address[2:].casefold())) <= 1
        or address.casefold() in FORBIDDEN_ADDRESSES
    ):
        return None
    network = network_for_address(address, hints)
    if network is None:
        return None
    normalized = canonical_address(address)
    return normalized, network


def _addresses(value: str, hints: set[str]) -> list[tuple[str, str]]:
    found: dict[tuple[str, str], None] = {}
    for candidate in ADDRESS_CANDIDATE_RE.findall(unquote(value)):
        parsed = _valid_address(candidate, hints)
        if parsed:
            found.setdefault(parsed, None)
    return list(found)


def extract_addresses(content: str) -> list[tuple[str, str]]:
    """Extract addresses only from explicit malicious-role fields."""
    lines = article_lines(content)
    article_hint_codes = network_hints(" ".join(lines[:20]))
    accepted: dict[tuple[str, str], None] = {}
    active_positive = False

    for line in lines:
        markers: list[tuple[int, int, bool]] = [
            (match.start(), match.end(), True)
            for match in POSITIVE_LABEL_RE.finditer(line)
        ]
        markers.extend(
            (match.start(), match.end(), False)
            for match in EXCLUDED_LABEL_RE.finditer(line)
        )
        markers.sort(key=lambda item: (item[0], not item[2], item[1]))

        if markers:
            active_positive = markers[-1][2]
            for index, (_, end, positive) in enumerate(markers):
                if not positive:
                    continue
                stop = markers[index + 1][0] if index + 1 < len(markers) else len(line)
                segment = line[end:stop]
                hints = article_hint_codes.union(network_hints(line[:stop]))
                for address in _addresses(segment, hints):
                    accepted.setdefault(address, None)
            continue

        # Support a label in one block followed by one address-only block.  Any
        # prose or a new labelled field immediately terminates this small state.
        if active_positive:
            candidates = _addresses(line, article_hint_codes.union(network_hints(line)))
            addressish = bool(candidates) and len(line) <= 500
            if addressish:
                for address in candidates:
                    accepted.setdefault(address, None)
            active_positive = False

    return list(accepted)


def row_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        canonical_address(str(row["address"])),
        row["network"],
        " ".join(str(row["incident_name"]).casefold().split()),
        row["incident_date"],
    )


def rows_to_table(rows: Iterable[dict[str, Any]]) -> pa.Table:
    return pa.Table.from_pylist(
        sorted(
            rows,
            key=lambda row: (
                row["incident_date"],
                row["incident_name"].casefold(),
                row["network"],
                row["address"],
            ),
        ),
        schema=OUTPUT_SCHEMA,
    )


def validate_table(table: pa.Table, source: str = "SolidityScan hack analysis") -> None:
    if not table.schema.equals(OUTPUT_SCHEMA, check_metadata=False):
        raise ValueError(f"Unexpected schema in {source}; expected {OUTPUT_SCHEMA}")
    if not table.num_rows:
        raise ValueError(f"Table is empty: {source}; refusing to upload")
    if any(table[field.name].null_count for field in OUTPUT_SCHEMA):
        raise ValueError(f"NULL values in {source}")

    seen: set[tuple[Any, ...]] = set()
    for row in table.to_pylist():
        address = str(row["address"])
        candidates = validated_network_codes(address)
        valid_networks = {NETWORK_NAMES[code] for code in candidates}
        if (
            canonical_address(address) != address
            or row["network"] not in valid_networks
            or (EVM_RE.fullmatch(address) and _valid_address(address, {"ETH"}) is None)
        ):
            raise ValueError(f"Invalid/noncanonical address or network in {source}: {address}")
        if not str(row["incident_name"]).strip():
            raise ValueError(f"Empty incident_name in {source}")
        if not date(2015, 1, 1) <= row["incident_date"] <= date.today():
            raise ValueError(f"Invalid incident_date in {source}: {row['incident_date']}")
        key = row_key(row)
        if key in seen:
            raise ValueError(f"Duplicate address/incident in {source}: {key}")
        seen.add(key)


def build_table_from_posts(posts: Iterable[HackPost]) -> pa.Table:
    records: dict[tuple[Any, ...], dict[str, Any]] = {}
    post_count = accepted_posts = skipped_date = 0
    for post in posts:
        post_count += 1
        name = incident_name(post.title)
        when = incident_date(post.content)
        addresses = extract_addresses(post.content)
        if not addresses:
            LOGGER.debug("SolidityScan %s: no explicitly attributed malicious addresses", post.link)
            continue
        if when is None:
            skipped_date += 1
            LOGGER.warning("SolidityScan %s: addresses found but incident date is ambiguous", post.link)
            continue
        accepted_posts += 1
        for address, network in addresses:
            row = {
                "address": address,
                "network": network,
                "incident_date": when,
                "incident_name": name,
            }
            records.setdefault(row_key(row), row)

    table = rows_to_table(records.values())
    if not table.num_rows:
        raise RuntimeError("SolidityScan returned no dated, explicitly attributed addresses")
    validate_table(table)
    LOGGER.info(
        "SolidityScan extraction: posts=%d, accepted_posts=%d, skipped_ambiguous_date=%d, "
        "rows=%d, unique_addresses=%d",
        post_count,
        accepted_posts,
        skipped_date,
        table.num_rows,
        len(set(table["address"].to_pylist())),
    )
    return table


def _positive_integer_header(headers: Mapping[str, str], name: str) -> int:
    value = str(headers.get(name, "")).strip()
    if not value.isdigit() or int(value) <= 0:
        raise ValueError(f"SolidityScan API omitted valid {name} pagination metadata")
    return int(value)


def _response_payload(response: requests.Response) -> bytes:
    output = io.BytesIO()
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if output.tell() + len(chunk) > MAX_PAGE_BYTES:
            raise ValueError("SolidityScan API response exceeds safety size limit")
        output.write(chunk)
    return output.getvalue()


def _parse_post(value: Any) -> HackPost:
    if not isinstance(value, dict):
        raise ValueError("SolidityScan API post is not an object")
    try:
        post_id = int(value["id"])
        published = datetime.fromisoformat(str(value["date"]).replace("Z", "+00:00")).date()
        link = str(value["link"])
        title = str(value["title"]["rendered"])
        content = str(value["content"]["rendered"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("SolidityScan API post has an unexpected shape") from error
    parsed_link = urlsplit(link)
    if (
        post_id <= 0
        or parsed_link.scheme != "https"
        or parsed_link.netloc.casefold() != "blog.solidityscan.com"
        or not parsed_link.path.strip("/")
        or not title.strip()
        or not content.strip()
    ):
        raise ValueError("SolidityScan API post contains invalid metadata")
    return HackPost(post_id, published, link, title, content)


def _fetch_page(
    session: requests.Session, page: int, timeout: int,
) -> tuple[list[HackPost], int, int]:
    with session.get(
        API_URL,
        params={
            "categories": CATEGORY_ID,
            "per_page": PER_PAGE,
            "page": page,
            "status": "publish",
            "orderby": "date",
            "order": "desc",
            "_fields": "id,date,link,title,content",
        },
        timeout=timeout,
        stream=True,
    ) as response:
        response.raise_for_status()
        total = _positive_integer_header(response.headers, "X-WP-Total")
        total_pages = _positive_integer_header(response.headers, "X-WP-TotalPages")
        payload = _response_payload(response)
    try:
        values = json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("SolidityScan API returned invalid JSON") from error
    if not isinstance(values, list) or not values:
        raise ValueError(f"SolidityScan API page {page} is empty or malformed")
    return [_parse_post(value) for value in values], total, total_pages


def fetch_all_posts(*, timeout: int, retries: int) -> list[HackPost]:
    if timeout <= 0 or not 0 <= retries <= 5:
        raise ValueError("Timeout must be positive; retries must be between 0 and 5")
    with requests.Session() as session:
        retry = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
        )
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.headers.update({
            "Accept": "application/json",
            "User-Agent": "stolen-assets-solidityscan-parser/1.0",
        })
        first, expected_total, total_pages = _fetch_page(session, 1, timeout)
        posts = list(first)
        for page in range(2, total_pages + 1):
            current, total, pages = _fetch_page(session, page, timeout)
            if (total, pages) != (expected_total, total_pages):
                raise RuntimeError("SolidityScan pagination changed during download")
            posts.extend(current)

    ids = [post.post_id for post in posts]
    links = [post.link for post in posts]
    if len(posts) != expected_total:
        raise RuntimeError(
            f"SolidityScan advertised {expected_total} posts but returned {len(posts)}"
        )
    if len(set(ids)) != len(ids) or len(set(links)) != len(links):
        raise RuntimeError("SolidityScan API returned duplicate posts")
    return posts


def merge_with_existing(
    existing: pa.Table | None, current: pa.Table,
) -> tuple[pa.Table, int, int]:
    """Append newly observed address/incident rows without deleting history."""
    validate_table(current, "current SolidityScan table")
    if existing is None:
        return current, current.num_rows, 0
    validate_table(existing, "existing SolidityScan S3 table")
    records = {row_key(row): row for row in existing.to_pylist()}
    added = 0
    for row in current.to_pylist():
        key = row_key(row)
        if key not in records:
            records[key] = row
            added += 1
    if not added:
        return existing, 0, 0
    merged = rows_to_table(records.values())
    validate_table(merged, "merged SolidityScan table")
    return merged, added, 0


def build_table() -> pa.Table:
    posts = fetch_all_posts(
        timeout=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "60")),
        retries=int(os.getenv("SOLIDITYSCAN_MAX_RETRIES", "3")),
    )
    return build_table_from_posts(posts)


def main() -> None:
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
    argparse.ArgumentParser(
        description="Parse SolidityScan hack-analysis addresses in memory; no S3 writes"
    ).parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    try:
        table = build_table()
        print(table.schema)
        print(f"Rows: {table.num_rows}; unique addresses: {len(set(table['address'].to_pylist()))}")
    except (OSError, RuntimeError, ValueError, requests.RequestException, pa.ArrowException):
        LOGGER.exception("SolidityScan hack-analysis parsing failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
