"""Read all published crypto addresses from SoKSPBlockchainInterop tables.

Only the complete bridge_hacks tables and the date CSV are used. Transaction
hashes are rejected; address roles are not filtered or inferred. Addresses in
text and URL targets are included, but linked websites/lists are not crawled.
Repository code is never executed; all downloads and Parquet data stay in memory.
"""
from __future__ import annotations

import argparse
import csv
import io
import logging
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import quote, unquote

import pyarrow as pa
import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from telegram_investigations_parser import (
    ADDRESS_CANDIDATE_RE, canonical_address, network_for_address,
    network_hints, normalize_source_address,
)


LOGGER = logging.getLogger("sok_interop")
REPOSITORY = "RafaelAPB/SoKSPBlockchainInterop"
GITHUB_URL = f"https://github.com/{REPOSITORY}"
S3_KEY = "stolen_assets/sok_interop.parquet"
ADDRESS_FILE = "bridge_hacks/txs_and_addresses_hashes.md"
RESPONSE_FILE = "bridge_hacks/incident_response.md"
DATE_FILE = "data/all_bridge_hacks.csv"
SOURCE_FILES = (ADDRESS_FILE, RESPONSE_FILE, DATE_FILE)
MAX_FILE_BYTES = 2 * 1024 * 1024
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
OUTPUT_SCHEMA = pa.schema([
    pa.field("address", pa.string(), nullable=False),
    pa.field("network", pa.string(), nullable=False),
    pa.field("hacked_bridge", pa.string(), nullable=False),
    pa.field("incident_date", pa.date32(), nullable=True),
    pa.field("link", pa.string(), nullable=False),
])
ADDRESS_HEADERS = ("Hacked Bridge", "Transaction, Addresses and Other details")
RESPONSE_HEADERS = ("Hacked Bridge", "First Transaction (Blockchain)", "Public Announcement")
POST_RE = re.compile(
    r"https://(?:www\.)?(?:twitter\.com|x\.com)/[A-Za-z0-9_]+/status/([0-9]{15,20})(?=[/?#)\s]|$)"
)
EVIDENCE_URL_RE = re.compile(
    re.escape(GITHUB_URL) + r"/blob/[0-9a-f]{40}/(?:"
    + "|".join(re.escape(path) for path in (ADDRESS_FILE, RESPONSE_FILE))
    + r")#L[1-9][0-9]*\Z"
)


@dataclass(frozen=True)
class MarkdownRow:
    cells: tuple[str, ...]
    line: int


class _CellText(HTMLParser):
    def __init__(self, *, include_links: bool = False) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.include_links = include_links

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"br", "p", "div", "li"}:
            self.parts.append("\n")
        if tag == "a" and self.include_links:
            href = dict(attrs).get("href")
            if href:
                self.parts.append(f" {href} ")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"p", "div", "li"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def cell_text(value: str) -> str:
    parser = _CellText()
    parser.feed(value)
    parser.close()
    return "".join(parser.parts).replace("**", "").replace("`", "").strip()


def bridge_key(name: str) -> str:
    # CSV uses 'Poly Network', 'pNetwork', 'Thorchain' and 'BXH'.
    name = re.sub(r"\s*#\d+\s*$", "", cell_text(name))
    key = re.sub(r"[^a-z0-9]", "", name.casefold())
    return {"boyxhighspeed": "bxh"}.get(key, key)


def parse_markdown_table(text: str, headers: tuple[str, ...]) -> list[MarkdownRow]:
    rows: list[MarkdownRow] = []
    found = separator_found = False
    for line_number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line.startswith("|") or not line.endswith("|"):
            if found and line:
                raise ValueError(f"Unexpected content inside table at line {line_number}")
            continue
        cells = tuple(part.strip().replace(r"\|", "|") for part in re.split(r"(?<!\\)\|", line[1:-1]))
        if not found:
            if tuple(cell_text(cell) for cell in cells) == headers:
                found = True
            continue
        if len(cells) != len(headers):
            raise ValueError(f"Wrong table width at line {line_number}")
        if not separator_found:
            if not all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                raise ValueError("Markdown table has no valid header separator")
            separator_found = True
            continue
        if not cell_text(cells[0]):
            raise ValueError(f"Missing bridge name at line {line_number}")
        rows.append(MarkdownRow(cells, line_number))
    if not found or not separator_found or not rows:
        raise ValueError(f"Missing or empty source table: {headers}")
    return rows


def parse_dates(text: str) -> dict[str, list[date]]:
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
    if reader.fieldnames != ["bridge", "date", "value"]:
        raise ValueError("Unexpected all_bridge_hacks.csv columns")
    dates: dict[str, list[date]] = defaultdict(list)
    for row in reader:
        if None in row or any(row[name] is None for name in reader.fieldnames):
            raise ValueError(f"Malformed incident CSV record at line {reader.line_num}")
        key = bridge_key(row["bridge"])
        if not key or not re.fullmatch(r"\d{2}/\d{2}/\d{4}", row["date"].strip()):
            raise ValueError(f"Invalid bridge/date at CSV line {reader.line_num}")
        dates[key].append(datetime.strptime(row["date"].strip(), "%d/%m/%Y").date())
    if not dates:
        raise ValueError("Incident date CSV is empty")
    return dict(dates)


def announcement_date(text: str) -> date | None:
    """Decode public post time only as a matching hint, NOT an incident date.

    Snowflake layout: twitter-archive/snowflake, IdWorker.scala (2010 version).
    No Twitter/X API request, login or post scraping is performed.
    """
    dates: set[date] = set()
    for match in POST_RE.finditer(text):
        post_id = int(match[1])
        if not 0 < post_id < 2**63:
            continue
        milliseconds = (post_id >> 22) + 1288834974657
        timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=milliseconds)
        if date(2011, 1, 1) <= timestamp.date() <= datetime.now(timezone.utc).date():
            dates.add(timestamp.date())
    return next(iter(dates)) if len(dates) == 1 else None


def resolve_incident_date(
    bridge: str, announcement: str, date_index: Mapping[str, list[date]], *, occurrences: int,
) -> date | None:
    candidates = list(date_index.get(bridge_key(bridge), ()))
    published = announcement_date(announcement)
    if published is not None:
        candidates = [value for value in candidates if (value.year, value.month) == (published.year, published.month)]
    elif occurrences > 1:
        candidates = []
    if len(candidates) == 1:
        return candidates[0]
    LOGGER.warning(
        "No unambiguous CSV incident date for %s (announcement=%s, candidates=%s); keeping NULL",
        bridge, published, [value.isoformat() for value in candidates],
    )
    return None


def _address(value: str, hints: set[str]) -> tuple[str, str] | None:
    value = normalize_source_address(value)
    network = network_for_address(value, hints)
    return (canonical_address(value), network) if network else None


def extract_addresses(details: str) -> list[tuple[str, str]]:
    """Scan all text and link targets, regardless of labels or claimed roles."""
    parser = _CellText(include_links=True)
    parser.feed(details)
    parser.close()
    # Decode URL-encoded addresses without requesting any linked resource.
    searchable = unquote("".join(parser.parts))
    accepted: dict[tuple[str, str], None] = {}
    hints: set[str] = set()
    for line in searchable.splitlines():
        if not line.strip():
            hints = set()
            continue
        line_hints = network_hints(line)
        if line_hints:
            hints = line_hints
        for candidate in ADDRESS_CANDIDATE_RE.findall(line):
            # Validate whole tokens: never truncate a transaction hash to 40 hex.
            found = _address(candidate, hints)
            if found is None and ":" in candidate:
                # Also support labels without a space, e.g. Address:0x... .
                found = _address(candidate.rsplit(":", 1)[1], hints)
            if found:
                accepted.setdefault(found, None)
    return list(accepted)


def extract_attacker_addresses(details: str) -> list[tuple[str, str]]:
    """Backward-compatible name; now returns ALL valid addresses, not roles."""
    return extract_addresses(details)


def row_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    # Keep #1/#2 labels in identities; only the CSV lookup drops numbering.
    bridge = " ".join(row["hacked_bridge"].casefold().split())
    return row["address"], row["network"], bridge, row["incident_date"]


def rows_to_table(rows: Iterable[dict[str, Any]]) -> pa.Table:
    return pa.Table.from_pylist(sorted(rows, key=lambda row: (
        row["incident_date"] or date.max, row["hacked_bridge"].casefold(), row["network"], row["address"], row["link"],
    )), schema=OUTPUT_SCHEMA)


def validate_table(table: pa.Table, source: str = "SoK interoperability") -> None:
    if not table.schema.equals(OUTPUT_SCHEMA, check_metadata=False):
        raise ValueError(f"Unexpected schema in {source}; expected {OUTPUT_SCHEMA}")
    if not table.num_rows:
        raise ValueError(f"Table is empty: {source}; refusing to upload")
    for field in OUTPUT_SCHEMA:
        if not field.nullable and table[field.name].null_count:
            raise ValueError(f"NULL in required column {field.name} in {source}")
    seen: set[tuple[Any, ...]] = set()
    for row in table.to_pylist():
        found = _address(row["address"], network_hints(row["network"]))
        if found != (row["address"], row["network"]):
            raise ValueError(f"Invalid/noncanonical address or network in {source}: {row['address']}")
        if not bridge_key(row["hacked_bridge"]) or not EVIDENCE_URL_RE.fullmatch(row["link"]):
            raise ValueError(f"Invalid bridge or evidence link in {source}")
        key = row_key(row)
        if key in seen:
            raise ValueError(f"Duplicate address/bridge/incident in {source}: {key}")
        seen.add(key)


def parse_snapshot(files: Mapping[str, str], commit: str) -> pa.Table:
    if not SHA_RE.fullmatch(commit):
        raise ValueError("Exact 40-character Git commit SHA is required")
    if any(path not in files for path in SOURCE_FILES):
        raise ValueError("Incomplete SoK source snapshot")
    details = parse_markdown_table(files[ADDRESS_FILE], ADDRESS_HEADERS)
    responses = parse_markdown_table(files[RESPONSE_FILE], RESPONSE_HEADERS)
    # These parallel source tables use the same order, including repeated names.
    # Never zip a partial/reordered table: a bridge name alone is not an incident ID.
    labels = [cell_text(row.cells[0]).casefold() for row in details]
    if labels != [cell_text(row.cells[0]).casefold() for row in responses]:
        raise ValueError("Bridge detail/response tables differ in row count or bridge order")
    date_index = parse_dates(files[DATE_FILE])
    occurrences = Counter(bridge_key(row.cells[0]) for row in details)
    records: dict[tuple[Any, ...], dict[str, Any]] = {}
    accepted_incidents = 0
    for detail, response in zip(details, responses):
        bridge = cell_text(detail.cells[0])
        addresses: dict[tuple[str, str], tuple[str, int]] = {}
        for path, source_row in ((ADDRESS_FILE, detail), (RESPONSE_FILE, response)):
            for address in extract_addresses("\n".join(source_row.cells[1:])):
                addresses.setdefault(address, (path, source_row.line))
        if not addresses:
            LOGGER.info("SoK %s at line %d: no valid crypto addresses published", bridge, detail.line)
            continue
        incident_date = resolve_incident_date(
            bridge, response.cells[2], date_index, occurrences=occurrences[bridge_key(bridge)],
        )
        accepted_incidents += 1
        for (address, network), (path, line) in addresses.items():
            row = {
                "address": address, "network": network, "hacked_bridge": bridge,
                "incident_date": incident_date,
                "link": f"{GITHUB_URL}/blob/{commit}/{path}#L{line}",
            }
            records.setdefault(row_key(row), row)
        LOGGER.info("SoK %s (%s): accepted addresses=%d", bridge, incident_date, len(addresses))
    table = rows_to_table(records.values())
    LOGGER.info(
        "SoK commit=%s; incident rows=%d; accepted incidents=%d; rows=%d; unique addresses=%d; missing dates=%d",
        commit, len(details), accepted_incidents, table.num_rows,
        len(set(table["address"].to_pylist())), table["incident_date"].null_count,
    )
    return table


def merge_with_existing(existing: pa.Table | None, current: pa.Table) -> tuple[pa.Table, int, int]:
    validate_table(current, "current SoK table")
    if existing is None:
        return current, current.num_rows, 0
    validate_table(existing, "existing SoK S3 table")
    records = {row_key(row): row for row in existing.to_pylist()}
    added = updated = 0
    for row in current.to_pylist():
        key = row_key(row)
        old = records.get(key)
        if old is None:
            added += 1
        elif old != row:
            updated += 1
        records[key] = row
    merged = rows_to_table(records.values())
    validate_table(merged, "merged SoK table")
    return merged, added, updated


def _download_text(session: requests.Session, url: str, timeout: int) -> str:
    with session.get(url, timeout=timeout, stream=True) as response:
        response.raise_for_status()
        output = io.BytesIO()
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if output.tell() + len(chunk) > MAX_FILE_BYTES:
                raise ValueError("SoK source response exceeds safety size limit")
            output.write(chunk)
    return output.getvalue().decode("utf-8-sig")


def download_snapshot(ref: str, timeout: int, retries: int) -> tuple[str, dict[str, str]]:
    if not ref.strip() or ref != ref.strip() or ref.startswith("-") or len(ref) > 200:
        raise ValueError("Invalid SOK_INTEROP_REF")
    if timeout <= 0 or not 0 <= retries <= 5:
        raise ValueError("Timeout must be positive; retries must be between 0 and 5")
    with requests.Session() as session:
        retry = Retry(total=retries, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504), allowed_methods=frozenset({"GET"}))
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.headers.update({"User-Agent": "stolen-assets-sok-interop-parser/1.0"})
        if SHA_RE.fullmatch(ref):
            commit = ref
        else:
            LOGGER.info("Resolving SoK Git ref %s", ref)
            response = session.get(
                f"https://api.github.com/repos/{REPOSITORY}/commits/{quote(ref, safe='')}",
                timeout=timeout, headers={"Accept": "application/vnd.github+json"},
            )
            response.raise_for_status()
            commit = str(response.json().get("sha", ""))
            if not SHA_RE.fullmatch(commit):
                raise ValueError("GitHub did not return a commit SHA")
        files: dict[str, str] = {}
        for path in SOURCE_FILES:
            LOGGER.info("Downloading SoK file %s at %s", path, commit)
            files[path] = _download_text(session, f"https://raw.githubusercontent.com/{REPOSITORY}/{commit}/{path}", timeout)
    return commit, files


def build_table(*, ref: str | None = None) -> pa.Table:
    commit, files = download_snapshot(
        ref if ref is not None else os.getenv("SOK_INTEROP_REF", "main"),
        int(os.getenv("REQUEST_TIMEOUT_SECONDS", "60")),
        int(os.getenv("SOK_INTEROP_MAX_RETRIES", "3")),
    )
    table = parse_snapshot(files, commit)
    validate_table(table)
    return table


def main() -> None:
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
    parser = argparse.ArgumentParser(description="Parse all published SoK bridge addresses in memory; no S3 writes")
    parser.add_argument("--ref", help="Git branch/tag or exact commit SHA; defaults to SOK_INTEROP_REF/main")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    try:
        table = build_table(ref=args.ref)
        print(table.schema)
        print(f"Rows: {table.num_rows}; unique addresses: {len(set(table['address'].to_pylist()))}")
    except (OSError, ValueError, RuntimeError, requests.RequestException, pa.ArrowException):
        LOGGER.exception("SoK interoperability parsing failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
