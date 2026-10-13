from __future__ import annotations

import argparse
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

import pyarrow as pa
import requests
from dotenv import load_dotenv

from telegram_investigations_parser import (
    ADDRESS_CANDIDATE_RE,
    LEGACY_SCHEMA,
    canonical_address,
    network_for_address,
    network_hints,
    normalize_source_address,
)


PROJECT_DIR = Path(__file__).resolve().parent
SHARED_ENV_FILE = PROJECT_DIR.parent / "terrorism_parser_new" / ".env"
if SHARED_ENV_FILE.exists():
    load_dotenv(SHARED_ENV_FILE, override=False)
load_dotenv(PROJECT_DIR / ".env", override=True)

LOGGER = logging.getLogger("slowmist_hacked_parser")
DEFAULT_SOURCE_URL = "https://hacked.slowmist.io/?c=&page=1"
S3_KEY = "stolen_assets/slowmist_hacked.parquet"
OUTPUT_SCHEMA = pa.schema(
    [*LEGACY_SCHEMA, pa.field("hacked_target", pa.string(), nullable=True)]
)
MAX_PAGE_BYTES = 5 * 1024 * 1024
HACKED_TARGET_RE = re.compile(r"^Hacked\s+target\s*:\s*(.*)$", re.IGNORECASE)
PAGINATION_RE = re.compile(r"\bPage\s+(\d+)\s+of\s+(\d+)\b", re.IGNORECASE)
TOTAL_EVENTS_RE = re.compile(
    r"\b([\d][\d, ]*)\s+hack\s+event(?:\(s\)|s)?\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SlowMistEvent:
    listed_date: date
    text: str
    links: tuple[str, ...]
    hacked_target: str | None = None


@dataclass(frozen=True)
class SlowMistPage:
    page_number: int
    total_pages: int
    total_events: int
    events: tuple[SlowMistEvent, ...]


class _SlowMistPageHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.events: list[SlowMistEvent] = []
        self.all_text: list[str] = []
        self._case_div_depth = 0
        self._event_parts: list[str] | None = None
        self._event_links: list[str] = []
        self._time_parts: list[str] = []
        self._inside_time = False
        self._heading_parts: list[str] | None = None
        self._hacked_target: str | None = None

    @staticmethod
    def _attributes(attributes: list[tuple[str, str | None]]) -> dict[str, str]:
        return {name: value or "" for name, value in attributes}

    def handle_starttag(
        self,
        tag: str,
        attributes: list[tuple[str, str | None]],
    ) -> None:
        values = self._attributes(attributes)
        classes = set(values.get("class", "").split())

        if tag == "div":
            if self._case_div_depth:
                self._case_div_depth += 1
            elif "case-content" in classes:
                self._case_div_depth = 1

        if self._case_div_depth and tag == "li" and self._event_parts is None:
            self._event_parts = []
            self._event_links = []
            self._time_parts = []
            self._heading_parts = None
            self._hacked_target = None

        if self._event_parts is None:
            return
        if tag == "span" and "time" in classes:
            self._inside_time = True
        if tag == "h3":
            self._heading_parts = []
        if tag == "br" and self._heading_parts is not None:
            self._heading_parts.append(" ")
        if tag == "a":
            href = values.get("href", "").strip()
            if href and not href.lower().startswith("javascript:"):
                self._event_links.append(href)

    def handle_data(self, data: str) -> None:
        if self._heading_parts is not None:
            # Keep inline fragments together: <a>warp.</a><b>green</b>.
            self._heading_parts.append(data)
        cleaned = " ".join(data.split())
        if not cleaned:
            return
        self.all_text.append(cleaned)
        if self._event_parts is not None:
            self._event_parts.append(cleaned)
            if self._inside_time:
                self._time_parts.append(cleaned)

    def handle_endtag(self, tag: str) -> None:
        if tag == "span" and self._inside_time:
            self._inside_time = False

        if tag == "h3" and self._heading_parts is not None:
            heading = " ".join("".join(self._heading_parts).split())
            match = HACKED_TARGET_RE.fullmatch(heading)
            if match is not None:
                self._hacked_target = match.group(1).strip() or None
            self._heading_parts = None

        if tag == "li" and self._event_parts is not None:
            date_text = " ".join(self._time_parts)
            try:
                listed_date = date.fromisoformat(date_text)
            except ValueError as error:
                raise ValueError(
                    f"SlowMist event has an invalid date: {date_text!r}"
                ) from error
            self.events.append(
                SlowMistEvent(
                    listed_date=listed_date,
                    text=" ".join(self._event_parts),
                    links=tuple(dict.fromkeys(self._event_links)),
                    hacked_target=self._hacked_target,
                )
            )
            self._event_parts = None
            self._event_links = []
            self._time_parts = []
            self._inside_time = False
            self._heading_parts = None
            self._hacked_target = None

        if tag == "div" and self._case_div_depth:
            self._case_div_depth -= 1


def optional_setting(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def integer_setting(name: str, default: int, *, allow_zero: bool = False) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    result = int(value)
    minimum = 0 if allow_zero else 1
    if result < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return result


def float_setting(name: str, default: float) -> float:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    result = float(value)
    if result < 0:
        raise ValueError(f"{name} must not be negative")
    return result


def page_url(base_url: str, page_number: int) -> str:
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["page"] = str(page_number)
    query.setdefault("c", "")
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path or "/", urlencode(query), parts.fragment)
    )


def parse_slowmist_page(html: str, *, expected_page: int | None = None) -> SlowMistPage:
    parser = _SlowMistPageHTMLParser()
    parser.feed(html)
    parser.close()

    page_text = " ".join(parser.all_text)
    pagination = PAGINATION_RE.search(page_text)
    if pagination is None:
        raise ValueError("SlowMist HTML has no 'Page N of M' pagination")
    page_number, total_pages = (int(value) for value in pagination.groups())
    if expected_page is not None and page_number != expected_page:
        raise ValueError(
            f"Requested SlowMist page {expected_page}, received page {page_number}"
        )
    total_match = TOTAL_EVENTS_RE.search(page_text)
    if total_match is None:
        raise ValueError("SlowMist HTML has no total hack-event count")
    total_events = int(total_match.group(1).replace(",", "").replace(" ", ""))
    if not parser.events:
        raise ValueError(f"SlowMist page {page_number} contains no hack events")
    return SlowMistPage(
        page_number=page_number,
        total_pages=total_pages,
        total_events=total_events,
        events=tuple(parser.events),
    )


def _decode_response(response: requests.Response) -> str:
    payload = response.content
    if len(payload) > MAX_PAGE_BYTES:
        raise ValueError(
            f"SlowMist response is too large: {len(payload)} > {MAX_PAGE_BYTES} bytes"
        )
    encoding = response.encoding
    if not encoding or encoding.lower() in {"iso-8859-1", "latin-1"}:
        encoding = "utf-8"
    return payload.decode(encoding, errors="replace")


def _fetch_page(
    session: requests.Session,
    *,
    url: str,
    page_number: int,
    timeout: int,
    max_retries: int,
) -> SlowMistPage:
    last_error: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            response = session.get(url, timeout=timeout)
            response.raise_for_status()
            return parse_slowmist_page(
                _decode_response(response),
                expected_page=page_number,
            )
        except (requests.RequestException, ValueError) as error:
            last_error = error
            if attempt >= max_retries:
                break
            backoff = min(2 ** (attempt - 1), 30)
            LOGGER.warning(
                "SlowMist page %d failed on attempt %d/%d: %s; retrying in %ds",
                page_number,
                attempt,
                max_retries,
                error,
                backoff,
            )
            time.sleep(backoff)
    assert last_error is not None
    raise RuntimeError(
        f"SlowMist page {page_number} failed after {max_retries} attempts"
    ) from last_error


def fetch_all_events(
    session: requests.Session,
    *,
    max_pages: int | None = None,
) -> list[SlowMistEvent]:
    base_url = optional_setting("SLOWMIST_HACKED_URL") or DEFAULT_SOURCE_URL
    timeout = integer_setting("REQUEST_TIMEOUT_SECONDS", 60)
    max_retries = integer_setting("SLOWMIST_MAX_RETRIES", 4)
    delay = float_setting("SLOWMIST_REQUEST_DELAY_SECONDS", 0.5)
    configured_limit = integer_setting("SLOWMIST_MAX_PAGES", 0, allow_zero=True)
    page_limit = configured_limit if max_pages is None else max_pages
    if page_limit is not None and page_limit < 0:
        raise ValueError("max_pages must not be negative")

    events: list[SlowMistEvent] = []
    expected_total_pages: int | None = None
    expected_total_events: int | None = None
    previous_signature: tuple[tuple[date, str], ...] | None = None
    page_number = 1
    reached_final_page = False

    while True:
        LOGGER.info("Downloading SlowMist Hacked HTML page %d", page_number)
        parsed = _fetch_page(
            session,
            url=page_url(base_url, page_number),
            page_number=page_number,
            timeout=timeout,
            max_retries=max_retries,
        )
        if expected_total_pages is None:
            expected_total_pages = parsed.total_pages
            expected_total_events = parsed.total_events
        elif (
            parsed.total_pages != expected_total_pages
            or parsed.total_events != expected_total_events
        ):
            raise RuntimeError(
                "SlowMist pagination changed during parsing; rerun to avoid missing "
                "or duplicating events"
            )

        signature = tuple((event.listed_date, event.text) for event in parsed.events)
        if signature == previous_signature:
            raise RuntimeError(f"SlowMist repeated HTML page {page_number}")
        previous_signature = signature
        events.extend(parsed.events)
        LOGGER.info(
            "SlowMist page %d/%d: events=%d, collected=%d of %d",
            page_number,
            parsed.total_pages,
            len(parsed.events),
            len(events),
            parsed.total_events,
        )

        if page_number >= parsed.total_pages:
            reached_final_page = True
            break
        if page_limit and page_number >= page_limit:
            LOGGER.warning(
                "SLOWMIST_MAX_PAGES=%d returned an explicitly partial debug dataset",
                page_limit,
            )
            break
        page_number += 1
        if delay:
            time.sleep(delay)

    if (
        reached_final_page
        and expected_total_events is not None
        and len(events) != expected_total_events
    ):
        raise RuntimeError(
            f"SlowMist advertised {expected_total_events} events but returned {len(events)}"
        )
    return events


def extract_addresses(event: SlowMistEvent) -> list[tuple[str, str]]:
    searchable = " ".join([event.text, *(unquote(link) for link in event.links)])
    hints = network_hints(searchable)
    detected: dict[str, tuple[str, str]] = {}
    for candidate in ADDRESS_CANDIDATE_RE.findall(searchable):
        address = normalize_source_address(candidate)
        network = network_for_address(address, hints)
        if network is None:
            continue
        normalized = canonical_address(address)
        detected.setdefault(normalized, (normalized, network))
    return list(detected.values())


def _observation_key(row: dict[str, Any]) -> tuple[date, bool, str, str]:
    """Pick an earliest event, breaking same-day ties deterministically."""
    target = row["hacked_target"] or ""
    return row["listed_date"], not bool(target), target.casefold(), target


def validate_table(table: pa.Table, source: str = "SlowMist") -> None:
    if not table.schema.equals(OUTPUT_SCHEMA, check_metadata=False):
        raise ValueError(f"Unexpected schema in {source}: {table.schema}")
    if not table.num_rows:
        raise ValueError(f"Table is empty: {source}")
    for field in OUTPUT_SCHEMA:
        if not field.nullable and table[field.name].null_count:
            raise ValueError(f"Column {field.name} contains nulls in {source}")
    keys: set[str] = set()
    for row in table.to_pylist():
        address = row["wallet_address"]
        if not address.strip() or not row["network"].strip():
            raise ValueError(f"Empty address or network in {source}")
        key = canonical_address(address)
        if key in keys:
            raise ValueError(f"Duplicate address {address} in {source}")
        keys.add(key)
        if row["hacked_target"] is not None and not row["hacked_target"].strip():
            raise ValueError(f"Empty hacked_target for {address}; use null in {source}")


def _rows_to_table(rows: Iterable[dict[str, Any]]) -> pa.Table:
    sorted_rows = sorted(
        rows,
        key=lambda row: (row["listed_date"], row["network"], row["wallet_address"]),
    )
    table = pa.Table.from_pylist(sorted_rows, schema=OUTPUT_SCHEMA)
    validate_table(table)
    return table


def build_table_from_events(events: Iterable[SlowMistEvent]) -> pa.Table:
    records: dict[str, dict[str, Any]] = {}
    observations = 0
    event_count = 0
    for event in events:
        event_count += 1
        for address, network in extract_addresses(event):
            observations += 1
            key = canonical_address(address)
            current = records.get(key)
            row = {
                "wallet_address": key,
                "network": network,
                "listed_date": event.listed_date,
                "hacked_target": event.hacked_target,
            }
            if current is None:
                records[key] = row
                continue
            if current["network"] != network:
                raise ValueError(
                    f"Address {address} resolved to conflicting networks: "
                    f"{current['network']} and {network}"
                )
            if _observation_key(row) < _observation_key(current):
                # Date and target always refer to the same event.
                records[key] = row

    if not records:
        raise RuntimeError("SlowMist Hacked returned no valid crypto addresses")
    table = _rows_to_table(records.values())
    LOGGER.info(
        "SlowMist extraction: events=%d, observations=%d, unique_addresses=%d",
        event_count,
        observations,
        table.num_rows,
    )
    return table


def merge_with_existing(
    existing: pa.Table | None, current: pa.Table,
) -> tuple[pa.Table, int, int]:
    """Union by address; keep the title paired with the earliest known date."""
    validate_table(current, "current SlowMist table")
    if existing is None:
        return current, current.num_rows, 0
    validate_table(existing, "existing SlowMist S3 table")
    records = {
        canonical_address(row["wallet_address"]): row
        for row in existing.to_pylist()
    }
    added = updated = 0
    for row in current.to_pylist():
        key = canonical_address(row["wallet_address"])
        old = records.get(key)
        if old is None:
            records[key] = row
            added += 1
            continue
        if old["network"] != row["network"]:
            raise ValueError(f"Conflicting networks for {key} in SlowMist merge")
        if row["listed_date"] < old["listed_date"] or (
            row["listed_date"] == old["listed_date"]
            and row["hacked_target"] is not None
            and row["hacked_target"] != old["hacked_target"]
        ):
            records[key] = row
            updated += 1
    if not added and not updated:
        return existing, 0, 0
    return _rows_to_table(records.values()), added, updated


def build_table(*, max_pages: int | None = None) -> pa.Table:
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
            "User-Agent": "stolen-assets-slowmist-parser/1.0",
        }
    )
    try:
        events = fetch_all_events(session, max_pages=max_pages)
    finally:
        session.close()
    return build_table_from_events(events)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    argument_parser = argparse.ArgumentParser(
        description="Parse crypto addresses from SlowMist Hacked HTML"
    )
    argument_parser.add_argument(
        "--max-pages",
        type=int,
        help="Limit pages for an explicitly partial debug run",
    )
    arguments = argument_parser.parse_args()
    if arguments.max_pages is not None and arguments.max_pages <= 0:
        argument_parser.error("--max-pages must be greater than zero")
    try:
        table = build_table(max_pages=arguments.max_pages)
        LOGGER.info("Validated %d unique SlowMist addresses", table.num_rows)
        LOGGER.info("Schema: %s", table.schema)
    except (OSError, RuntimeError, ValueError, requests.RequestException, pa.ArrowException):
        LOGGER.exception("SlowMist Hacked parsing failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
