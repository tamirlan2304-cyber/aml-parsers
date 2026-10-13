from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import math
import os
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import pyarrow as pa
import pyarrow.parquet as pq
from dotenv import load_dotenv

from phishing_common import (
    CHAINABUSE_SCHEMA,
    canonical_address,
    normalize_domain,
    normalize_network,
    parse_html_report_date,
    valid_source_address,
)


PROJECT_DIR = Path(__file__).resolve().parent
SHARED_ENV_FILE = PROJECT_DIR.parent / "terrorism_parser_new" / ".env"
if SHARED_ENV_FILE.exists():
    load_dotenv(SHARED_ENV_FILE, override=False)
load_dotenv(PROJECT_DIR / ".env", override=True)

LOGGER = logging.getLogger("chainabuse_parser")
DEFAULT_URL = "https://chainabuse.com/category/phishing"
DEFAULT_CHECKPOINT_DIR = PROJECT_DIR / "chainabuse_checkpoints"
DEFAULT_CHECKPOINT_INTERVAL_PAGES = 500
DEFAULT_CONCURRENCY = 10
DEFAULT_REQUEST_RETRIES = 4
PAGE_SIZE = 50  # Chainabuse currently caps GetReports responses at 50 reports.
CHECKPOINT_VERSION = "3"
CHECKPOINT_GLOB = "chainabuse_checkpoint_page_*_items_*.parquet"
CHECKPOINT_FILE_RE = re.compile(
    r"^chainabuse_checkpoint_page_(?P<page>\d+)_items_"
    r"(?P<first>\d+)-(?P<last>\d+)\.parquet$"
)
CURSOR_PREFIX = "arrayconnection:"
PAGINATION_RE = re.compile(
    r"(?P<first>[\d ,]+)\s*-\s*(?P<last>[\d ,]+)\s+of\s+"
    r"(?P<total>[\d ,]+)\s+items",
    re.IGNORECASE,
)

GET_REPORTS_QUERY = """
query GetReports($input: ReportsInput, $after: String, $first: Float) {
  reports(input: $input, after: $after, first: $first) {
    pageInfo { hasNextPage startCursor endCursor }
    edges {
      cursor
      node {
        id
        createdAt
        addresses { id address chain domain }
      }
    }
    count
    totalCount
  }
}
"""


@dataclass(frozen=True)
class CheckpointState:
    path: Path
    table: pa.Table
    next_page_index: int
    item_first: int
    item_last: int
    total_reports: int
    complete: bool


@dataclass(frozen=True)
class ReportPage:
    page_index: int
    total_reports: int
    reports: list[dict[str, Any]]
    report_ids: tuple[str, ...]


@dataclass(frozen=True)
class RecentReports:
    reports: list[dict[str, Any]]
    snapshot_total: int
    newest_date: date
    cutoff_date: date


def optional_setting(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def boolean_setting(name: str, default: bool) -> bool:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    if value == "True":
        return True
    if value == "False":
        return False
    raise ValueError(f"{name} must be exactly 'True' or 'False'")


def integer_setting(name: str, default: int, *, allow_zero: bool = False) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    result = int(value)
    minimum = 0 if allow_zero else 1
    if result < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return result


def checkpoint_directory() -> Path:
    configured = optional_setting("CHAINABUSE_CHECKPOINT_DIR")
    directory = Path(configured) if configured else DEFAULT_CHECKPOINT_DIR
    if not directory.is_absolute():
        directory = PROJECT_DIR / directory
    return directory.resolve()


def normalize_report_id(value: object) -> str:
    raw = str(value or "").strip()
    try:
        return str(UUID(raw))
    except (ValueError, AttributeError) as error:
        raise ValueError(f"Invalid Chainabuse report id: {raw!r}") from error


def report_key(row: Mapping[str, Any]) -> str:
    """Return the single row key used by Chainabuse: the canonical address."""
    return canonical_address(str(row["wallet_address"]))


def _sorted_rows(records: Mapping[object, dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        records.values(),
        key=lambda row: (
            row["report_date"] is not None,
            row["report_date"] or date.min,
            row["network"],
            row["wallet_address"],
        ),
    )


def _table_from_records(records: Mapping[object, dict[str, Any]]) -> pa.Table:
    return pa.Table.from_pylist(_sorted_rows(records), schema=CHAINABUSE_SCHEMA)


def _checkpoint_metadata(
    *,
    base_url: str,
    next_page_index: int,
    item_first: int,
    item_last: int,
    total_reports: int,
    complete: bool,
) -> dict[bytes, bytes]:
    return {
        b"chainabuse.checkpoint_version": CHECKPOINT_VERSION.encode("ascii"),
        b"chainabuse.source_url": base_url.encode("utf-8"),
        b"chainabuse.next_page_index": str(next_page_index).encode("ascii"),
        b"chainabuse.item_first": str(item_first).encode("ascii"),
        b"chainabuse.item_last": str(item_last).encode("ascii"),
        b"chainabuse.total_reports": str(total_reports).encode("ascii"),
        b"chainabuse.complete": (b"true" if complete else b"false"),
        b"chainabuse.saved_at_utc": datetime.now(timezone.utc).isoformat().encode("ascii"),
    }


def delete_older_checkpoints(
    directory: Path,
    *,
    keep_path: Path,
    keep_page_index: int,
) -> list[Path]:
    """Delete completed checkpoint files older than the newly saved checkpoint."""
    resolved_directory = directory.resolve()
    resolved_keep_path = keep_path.resolve()
    if resolved_keep_path.parent != resolved_directory:
        raise ValueError("Checkpoint to keep is outside the checkpoint directory")

    deleted: list[Path] = []
    for candidate in directory.glob(CHECKPOINT_GLOB):
        match = CHECKPOINT_FILE_RE.match(candidate.name)
        if match is None or candidate.resolve() == resolved_keep_path:
            continue
        if int(match.group("page")) > keep_page_index:
            continue
        try:
            candidate.unlink()
        except FileNotFoundError:
            continue
        except OSError as error:
            LOGGER.warning("Cannot delete old checkpoint %s: %s", candidate, error)
            continue
        deleted.append(candidate)
    return deleted


def save_checkpoint(
    records: Mapping[object, dict[str, Any]],
    *,
    base_url: str,
    next_page_index: int,
    item_first: int,
    item_last: int,
    total_reports: int,
    complete: bool,
) -> Path:
    """Atomically write a cumulative v2 Parquet checkpoint."""
    if next_page_index <= 0 or not records:
        raise ValueError("Cannot save an empty Chainabuse checkpoint")
    directory = checkpoint_directory()
    directory.mkdir(parents=True, exist_ok=True)
    filename = (
        f"chainabuse_checkpoint_page_{next_page_index:08d}_items_"
        f"{item_first:08d}-{item_last:08d}.parquet"
    )
    output_path = directory / filename
    temporary_path = directory / f".{filename}.tmp"
    table = _table_from_records(records).replace_schema_metadata(
        _checkpoint_metadata(
            base_url=base_url,
            next_page_index=next_page_index,
            item_first=item_first,
            item_last=item_last,
            total_reports=total_reports,
            complete=complete,
        )
    )
    try:
        pq.write_table(table, temporary_path, compression="zstd")
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    deleted = delete_older_checkpoints(
        directory,
        keep_path=output_path,
        keep_page_index=next_page_index,
    )
    LOGGER.info(
        "Saved Chainabuse checkpoint: %s (pages=%d, items=%d-%d, rows=%d, complete=%s)",
        output_path,
        next_page_index,
        item_first,
        item_last,
        table.num_rows,
        complete,
    )
    if deleted:
        LOGGER.info("Deleted %d older Chainabuse checkpoint(s)", len(deleted))
    return output_path


def _metadata_text(metadata: dict[bytes, bytes], name: str) -> str:
    key = f"chainabuse.{name}".encode("ascii")
    value = metadata.get(key)
    if value is None:
        raise ValueError(f"Checkpoint metadata has no {key.decode('ascii')}")
    return value.decode("utf-8")


def _read_checkpoint(path: Path, *, base_url: str) -> CheckpointState:
    table = pq.read_table(path)
    if table.column_names != CHAINABUSE_SCHEMA.names:
        raise ValueError(f"Unexpected checkpoint columns: {table.column_names}")
    metadata = table.schema.metadata or {}
    if _metadata_text(metadata, "checkpoint_version") != CHECKPOINT_VERSION:
        raise ValueError("Unsupported checkpoint version")
    if _metadata_text(metadata, "source_url") != base_url:
        raise ValueError("Checkpoint belongs to another CHAINABUSE_URL")
    next_page_index = int(_metadata_text(metadata, "next_page_index"))
    item_first = int(_metadata_text(metadata, "item_first"))
    item_last = int(_metadata_text(metadata, "item_last"))
    total_reports = int(_metadata_text(metadata, "total_reports"))
    complete = _metadata_text(metadata, "complete") == "true"
    if next_page_index <= 0 or item_first <= 0 or item_last < item_first:
        raise ValueError("Checkpoint has invalid page/range metadata")
    table = table.cast(CHAINABUSE_SCHEMA)
    records: dict[str, dict[str, Any]] = {}
    _combine_rows(records, table.to_pylist())
    if len(records) != table.num_rows:
        raise ValueError("Checkpoint contains duplicate wallet addresses")
    return CheckpointState(
        path=path,
        table=table,
        next_page_index=next_page_index,
        item_first=item_first,
        item_last=item_last,
        total_reports=total_reports,
        complete=complete,
    )


def load_latest_checkpoint(*, base_url: str) -> CheckpointState | None:
    directory = checkpoint_directory()
    if not directory.exists():
        return None
    candidates: list[tuple[int, float, Path]] = []
    for path in directory.glob(CHECKPOINT_GLOB):
        match = CHECKPOINT_FILE_RE.match(path.name)
        if match:
            candidates.append((int(match.group("page")), path.stat().st_mtime, path))
    for _, _, path in sorted(candidates, reverse=True):
        try:
            return _read_checkpoint(path, base_url=base_url)
        except (OSError, ValueError, pa.ArrowException) as error:
            LOGGER.warning("Ignoring unusable checkpoint %s: %s", path, error)
    return None


def graphql_url(base_url: str) -> str:
    parts = urlsplit(base_url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError(f"Invalid CHAINABUSE_URL: {base_url!r}")
    return urlunsplit((parts.scheme, parts.netloc, "/api/graphql-proxy", "", ""))


def parse_pagination(text: str) -> tuple[int, int, int]:
    """Parse the legacy HTML counter; kept for compatibility with callers/tests."""
    match = PAGINATION_RE.search(text)
    if not match:
        raise ValueError("Cannot find Chainabuse pagination in rendered HTML")
    return tuple(
        int(match.group(name).replace(",", "").replace(" ", ""))
        for name in ("first", "last", "total")
    )  # type: ignore[return-value]


def cursor_for_page(page_index: int) -> str:
    if page_index < 0:
        raise ValueError("page_index must not be negative")
    cursor = f"{CURSOR_PREFIX}{page_index * PAGE_SIZE - 1}"
    return base64.b64encode(cursor.encode("ascii")).decode("ascii")


def cursor_index(value: object) -> int:
    try:
        decoded = base64.b64decode(str(value), validate=True).decode("ascii")
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError(f"Invalid Chainabuse cursor: {value!r}") from error
    if not decoded.startswith(CURSOR_PREFIX):
        raise ValueError(f"Unexpected Chainabuse cursor: {decoded!r}")
    return int(decoded.removeprefix(CURSOR_PREFIX))


def _domain_values(values: Iterable[object]) -> set[str]:
    return {
        domain
        for value in values
        for domain in [normalize_domain(value)]
        if domain
    }


def _parse_api_date(value: object) -> date:
    raw = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"Invalid Chainabuse createdAt: {raw!r}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).date()


def rows_from_api_reports(reports: object) -> list[dict[str, Any]]:
    if not isinstance(reports, list):
        raise ValueError("Chainabuse reports must be an array")
    records: dict[str, dict[str, Any]] = {}
    skipped: list[str] = []
    for report_index, report in enumerate(reports):
        if not isinstance(report, dict):
            raise ValueError(f"Chainabuse report {report_index} is not an object")
        report_id = normalize_report_id(report.get("id"))
        report_date = _parse_api_date(report.get("createdAt"))
        indicators = report.get("addresses")
        if not isinstance(indicators, list):
            raise ValueError(f"Chainabuse report {report_id} has no addresses array")
        domains = _domain_values(
            indicator.get("domain")
            for indicator in indicators
            if isinstance(indicator, dict)
        )
        # A report can repeat the same address in its indicators. Build the
        # report locally first so that such duplicates count as one report.
        report_records: dict[str, dict[str, Any]] = {}
        for indicator_index, indicator in enumerate(indicators):
            if not isinstance(indicator, dict):
                skipped.append(f"report {report_id}, indicator {indicator_index}: not an object")
                continue
            address = str(indicator.get("address") or "").strip()
            chain = str(indicator.get("chain") or "").strip()
            if not address:
                continue  # Domain-only indicator.
            if not valid_source_address(address, chain):
                skipped.append(
                    f"report {report_id}, indicator {indicator_index}: "
                    f"invalid {chain!r} address {address[:70]!r}"
                )
                continue
            row = {
                "wallet_address": canonical_address(address),
                "network": normalize_network(chain),
                "domain": "; ".join(sorted(domains)),
                "report_date": report_date,
                "report_id": report_id,
                "report_count": 1,
            }
            address_key = report_key(row)
            current = report_records.get(address_key)
            if current is None:
                report_records[address_key] = row
            elif current["network"] != row["network"]:
                raise ValueError(
                    f"Report {report_id} assigns conflicting networks to "
                    f"{row['wallet_address']}: {current['network']} and {row['network']}"
                )
        _combine_rows(records, report_records.values())
    if skipped:
        LOGGER.warning("Skipped %d malformed API values; sample=%s", len(skipped), skipped[:5])
    return list(records.values())


def rows_from_html_cards(
    cards: object,
    *,
    observed_at: datetime | None = None,
) -> list[dict[str, Any]]:
    """Backward-compatible test/helper parser; production uses rows_from_api_reports."""
    if not isinstance(cards, list):
        raise ValueError("Rendered Chainabuse cards must be an array")
    reports: list[dict[str, Any]] = []
    for card_index, card in enumerate(cards):
        if not isinstance(card, dict):
            raise ValueError(f"Rendered Chainabuse card {card_index} is not an object")
        report_date = parse_html_report_date(
            str(card.get("submitted", "")), observed_at=observed_at
        )
        if report_date is None:
            raise ValueError(f"Cannot parse report date for card {card_index}")
        reports.append(
            {
                "id": card.get("reportId"),
                "createdAt": datetime.combine(
                    report_date, datetime.min.time(), tzinfo=timezone.utc
                ).isoformat(),
                "addresses": [
                    {
                        "address": indicator.get("address"),
                        "chain": indicator.get("chain"),
                        "domain": None,
                    }
                    for indicator in card.get("addresses", [])
                    if isinstance(indicator, dict)
                ]
                + [
                    {"address": None, "chain": None, "domain": domain}
                    for domain in card.get("domains", [])
                ],
            }
        )
    return rows_from_api_reports(reports)


def _combine_rows(
    target: dict[str, dict[str, Any]],
    rows: Iterable[dict[str, Any]],
) -> None:
    for source_row in rows:
        row = dict(source_row)
        row["report_id"] = normalize_report_id(row["report_id"])
        row["wallet_address"] = canonical_address(str(row["wallet_address"]))
        try:
            row["report_count"] = int(row["report_count"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Chainabuse row has invalid report_count") from error
        if row["report_count"] <= 0:
            raise ValueError("Chainabuse report_count must be greater than zero")
        key = report_key(row)
        current = target.get(key)
        if current is None:
            target[key] = row
            continue
        if current["network"] != row["network"]:
            raise ValueError(
                f"Report {row['report_id']} assigns conflicting networks to "
                f"{row['wallet_address']}: {current['network']} and {row['network']}"
            )
        domains = {
            item.strip()
            for value in (current["domain"], row["domain"])
            for item in value.split(";")
            if item.strip()
        }
        current["domain"] = "; ".join(sorted(domains))
        current["report_count"] += row["report_count"]
        # report_id deliberately remains the first non-empty ID stored for the
        # address. report_date tracks the latest activity and is the watermark
        # used by the daily incremental parser.
        if row["report_date"] is not None and (
            current["report_date"] is None
            or row["report_date"] > current["report_date"]
        ):
            current["report_date"] = row["report_date"]


def parse_reports_payload(
    payload: object,
    *,
    page_index: int,
    snapshot_total: int | None = None,
) -> ReportPage:
    if not isinstance(payload, dict):
        raise ValueError("Chainabuse GraphQL response is not an object")
    errors = payload.get("errors")
    if errors:
        raise ValueError(f"Chainabuse GraphQL returned errors: {errors!r}")
    data = payload.get("data")
    connection = data.get("reports") if isinstance(data, dict) else None
    if not isinstance(connection, dict):
        raise ValueError("Chainabuse GraphQL response has no data.reports")
    try:
        total_reports = int(connection["totalCount"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Chainabuse GraphQL response has invalid totalCount") from error
    if total_reports < 0:
        raise ValueError("Chainabuse totalCount must not be negative")
    if snapshot_total is None:
        snapshot_total = total_reports
    if total_reports < snapshot_total:
        raise RuntimeError(
            f"Chainabuse totalCount decreased during parsing: {total_reports} < {snapshot_total}"
        )
    edges = connection.get("edges")
    if not isinstance(edges, list):
        raise ValueError("Chainabuse GraphQL response has no edges array")
    first_index = page_index * PAGE_SIZE
    expected_count = max(0, min(PAGE_SIZE, snapshot_total - first_index))
    if len(edges) < expected_count:
        raise RuntimeError(
            f"Chainabuse page {page_index + 1} returned {len(edges)} reports; "
            f"expected at least {expected_count}"
        )
    reports: list[dict[str, Any]] = []
    report_ids: list[str] = []
    for offset, edge in enumerate(edges[:expected_count]):
        if not isinstance(edge, dict) or not isinstance(edge.get("node"), dict):
            raise ValueError(f"Chainabuse page {page_index + 1} contains an invalid edge")
        expected_cursor = first_index + offset
        actual_cursor = cursor_index(edge.get("cursor"))
        if actual_cursor != expected_cursor:
            raise RuntimeError(
                f"Chainabuse page {page_index + 1} cursor mismatch: "
                f"expected {expected_cursor}, got {actual_cursor}"
            )
        node = edge["node"]
        report_id = normalize_report_id(node.get("id"))
        reports.append(node)
        report_ids.append(report_id)
    if len(set(report_ids)) != len(report_ids):
        raise RuntimeError(f"Chainabuse page {page_index + 1} contains duplicate report ids")
    return ReportPage(page_index, total_reports, reports, tuple(report_ids))


def _request_payload(
    page_index: int,
    *,
    order_direction: str = "ASC",
) -> dict[str, Any]:
    if order_direction not in {"ASC", "DESC"}:
        raise ValueError("order_direction must be ASC or DESC")
    return {
        "operationName": "GetReports",
        "query": GET_REPORTS_QUERY,
        "variables": {
            "input": {
                "chains": [],
                "scamCategories": ["PHISHING"],
                "orderBy": {"field": "CREATED_AT", "direction": order_direction},
            },
            "after": cursor_for_page(page_index),
            "first": PAGE_SIZE,
        },
    }


async def _fetch_page(
    request_context: Any,
    semaphore: asyncio.Semaphore,
    *,
    endpoint: str,
    page_index: int,
    timeout_ms: int,
    retries: int,
    snapshot_total: int | None,
    order_direction: str = "ASC",
) -> ReportPage:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            async with semaphore:
                response = await request_context.post(
                    endpoint,
                    data=_request_payload(
                        page_index,
                        order_direction=order_direction,
                    ),
                    timeout=timeout_ms,
                )
                try:
                    status = response.status
                    body = await response.text()
                finally:
                    await response.dispose()
            if status != 200:
                raise RuntimeError(
                    f"Chainabuse HTTP {status} on page {page_index + 1}: {body[:300]}"
                )
            return parse_reports_payload(
                json.loads(body),
                page_index=page_index,
                snapshot_total=snapshot_total,
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            last_error = error
            if attempt == retries:
                break
            delay = min(2 ** (attempt - 1), 8)
            LOGGER.warning(
                "Chainabuse page %d failed (%d/%d): %s; retrying in %ds",
                page_index + 1,
                attempt,
                retries,
                error,
                delay,
            )
            await asyncio.sleep(delay)
    raise RuntimeError(
        f"Chainabuse page {page_index + 1} failed after {retries} attempts"
    ) from last_error


async def fetch_recent_reports_async(cutoff_date: date) -> RecentReports:
    """Fetch newest reports backwards, including every report on cutoff_date."""
    try:
        from playwright.async_api import async_playwright
    except ImportError as error:
        raise RuntimeError(
            "Playwright is required. Run: "
            "..\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt"
        ) from error

    base_url = optional_setting("CHAINABUSE_URL") or DEFAULT_URL
    endpoint = graphql_url(base_url)
    timeout_ms = integer_setting("CHAINABUSE_PAGE_TIMEOUT_SECONDS", 120) * 1000
    concurrency = integer_setting("CHAINABUSE_CONCURRENCY", DEFAULT_CONCURRENCY)
    retries = integer_setting("CHAINABUSE_REQUEST_RETRIES", DEFAULT_REQUEST_RETRIES)

    playwright = await async_playwright().start()
    request_context = await playwright.request.new_context(
        extra_http_headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}",
            "Referer": base_url,
        }
    )
    semaphore = asyncio.Semaphore(concurrency)
    reports: list[dict[str, Any]] = []
    seen_report_ids: set[str] = set()
    try:
        first_page = await _fetch_page(
            request_context,
            semaphore,
            endpoint=endpoint,
            page_index=0,
            timeout_ms=timeout_ms,
            retries=retries,
            snapshot_total=None,
            order_direction="DESC",
        )
        if first_page.total_reports == 0 or not first_page.reports:
            raise RuntimeError("Chainabuse returned no phishing reports")
        snapshot_total = first_page.total_reports
        total_pages = math.ceil(snapshot_total / PAGE_SIZE)
        newest_date = _parse_api_date(first_page.reports[0].get("createdAt"))
        batch_start = 0
        reached_older_report = False

        while batch_start < total_pages and not reached_older_report:
            batch_stop = min(batch_start + concurrency, total_pages)
            tasks = []
            for page_index in range(batch_start, batch_stop):
                if page_index == 0:
                    tasks.append(asyncio.sleep(0, result=first_page))
                else:
                    tasks.append(
                        _fetch_page(
                            request_context,
                            semaphore,
                            endpoint=endpoint,
                            page_index=page_index,
                            timeout_ms=timeout_ms,
                            retries=retries,
                            snapshot_total=snapshot_total,
                            order_direction="DESC",
                        )
                    )
            pages = await asyncio.gather(*tasks)
            pages.sort(key=lambda value: value.page_index)
            for report_page in pages:
                duplicates = seen_report_ids.intersection(report_page.report_ids)
                if duplicates:
                    raise RuntimeError(
                        "Chainabuse repeated report id(s) across recent pages: "
                        f"{sorted(duplicates)[:3]}"
                    )
                seen_report_ids.update(report_page.report_ids)
                for report in report_page.reports:
                    report_date = _parse_api_date(report.get("createdAt"))
                    if report_date >= cutoff_date:
                        reports.append(report)
                    else:
                        reached_older_report = True
            batch_start = batch_stop
            LOGGER.info(
                "Fetched recent Chainabuse pages 1-%d; reports on/after %s=%d",
                batch_stop,
                cutoff_date.isoformat(),
                len(reports),
            )
    finally:
        await request_context.dispose()
        await playwright.stop()

    reports.sort(
        key=lambda report: (
            _parse_api_date(report.get("createdAt")),
            normalize_report_id(report.get("id")),
        )
    )
    return RecentReports(
        reports=reports,
        snapshot_total=snapshot_total,
        newest_date=newest_date,
        cutoff_date=cutoff_date,
    )


async def build_table_async(
    *,
    max_pages: int | None = None,
    allow_partial: bool | None = None,
    resume: bool | None = None,
) -> pa.Table:
    try:
        from playwright.async_api import async_playwright
    except ImportError as error:
        raise RuntimeError(
            "Playwright is required. Run: "
            "..\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt"
        ) from error

    base_url = optional_setting("CHAINABUSE_URL") or DEFAULT_URL
    endpoint = graphql_url(base_url)
    configured_max = integer_setting("CHAINABUSE_MAX_PAGES", 0, allow_zero=True)
    page_limit = configured_max if max_pages is None else max_pages
    if page_limit is not None and page_limit < 0:
        raise ValueError("max_pages must not be negative")
    partial_ok = (
        boolean_setting("CHAINABUSE_ALLOW_PARTIAL", False)
        if allow_partial is None
        else allow_partial
    )
    timeout_ms = integer_setting("CHAINABUSE_PAGE_TIMEOUT_SECONDS", 120) * 1000
    concurrency = integer_setting("CHAINABUSE_CONCURRENCY", DEFAULT_CONCURRENCY)
    retries = integer_setting("CHAINABUSE_REQUEST_RETRIES", DEFAULT_REQUEST_RETRIES)
    checkpoint_interval = integer_setting(
        "CHAINABUSE_CHECKPOINT_INTERVAL_PAGES", DEFAULT_CHECKPOINT_INTERVAL_PAGES
    )
    resume_enabled = boolean_setting("CHAINABUSE_RESUME", True) if resume is None else resume
    checkpoint_enabled = not page_limit
    records: dict[str, dict[str, Any]] = {}
    completed_pages = 0
    item_first = 0
    item_last = 0
    checkpoint_total = 0
    checkpoint_complete = False
    snapshot_total = 0

    if checkpoint_enabled and resume_enabled:
        checkpoint = load_latest_checkpoint(base_url=base_url)
        if checkpoint is not None:
            _combine_rows(records, checkpoint.table.to_pylist())
            completed_pages = checkpoint.next_page_index
            item_first = checkpoint.item_first
            item_last = checkpoint.item_last
            checkpoint_total = checkpoint.total_reports
            checkpoint_complete = checkpoint.complete
            LOGGER.info(
                "Loaded Chainabuse checkpoint %s: pages=%d, reports=%d, rows=%d",
                checkpoint.path,
                completed_pages,
                checkpoint_total,
                checkpoint.table.num_rows,
            )
    elif page_limit:
        LOGGER.info("Checkpoint resume/save is disabled for page-limited debug runs")
    elif not resume_enabled:
        LOGGER.info("Checkpoint resume is disabled; starting from the oldest report")

    playwright = await async_playwright().start()
    request_context = await playwright.request.new_context(
        extra_http_headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}",
            "Referer": base_url,
        }
    )
    semaphore = asyncio.Semaphore(concurrency)
    try:
        first_page = await _fetch_page(
            request_context,
            semaphore,
            endpoint=endpoint,
            page_index=0,
            timeout_ms=timeout_ms,
            retries=retries,
            snapshot_total=None,
        )
        snapshot_total = first_page.total_reports
        if snapshot_total == 0:
            raise RuntimeError("Chainabuse returned no phishing reports")
        if checkpoint_total > snapshot_total:
            raise RuntimeError(
                f"Checkpoint has {checkpoint_total} reports, but Chainabuse now reports "
                f"only {snapshot_total}"
            )
        total_pages = math.ceil(snapshot_total / PAGE_SIZE)
        target_pages = min(total_pages, page_limit) if page_limit else total_pages

        start_page = completed_pages
        resume_skip_count = 0
        if checkpoint_complete and checkpoint_total < snapshot_total:
            # Re-read the old partial final page because new reports are appended
            # to it until it reaches PAGE_SIZE.
            if checkpoint_total % PAGE_SIZE:
                start_page = max(0, completed_pages - 1)
                resume_skip_count = checkpoint_total % PAGE_SIZE
            LOGGER.info(
                "Chainabuse has %d new report(s); continuing at API page %d",
                snapshot_total - checkpoint_total,
                start_page + 1,
            )
        elif checkpoint_complete and checkpoint_total == snapshot_total:
            start_page = total_pages
            LOGGER.info("Chainabuse checkpoint is already current")
        elif completed_pages > total_pages:
            raise RuntimeError("Checkpoint page index exceeds the current report count")

        if page_limit:
            start_page = 0
            records.clear()
        if start_page > target_pages:
            start_page = target_pages

        seen_report_ids: set[str] = set()
        next_checkpoint_at = (
            ((completed_pages // checkpoint_interval) + 1) * checkpoint_interval
        )
        batch_start = start_page
        while batch_start < target_pages:
            batch_stop = min(batch_start + concurrency, target_pages)
            if checkpoint_enabled and batch_start < next_checkpoint_at:
                batch_stop = min(batch_stop, next_checkpoint_at)
            page_indices = list(range(batch_start, batch_stop))
            tasks = []
            for page_index in page_indices:
                if page_index == 0:
                    tasks.append(asyncio.sleep(0, result=first_page))
                else:
                    tasks.append(
                        _fetch_page(
                            request_context,
                            semaphore,
                            endpoint=endpoint,
                            page_index=page_index,
                            timeout_ms=timeout_ms,
                            retries=retries,
                            snapshot_total=snapshot_total,
                        )
                    )
            pages = await asyncio.gather(*tasks)
            pages.sort(key=lambda value: value.page_index)
            for report_page in pages:
                page_reports = report_page.reports
                page_report_ids = report_page.report_ids
                if (
                    resume_skip_count
                    and report_page.page_index == start_page
                ):
                    page_reports = page_reports[resume_skip_count:]
                    page_report_ids = page_report_ids[resume_skip_count:]
                duplicates = seen_report_ids.intersection(page_report_ids)
                if duplicates:
                    raise RuntimeError(
                        f"Chainabuse repeated report id(s) across pages: {sorted(duplicates)[:3]}"
                    )
                seen_report_ids.update(page_report_ids)
                _combine_rows(records, rows_from_api_reports(page_reports))

            completed_pages = page_indices[-1] + 1
            item_first = 1
            item_last = min(snapshot_total, completed_pages * PAGE_SIZE)
            complete = completed_pages >= total_pages
            LOGGER.info(
                "API items %d-%d of %d; unique addresses=%d",
                batch_start * PAGE_SIZE + 1,
                item_last,
                snapshot_total,
                len(records),
            )
            if checkpoint_enabled and records and (
                completed_pages >= next_checkpoint_at or complete
            ):
                save_checkpoint(
                    records,
                    base_url=base_url,
                    next_page_index=completed_pages,
                    item_first=item_first,
                    item_last=item_last,
                    total_reports=snapshot_total,
                    complete=complete,
                )
                while next_checkpoint_at <= completed_pages:
                    next_checkpoint_at += checkpoint_interval
            batch_start = completed_pages

        if target_pages < total_pages:
            message = (
                f"CHAINABUSE_MAX_PAGES={target_pages} stopped before all "
                f"{total_pages} API pages were fetched"
            )
            if partial_ok:
                LOGGER.warning("%s; returning explicitly allowed partial data", message)
            else:
                raise RuntimeError(message)
    except asyncio.CancelledError:
        if checkpoint_enabled and records and completed_pages > 0:
            save_checkpoint(
                records,
                base_url=base_url,
                next_page_index=completed_pages,
                item_first=item_first or 1,
                item_last=item_last,
                total_reports=snapshot_total or checkpoint_total or item_last,
                complete=False,
            )
            LOGGER.warning("Parsing paused safely after API page %d", completed_pages)
        raise
    finally:
        await request_context.dispose()
        await playwright.stop()

    if not records:
        raise RuntimeError("Chainabuse API returned no valid phishing addresses")
    table = _table_from_records(records)
    LOGGER.info("Validated %d unique Chainabuse addresses", table.num_rows)
    return table


def build_table(
    *,
    max_pages: int | None = None,
    allow_partial: bool | None = None,
    resume: bool | None = None,
) -> pa.Table:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(
            build_table_async(
                max_pages=max_pages,
                allow_partial=allow_partial,
                resume=resume,
            )
        )
    raise RuntimeError(
        "build_table() cannot run inside an active event loop; await build_table_async()"
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    parser = argparse.ArgumentParser(
        description="Parse Chainabuse phishing reports concurrently via GraphQL"
    )
    parser.add_argument("--max-pages", type=int, help="Limit 50-report API pages for debugging")
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Allow a deliberately partial debug table; never use for production",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Ignore existing v2 checkpoints and start a full run from the oldest report",
    )
    arguments = parser.parse_args()
    try:
        table = build_table(
            max_pages=arguments.max_pages,
            allow_partial=arguments.allow_partial,
            resume=not arguments.no_resume,
        )
        LOGGER.info("Schema: %s", table.schema)
    except KeyboardInterrupt:
        LOGGER.warning("Chainabuse parsing paused safely by the user")
        raise SystemExit(130)
    except (OSError, RuntimeError, ValueError, pa.ArrowException):
        LOGGER.exception("Chainabuse parsing failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
