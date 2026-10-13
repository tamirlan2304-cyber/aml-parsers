from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Mapping

import pyarrow as pa
import pyarrow.parquet as pq

from chainabuse_parser import (
    _combine_rows,
    _parse_api_date,
    _table_from_records,
    fetch_recent_reports_async,
    normalize_report_id,
    report_key,
    rows_from_api_reports,
)
from phishing_common import CHAINABUSE_SCHEMA


LOGGER = logging.getLogger("chainabuse_incremental")
DEFAULT_OVERLAP_DAYS = 5
STATE_VERSION = "1"
STATE_VERSION_KEY = b"chainabuse.incremental_state_version"
RECENT_REPORTS_KEY = b"chainabuse.incremental_recent_reports"
WATERMARK_KEY = b"chainabuse.incremental_watermark_date"
LEGACY_REPORT_SCHEMA_NAMES = [
    "wallet_address",
    "network",
    "domain",
    "report_date",
    "report_id",
]


def _metadata(table: pa.Table) -> dict[bytes, bytes]:
    return dict(table.schema.metadata or {})


def _decode_recent_reports(table: pa.Table) -> dict[str, date] | None:
    metadata = _metadata(table)
    if metadata.get(STATE_VERSION_KEY) != STATE_VERSION.encode("ascii"):
        return None
    raw = metadata.get(RECENT_REPORTS_KEY)
    if raw is None:
        raise ValueError("Incremental metadata has no recent report IDs")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Invalid incremental recent-report metadata") from error
    if not isinstance(payload, dict):
        raise ValueError("Incremental recent-report metadata must be an object")
    result: dict[str, date] = {}
    for report_id, report_date in payload.items():
        canonical_id = normalize_report_id(report_id)
        try:
            result[canonical_id] = date.fromisoformat(str(report_date))
        except ValueError as error:
            raise ValueError(
                f"Invalid incremental report date for {canonical_id}: {report_date!r}"
            ) from error
    return result


def _metadata_watermark(table: pa.Table) -> date | None:
    raw = _metadata(table).get(WATERMARK_KEY)
    if raw is None:
        return None
    try:
        return date.fromisoformat(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("Invalid incremental watermark metadata") from error


def _with_incremental_metadata(
    table: pa.Table,
    *,
    recent_reports: Mapping[str, date],
    watermark: date,
) -> pa.Table:
    metadata = _metadata(table)
    metadata[STATE_VERSION_KEY] = STATE_VERSION.encode("ascii")
    metadata[WATERMARK_KEY] = watermark.isoformat().encode("ascii")
    metadata[RECENT_REPORTS_KEY] = json.dumps(
        {
            normalize_report_id(report_id): report_date.isoformat()
            for report_id, report_date in sorted(recent_reports.items())
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return table.replace_schema_metadata(metadata)


def normalize_existing_table(table: pa.Table) -> pa.Table:
    """Validate the current schema or migrate the former report/address schema."""
    if table.column_names == LEGACY_REPORT_SCHEMA_NAMES:
        rows = sorted(
            table.to_pylist(),
            key=lambda row: (
                row["report_date"] is None,
                row["report_date"] or date.max,
                str(row["report_id"]),
            ),
        )
        records: dict[str, dict[str, Any]] = {}
        for source_row in rows:
            row = dict(source_row)
            row["report_count"] = 1
            _combine_rows(records, [row])
        migrated = _table_from_records(records)
        LOGGER.info(
            "Migrated legacy Chainabuse table: report/address rows=%d, unique addresses=%d",
            table.num_rows,
            migrated.num_rows,
        )
        return migrated.replace_schema_metadata(_metadata(table))

    if table.column_names != CHAINABUSE_SCHEMA.names:
        raise ValueError(
            f"Unexpected Chainabuse columns: {table.column_names}; "
            f"expected {CHAINABUSE_SCHEMA.names}"
        )
    table = table.cast(CHAINABUSE_SCHEMA)
    records: dict[str, dict[str, Any]] = {}
    for row in table.to_pylist():
        key = report_key(row)
        if key in records:
            raise ValueError(f"Duplicate wallet address in existing table: {key}")
        _combine_rows(records, [row])
    return _table_from_records(records).replace_schema_metadata(_metadata(table))


def latest_report_date(table: pa.Table) -> date:
    values = [value for value in table["report_date"].to_pylist() if value is not None]
    if not values:
        raise ValueError("Existing Chainabuse table has no report dates")
    latest = max(values)
    metadata_latest = _metadata_watermark(table)
    return max(latest, metadata_latest) if metadata_latest else latest


def incremental_cutoff(table: pa.Table, *, overlap_days: int = DEFAULT_OVERLAP_DAYS) -> date:
    if overlap_days < 0:
        raise ValueError("overlap_days must not be negative")
    return latest_report_date(table) - timedelta(days=overlap_days)


async def build_incremental_table_async(
    existing_table: pa.Table,
    *,
    overlap_days: int = DEFAULT_OVERLAP_DAYS,
) -> pa.Table:
    """Fetch a date overlap and merge only previously unseen report IDs."""
    existing = normalize_existing_table(existing_table)
    previous_watermark = latest_report_date(existing)
    cutoff = incremental_cutoff(existing, overlap_days=overlap_days)
    known_reports = _decode_recent_reports(existing)

    LOGGER.info(
        "Incremental Chainabuse range: newest backwards through %s inclusive "
        "(S3 watermark=%s, overlap=%d days)",
        cutoff.isoformat(),
        previous_watermark.isoformat(),
        overlap_days,
    )
    recent = await fetch_recent_reports_async(cutoff)
    fetched_reports = {
        normalize_report_id(report.get("id")): _parse_api_date(report.get("createdAt"))
        for report in recent.reports
    }

    if known_reports is None:
        # The first incremental run upgrades an older Parquet file. Reports on
        # or before its watermark are used to seed exact de-duplication state,
        # but are not counted a second time.
        new_reports = [
            report
            for report in recent.reports
            if _parse_api_date(report.get("createdAt")) > previous_watermark
        ]
        known_reports = {}
        LOGGER.info(
            "Initialized incremental state from an existing table; overlap rows "
            "through %s will not be counted again",
            previous_watermark.isoformat(),
        )
    else:
        new_reports = [
            report
            for report in recent.reports
            if normalize_report_id(report.get("id")) not in known_reports
        ]

    records = {report_key(row): row for row in existing.to_pylist()}
    if new_reports:
        # The endpoint was fetched newest-first. Restore chronological order so
        # a newly seen address keeps its earliest report_id.
        new_reports.sort(
            key=lambda report: (
                _parse_api_date(report.get("createdAt")),
                normalize_report_id(report.get("id")),
            )
        )
        _combine_rows(records, rows_from_api_reports(new_reports))

    watermark = max(previous_watermark, recent.newest_date)
    retained_from = watermark - timedelta(days=overlap_days)
    known_reports.update(fetched_reports)
    known_reports = {
        report_id: report_date
        for report_id, report_date in known_reports.items()
        if report_date >= retained_from
    }
    result = _with_incremental_metadata(
        _table_from_records(records),
        recent_reports=known_reports,
        watermark=watermark,
    )
    LOGGER.info(
        "Incremental Chainabuse merge complete: fetched_reports=%d, "
        "new_reports=%d, unique_addresses=%d",
        len(recent.reports),
        len(new_reports),
        result.num_rows,
    )
    return result


def build_incremental_table(
    existing_table: pa.Table,
    *,
    overlap_days: int = DEFAULT_OVERLAP_DAYS,
) -> pa.Table:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(
            build_incremental_table_async(
                existing_table,
                overlap_days=overlap_days,
            )
        )
    raise RuntimeError(
        "build_incremental_table() cannot run inside an active event loop; "
        "await build_incremental_table_async()"
    )


def _save_table(table: pa.Table, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.tmp")
    try:
        pq.write_table(table, temporary_path, compression="zstd")
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    parser = argparse.ArgumentParser(
        description="Incrementally update an existing local Chainabuse Parquet file"
    )
    parser.add_argument("input", type=Path, help="Existing Parquet downloaded from S3")
    parser.add_argument("output", type=Path, help="Path for the updated Parquet")
    parser.add_argument("--overlap-days", type=int, default=DEFAULT_OVERLAP_DAYS)
    arguments = parser.parse_args()
    if arguments.overlap_days < 0:
        parser.error("--overlap-days must not be negative")

    existing = pq.read_table(arguments.input.expanduser().resolve())
    updated = build_incremental_table(existing, overlap_days=arguments.overlap_days)
    output_path = arguments.output.expanduser().resolve()
    _save_table(updated, output_path)
    LOGGER.info("Saved %s: rows=%d", output_path, updated.num_rows)


if __name__ == "__main__":
    main()
