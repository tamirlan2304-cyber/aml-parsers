from __future__ import annotations

import argparse
import logging
import os
from datetime import date
from pathlib import Path
from typing import Any, Callable, Iterable

import boto3
import pyarrow as pa
import pyarrow.parquet as pq
import requests
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

import defihacklabs_parser
import slowmist_hacked_parser
import sok_interop_parser
import solidityscan_hack_parser
import telegram_investigations_parser
from slowmist_hacked_parser import build_table as build_slowmist_hacked_table
from telegram_investigations_parser import (
    LEGACY_SCHEMA as OUTPUT_SCHEMA,
    build_table as build_telegram_investigations_table,
    canonical_address,
)


PROJECT_DIR = Path(__file__).resolve().parent
SHARED_ENV_FILE = PROJECT_DIR.parent / "terrorism_parser_new" / ".env"
if SHARED_ENV_FILE.exists():
    load_dotenv(SHARED_ENV_FILE, override=False)
load_dotenv(PROJECT_DIR / ".env", override=True)

LOGGER = logging.getLogger("stolen_assets_s3")
MISSING_OBJECT_CODES = {"404", "NoSuchKey", "NotFound"}
PRODUCTION_S3_KEY = "stolen_assets/stolen_assets.parquet"

# Legacy mixed output is retained for compatibility; source-specific columns
# are preserved in independent Telegram and SlowMist outputs.
SOURCE_BUILDERS: tuple[tuple[str, Callable[[], pa.Table]], ...] = (
    ("telegram_investigations", build_telegram_investigations_table),
    ("slowmist_hacked", build_slowmist_hacked_table),
)
SOURCE_NAMES = (
    *tuple(name for name, _ in SOURCE_BUILDERS),
    "defihacklabs",
    "sok_interop",
    "solidityscan_hack_analysis",
)


def required_setting(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value


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


def production_s3_key() -> str:
    configured = optional_setting("S3_KEY") or PRODUCTION_S3_KEY
    if configured != PRODUCTION_S3_KEY:
        raise ValueError(
            f"S3_KEY must be exactly {PRODUCTION_S3_KEY!r}, got {configured!r}"
        )
    return configured


def create_s3_client():
    addressing_style = optional_setting("S3_ADDRESSING_STYLE") or "auto"
    if addressing_style not in {"auto", "path", "virtual"}:
        raise ValueError("S3_ADDRESSING_STYLE must be auto, path, or virtual")
    return boto3.client(
        "s3",
        region_name=optional_setting("AWS_REGION"),
        endpoint_url=optional_setting("S3_ENDPOINT_URL"),
        verify=boolean_setting("S3_VERIFY_SSL", True),
        config=Config(s3={"addressing_style": addressing_style}),
    )


def validate_table(table: pa.Table, source: str) -> None:
    if table.column_names != OUTPUT_SCHEMA.names:
        raise ValueError(
            f"Unexpected columns in {source}: {table.column_names}; "
            f"expected {OUTPUT_SCHEMA.names}"
        )
    if table.num_rows == 0:
        raise ValueError(f"Table is empty: {source}")
    for field_name in OUTPUT_SCHEMA.names:
        if table[field_name].null_count:
            raise ValueError(f"Column {field_name} contains nulls in {source}")

    keys: set[str] = set()
    for row in table.to_pylist():
        address = str(row["wallet_address"])
        network = str(row["network"]).strip()
        if not network:
            raise ValueError(f"Empty network for {address} in {source}")
        key = canonical_address(address)
        if key in keys:
            raise ValueError(f"Duplicate address {address} in {source}")
        keys.add(key)


def _rows_to_table(rows: Iterable[dict[str, Any]]) -> pa.Table:
    sorted_rows = sorted(
        rows,
        key=lambda row: (row["listed_date"], row["network"], row["wallet_address"]),
    )
    return pa.Table.from_pylist(sorted_rows, schema=OUTPUT_SCHEMA)


def combine_source_tables(source_tables: list[tuple[str, pa.Table]]) -> pa.Table:
    records: dict[str, dict[str, Any]] = {}
    for source_name, table in source_tables:
        source_parser = {
            "telegram_investigations": telegram_investigations_parser,
            "slowmist_hacked": slowmist_hacked_parser,
        }.get(source_name)
        if source_parser is not None and table.column_names == source_parser.OUTPUT_SCHEMA.names:
            source_parser.validate_table(table)
            table = table.select(OUTPUT_SCHEMA.names).cast(OUTPUT_SCHEMA)
        validate_table(table, source_name)
        for row in table.to_pylist():
            key = canonical_address(str(row["wallet_address"]))
            current = records.get(key)
            if current is None:
                records[key] = row
                continue
            if current["network"] != row["network"]:
                raise ValueError(
                    f"Address {row['wallet_address']} has conflicting networks "
                    f"across sources: {current['network']} and {row['network']}"
                )
            if row["listed_date"] < current["listed_date"]:
                current["listed_date"] = row["listed_date"]

    if not records:
        raise RuntimeError("All source parsers returned no addresses")
    combined = _rows_to_table(records.values())
    validate_table(combined, "combined current table")
    return combined


def _build_legacy_inputs(selection: str) -> list[tuple[str, pa.Table]]:
    source_tables: list[tuple[str, pa.Table]] = []
    for source_name, builder in SOURCE_BUILDERS:
        if selection != "all" and source_name != selection:
            continue
        LOGGER.info("Running source parser: %s", source_name)
        table = builder()
        LOGGER.info("Source %s returned %d rows", source_name, table.num_rows)
        source_tables.append((source_name, table))
    return source_tables


def build_current_table(selection: str = "all") -> pa.Table:
    """One table. 'all' retains the original, three-column combined-table API.

    For ALL output objects, including DeFiHackLabs, use build_output_tables().
    """
    if selection != "all" and selection not in SOURCE_NAMES:
        raise ValueError(f"Unknown source: {selection}")
    if selection in {"defihacklabs", "sok_interop", "solidityscan_hack_analysis"}:
        LOGGER.info("Running source parser: %s", selection)
        source_parser = {
            "defihacklabs": defihacklabs_parser,
            "sok_interop": sok_interop_parser,
            "solidityscan_hack_analysis": solidityscan_hack_parser,
        }[selection]
        table = source_parser.build_table()
        source_parser.validate_table(table)
        return table
    source_tables = _build_legacy_inputs(selection)
    if selection in {"telegram_investigations", "slowmist_hacked"}:
        table = source_tables[0][1]
        source_parser = {
            "telegram_investigations": telegram_investigations_parser,
            "slowmist_hacked": slowmist_hacked_parser,
        }[selection]
        source_parser.validate_table(table)
        return table
    return combine_source_tables(source_tables)


def build_output_tables(selection: str = "all") -> list[tuple[str, pa.Table]]:
    """Keep independent schemas in independent output tables/S3 objects."""
    if selection in SOURCE_NAMES:
        return [(selection, build_current_table(selection))]
    if selection == "all":
        # Download each source ONCE, then reuse it for the legacy projection.
        source_tables = _build_legacy_inputs(selection)
        telegram = dict(source_tables)["telegram_investigations"]
        slowmist = dict(source_tables)["slowmist_hacked"]
        telegram_investigations_parser.validate_table(telegram)
        slowmist_hacked_parser.validate_table(slowmist)
        outputs = [
            ("stolen_assets", combine_source_tables(source_tables)),
            ("telegram_investigations", telegram),
            ("slowmist_hacked", slowmist),
        ]
        outputs.append(("defihacklabs", build_current_table("defihacklabs")))
        outputs.append(("sok_interop", build_current_table("sok_interop")))
        outputs.append((
            "solidityscan_hack_analysis",
            build_current_table("solidityscan_hack_analysis"),
        ))
        return outputs
    raise ValueError(f"Unknown source: {selection}")


def output_s3_key(output_name: str) -> str:
    if output_name == "defihacklabs":
        return defihacklabs_parser.S3_KEY
    if output_name == "telegram_investigations":
        return telegram_investigations_parser.S3_KEY
    if output_name == "slowmist_hacked":
        return slowmist_hacked_parser.S3_KEY
    if output_name == "sok_interop":
        return sok_interop_parser.S3_KEY
    if output_name == "solidityscan_hack_analysis":
        return solidityscan_hack_parser.S3_KEY
    if output_name == "stolen_assets":
        return production_s3_key()
    raise ValueError(f"Unknown output: {output_name}")


def parquet_bytes(table: pa.Table) -> bytes:
    output = pa.BufferOutputStream()
    pq.write_table(table, output, compression="zstd")
    return output.getvalue().to_pybytes()


def read_s3(
    client: Any, bucket: str, key: str, *, output_name: str = "stolen_assets",
) -> pa.Table | None:
    if output_name not in {"stolen_assets", *SOURCE_NAMES}:
        raise ValueError(f"Unknown output: {output_name}")
    try:
        response = client.get_object(Bucket=bucket, Key=key)
    except ClientError as error:
        code = str(error.response.get("Error", {}).get("Code", ""))
        status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in MISSING_OBJECT_CODES or status == 404:
            return None
        raise RuntimeError(f"Failed to read s3://{bucket}/{key}: {code or error}") from error

    body = response["Body"]
    try:
        payload = body.read()
    finally:
        body.close()
    if not payload:
        raise ValueError(f"S3 object is empty: s3://{bucket}/{key}")

    schema, validator = {
        "stolen_assets": (OUTPUT_SCHEMA, validate_table),
        "defihacklabs": (defihacklabs_parser.OUTPUT_SCHEMA, defihacklabs_parser.validate_table),
        "telegram_investigations": (telegram_investigations_parser.OUTPUT_SCHEMA, telegram_investigations_parser.validate_table),
        "slowmist_hacked": (slowmist_hacked_parser.OUTPUT_SCHEMA, slowmist_hacked_parser.validate_table),
        "sok_interop": (sok_interop_parser.OUTPUT_SCHEMA, sok_interop_parser.validate_table),
        "solidityscan_hack_analysis": (
            solidityscan_hack_parser.OUTPUT_SCHEMA,
            solidityscan_hack_parser.validate_table,
        ),
    }[output_name]
    table = pq.read_table(pa.BufferReader(payload)).cast(schema)
    validator(table, f"s3://{bucket}/{key}")
    return table


def merge_with_existing(
    existing: pa.Table | None,
    current: pa.Table,
) -> tuple[pa.Table, int, int]:
    """Union by address; add new rows and retain the earliest known list date."""
    validate_table(current, "current table")
    if existing is None:
        return current, current.num_rows, 0

    validate_table(existing, "existing S3 table")
    records = {
        canonical_address(str(row["wallet_address"])): row
        for row in existing.to_pylist()
    }
    added = 0
    updated = 0
    for row in current.to_pylist():
        key = canonical_address(str(row["wallet_address"]))
        old_row = records.get(key)
        if old_row is None:
            records[key] = row
            added += 1
            continue
        if old_row["network"] != row["network"]:
            raise ValueError(
                f"Address {row['wallet_address']} changed network from "
                f"{old_row['network']} to {row['network']}"
            )
        old_date: date = old_row["listed_date"]
        new_date: date = row["listed_date"]
        if new_date < old_date:
            old_row["listed_date"] = new_date
            updated += 1

    if added == 0 and updated == 0:
        return existing.cast(OUTPUT_SCHEMA), 0, 0
    merged = _rows_to_table(records.values())
    validate_table(merged, "merged S3 table")
    return merged, added, updated


def upload(client: Any, bucket: str, key: str, table: pa.Table) -> int:
    payload = parquet_bytes(table)
    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=payload,
        ContentType="application/vnd.apache.parquet",
    )
    remote = client.head_object(Bucket=bucket, Key=key)
    remote_size = int(remote["ContentLength"])
    if remote_size != len(payload):
        raise RuntimeError(
            f"S3 size mismatch for s3://{bucket}/{key}: "
            f"sent={len(payload)}, stored={remote_size}"
        )
    return remote_size


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    argument_parser = argparse.ArgumentParser(
        description=(
            "Run all stolen-assets parsers, build Parquet in memory and update "
            "the production S3 objects (separate schemas stay separate)"
        )
    )
    argument_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and serialize in memory without contacting S3",
    )
    argument_parser.add_argument(
        "--source",
        choices=("all", *SOURCE_NAMES),
        default="all",
        help="Each source has a separate S3 object; all also updates the legacy mixed object",
    )
    arguments = argument_parser.parse_args()

    try:
        output_tables = build_output_tables(arguments.source)

        if arguments.dry_run:
            for output_name, current in output_tables:
                LOGGER.info(
                    "Dry run successful: output=%s, rows=%d, parquet_bytes=%d, target_key=%s",
                    output_name, current.num_rows, len(parquet_bytes(current)), output_s3_key(output_name),
                )
            return

        bucket = required_setting("S3_BUCKET")
        client = create_s3_client()
        for output_name, current in output_tables:
            key = output_s3_key(output_name)
            existing = read_s3(client, bucket, key, output_name=output_name)
            merger = {
                "defihacklabs": defihacklabs_parser.merge_with_existing,
                "telegram_investigations": telegram_investigations_parser.merge_with_existing,
                "slowmist_hacked": slowmist_hacked_parser.merge_with_existing,
                "sok_interop": sok_interop_parser.merge_with_existing,
                "solidityscan_hack_analysis": solidityscan_hack_parser.merge_with_existing,
                "stolen_assets": merge_with_existing,
            }[output_name]
            merged, added, updated = merger(existing, current)
            if existing is not None and added == 0 and updated == 0:
                LOGGER.info("s3://%s/%s is current; no upload is needed", bucket, key)
                continue
            size = upload(client, bucket, key, merged)
            LOGGER.info(
                "Uploaded s3://%s/%s: rows=%d, previous_rows=%d, added=%d, changed_or_removed_rows=%d, bytes=%d",
                bucket, key, merged.num_rows, 0 if existing is None else existing.num_rows,
                added, updated, size,
            )
    except (
        BotoCoreError,
        ClientError,
        OSError,
        RuntimeError,
        ValueError,
        requests.RequestException,
        pa.ArrowException,
    ):
        LOGGER.exception("Stolen-assets pipeline failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
