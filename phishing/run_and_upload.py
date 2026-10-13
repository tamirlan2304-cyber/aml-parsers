from __future__ import annotations

import argparse
import logging
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Callable

import boto3
import pyarrow as pa
import pyarrow.parquet as pq
import requests
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

from chainabuse_parser import (
    build_table as build_chainabuse_table,
    normalize_report_id,
    report_key,
)
from phishing_common import CHAINABUSE_SCHEMA, canonical_address
from scamsniffer_parser import (
    SCAMSNIFFER_SCHEMA,
    build_table as build_scamsniffer_table,
)


PROJECT_DIR = Path(__file__).resolve().parent
SHARED_ENV_FILE = PROJECT_DIR.parent / "terrorism_parser_new" / ".env"
if SHARED_ENV_FILE.exists():
    load_dotenv(SHARED_ENV_FILE, override=False)
load_dotenv(PROJECT_DIR / ".env", override=True)

LOGGER = logging.getLogger("phishing_s3")
MISSING_OBJECT_CODES = {"404", "NoSuchKey", "NotFound"}


@dataclass(frozen=True)
class SourceSpec:
    name: str
    key: str
    schema: pa.Schema
    builder: Callable[[], pa.Table]


SOURCES = {
    "scamsniffer": SourceSpec(
        name="scamsniffer",
        key="phishing/scamsniffer.parquet",
        schema=SCAMSNIFFER_SCHEMA,
        builder=build_scamsniffer_table,
    ),
    "chainabuse": SourceSpec(
        name="chainabuse",
        key="phishing/chainabuse.parquet",
        schema=CHAINABUSE_SCHEMA,
        builder=build_chainabuse_table,
    ),
}


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


def enabled_specs(selection: str) -> list[SourceSpec]:
    if selection != "all":
        return [SOURCES[selection]]
    result = [SOURCES["scamsniffer"]]
    if boolean_setting("CHAINABUSE_ENABLED", False):
        result.append(SOURCES["chainabuse"])
    else:
        LOGGER.warning(
            "Chainabuse is disabled. Set CHAINABUSE_ENABLED=True to include it."
        )
    return result


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


def validate_table(table: pa.Table, spec: SourceSpec, source: str) -> None:
    if table.column_names != spec.schema.names:
        raise ValueError(
            f"Unexpected columns in {source}: {table.column_names}; "
            f"expected {spec.schema.names}"
        )
    if table.num_rows == 0:
        raise ValueError(f"Table is empty: {source}")
    for field in spec.schema:
        if not field.nullable and table[field.name].null_count:
            raise ValueError(f"Column {field.name} contains nulls in {source}")

    keys: set[object] = set()
    for row in table.to_pylist():
        if spec.name == "chainabuse":
            report_id = normalize_report_id(row["report_id"])
            if report_id != row["report_id"]:
                raise ValueError(f"Non-canonical report_id {row['report_id']!r} in {source}")
            if not isinstance(row["report_count"], int) or row["report_count"] <= 0:
                raise ValueError(
                    f"Invalid report_count {row['report_count']!r} in {source}"
                )
            key: object = report_key(row)
        else:
            key = canonical_address(str(row["wallet_address"]))
        if key in keys:
            raise ValueError(f"Duplicate source key {key!r} in {source}")
        keys.add(key)


def parquet_bytes(table: pa.Table) -> bytes:
    output = pa.BufferOutputStream()
    pq.write_table(table, output, compression="zstd")
    return output.getvalue().to_pybytes()


def read_s3(client: Any, bucket: str, spec: SourceSpec) -> pa.Table | None:
    try:
        response = client.get_object(Bucket=bucket, Key=spec.key)
    except ClientError as error:
        code = str(error.response.get("Error", {}).get("Code", ""))
        status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in MISSING_OBJECT_CODES or status == 404:
            return None
        raise RuntimeError(
            f"Failed to read s3://{bucket}/{spec.key}: {code or error}"
        ) from error
    body = response["Body"]
    try:
        payload = body.read()
    finally:
        body.close()
    if not payload:
        raise ValueError(f"S3 object is empty: s3://{bucket}/{spec.key}")
    table = pq.read_table(pa.BufferReader(payload))
    legacy_chainabuse_schemas = (
        ["wallet_address", "network", "domain", "report_date"],
        ["wallet_address", "network", "domain", "report_date", "report_id"],
    )
    if spec.name == "chainabuse" and table.column_names in legacy_chainabuse_schemas:
        LOGGER.warning(
            "Ignoring legacy Chainabuse Parquet with the former row schema; "
            "the complete current snapshot will replace it"
        )
        return None
    table = table.cast(spec.schema)
    validate_table(table, spec, f"s3://{bucket}/{spec.key}")
    return table


def _merge_domains(first: str, second: str) -> str:
    values = {
        item.strip().lower()
        for value in (first, second)
        for item in value.split(";")
        if item.strip()
    }
    return "; ".join(sorted(values))


def merge_tables(
    spec: SourceSpec,
    existing: pa.Table | None,
    current: pa.Table,
) -> tuple[pa.Table, int, int]:
    validate_table(current, spec, f"current {spec.name}")
    if existing is None:
        return current, current.num_rows, 0
    validate_table(existing, spec, f"existing {spec.name}")
    records = {
        (
            report_key(row)
            if spec.name == "chainabuse"
            else canonical_address(str(row["wallet_address"]))
        ): row
        for row in existing.to_pylist()
    }
    added = 0
    enriched = 0
    for row in current.to_pylist():
        key = (
            report_key(row)
            if spec.name == "chainabuse"
            else canonical_address(str(row["wallet_address"]))
        )
        old = records.get(key)
        if old is None:
            records[key] = row
            added += 1
            continue
        if spec.name != "chainabuse":
            continue
        if old["network"] != row["network"]:
            raise ValueError(
                f"Address {row['wallet_address']} changed network from "
                f"{old['network']} to {row['network']}"
            )
        changed = False
        domains = _merge_domains(old["domain"], row["domain"])
        if domains != old["domain"]:
            old["domain"] = domains
            changed = True
        old_date = old["report_date"]
        new_date = row["report_date"]
        if new_date is not None and (old_date is None or new_date > old_date):
            old["report_date"] = new_date
            changed = True
        if row["report_count"] > old["report_count"]:
            old["report_count"] = row["report_count"]
            changed = True
        if changed:
            enriched += 1

    if added == 0 and enriched == 0:
        return existing.cast(spec.schema), 0, 0
    rows = list(records.values())
    if spec.name == "chainabuse":
        rows.sort(
            key=lambda row: (
                row["report_date"] is not None,
                row["report_date"] or date.min,
                row["network"],
                row["wallet_address"],
            )
        )
    else:
        rows.sort(key=lambda row: row["wallet_address"])
    merged = pa.Table.from_pylist(rows, schema=spec.schema)
    validate_table(merged, spec, f"merged {spec.name}")
    return merged, added, enriched


def upload(client: Any, bucket: str, spec: SourceSpec, table: pa.Table) -> int:
    payload = parquet_bytes(table)
    client.put_object(
        Bucket=bucket,
        Key=spec.key,
        Body=payload,
        ContentType="application/vnd.apache.parquet",
    )
    remote_size = int(client.head_object(Bucket=bucket, Key=spec.key)["ContentLength"])
    if remote_size != len(payload):
        raise RuntimeError(
            f"S3 size mismatch for s3://{bucket}/{spec.key}: "
            f"sent={len(payload)}, stored={remote_size}"
        )
    return remote_size


def build_source_tables(
    selection: str,
    *,
    chainabuse_max_pages: int | None = None,
    chainabuse_allow_partial: bool | None = None,
) -> list[tuple[SourceSpec, pa.Table]]:
    result: list[tuple[SourceSpec, pa.Table]] = []
    for spec in enabled_specs(selection):
        LOGGER.info("Running source parser: %s", spec.name)
        if spec.name == "chainabuse":
            table = build_chainabuse_table(
                max_pages=chainabuse_max_pages,
                allow_partial=chainabuse_allow_partial,
            )
        else:
            table = spec.builder()
        validate_table(table, spec, f"current {spec.name}")
        LOGGER.info("Source %s returned %d rows", spec.name, table.num_rows)
        result.append((spec, table))
    return result


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    parser = argparse.ArgumentParser(
        description="Build separate phishing Parquet tables in memory and update S3"
    )
    parser.add_argument("--dry-run", action="store_true", help="Do not contact S3")
    parser.add_argument(
        "--source",
        choices=("all", "scamsniffer", "chainabuse"),
        default="all",
    )
    arguments = parser.parse_args()
    try:
        source_tables = build_source_tables(arguments.source)
        if arguments.dry_run:
            for spec, table in source_tables:
                LOGGER.info(
                    "Dry run: source=%s, rows=%d, parquet_bytes=%d, key=%s",
                    spec.name,
                    table.num_rows,
                    len(parquet_bytes(table)),
                    spec.key,
                )
            return

        bucket = required_setting("S3_BUCKET")
        client = create_s3_client()
        for spec, current in source_tables:
            existing = read_s3(client, bucket, spec)
            merged, added, enriched = merge_tables(spec, existing, current)
            if existing is not None and added == 0 and enriched == 0:
                LOGGER.info("s3://%s/%s is current", bucket, spec.key)
                continue
            size = upload(client, bucket, spec, merged)
            LOGGER.info(
                "Uploaded s3://%s/%s: rows=%d, added=%d, enriched=%d, bytes=%d",
                bucket,
                spec.key,
                merged.num_rows,
                added,
                enriched,
                size,
            )
    except KeyboardInterrupt:
        LOGGER.warning(
            "Parsing paused safely. Run the same command later to resume from the latest checkpoint."
        )
        raise SystemExit(130)
    except (
        BotoCoreError,
        ClientError,
        OSError,
        RuntimeError,
        ValueError,
        requests.RequestException,
        pa.ArrowException,
    ):
        LOGGER.exception("Phishing pipeline failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
