from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
from typing import Any

import boto3
import pyarrow as pa
import pyarrow.parquet as pq
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

from terrorism_parser import OUTPUT_SCHEMA, build_table, canonical_address


PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env")

LOGGER = logging.getLogger("terrorism_s3")
MISSING_OBJECT_CODES = {"404", "NoSuchKey", "NotFound"}
PRODUCTION_S3_KEY = "terrorism/NBCTF.parquet"


def required_setting(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value


def optional_setting(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def production_s3_key() -> str:
    configured = optional_setting("S3_KEY") or PRODUCTION_S3_KEY
    if configured != PRODUCTION_S3_KEY:
        raise ValueError(
            f"S3_KEY must be exactly {PRODUCTION_S3_KEY!r}, got {configured!r}"
        )
    return configured


def boolean_setting(name: str, default: bool) -> bool:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    if value == "True":
        return True
    if value == "False":
        return False
    raise ValueError(f"{name} must be exactly 'True' or 'False'")


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


def parquet_bytes(table: pa.Table) -> bytes:
    output = pa.BufferOutputStream()
    pq.write_table(table, output, compression="zstd")
    return output.getvalue().to_pybytes()


def validate_schema(table: pa.Table, source: str) -> None:
    expected = OUTPUT_SCHEMA.names
    if table.column_names != expected:
        raise ValueError(
            f"Unexpected columns in {source}: {table.column_names}; expected {expected}"
        )


def read_s3(client: Any, bucket: str, key: str) -> pa.Table | None:
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
    table = pq.read_table(pa.BufferReader(payload))
    validate_schema(table, f"s3://{bucket}/{key}")
    return table.cast(OUTPUT_SCHEMA)


def append_new_addresses(
    existing: pa.Table | None,
    current: pa.Table,
) -> tuple[pa.Table, int]:
    """Keep all existing rows and append only previously unseen addresses."""
    if existing is None:
        return current, current.num_rows

    existing_keys = {
        canonical_address(str(row["wallet_address"]))
        for row in existing.to_pylist()
    }
    new_rows: list[dict[str, Any]] = []
    for row in current.to_pylist():
        key = canonical_address(str(row["wallet_address"]))
        if key in existing_keys:
            continue
        existing_keys.add(key)
        new_rows.append(row)

    if not new_rows:
        return existing, 0

    additions = pa.Table.from_pylist(new_rows, schema=OUTPUT_SCHEMA)
    combined = pa.concat_tables([existing, additions]).cast(OUTPUT_SCHEMA)
    return combined, len(new_rows)


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
            f"S3 size mismatch for s3://{bucket}/{key}: sent={len(payload)}, stored={remote_size}"
        )
    return remote_size


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    argument_parser = argparse.ArgumentParser(
        description=(
            "Build the current NBCTF table in memory and append previously unseen "
            "addresses to the S3 Parquet object"
        )
    )
    argument_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build and validate the in-memory Parquet payload without contacting S3",
    )
    arguments = argument_parser.parse_args()

    try:
        current = build_table()
        validate_schema(current, "NBCTF in-memory table")
        payload_size = len(parquet_bytes(current))
        key = production_s3_key()
        if arguments.dry_run:
            LOGGER.info(
                "Dry run successful: rows=%d, parquet_bytes=%d, target_key=%s",
                current.num_rows,
                payload_size,
                key,
            )
            return

        bucket = required_setting("S3_BUCKET")
        client = create_s3_client()
        existing = read_s3(client, bucket, key)
        combined, added = append_new_addresses(existing, current)

        if existing is not None and added == 0:
            LOGGER.info(
                "s3://%s/%s already contains all %d current addresses; no upload is needed",
                bucket,
                key,
                current.num_rows,
            )
            return

        size = upload(client, bucket, key, combined)
        LOGGER.info(
            "Uploaded append-only snapshot to s3://%s/%s: rows=%d, previous_rows=%d, added=%d, bytes=%d",
            bucket,
            key,
            combined.num_rows,
            0 if existing is None else existing.num_rows,
            added,
            size,
        )
    except (BotoCoreError, ClientError, OSError, RuntimeError, ValueError, pa.ArrowException):
        LOGGER.exception("S3 upload failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
