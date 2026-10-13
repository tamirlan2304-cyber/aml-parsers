"""Parse OFAC, UK and EU crypto sanctions and synchronize them with S3.

The parser outputs are created only in a temporary system directory. Existing
S3 objects are preserved byte-for-byte when a source contains no new wallet
addresses.

Run:
    python run_all_parsers.py
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
from dotenv import load_dotenv

if __package__:
    from .s3_client import (
        create_s3_client,
        read_parquet_object,
        required_setting,
        write_parquet_object,
    )
    from .utils import (
        BASE_OUTPUT_SCHEMA,
        OFAC_OUTPUT_SCHEMA,
        canonical_address,
        single_network,
    )
else:
    from s3_client import (
        create_s3_client,
        read_parquet_object,
        required_setting,
        write_parquet_object,
    )
    from utils import (
        BASE_OUTPUT_SCHEMA,
        OFAC_OUTPUT_SCHEMA,
        canonical_address,
        single_network,
    )


BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"


@dataclass(frozen=True)
class ParserJob:
    source: str
    script: Path
    s3_key_setting: str
    temporary_name: str
    schema: pa.Schema


PARSER_JOBS = (
    ParserJob(
        "OFAC",
        BASE_DIR / "ofac_xml_to_parquet.py",
        "S3_OFAC_KEY",
        "ofac.parquet",
        OFAC_OUTPUT_SCHEMA,
    ),
    ParserJob(
        "UK",
        BASE_DIR / "uk_csv_to_parquet.py",
        "S3_UK_KEY",
        "UK.parquet",
        BASE_OUTPUT_SCHEMA,
    ),
    ParserJob(
        "EU",
        BASE_DIR / "eu_csv_to_parquet.py",
        "S3_EU_KEY",
        "EU.parquet",
        BASE_OUTPUT_SCHEMA,
    ),
)


def positive_integer_setting(name: str, default: int) -> int:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default
    try:
        value = int(raw_value)
    except ValueError as error:
        raise ValueError(f"{name} must be a positive integer") from error
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def configure_logging() -> logging.Logger:
    level_name = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        raise ValueError(f"Unknown LOG_LEVEL: {level_name}")

    logger = logging.getLogger("sanctions_parsers")
    logger.setLevel(level)
    logger.propagate = False
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(handler)
    return logger


def validate_table(table: pa.Table, label: str, expected_schema: pa.Schema) -> None:
    if not table.schema.equals(expected_schema, check_metadata=False):
        raise ValueError(
            f"Unexpected schema in {label}. Expected {expected_schema}, received {table.schema}"
        )
    if table.num_rows == 0:
        raise ValueError(f"{label} contains no crypto addresses")

    addresses = table.column("wallet_address").to_pylist()
    networks = table.column("network").to_pylist()
    if any(not isinstance(value, str) or not value.strip() for value in addresses):
        raise ValueError(f"{label} contains an empty wallet_address")
    if any(not isinstance(value, str) or not value.strip() for value in networks):
        raise ValueError(f"{label} contains an empty network")
    if any("|" in value for value in networks):
        raise ValueError(f"{label} contains an address with more than one network")
    for address, network in zip(addresses, networks):
        normalized = single_network(address.strip(), network.strip())
        if network.strip() != normalized:
            raise ValueError(
                f"{label} has network {network!r} for {address}; expected {normalized!r}"
            )

    if "country" in expected_schema.names:
        countries = table.column("country").to_pylist()
        if any(not isinstance(value, str) or not value.strip() for value in countries):
            raise ValueError(f"{label} contains an empty country")
        if any("|" in value for value in countries):
            raise ValueError(f"{label} contains more than one country for an address")

    canonical = [canonical_address(value) for value in addresses]
    duplicate_count = len(canonical) - len(set(canonical))
    if duplicate_count:
        raise ValueError(f"{label} contains {duplicate_count} duplicate wallet addresses")


def normalize_existing_table(job: ParserJob, table: pa.Table) -> tuple[pa.Table, int]:
    """Upgrade legacy OFAC schema and normalize old multi-network values."""
    changes = 0
    if job.source == "OFAC" and table.schema.equals(BASE_OUTPUT_SCHEMA, check_metadata=False):
        table = table.append_column(
            "country",
            pa.array(["unknown"] * table.num_rows, type=pa.string()),
        )
        changes += 1
    elif not table.schema.equals(job.schema, check_metadata=False):
        raise ValueError(
            f"Unexpected schema in existing {job.source} S3 object. "
            f"Expected {job.schema}, received {table.schema}"
        )

    rows = table.to_pylist()
    for row in rows:
        network = single_network(row["wallet_address"], row.get("network"))
        if row.get("network") != network:
            row["network"] = network
            changes += 1
        if job.source == "OFAC":
            country = str(row.get("country") or "").strip()
            country = next(
                (part.strip() for part in country.split("|") if part.strip()),
                "unknown",
            )
            country = "unknown" if not country or country.casefold() == "unknown" else country
            if row.get("country") != country:
                row["country"] = country
                changes += 1

    if changes:
        table = pa.Table.from_pylist(rows, schema=job.schema)
    return table, changes


def read_local_table(path: Path, job: ParserJob) -> pa.Table:
    if not path.is_file():
        raise FileNotFoundError(f"{job.source} parser did not create its temporary output")
    try:
        table = pq.read_table(path)
    except (pa.ArrowException, OSError) as error:
        raise ValueError(f"{job.source} parser produced an unreadable Parquet file") from error
    validate_table(table, f"{job.source} parser output", job.schema)
    return table


def log_process_output(logger: logging.Logger, source: str, output: str, level: int) -> None:
    for line in output.splitlines():
        if line.strip():
            logger.log(level, "%s | %s", source, line)


def run_parser(
    logger: logging.Logger,
    job: ParserJob,
    output: Path,
    timeout_seconds: int,
) -> pa.Table:
    if not job.script.is_file():
        raise FileNotFoundError(f"Parser script not found: {job.script}")

    logger.info("%s | parsing source", job.source)
    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "utf-8"
    try:
        result = subprocess.run(
            [sys.executable, str(job.script), "--output", str(output)],
            cwd=BASE_DIR,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError(f"{job.source} parser exceeded {timeout_seconds} seconds") from error

    log_process_output(logger, job.source, result.stdout, logging.INFO)
    log_process_output(logger, job.source, result.stderr, logging.ERROR)
    if result.returncode != 0:
        raise RuntimeError(f"{job.source} parser exited with code {result.returncode}")

    table = read_local_table(output, job)
    logger.info("%s | parsed and validated: %s unique addresses", job.source, table.num_rows)
    return table


def merge_tables(
    existing: pa.Table | None,
    current: pa.Table,
    schema: pa.Schema,
) -> tuple[pa.Table, int, int]:
    """Append new addresses and synchronize OFAC country values."""
    validate_table(current, "current parser output", schema)
    if existing is None:
        return current, current.num_rows, 0

    validate_table(existing, "existing S3 object", schema)
    existing_rows = existing.to_pylist()
    seen = {canonical_address(row["wallet_address"]) for row in existing_rows}
    current_by_address = {
        canonical_address(row["wallet_address"]): row for row in current.to_pylist()
    }
    updated_count = 0
    if "country" in schema.names:
        for row in existing_rows:
            current_row = current_by_address.get(canonical_address(row["wallet_address"]))
            if not current_row:
                continue
            old_country = str(row.get("country") or "").strip()
            new_country = str(current_row.get("country") or "").strip() or "unknown"
            if old_country != new_country:
                row["country"] = new_country
                updated_count += 1

    new_rows: list[dict[str, Any]] = []
    for row in current_by_address.values():
        address = canonical_address(row["wallet_address"])
        if address in seen:
            continue
        seen.add(address)
        new_rows.append(row)

    if not new_rows and not updated_count:
        return existing, 0, 0
    return (
        pa.Table.from_pylist(existing_rows + new_rows, schema=schema),
        len(new_rows),
        updated_count,
    )


def load_configuration() -> tuple[str, dict[str, str], int, str]:
    if not ENV_FILE.is_file():
        raise FileNotFoundError(f"Configuration file not found: {ENV_FILE}")
    load_dotenv(ENV_FILE, override=False)

    bucket = required_setting("S3_BUCKET")
    keys = {job.source: required_setting(job.s3_key_setting) for job in PARSER_JOBS}
    timeout_seconds = positive_integer_setting("PARSER_TIMEOUT_SECONDS", 900)
    compression = os.getenv("PARQUET_COMPRESSION", "zstd").strip() or "zstd"
    return bucket, keys, timeout_seconds, compression


def main() -> int:
    try:
        bucket, keys, timeout_seconds, compression = load_configuration()
        logger = configure_logging()
        client = create_s3_client()
    except Exception as error:
        print(f"Startup error: {error}", file=sys.stderr)
        return 1

    logger.info("Starting sanctions synchronization with S3")
    existing_tables: dict[str, pa.Table | None] = {}
    pending_normalizations: dict[str, int] = {}

    # All three objects are checked before any external source is parsed.
    try:
        for job in PARSER_JOBS:
            key = keys[job.source]
            table, etag = read_parquet_object(client, bucket, key)
            if table is None:
                logger.info("%s | S3 object does not exist yet: s3://%s/%s", job.source, bucket, key)
                pending_normalizations[job.source] = 0
            else:
                table, normalization_count = normalize_existing_table(job, table)
                validate_table(table, f"s3://{bucket}/{key}", job.schema)
                pending_normalizations[job.source] = normalization_count
                logger.info(
                    "%s | found S3 object: %s rows, ETag=%s, pending normalizations=%s",
                    job.source,
                    table.num_rows,
                    etag or "unknown",
                    normalization_count,
                )
            existing_tables[job.source] = table
    except Exception:
        logger.exception("S3 preflight failed; parsing was not started")
        return 1

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="sanctions-parsers-") as temporary_directory:
        temporary_root = Path(temporary_directory)
        for job in PARSER_JOBS:
            key = keys[job.source]
            output = temporary_root / job.temporary_name
            try:
                current = run_parser(logger, job, output, timeout_seconds)
                merged, new_count, updated_count = merge_tables(
                    existing_tables[job.source],
                    current,
                    job.schema,
                )
                normalization_count = pending_normalizations[job.source]
                if new_count == 0 and updated_count == 0 and normalization_count == 0:
                    logger.info(
                        "%s | no new addresses; s3://%s/%s was left unchanged",
                        job.source,
                        bucket,
                        key,
                    )
                    continue

                result = write_parquet_object(client, bucket, key, merged, compression)
                previous_count = 0 if existing_tables[job.source] is None else existing_tables[job.source].num_rows
                logger.info(
                    "%s | uploaded s3://%s/%s: previous=%s, parsed=%s, new=%s, "
                    "country_updates=%s, normalizations=%s, total=%s, bytes=%s",
                    job.source,
                    bucket,
                    key,
                    previous_count,
                    current.num_rows,
                    new_count,
                    updated_count,
                    normalization_count,
                    merged.num_rows,
                    result["size_bytes"],
                )
            except Exception as error:
                failures.append(f"{job.source}: {error}")
                logger.exception("%s | synchronization failed", job.source)

    if failures:
        logger.error("Synchronization finished with %s failure(s): %s", len(failures), "; ".join(failures))
        return 1
    logger.info("All three sanctions sources synchronized successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
