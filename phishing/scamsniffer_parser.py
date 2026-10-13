from __future__ import annotations

import argparse
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pyarrow as pa
import requests
from dotenv import load_dotenv


PROJECT_DIR = Path(__file__).resolve().parent
SHARED_ENV_FILE = PROJECT_DIR.parent / "terrorism_parser_new" / ".env"
if SHARED_ENV_FILE.exists():
    load_dotenv(SHARED_ENV_FILE, override=False)
load_dotenv(PROJECT_DIR / ".env", override=True)

LOGGER = logging.getLogger("scamsniffer_parser")
DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/"
    "scamsniffer/scam-database/main/blacklist/address.json"
)
MAX_SOURCE_BYTES = 20 * 1024 * 1024
EVM_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")

SCAMSNIFFER_SCHEMA = pa.schema(
    [
        pa.field("wallet_address", pa.string(), nullable=False),
        pa.field("network", pa.string(), nullable=False),
        pa.field("category", pa.string(), nullable=False),
        pa.field("source", pa.string(), nullable=False),
        pa.field("source_url", pa.string(), nullable=False),
        pa.field("first_seen_at", pa.timestamp("us", tz="UTC"), nullable=False),
    ]
)


def optional_setting(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def integer_setting(name: str, default: int) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    result = int(value)
    if result <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return result


def source_url() -> str:
    return optional_setting("SCAMSNIFFER_ADDRESS_URL") or DEFAULT_SOURCE_URL


def canonical_address(address: str) -> str:
    return address.strip().lower()


def parse_source_payload(
    payload: bytes,
    *,
    observed_at: datetime | None = None,
    url: str | None = None,
) -> pa.Table:
    if not payload:
        raise ValueError("ScamSniffer response is empty")
    try:
        decoded = json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("ScamSniffer response is not valid UTF-8 JSON") from error
    if not isinstance(decoded, list):
        raise ValueError("Unexpected ScamSniffer JSON structure: expected an array")

    timestamp = observed_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc)
    effective_url = url or source_url()
    records: dict[str, dict[str, Any]] = {}
    invalid: list[str] = []
    for index, raw_value in enumerate(decoded):
        if not isinstance(raw_value, str):
            invalid.append(f"row {index}: non-string value")
            continue
        address = raw_value.strip()
        if EVM_ADDRESS_RE.fullmatch(address) is None:
            invalid.append(f"row {index}: {address[:80]!r}")
            continue
        key = canonical_address(address)
        records.setdefault(
            key,
            {
                "wallet_address": key,
                "network": "Ethereum",
                "category": "phishing",
                "source": "ScamSniffer",
                "source_url": effective_url,
                "first_seen_at": timestamp,
            },
        )
    if invalid:
        raise ValueError(
            "ScamSniffer contains invalid EVM addresses: "
            f"count={len(invalid)}, sample={invalid[:5]}"
        )
    if not records:
        raise RuntimeError("ScamSniffer returned no valid phishing addresses")
    return pa.Table.from_pylist(
        [records[key] for key in sorted(records)], schema=SCAMSNIFFER_SCHEMA
    )


def build_table(*, observed_at: datetime | None = None) -> pa.Table:
    url = source_url()
    timeout = integer_setting("REQUEST_TIMEOUT_SECONDS", 120)
    session = requests.Session()
    session.headers.update(
        {"Accept": "application/json", "User-Agent": "phishing-address-parser/3.0"}
    )
    try:
        LOGGER.info("Downloading ScamSniffer blacklist from %s", url)
        with session.get(url, stream=True, timeout=(15, timeout)) as response:
            response.raise_for_status()
            payload = response.content
    finally:
        session.close()
    if len(payload) > MAX_SOURCE_BYTES:
        raise ValueError(f"ScamSniffer response exceeds {MAX_SOURCE_BYTES} bytes")
    table = parse_source_payload(payload, observed_at=observed_at, url=url)
    LOGGER.info("Validated %d unique ScamSniffer addresses", table.num_rows)
    return table


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    argparse.ArgumentParser(description="Parse ScamSniffer in memory").parse_args()
    try:
        LOGGER.info("Schema: %s", build_table().schema)
    except (OSError, RuntimeError, ValueError, requests.RequestException, pa.ArrowException):
        LOGGER.exception("ScamSniffer parsing failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
