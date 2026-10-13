from __future__ import annotations

import hashlib
import importlib
import re
import ssl
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen

import pyarrow as pa
import pyarrow.parquet as pq


USER_AGENT = "sanctions-crypto-parquet-converter/3.0"

BASE_OUTPUT_SCHEMA = pa.schema(
    [
        pa.field("wallet_address", pa.string()),
        pa.field("network", pa.string()),
        pa.field("name", pa.string()),
        pa.field("designation_date", pa.date32()),
        pa.field("reason_text", pa.string()),
    ]
)
OFAC_OUTPUT_SCHEMA = pa.schema(
    [
        *BASE_OUTPUT_SCHEMA,
        pa.field("country", pa.string()),
    ]
)

NETWORK_LABELS = {
    "ETH": "Ethereum",
    "TRX": "TRON",
    "BTC": "Bitcoin",
    "LTC": "Litecoin",
    "XMR": "Monero",
    "BCH": "Bitcoin Cash",
    "DASH": "Dash",
    "ZEC": "Zcash",
    "SOL": "Solana",
    "DOGE": "Dogecoin",
    "BTG": "Bitcoin Gold",
    "BSV": "Bitcoin SV",
    "XVG": "Verge",
    "XRP": "XRP Ledger",
}

LABEL_PATTERN = "|".join(
    sorted(NETWORK_LABELS, key=len, reverse=True)
)
LABELLED_ADDRESS_RE = re.compile(
    rf"\b(?P<label>{LABEL_PATTERN})\b\s*(?::|=|-)?\s*"
    rf"(?P<address>[A-Za-z0-9]{{20,128}})",
    re.IGNORECASE,
)
CRYPTO_CONTEXT_RE = re.compile(
    r"crypto|wallet|digital currency|digital address|blockchain|"
    rf"\b(?:{LABEL_PATTERN})\b",
    re.IGNORECASE,
)
EVM_RE = re.compile(r"0x[a-fA-F0-9]{40}")
TRON_RE = re.compile(r"T[1-9A-HJ-NP-Za-km-z]{33}")
BECH32_RE = re.compile(r"bc1[ac-hj-np-z02-9]{11,71}", re.IGNORECASE)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {character: index for index, character in enumerate(BASE58_ALPHABET)}


def clean(value: str | None) -> str | None:
    if value is None:
        return None
    result = " ".join(value.replace("\\n", " ").replace("\\r", " ").split())
    return result or None


def unique(values: Iterable[str | None]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def joined(values: Iterable[str | None], separator: str = " | ") -> str | None:
    items = unique(values)
    return separator.join(items) if items else None


def parse_date(value: str | None, formats: Sequence[str]) -> date | None:
    value = clean(value)
    if not value:
        return None
    for pattern in formats:
        try:
            return datetime.strptime(value, pattern).date()
        except ValueError:
            continue
    return None


def canonical_address(address: str) -> str:
    stripped = address.strip()
    return stripped.casefold() if stripped.startswith(("0x", "0X")) else stripped


def base58check_is_valid(value: str, versions: set[int]) -> bool:
    try:
        number = 0
        for character in value:
            number = number * 58 + BASE58_INDEX[character]
        decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
        decoded = b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded
    except (KeyError, ValueError):
        return False
    if len(decoded) != 25 or decoded[0] not in versions:
        return False
    checksum = hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()[:4]
    return decoded[-4:] == checksum


def bitcoin_base58_addresses(value: str) -> list[str]:
    result: list[str] = []
    for start, character in enumerate(value):
        if character not in {"1", "3"}:
            continue
        for length in range(26, 36):
            candidate = value[start : start + length]
            if len(candidate) == length and base58check_is_valid(candidate, {0, 5}):
                result.append(candidate)
                break
    return unique(result)


def inferred_network(address: str) -> str | None:
    if EVM_RE.fullmatch(address):
        return "Ethereum"
    if TRON_RE.fullmatch(address) and base58check_is_valid(address, {65}):
        return "TRON"
    if BECH32_RE.fullmatch(address) or base58check_is_valid(address, {0, 5}):
        return "Bitcoin"
    return None


def network_for_address(address: str, source_label: str | None = None) -> str:
    """Return exactly one network, with address format taking precedence over labels."""
    inferred = inferred_network(address)
    if inferred:
        return inferred
    label = (source_label or "").strip().upper()
    if not label or label == "UNKNOWN":
        return "Unknown"
    # ETH is assigned only by the EVM address format checked above.
    if label == "ETH":
        return "Unknown"
    return NETWORK_LABELS.get(label, "Unknown")


def single_network(address: str, network: str | None) -> str:
    """Normalize legacy multi-network values to one deterministic network."""
    inferred = inferred_network(address)
    if inferred:
        return inferred
    first = next((item.strip() for item in (network or "").split("|") if item.strip()), None)
    if first == "Ethereum" or (first or "").upper() == "ETH":
        return "Unknown"
    if first in NETWORK_LABELS.values():
        return first
    return NETWORK_LABELS.get((first or "").upper(), "Unknown")


def contains_crypto_data(value: str) -> bool:
    """Return True when text has a crypto marker or a supported address format."""
    if CRYPTO_CONTEXT_RE.search(value) or EVM_RE.search(value) or BECH32_RE.search(value):
        return True
    if any(base58check_is_valid(item, {65}) for item in TRON_RE.findall(value)):
        return True
    return bool(bitcoin_base58_addresses(value))


def extract_crypto_addresses(value: str) -> list[tuple[str, str]]:
    """Extract common crypto-address formats and return one network per address."""
    addresses: dict[str, str] = {}
    networks: dict[str, str] = {}

    for match in LABELLED_ADDRESS_RE.finditer(value):
        label, candidate = match.group("label"), match.group("address")
        address: str | None = None
        if label.upper() == "ETH" and not candidate.startswith(("0x", "0X")):
            address = None
        elif candidate.startswith(("0x", "0X")) and len(candidate) >= 42:
            address = candidate[:42] if EVM_RE.fullmatch(candidate[:42]) else None
        elif candidate.startswith("T") and len(candidate) >= 34:
            possible = candidate[:34]
            address = possible if base58check_is_valid(possible, {65}) else None
        elif candidate.casefold().startswith("bc1"):
            match_address = BECH32_RE.match(candidate)
            address = match_address.group(0) if match_address else None
        else:
            base58_values = bitcoin_base58_addresses(candidate)
            address = base58_values[0] if base58_values else candidate
        if address:
            key = canonical_address(address)
            addresses.setdefault(key, address)
            networks.setdefault(key, network_for_address(address, label))

    generic: list[str] = EVM_RE.findall(value)
    generic += [item for item in TRON_RE.findall(value) if base58check_is_valid(item, {65})]
    generic += BECH32_RE.findall(value)
    generic += bitcoin_base58_addresses(value)
    for address in generic:
        key = canonical_address(address)
        addresses.setdefault(key, address)
        networks.setdefault(key, network_for_address(address))

    return [(addresses[key], networks.get(key, "Unknown")) for key in addresses]


def add_wallet_observation(
    by_address: dict[str, dict[str, Any]],
    *,
    address: str,
    network: str,
    name: str | None,
    designation_date: date | None,
    reason: str | None,
    country: str | None = None,
) -> None:
    """Merge one source observation into an address-level record."""
    key = canonical_address(address)
    normalized_network = single_network(address, network)
    record = by_address.setdefault(
        key,
        {
            "wallet_address": address.strip(),
            "network": normalized_network,
            "_names": {},
            "_dates": {},
            "_reasons": {},
            "country": "unknown",
        },
    )
    if record["network"] == "Unknown" and normalized_network != "Unknown":
        record["network"] = normalized_network
    if name:
        record["_names"][name] = None
    if designation_date:
        record["_dates"][designation_date] = None
    if reason:
        record["_reasons"][reason] = None
    cleaned_country = clean(country)
    if record["country"] == "unknown" and cleaned_country:
        record["country"] = cleaned_country


def wallet_rows(
    by_address: dict[str, dict[str, Any]],
    *,
    include_country: bool = False,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key in sorted(by_address):
        record = by_address[key]
        dates = list(record["_dates"])
        row = {
            "wallet_address": record["wallet_address"],
            "network": single_network(record["wallet_address"], record["network"]),
            "name": joined(record["_names"]),
            "designation_date": min(dates) if dates else None,
            "reason_text": joined(record["_reasons"]),
        }
        if include_country:
            row["country"] = record["country"]
        result.append(row)
    return result


def certificate_context() -> ssl.SSLContext | None:
    for module_name in ("certifi", "pip._vendor.certifi"):
        try:
            module = importlib.import_module(module_name)
            return ssl.create_default_context(cafile=module.where())
        except (ImportError, AttributeError, OSError):
            continue
    return None


def open_url(url: str, accept: str):
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    try:
        return urlopen(request, timeout=120)
    except URLError as error:
        context = certificate_context()
        if context is None or not isinstance(error.reason, ssl.SSLCertVerificationError):
            raise
        return urlopen(request, timeout=120, context=context)


def write_parquet(
    rows: list[dict[str, Any]],
    output: Path,
    schema: pa.Schema,
) -> pa.Table:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    table = pa.Table.from_pylist(rows, schema=schema)
    try:
        pq.write_table(table, temporary, compression="zstd")
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()
    return table
