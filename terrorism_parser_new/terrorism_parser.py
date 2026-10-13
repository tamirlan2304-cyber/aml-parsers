from __future__ import annotations

import argparse
import binascii
import csv
import hashlib
import io
import logging
import os
import re
import zlib
from base64 import b32decode, urlsafe_b64decode
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable

import pyarrow as pa
import pyarrow.parquet as pq
import requests
from dotenv import load_dotenv


PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env")

LOGGER = logging.getLogger("terrorism_parser")

OUTPUT_SCHEMA = pa.schema(
    [
        pa.field("wallet_address", pa.string(), nullable=False),
        pa.field("network", pa.string(), nullable=False),
        pa.field("name", pa.string(), nullable=False),
        pa.field("designation_date", pa.date32()),
    ]
)

NETWORK_NAMES = {
    "ETH": "Ethereum",
    "TRX": "TRON",
    "BTC": "Bitcoin",
    "LTC": "Litecoin",
    "BCH": "Bitcoin Cash",
    "XMR": "Monero",
    "DASH": "Dash",
    "ZEC": "Zcash",
    "SOL": "Solana",
    "DOGE": "Dogecoin",
    "XRP": "XRP Ledger",
    "ADA": "Cardano",
    "TON": "TON",
    "XLM": "Stellar",
    "SC": "Siacoin",
    "LSK": "Lisk",
    "IOST": "IOST",
    "BNB": "BNB Chain",
    "DGB": "DigiByte",
    "ALGO": "Algorand",
    "STRAT": "Stratis",
    "XVG": "Verge",
    "KMD": "Komodo",
}

ADDRESS_HOMOGLYPHS = {"ᴠ": "v", "ᴑ": "o", "ᴄ": "c", "ᴡ": "w", "ᴢ": "z", "Α": "A", "Β": "B", "Ε": "E",
                       "Ζ": "Z", "Η": "H", "ϳ": "j", "Κ": "K", "Μ": "M", "Ν": "N", "ο": "o", "Ρ": "P",
                       "Ϲ": "C", "Τ": "T", "Υ": "Y", "Χ": "X", "а": "a", "А": "A", "В": "B", "ԁ": "d",
                       "е": "e", "Е": "E", "ѕ": "s", "Ѕ": "S", "ј": "j", "Ј": "J", "ԛ": "q", "М": "M",
                       "Н": "H", "о": "o", "р": "p", "Р": "P", "с": "c", "С": "C", "Ԍ": "G", "Т": "T",
                       "Ү": "Y", "х": "x", "Х": "X", "ԝ": "w", "Ԝ": "W", "հ": "h", "ո": "n", "ս": "u",
                       "Ս": "U", "օ": "o",
                     }

EVM_RE = re.compile(r"0x[0-9a-fA-F]{40}")
TRON_RE = re.compile(r"T[1-9A-HJ-NP-Za-km-z]{33}")
MONERO_RE = re.compile(r"[48][1-9A-HJ-NP-Za-km-z]{94}|[48][1-9A-HJ-NP-Za-km-z]{105}")
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {character: index for index, character in enumerate(BASE58_ALPHABET)}
RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
RIPPLE_INDEX = {character: index for index, character in enumerate(RIPPLE_ALPHABET)}
BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_INDEX = {character: index for index, character in enumerate(BECH32_ALPHABET)}
CASHADDR_ALPHABET = BECH32_ALPHABET
CASHADDR_INDEX = BECH32_INDEX


def required_setting(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value


def integer_setting(name: str, default: int) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    try:
        result = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if result <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return result


EMPTY_VALUES = {"", "-", "n/a", "na", "none", "null", "unknown"}
ADDRESS_CANDIDATE_RE = re.compile(r"(?:bitcoincash:)?[A-Za-z0-9:_-]{5,128}", re.IGNORECASE)
CUSTODIAL_TAG_RE = re.compile(
    r"\(\s*(?:address\s+tag|destination\s+tag|memo)\b",
    re.IGNORECASE,
)
INVISIBLE_ADDRESS_CHARACTERS = {
    "\u00ad",  # soft hyphen
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero-width no-break space / BOM
}


def clean_text(value: Any) -> str:
    return " ".join(str(value or "").replace("\ufeff", "").split())


def decode_base58(value: str, alphabet_index: dict[str, int]) -> bytes | None:
    number = 0
    try:
        for character in value:
            number = number * 58 + alphabet_index[character]
    except KeyError:
        return None

    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zero_character = next(character for character, index in alphabet_index.items() if index == 0)
    return b"\x00" * (len(value) - len(value.lstrip(zero_character))) + decoded


def valid_base58check(value: str, alphabet_index: dict[str, int] = BASE58_INDEX) -> bytes | None:
    decoded = decode_base58(value, alphabet_index)
    if decoded is None or len(decoded) < 5:
        return None
    checksum = hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()[:4]
    return decoded if decoded[-4:] == checksum else None


def bech32_polymod(values: Iterable[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        high = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (high >> index) & 1:
                checksum ^= generator
    return checksum


def bech32_hrp(address: str) -> str | None:
    if address.lower() != address and address.upper() != address:
        return None
    value = address.lower()
    separator = value.rfind("1")
    if separator < 1 or separator + 7 > len(value) or len(value) > 90:
        return None
    try:
        data = [BECH32_INDEX[character] for character in value[separator + 1 :]]
    except KeyError:
        return None
    hrp = value[:separator]
    expanded = [ord(character) >> 5 for character in hrp]
    expanded += [0]
    expanded += [ord(character) & 31 for character in hrp]
    return hrp if bech32_polymod(expanded + data) in {1, 0x2BC830A3} else None


def cashaddr_polymod(values: Iterable[int]) -> int:
    generators = (
        0x98F2BC8E61,
        0x79B76D99E2,
        0xF33E5FB3C4,
        0xAE2EABE2A8,
        0x1E4F43E470,
    )
    checksum = 1
    for value in values:
        high = checksum >> 35
        checksum = ((checksum & 0x07FFFFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (high >> index) & 1:
                checksum ^= generator
    return checksum ^ 1


def cashaddr_is_valid(address: str) -> bool:
    value = address.lower()
    if value != address and address.upper() != address:
        return False
    if ":" in value:
        prefix, payload = value.split(":", 1)
    else:
        prefix, payload = "bitcoincash", value
    if prefix != "bitcoincash" or len(payload) < 42:
        return False
    try:
        values = [CASHADDR_INDEX[character] for character in payload]
    except KeyError:
        return False
    prefix_values = [ord(character) & 31 for character in prefix] + [0]
    return cashaddr_polymod(prefix_values + values) == 0


def ton_address_is_valid(address: str) -> bool:
    if len(address) != 48 or not re.fullmatch(r"[A-Za-z0-9_-]{48}", address):
        return False
    try:
        decoded = urlsafe_b64decode(address + "==")
    except ValueError:
        return False
    if len(decoded) != 36:
        return False
    checksum = 0
    for byte in decoded[:34]:
        checksum ^= byte << 8
        for _ in range(8):
            checksum = ((checksum << 1) ^ 0x1021) & 0xFFFF if checksum & 0x8000 else (checksum << 1) & 0xFFFF
    return decoded[34:] == checksum.to_bytes(2, "big")


def lisk_legacy_address_is_valid(address: str) -> bool:
    """Validate the numeric legacy Lisk address format (uint64 + ``L``)."""
    if not re.fullmatch(r"[1-9]\d{0,19}L", address):
        return False
    return int(address[:-1]) <= 0xFFFFFFFFFFFFFFFF


def siacoin_address_is_valid(address: str) -> bool:
    """Validate a Sia unlock hash and its six-byte BLAKE2b checksum."""
    if not re.fullmatch(r"[0-9a-fA-F]{76}", address):
        return False
    decoded = bytes.fromhex(address)
    checksum = hashlib.blake2b(decoded[:-6], digest_size=32).digest()[:6]
    return decoded[-6:] == checksum


def stellar_address_is_valid(address: str) -> bool:
    """Validate a Stellar ed25519 public account StrKey (``G...``)."""
    if not re.fullmatch(r"G[A-Z2-7]{55}", address):
        return False
    try:
        decoded = b32decode(address)
    except (ValueError, binascii.Error):
        return False
    if len(decoded) != 35 or decoded[0] != 6 << 3:
        return False
    checksum = binascii.crc_hqx(decoded[:-2], 0).to_bytes(2, "little")
    return decoded[-2:] == checksum


def algorand_address_is_valid(address: str) -> bool:
    """Validate an Algorand address and its four-byte SHA-512/256 checksum."""
    if not re.fullmatch(r"[A-Z2-7]{58}", address):
        return False
    padding = "=" * ((8 - len(address) % 8) % 8)
    try:
        decoded = b32decode(address + padding)
    except (ValueError, binascii.Error):
        return False
    if len(decoded) != 36:
        return False
    checksum = hashlib.new("sha512_256", decoded[:-4]).digest()[-4:]
    return decoded[-4:] == checksum


def cardano_byron_address_is_valid(address: str) -> bool:
    """Validate the CBOR envelope and CRC32 of a legacy Cardano Byron address."""
    decoded = decode_base58(address, BASE58_INDEX)
    if decoded is None or len(decoded) < 11 or decoded[:4] != b"\x82\xd8\x18\x58":
        return False

    payload_length = decoded[4]
    payload_start = 5
    checksum_marker = payload_start + payload_length
    if checksum_marker + 5 != len(decoded) or decoded[checksum_marker] != 0x1A:
        return False

    payload = decoded[payload_start:checksum_marker]
    expected_checksum = int.from_bytes(decoded[checksum_marker + 1 :], "big")
    return zlib.crc32(payload) == expected_checksum


def network_hints(values: Iterable[str]) -> set[str]:
    result: set[str] = set()
    for value in values:
        upper = clean_text(value).upper()
        for key, network_name in NETWORK_NAMES.items():
            if re.search(rf"(^|[^A-Z0-9]){re.escape(key)}([^A-Z0-9]|$)", upper):
                result.add(key)
            if upper == network_name.upper():
                result.add(key)
    return result


def clean_public_key(value: str) -> str:
    address = value.strip().strip("\"'()[]{}<>,;*")
    for prefix in ("bitcoin:", "litecoin:", "bitcoincash:"):
        if address.lower().startswith(prefix):
            address = address[len(prefix) :]
            break
    return address.split("?", 1)[0]


def normalize_source_address(value: Any) -> str:
    cleaned = clean_text(value)
    cleaned = "".join(
        ADDRESS_HOMOGLYPHS.get(character, character)
        for character in cleaned
        if character not in INVISIBLE_ADDRESS_CHARACTERS
    )
    return clean_public_key(cleaned)


def validated_network_codes(address: str) -> set[str]:
    """Return networks whose address rules accept the value.

    Source metadata is deliberately not used here. A value must first pass a
    blockchain-specific structure and, where available, checksum validation.
    """
    if EVM_RE.fullmatch(address):
        return {"ETH"}

    if TRON_RE.fullmatch(address):
        decoded = valid_base58check(address)
        if decoded is not None and decoded[:-4].startswith(b"\x41"):
            return {"TRX"}

    hrp = bech32_hrp(address)
    if hrp == "bc":
        return {"BTC"}
    if hrp == "ltc":
        return {"LTC"}
    if hrp == "addr":
        return {"ADA"}
    if hrp == "bnb":
        return {"BNB"}

    if cashaddr_is_valid(address):
        return {"BCH"}
    if ton_address_is_valid(address):
        return {"TON"}
    if cardano_byron_address_is_valid(address):
        return {"ADA"}
    if stellar_address_is_valid(address):
        return {"XLM"}
    if algorand_address_is_valid(address):
        return {"ALGO"}
    if siacoin_address_is_valid(address):
        return {"SC"}
    if lisk_legacy_address_is_valid(address):
        return {"LSK"}

    decoded = valid_base58check(address)
    if decoded is not None:
        payload = decoded[:-4]
        if len(payload) == 21:
            version = payload[0]
            if version == 0:
                return {"BTC"}
            if version == 5:
                return {"BTC", "LTC"}
            if version in {48, 50}:
                return {"LTC"}
            if version == 30:
                return {"DOGE", "DGB", "XVG"}
            if version == 22:
                return {"DOGE"}
            if version in {76, 16}:
                return {"DASH"}
            if version == 60:
                return {"KMD"}
            if version == 63:
                return {"STRAT"}
        if len(payload) == 22 and payload[:2] in {b"\x1c\xb8", b"\x1c\xbd"}:
            return {"ZEC"}

    if address.startswith("r"):
        ripple = valid_base58check(address, RIPPLE_INDEX)
        if ripple is not None and len(ripple) == 25:
            return {"XRP"}

    decoded_solana = decode_base58(address, BASE58_INDEX)
    if decoded_solana is not None and len(decoded_solana) == 32:
        return {"SOL"}

    if MONERO_RE.fullmatch(address):
        return {"XMR"}

    return set()


def network_for_address(address: str, hints: set[str]) -> str | None:
    """Validate the address first, then resolve its network.

    Currency/platform hints may only disambiguate formats shared by multiple
    networks. They can never make an invalid value acceptable.
    """
    candidates = validated_network_codes(address)
    if not candidates:
        return None

    hinted_candidates = candidates.intersection(hints)
    if len(hinted_candidates) == 1:
        return NETWORK_NAMES[next(iter(hinted_candidates))]
    if len(candidates) == 1:
        return NETWORK_NAMES[next(iter(candidates))]
    return None


def canonical_address(address: str) -> str:
    if (
        EVM_RE.fullmatch(address)
        or bech32_hrp(address)
        or cashaddr_is_valid(address)
        or siacoin_address_is_valid(address)
    ):
        return address.lower()
    if stellar_address_is_valid(address) or algorand_address_is_valid(address):
        return address.upper()
    return address


def parse_date(value: str) -> date | None:
    cleaned = clean_text(value)
    if not cleaned:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[T ].*)?", cleaned):
        cleaned = cleaned[:10]

    formats = (
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%d.%m.%Y",
        "%d-%m-%Y",
        "%m/%d/%Y",
        "%d/%m/%y",
        "%d.%m.%y",
        "%d-%m-%y",
        "%B %d, %Y",
        "%b %d, %Y",
        "%d %B %Y",
        "%d %b %Y",
    )
    for date_format in formats:
        try:
            return datetime.strptime(cleaned, date_format).date()
        except ValueError:
            continue
    return None


def address_values(row: dict[str, str]) -> list[tuple[str, str]]:
    hints = network_hints((row.get("currency", ""), row.get("platform", "")))
    detected: dict[str, tuple[str, str]] = {}
    raw_wallet_value = clean_text(row.get("wallet_address"))
    if not raw_wallet_value or CUSTODIAL_TAG_RE.search(raw_wallet_value):
        return []

    wallet_value = normalize_source_address(raw_wallet_value)
    if not wallet_value:
        return []

    candidates = ADDRESS_CANDIDATE_RE.findall(wallet_value)

    for candidate in candidates:
        address = clean_public_key(candidate)
        network = network_for_address(address, hints)
        if network is None:
            continue
        key = canonical_address(address)
        detected.setdefault(key, (address, network))
    return list(detected.values())


def holder_name(row: dict[str, str], addresses: set[str]) -> str:
    value = clean_text(row.get("name"))
    if value.casefold() in EMPTY_VALUES:
        return "unknown"
    if canonical_address(value) in addresses:
        return "unknown"
    return value


def designation_date(row: dict[str, str]) -> date | None:
    return parse_date(row.get("start_date", ""))


def wallet_rows_from_csv(row: dict[str, str]) -> list[dict[str, Any]]:
    detected = address_values(row)
    address_keys = {canonical_address(address) for address, _ in detected}
    name = holder_name(row, address_keys)
    listed_on = designation_date(row)
    return [
        {
            "wallet_address": address,
            "network": network,
            "name": name,
            "designation_date": listed_on,
        }
        for address, network in detected
    ]


def merge_row(records: dict[str, dict[str, Any]], row: dict[str, Any]) -> None:
    key = canonical_address(row["wallet_address"])
    current = records.get(key)
    if current is None:
        records[key] = row
        return
    if current["name"] == "unknown" and row["name"] != "unknown":
        current["name"] = row["name"]
    old_date = current["designation_date"]
    new_date = row["designation_date"]
    if old_date is None or (new_date is not None and new_date < old_date):
        current["designation_date"] = new_date


def csv_rows(stream: Iterable[str]) -> Iterable[dict[str, str]]:
    reader = csv.DictReader(stream)
    if not reader.fieldnames:
        raise ValueError("NBCTF CSV has no header row")

    headers = [clean_text(header).casefold() for header in reader.fieldnames if header]
    required_headers = {"wallet_address", "currency", "name", "start_date"}
    missing_headers = required_headers.difference(headers)
    if missing_headers:
        missing = ", ".join(sorted(missing_headers))
        raise ValueError(f"NBCTF CSV is missing required columns: {missing}")
    LOGGER.info("NBCTF CSV columns: %s", ", ".join(headers))
    for line_number, raw_row in enumerate(reader, start=2):
        row: dict[str, str] = {}
        for header, value in raw_row.items():
            if header is None:
                continue
            cleaned_header = clean_text(header).casefold()
            if not cleaned_header:
                continue
            if isinstance(value, list):
                cleaned_value = " ".join(clean_text(item) for item in value)
            else:
                cleaned_value = clean_text(value)
            row[cleaned_header] = cleaned_value
        if row:
            yield row
        elif any(value for value in raw_row.values()):
            raise ValueError(f"Could not parse NBCTF CSV row {line_number}")


def read_nbctf_csv(
    session: requests.Session,
    records: dict[str, dict[str, Any]],
    timeout: int,
) -> None:
    url = required_setting("NBCTF_CSV_URL")
    LOGGER.info("Downloading NBCTF CSV from Google Sheets")
    with session.get(url, stream=True, timeout=(15, timeout)) as response:
        response.raise_for_status()
        payload = response.content
        if not payload:
            raise ValueError("NBCTF CSV response is empty")
        try:
            csv_text = payload.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ValueError("NBCTF CSV is not valid UTF-8") from error
        text_stream = io.StringIO(csv_text, newline="")
        source_rows = 0
        accepted = 0
        for source_row in csv_rows(text_stream):
            source_rows += 1
            for wallet_row in wallet_rows_from_csv(source_row):
                merge_row(records, wallet_row)
                accepted += 1
    LOGGER.info(
        "NBCTF CSV: processed rows=%d, valid address observations=%d",
        source_rows,
        accepted,
    )


def build_table() -> pa.Table:
    timeout = integer_setting("REQUEST_TIMEOUT_SECONDS", 120)
    records: dict[str, dict[str, Any]] = {}

    session = requests.Session()
    session.headers.update(
        {
            "Accept": "text/csv,*/*;q=0.8",
            "User-Agent": "terrorism-crypto-address-parser/1.0",
        }
    )
    try:
        read_nbctf_csv(session, records, timeout)
    finally:
        session.close()

    rows = [records[key] for key in sorted(records)]
    if not rows:
        raise RuntimeError("NBCTF returned no valid terrorism-related crypto addresses")
    return pa.Table.from_pylist(rows, schema=OUTPUT_SCHEMA)


def output_path(value: str | None) -> Path:
    configured = value or os.getenv("OUTPUT_FILE", "terrorism.parquet")
    path = Path(configured)
    return path if path.is_absolute() else PROJECT_DIR / path


def write_parquet(table: pa.Table, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        pq.write_table(table, temporary, compression="zstd")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    argument_parser = argparse.ArgumentParser(
        description="Parse terrorism-related blockchain addresses from the NBCTF CSV"
    )
    argument_parser.add_argument("--output", help="Parquet output path")
    arguments = argument_parser.parse_args()

    try:
        table = build_table()
        destination = output_path(arguments.output)
        write_parquet(table, destination)
        LOGGER.info("Saved %d unique addresses to %s", table.num_rows, destination)
    except (OSError, ValueError, RuntimeError, requests.RequestException, pa.ArrowException):
        LOGGER.exception("Parsing failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
