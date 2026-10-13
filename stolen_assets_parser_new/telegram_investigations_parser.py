from __future__ import annotations

import argparse
import binascii
import hashlib
import logging
import os
import re
import time
import zlib
from base64 import b32decode, urlsafe_b64decode
from dataclasses import dataclass
from datetime import date, datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse

import pyarrow as pa
import requests
from dotenv import load_dotenv


PROJECT_DIR = Path(__file__).resolve().parent
SHARED_ENV_FILE = PROJECT_DIR.parent / "terrorism_parser_new" / ".env"
if SHARED_ENV_FILE.exists():
    load_dotenv(SHARED_ENV_FILE, override=False)
load_dotenv(PROJECT_DIR / ".env", override=True)

LOGGER = logging.getLogger("telegram_investigations_parser")

DEFAULT_SOURCE_URL = "https://t.me/s/investigations"
DEFAULT_CHANNEL = "investigations"
MAX_PAGE_BYTES = 5 * 1024 * 1024

LEGACY_SCHEMA = pa.schema(
    [
        pa.field("wallet_address", pa.string(), nullable=False),
        pa.field("network", pa.string(), nullable=False),
        pa.field("listed_date", pa.date32(), nullable=False),
    ]
)
OUTPUT_SCHEMA = pa.schema([*LEGACY_SCHEMA, pa.field("message_url", pa.string(), nullable=False)])
S3_KEY = "stolen_assets/telegram_investigations.parquet"

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
    "BNB": "BNB Chain",
    "DGB": "DigiByte",
    "ALGO": "Algorand",
    "STRAT": "Stratis",
    "XVG": "Verge",
    "KMD": "Komodo",
}

NETWORK_HINT_PATTERNS = {
    "ETH": re.compile(
        r"\b(?:ethereum|ether|eth|evm|erc-?20|arbitrum|optimism|base|polygon|matic|bsc|binance smart chain|avalanche|fantom)\b",
        re.IGNORECASE,
    ),
    "TRX": re.compile(r"\b(?:tron|trx|tronscan)\b", re.IGNORECASE),
    "BTC": re.compile(r"\b(?:bitcoin|btc|mempool\.space)\b", re.IGNORECASE),
    "LTC": re.compile(r"\b(?:litecoin|ltc)\b", re.IGNORECASE),
    "BCH": re.compile(r"\b(?:bitcoin cash|bch|bitcoincash)\b", re.IGNORECASE),
    "XMR": re.compile(r"\b(?:monero|xmr)\b", re.IGNORECASE),
    "DASH": re.compile(r"\bdash\b", re.IGNORECASE),
    "ZEC": re.compile(r"\b(?:zcash|zec)\b", re.IGNORECASE),
    "SOL": re.compile(r"\b(?:solana|sol|solscan)\b", re.IGNORECASE),
    "DOGE": re.compile(r"\b(?:dogecoin|doge)\b", re.IGNORECASE),
    "XRP": re.compile(r"\b(?:ripple|xrp)\b", re.IGNORECASE),
    "ADA": re.compile(r"\b(?:cardano|ada)\b", re.IGNORECASE),
    "TON": re.compile(r"\b(?:the open network|ton)\b", re.IGNORECASE),
    "XLM": re.compile(r"\b(?:stellar|xlm)\b", re.IGNORECASE),
    "ALGO": re.compile(r"\b(?:algorand|algo)\b", re.IGNORECASE),
    "BNB": re.compile(r"\b(?:bnb beacon|bnb chain)\b", re.IGNORECASE),
}

EVM_RE = re.compile(r"0[xX][0-9a-fA-F]{40}")
TRON_RE = re.compile(r"T[1-9A-HJ-NP-Za-km-z]{33}")
MONERO_RE = re.compile(
    r"(?:[48][1-9A-HJ-NP-Za-km-z]{94}|[48][1-9A-HJ-NP-Za-km-z]{105})"
)
ADDRESS_CANDIDATE_RE = re.compile(
    r"(?:bitcoincash:)?[A-Za-z0-9:_-]{5,128}",
    re.IGNORECASE,
)

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {character: index for index, character in enumerate(BASE58_ALPHABET)}
RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
RIPPLE_INDEX = {character: index for index, character in enumerate(RIPPLE_ALPHABET)}
BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_INDEX = {character: index for index, character in enumerate(BECH32_ALPHABET)}

INVISIBLE_ADDRESS_CHARACTERS = {
    "\u00ad",
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
}


@dataclass(frozen=True)
class TelegramMessage:
    message_id: int
    posted_at: datetime
    text: str
    links: tuple[str, ...]
    message_url: str = ""
    # HTML body links have already been inserted beside their visible labels.
    links_in_text: bool = False


def optional_setting(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


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


def nonnegative_float_setting(name: str, default: float) -> float:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    try:
        result = float(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a number") from error
    if result < 0:
        raise ValueError(f"{name} must be zero or greater")
    return result


def source_url() -> str:
    return optional_setting("TELEGRAM_INVESTIGATIONS_URL") or DEFAULT_SOURCE_URL


def source_channel(url: str) -> str:
    path_parts = [part for part in urlparse(url).path.split("/") if part]
    if len(path_parts) >= 2 and path_parts[0] == "s":
        return path_parts[1]
    raise ValueError(f"Telegram source URL must look like https://t.me/s/channel: {url}")


def parse_datetime(value: str) -> datetime:
    cleaned = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError as error:
        raise ValueError(f"Invalid Telegram message datetime: {value!r}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def grouped_post_id(href: str, channel: str) -> int | None:
    """Return the Telegram message ID represented by an album ``?single`` link."""
    parsed = urlparse(href)
    if parsed.netloc and parsed.netloc.lower() not in {"t.me", "www.t.me"}:
        return None
    query_names = {
        part.split("=", 1)[0]
        for part in parsed.query.split("&")
        if part
    }
    if "single" not in query_names:
        return None
    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) != 2 or path_parts[0] != channel:
        return None
    try:
        return int(path_parts[1])
    except ValueError:
        return None


class _TelegramPageHTMLParser(HTMLParser):
    def __init__(self, channel: str) -> None:
        super().__init__(convert_charrefs=True)
        self.channel = channel
        self.messages: list[TelegramMessage] = []
        self._message_id: int | None = None
        self._message_div_depth = 0
        self._text_div_depth: int | None = None
        self._text_parts: list[str] = []
        self._links: list[str] = []
        self._posted_at: datetime | None = None
        self._represented_message_ids: set[int] = set()
        self._anchor: tuple[str, int] | None = None

    @staticmethod
    def _attributes(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {key: value or "" for key, value in attrs}

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = self._attributes(attrs)

        if tag == "div":
            if self._message_id is None:
                data_post = attributes.get("data-post", "")
                match = re.fullmatch(
                    rf"{re.escape(self.channel)}/(\d+)",
                    data_post,
                )
                if match:
                    self._message_id = int(match.group(1))
                    self._message_div_depth = 1
                    self._text_parts = []
                    self._links = []
                    self._posted_at = None
                    self._represented_message_ids = {self._message_id}
                    self._anchor = None
                return

            self._message_div_depth += 1
            classes = set(attributes.get("class", "").split())
            if "tgme_widget_message_text" in classes:
                if self._text_parts:
                    self._text_parts.append("\n")
                self._text_div_depth = self._message_div_depth
            return

        if self._message_id is None:
            return

        if tag in {"br", "p", "li"} and self._text_div_depth is not None:
            self._text_parts.append("\n")
        elif tag == "a":
            href = attributes.get("href", "").strip()
            if href:
                self._links.append(href)
                if self._text_div_depth is not None:
                    self._anchor = (href, len(self._text_parts))
                related_id = grouped_post_id(href, self.channel)
                if related_id is not None:
                    self._represented_message_ids.add(related_id)
        elif tag == "time":
            datetime_value = attributes.get("datetime", "").strip()
            if datetime_value:
                self._posted_at = parse_datetime(datetime_value)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._anchor is not None:
            href, start = self._anchor
            visible = "".join(self._text_parts[start:])
            # An abbreviated address/explorer link must retain its label context.
            if href not in visible:
                self._text_parts.append(f" ({unquote(href)})")
            self._anchor = None
        if tag in {"p", "li"} and self._text_div_depth is not None:
            self._text_parts.append("\n")
        if tag != "div" or self._message_id is None:
            return

        if self._text_div_depth == self._message_div_depth:
            self._text_div_depth = None

        self._message_div_depth -= 1
        if self._message_div_depth != 0:
            return

        if self._posted_at is None:
            raise ValueError(
                f"Telegram message {self.channel}/{self._message_id} has no datetime"
            )

        # Flattening all <br>s used to detach 'Victim'/'KuCoin deposits' headings
        # from their address lists. Preserve line/paragraph boundaries instead.
        text = "\n".join(" ".join(line.split()) for line in "".join(self._text_parts).splitlines()).strip()
        links = tuple(dict.fromkeys(self._links))
        for represented_id in sorted(self._represented_message_ids):
            self.messages.append(
                TelegramMessage(
                    message_id=represented_id,
                    posted_at=self._posted_at,
                    text=text,
                    links=links,
                    message_url=f"https://t.me/{self.channel}/{self._message_id}",
                    links_in_text=True,
                )
            )
        self._message_id = None
        self._text_div_depth = None
        self._represented_message_ids = set()

    def handle_data(self, data: str) -> None:
        if self._message_id is not None and self._text_div_depth is not None:
            self._text_parts.append(data)


def parse_telegram_page(html: str, channel: str) -> list[TelegramMessage]:
    parser = _TelegramPageHTMLParser(channel)
    parser.feed(html)
    parser.close()
    return parser.messages


def _get_page(
    session: requests.Session,
    url: str,
    before: int | None,
    timeout: int,
    max_retries: int,
) -> str:
    params = {"before": before} if before is not None else None
    last_error: requests.RequestException | None = None
    for attempt in range(1, max_retries + 1):
        try:
            response = session.get(
                url,
                params=params,
                timeout=(15, timeout),
            )
            if response.status_code == 429 or response.status_code >= 500:
                if attempt == max_retries:
                    response.raise_for_status()
                retry_after = response.headers.get("Retry-After", "")
                try:
                    pause = max(float(retry_after), float(attempt))
                except ValueError:
                    pause = float(attempt)
                time.sleep(min(pause, 30.0))
                continue
            response.raise_for_status()
            if len(response.content) > MAX_PAGE_BYTES:
                raise ValueError(
                    f"Telegram HTML page exceeds {MAX_PAGE_BYTES} bytes"
                )
            return response.text
        except requests.RequestException as error:
            last_error = error
            if attempt == max_retries:
                raise
            time.sleep(float(attempt))
    raise RuntimeError(f"Could not download Telegram page: {last_error}")


def fetch_all_messages(session: requests.Session) -> list[TelegramMessage]:
    url = source_url()
    channel = source_channel(url)
    timeout = integer_setting("REQUEST_TIMEOUT_SECONDS", 60)
    max_pages = integer_setting("TELEGRAM_MAX_PAGES", 200)
    max_retries = integer_setting("TELEGRAM_MAX_RETRIES", 3)
    request_delay = nonnegative_float_setting(
        "TELEGRAM_REQUEST_DELAY_SECONDS",
        0.25,
    )

    messages_by_id: dict[int, TelegramMessage] = {}
    before: int | None = None
    for page_number in range(1, max_pages + 1):
        html = _get_page(session, url, before, timeout, max_retries)
        if "tgme_channel_history" not in html:
            raise RuntimeError(
                f"Telegram page {page_number} has no channel-history container; "
                "refusing to treat an error/login page as the end of history"
            )
        page_messages = parse_telegram_page(html, channel)
        if not page_messages:
            if page_number == 1:
                raise RuntimeError(
                    "Telegram returned no public messages; the HTML layout or channel "
                    "availability may have changed"
                )
            break

        for message in page_messages:
            messages_by_id.setdefault(message.message_id, message)

        oldest_id = min(message.message_id for message in page_messages)
        LOGGER.info(
            "Telegram page %d: messages=%d, id_range=%d..%d",
            page_number,
            len(page_messages),
            oldest_id,
            max(message.message_id for message in page_messages),
        )
        if oldest_id <= 1:
            break
        if before is not None and oldest_id >= before:
            raise RuntimeError(
                f"Telegram pagination did not move backwards: before={before}, "
                f"oldest_id={oldest_id}"
            )
        before = oldest_id
        if request_delay:
            time.sleep(request_delay)
    else:
        raise RuntimeError(
            f"Telegram history exceeded TELEGRAM_MAX_PAGES={max_pages}"
        )

    if not messages_by_id:
        raise RuntimeError("Telegram returned no messages")
    return [messages_by_id[key] for key in sorted(messages_by_id)]


def decode_base58(value: str, alphabet_index: dict[str, int]) -> bytes | None:
    number = 0
    try:
        for character in value:
            number = number * 58 + alphabet_index[character]
    except KeyError:
        return None

    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zero_character = next(
        character for character, index in alphabet_index.items() if index == 0
    )
    return b"\x00" * (len(value) - len(value.lstrip(zero_character))) + decoded


def valid_base58check(
    value: str,
    alphabet_index: dict[str, int] = BASE58_INDEX,
) -> bytes | None:
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
        values = [BECH32_INDEX[character] for character in payload]
    except KeyError:
        return False
    prefix_values = [ord(character) & 31 for character in prefix] + [0]
    return cashaddr_polymod(prefix_values + values) == 0


def ton_address_is_valid(address: str) -> bool:
    if len(address) != 48 or re.fullmatch(r"[A-Za-z0-9_-]{48}", address) is None:
        return False
    try:
        decoded = urlsafe_b64decode(address + "==")
    except (ValueError, binascii.Error):
        return False
    if len(decoded) != 36:
        return False
    checksum = 0
    for byte in decoded[:34]:
        checksum ^= byte << 8
        for _ in range(8):
            if checksum & 0x8000:
                checksum = ((checksum << 1) ^ 0x1021) & 0xFFFF
            else:
                checksum = (checksum << 1) & 0xFFFF
    return decoded[34:] == checksum.to_bytes(2, "big")


def stellar_address_is_valid(address: str) -> bool:
    if re.fullmatch(r"G[A-Z2-7]{55}", address) is None:
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
    if re.fullmatch(r"[A-Z2-7]{58}", address) is None:
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


def siacoin_address_is_valid(address: str) -> bool:
    if re.fullmatch(r"[0-9a-fA-F]{76}", address) is None:
        return False
    decoded = bytes.fromhex(address)
    checksum = hashlib.blake2b(decoded[:-6], digest_size=32).digest()[:6]
    return decoded[-6:] == checksum


def lisk_legacy_address_is_valid(address: str) -> bool:
    if re.fullmatch(r"[1-9]\d{0,19}L", address) is None:
        return False
    return int(address[:-1]) <= 0xFFFFFFFFFFFFFFFF


def network_hints(value: str) -> set[str]:
    return {
        network_code
        for network_code, pattern in NETWORK_HINT_PATTERNS.items()
        if pattern.search(value)
    }


def clean_public_key(value: str) -> str:
    address = value.strip().strip("\"'()[]{}<>,;*.`")
    for prefix in (
        "bitcoin:",
        "litecoin:",
        "bitcoincash:",
        "ethereum:",
        "solana:",
        "tron:",
    ):
        if address.lower().startswith(prefix):
            address = address[len(prefix) :]
            break
    return address.split("?", 1)[0]


def normalize_source_address(value: str) -> str:
    cleaned = "".join(
        character
        for character in value.strip()
        if character not in INVISIBLE_ADDRESS_CHARACTERS
    )
    return clean_public_key(cleaned)


def validated_network_codes(address: str) -> set[str]:
    """Validate the address before using any source network hints."""
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
    candidates = validated_network_codes(address)
    if not candidates:
        return None
    if candidates == {"ETH"}:
        return "Ethereum"
    hinted_candidates = candidates.intersection(hints)
    if len(hinted_candidates) == 1:
        return NETWORK_NAMES[next(iter(hinted_candidates))]
    if len(candidates) == 1:
        return NETWORK_NAMES[next(iter(candidates))]
    return None


def canonical_address(address: str) -> str:
    if EVM_RE.fullmatch(address) or bech32_hrp(address) or cashaddr_is_valid(address):
        return address.lower()
    if stellar_address_is_valid(address) or algorand_address_is_valid(address):
        return address.upper()
    return address


_CONTEXT_CANDIDATE_RE = re.compile(r"(?:bitcoincash:)?[A-Za-z0-9_-]{5,128}", re.I)
_URL_RE = re.compile(r"https?://[^\s<>]+", re.I)
_SUBJECT = "subject"
_CEX_NAMES = r"binance|kucoin|coinbase|bybit|okx|okex|kraken|bitget|bitfinex|bitstamp|gate(?:\.io)?|mexc|htx|huobi|ascendex|bitmax|bitmart|poloniex|gemini|crypto\.com|upbit|bithumb"
_ROLE_PATTERNS = (
    ("victim", re.compile(r"\b(?:victims?|victim['’]s|жертв\w*|пострадавш\w*|compromised (?:wallet|address|account)|hacked (?:wallet|address))\b", re.I)),
    ("protocol", re.compile(r"\b(?:protocols?|vulnerable (?:contract|address)|governance contract|протокол\w*|уязвим\w* контракт\w*)\b", re.I)),
    ("liquidity_pool", re.compile(r"\b(?:liquidity pools?|pools?|LP (?:pair|token|address)|pair (?:address|contract)|пул\w* ликвидност\w*)\b", re.I)),
    ("token", re.compile(r"\b(?:tokens?|token\d+|токен\w*|CA(?=\s*:))\b", re.I)),
    ("bridge", re.compile(r"\b(?:bridges?|мост\w*)\b", re.I)),
    ("cex", re.compile(rf"\b(?:CEX|centralized exchanges?|exchange (?:deposit|wallet|address)|{_CEX_NAMES})\b|\b(?:бирж\w*|депозит\w* бирж\w*)\b", re.I)),
    ("service_wallet", re.compile(r"\b(?:hot wallets?|deposit (?:addresses|address)|депозитн\w* адрес\w*)\b", re.I)),
    ("service_contract", re.compile(r"\b(?:routers?|роутер\w*|foundry|cheatcodes?|hevm|multicall3|служебн\w* контракт\w*)\b", re.I)),
    ("test_address", re.compile(r"\b(?:test(?:ing|net)? (?:addresses|address|wallets?|accounts?|contracts?)|mock|dummy|placeholder|makeAddr|vm\.(?:prank|startPrank|deal)|тестов\w* адрес\w*)\b", re.I)),
    (_SUBJECT, re.compile(r"\b(?:(?:theft|attacker|exploiter|hacker|scammer|drainer|recipient|consolidation|laundering) (?:addresses|address|wallets?|contracts?)|attacker|exploiter|scammer|адрес\w* (?:краж\w*|атакующ\w*|мошенник\w*)|злоумышленник\w*)\b", re.I)),
)
_NON_SUBJECT_EVM = frozenset({
    # Foundry VM/console/default test accounts; canonical tokens and routers.
    "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d",
    "0x000000000000000000636f6e736f6c652e6c6f67",
    "0x7fa9385be102ac3eac297483dd6233d62b3e1496",
    "0x1804c8ab1f12e6bbf3894d4083f33e07309d1f38",
    "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    "0x6b175474e89094c44da98b954eedeac495271d0f",
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
    "0x10ed43c718714eb63d5aa57b78b54704e256024e",
    "0xca11bde05977b3631167028862be2a173976ca11",
})


def message_link(message: TelegramMessage) -> str:
    return message.message_url or f"https://t.me/{DEFAULT_CHANNEL}/{message.message_id}"


def _role_in_context(value: str) -> str | None:
    """Use the closest local label, not keywords elsewhere in the message."""
    cleaned = _URL_RE.sub(" ", value).strip()[-140:]
    hits = [(match.start(), role) for role, pattern in _ROLE_PATTERNS for match in pattern.finditer(cleaned)]
    if not hits:
        return None
    position, role = max(hits)
    # Long explanatory prose is not a field label for an unrelated next address.
    if len(cleaned[position:].split()) > 12:
        return None
    return role


def _suffix_role(value: str) -> str | None:
    cleaned = _URL_RE.sub("", value).lstrip(" )]`")
    # Suffix attribution must be explicit: A (victim), A - victim, A is a victim.
    # 'A sent funds to the victim' must not label A as the victim.
    cleaned = re.sub(r"^(?:[(\[]\s*|[-–—,:]\s*|is\s+(?:(?:the|a|an)\s+)?)", "", cleaned, flags=re.I)
    for role, pattern in _ROLE_PATTERNS:
        if pattern.match(cleaned):
            return role
    return None


def _static_exclusion(address: str) -> str | None:
    if EVM_RE.fullmatch(address):
        if int(address[2:], 16) <= 0xFFFFFFFF or len(set(address[2:].lower())) == 1:
            return "zero/burn/placeholder"
        if address.lower() in _NON_SUBJECT_EVM:
            return "known infrastructure/test constant"
    if address == "11111111111111111111111111111111":
        return "Solana system program"
    return None


def _url_exclusion(value: str) -> str | None:
    parsed = urlparse(value)
    route = parsed.path + "/" + parsed.fragment
    if parsed.netloc.lower() in {"dexscreener.com", "www.dexscreener.com", "www.geckoterminal.com", "geckoterminal.com"}:
        return "token/pool catalogue URL"
    # A wallet's /transactions or /tokens subpage still describes the WALLET.
    if re.search(r"/(?:address|addresses|account|wallet|profile)/", route, re.I):
        return None
    if re.search(r"/(?:token(?:20|721|1155)?|tokens|pool|pools|pair)(?:/|$)", route, re.I):
        return "token/pool URL"
    # A transaction, grant round, or arbitrary query parameter is not an address
    # attribution. Ignore it rather than globally blacklisting the same string.
    return "unrelated resource URL"


def _occurrences(text: str, hints: set[str]) -> list[tuple[int, int, str, str, str | None]]:
    urls = list(_URL_RE.finditer(text))
    result = []
    for match in _CONTEXT_CANDIDATE_RE.finditer(text):
        address = normalize_source_address(match[0])
        network = network_for_address(address, hints)
        if network is None:
            continue
        address = canonical_address(address)
        reason = _static_exclusion(address)
        for url in urls:
            if url.start() <= match.start() < url.end():
                reason = reason or _url_exclusion(url[0])
                break
        if reason == "unrelated resource URL":
            continue
        result.append((match.start(), match.end(), address, network, reason))
    return result


def extract_addresses_with_exclusions(
    message: TelegramMessage,
) -> tuple[list[tuple[str, str]], dict[str, str]]:
    text = "".join(c for c in message.text if c not in INVISIBLE_ADDRESS_CHARACTERS)
    # Older callers may construct messages without inline link contexts. Only
    # attach their links when there are no addresses in the text to misattribute.
    if not message.links_in_text and not _occurrences(text, network_hints(text)):
        text += " " + " ".join(unquote(link) for link in message.links)
    hints = network_hints(text)
    # Explicit postfix on the next line: 'A\n(victim)' or terminal 'A\nvictim'.
    # A bare heading followed by B still belongs to B, never to the previous A.
    lines = text.splitlines()
    for index in range(1, len(lines)):
        label = lines[index].strip()
        if not label or len(label) > 60:
            continue
        postfix = label.startswith(("(", "[")) or not any(s.strip() for s in lines[index + 1:])
        if postfix and _occurrences(lines[index - 1], hints) and _suffix_role(label) not in {None, _SUBJECT}:
            lines[index - 1] += " " + label
            lines[index] = ""
    text = "\n".join(lines)
    detected: dict[str, tuple[str, str]] = {}
    excluded: dict[str, str] = {}
    active_role: str | None = None
    for part in re.split(r"\n|;|\|", text):
        if not part.strip():
            continue
        occurrences = _occurrences(part, hints)
        if not occurrences:
            # A compact heading governs the following address list. Normal prose
            # or an unknown new heading ends inheritance from the preceding list.
            active_role = _role_in_context(part) if len(part.strip()) <= 100 else None
            continue
        for index, (start, end, address, network, static_reason) in enumerate(occurrences):
            previous_end = occurrences[index - 1][1] if index else 0
            next_start = occurrences[index + 1][0] if index + 1 < len(occurrences) else len(part)
            prefix = part[previous_end:start]
            if index:
                # Do not give A's parenthesized suffix to B in 'A (victim), B'.
                prefix = re.sub(r"^\s*\([^)]*\)\s*[,;]?", "", prefix)
                prefix = re.sub(r"^\s*[-–—]\s*[^,]+,\s*", "", prefix)
            before_role = _role_in_context(prefix)
            suffix = part[end:next_start]
            # A bare label between two addresses is a prefix for the NEXT one;
            # only brackets/'is'/'-' explicitly attach it to the preceding one.
            explicit_suffix = index + 1 == len(occurrences) or bool(re.match(r"\s*(?:[(\[]|[-–—]|is\b)", suffix, re.I))
            after_role = _suffix_role(suffix) if explicit_suffix else None
            if before_role:
                active_role = before_role
            elif prefix.strip(" ,:()[]`-–—") and len(prefix.split()) > 8:
                active_role = None
            local_excluded = [r for r in (before_role, after_role) if r and r != _SUBJECT]
            reason = static_reason or (local_excluded[0] if local_excluded else None)
            if reason is None and before_role != _SUBJECT and active_role not in {None, _SUBJECT}:
                reason = active_role
            if reason:
                excluded[address] = reason
                LOGGER.debug("Excluded %s (%s), message=%s", address, reason, message_link(message))
            else:
                detected.setdefault(address, (address, network))
    # A second occurrence or an unlabelled explorer link cannot resurrect a victim.
    return [value for key, value in detected.items() if key not in excluded], excluded


def extract_addresses(message: TelegramMessage) -> list[tuple[str, str]]:
    return extract_addresses_with_exclusions(message)[0]


def build_table_from_messages(messages: Iterable[TelegramMessage]) -> pa.Table:
    records: dict[str, dict[str, Any]] = {}
    observations = 0
    parsed_messages = []
    excluded_addresses: set[str] = set()
    for message in messages:
        addresses, excluded = extract_addresses_with_exclusions(message)
        parsed_messages.append((message, addresses))
        excluded_addresses.update(excluded)
    # Exclusion anywhere in the downloaded history wins over an unlabelled repeat.
    timestamps: dict[str, tuple[datetime, int]] = {}
    for message, addresses in parsed_messages:
        listed_date = message.posted_at.astimezone(timezone.utc).date()
        for address, network in addresses:
            if address in excluded_addresses:
                continue
            observations += 1
            key = canonical_address(address)
            url = message_link(message)
            evidence_order = (message.posted_at.astimezone(timezone.utc), int(url.rsplit("/", 1)[-1]))
            current = records.get(key)
            if current is None:
                records[key] = {
                    "wallet_address": address,
                    "network": network,
                    "listed_date": listed_date,
                    "message_url": url,
                }
                timestamps[key] = evidence_order
                continue
            if current["network"] != network:
                raise ValueError(
                    f"Address {address} resolved to conflicting networks: "
                    f"{current['network']} and {network}"
                )
            if evidence_order < timestamps[key]:
                current["listed_date"] = listed_date
                current["message_url"] = url
                timestamps[key] = evidence_order

    if not records:
        raise RuntimeError("Telegram history returned no addresses after context filtering; refusing an empty output")

    rows = sorted(
        records.values(),
        key=lambda row: (row["listed_date"], row["network"], row["wallet_address"]),
    )
    LOGGER.info(
        "Address extraction: accepted_observations=%d, unique_addresses=%d, excluded_addresses=%d",
        observations,
        len(rows),
        len(excluded_addresses),
    )
    table = pa.Table.from_pylist(rows, schema=OUTPUT_SCHEMA)
    validate_table(table)
    return table


def validate_table(table: pa.Table, source: str = "Telegram") -> None:
    if not table.schema.equals(OUTPUT_SCHEMA, check_metadata=False):
        raise ValueError(f"Unexpected Telegram schema in {source}: {table.schema}")
    if not table.num_rows or any(table[c].null_count for c in OUTPUT_SCHEMA.names):
        raise ValueError(f"Empty table or NULL values in {source}")
    addresses: set[str] = set()
    for row in table.to_pylist():
        address = row["wallet_address"]
        if not validated_network_codes(address) or canonical_address(address) != address:
            raise ValueError(f"Invalid/noncanonical address in {source}: {address}")
        if not row["network"].strip() or not re.fullmatch(r"https://t\.me/[A-Za-z0-9_]+/[1-9]\d*", row["message_url"]):
            raise ValueError(f"Missing network or invalid Telegram message URL in {source}")
        if address in addresses:
            raise ValueError(f"Duplicate address in {source}: {address}")
        addresses.add(address)


def merge_with_existing(existing: pa.Table | None, current: pa.Table) -> tuple[pa.Table, int, int]:
    """Synchronize the FULL filtered history; never re-add old excluded addresses.

    Only used for Telegram's separate S3 object, never the old mixed dataset.
    Third return value counts changed AND removed rows so removals trigger PUT.
    """
    validate_table(current, "current Telegram snapshot")
    if existing is None:
        return current, current.num_rows, 0
    validate_table(existing, "existing Telegram snapshot")
    old = {r["wallet_address"]: r for r in existing.to_pylist()}
    new = {r["wallet_address"]: r for r in current.to_pylist()}
    added = len(new.keys() - old.keys())
    removed = len(old.keys() - new.keys())
    updated = sum(old[a] != new[a] for a in old.keys() & new.keys())
    LOGGER.info("Telegram full-history sync: added=%d, updated=%d, removed=%d", added, updated, removed)
    return current, added, updated + removed


def build_table() -> pa.Table:
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
            "User-Agent": "stolen-assets-telegram-parser/1.0",
        }
    )
    try:
        messages = fetch_all_messages(session)
    finally:
        session.close()

    LOGGER.info("Downloaded %d unique Telegram messages", len(messages))
    return build_table_from_messages(messages)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    argument_parser = argparse.ArgumentParser(
        description=(
            "Parse context-filtered addresses and message URLs from the public "
            "@investigations Telegram history into an in-memory Arrow table"
        )
    )
    argument_parser.add_argument("--verbose", action="store_true", help="Log excluded addresses and their message URLs")
    arguments = argument_parser.parse_args()
    if arguments.verbose:
        LOGGER.setLevel(logging.DEBUG)

    try:
        table = build_table()
        LOGGER.info("In-memory schema: %s", table.schema)
    except (
        OSError,
        RuntimeError,
        ValueError,
        requests.RequestException,
        pa.ArrowException,
    ):
        LOGGER.exception("Telegram parsing failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
