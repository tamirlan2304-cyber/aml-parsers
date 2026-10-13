from __future__ import annotations

import re
from datetime import date, datetime, timezone
from urllib.parse import urlsplit

import pyarrow as pa


CHAINABUSE_SCHEMA = pa.schema(
    [
        pa.field("wallet_address", pa.string(), nullable=False),
        pa.field("network", pa.string(), nullable=False),
        pa.field("domain", pa.string(), nullable=False),
        pa.field("report_date", pa.date32(), nullable=True),
        pa.field("report_id", pa.string(), nullable=False),
        pa.field("report_count", pa.int64(), nullable=False),
    ]
)

EVM_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
GENERIC_ADDRESS_RE = re.compile(r"[A-Za-z0-9._:-]{10,180}")

EVM_CHAINS = {
    "ETH",
    "ETHEREUM",
    "EVM",
    "POLYGON",
    "MATIC",
    "BINANCE",
    "BINANCE_SMART_CHAIN",
    "BSC",
    "AVALANCHE",
    "AVALANCHE_0X",
    "ARBITRUM",
    "BASE",
    "OPTIMISM",
    "LINEA",
    "ZKSYNC",
    "CELO",
    "SONIC",
    "UNICHAIN",
    "BERACHAIN",
    "GNOSIS",
    "FANTOM",
    "KLAYTN",
    "WORLDCHAIN",
    "MANTLE",
    "PLUME",
    "KATANA",
    "TEMPO",
}

NETWORK_NAMES = {
    "BTC": "Bitcoin",
    "BITCOIN": "Bitcoin",
    "TRON": "Tron",
    "TRX": "Tron",
    "SOL": "Solana",
    "SOLANA": "Solana",
    "BCH": "Bitcoin Cash",
    "BITCOIN_CASH": "Bitcoin Cash",
    "LTC": "Litecoin",
    "LITECOIN": "Litecoin",
    "DOGE": "Dogecoin",
    "DOGECOIN": "Dogecoin",
    "XRP": "XRP",
    "NEAR": "Near",
    "HBAR": "Hedera",
    "HEDERA": "Hedera",
    "CARDANO": "Cardano",
    "ADA": "Cardano",
    "MULTIVERSX": "MultiversX",
    "ALGORAND": "Algorand",
    "TON": "Ton",
    "APTOS": "Aptos",
    "SUI": "Sui",
    "SEI": "Sei",
    "DASH": "Dash",
    "STELLAR": "Stellar",
    "COSMOS": "Cosmos",
    "POLKADOT": "Polkadot",
    "FLUX": "Flux",
    "KASPA": "Kaspa",
}


def chain_code(value: str) -> str:
    cleaned = re.sub(r"\s+logo$", "", value.strip(), flags=re.IGNORECASE)
    return re.sub(r"[^A-Z0-9]+", "_", cleaned.upper()).strip("_")


def normalize_network(value: str) -> str:
    code = chain_code(value)
    if not code:
        raise ValueError("Address has no blockchain")
    if code in EVM_CHAINS:
        return "Ethereum"
    return NETWORK_NAMES.get(code, code.replace("_", " ").title())


def canonical_address(address: str) -> str:
    value = address.strip()
    lower = value.lower()
    if EVM_ADDRESS_RE.fullmatch(value):
        return lower
    if lower.startswith(
        ("bc1", "ltc1", "bitcoincash:", "cosmos1", "erd1", "addr1", "kaspa:")
    ):
        return lower
    return value


def valid_source_address(address: str, chain: str) -> bool:
    value = address.strip()
    if not value or any(character.isspace() for character in value):
        return False
    if "://" in value or "@" in value or "/" in value:
        return False
    try:
        network = normalize_network(chain)
    except ValueError:
        return False
    if network == "Ethereum":
        return EVM_ADDRESS_RE.fullmatch(value) is not None
    return GENERIC_ADDRESS_RE.fullmatch(value) is not None


def normalize_domain(value: object) -> str:
    if not isinstance(value, str):
        return ""
    raw = value.strip()
    if not raw or any(character.isspace() for character in raw):
        return ""
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or "").rstrip(".").lower()


def parse_html_report_date(value: str, observed_at: datetime | None = None) -> date | None:
    text = " ".join(value.strip().split())
    observed = observed_at or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    observed_date = observed.astimezone(timezone.utc).date()

    exact_match = re.search(r"\bon ([A-Z][a-z]{2,8} \d{1,2}, \d{4})\b", text)
    if exact_match:
        for date_format in ("%b %d, %Y", "%B %d, %Y"):
            try:
                return datetime.strptime(exact_match.group(1), date_format).date()
            except ValueError:
                continue
        return None

    lowered = text.lower()
    if "just now" in lowered or re.search(r"\b(?:minute|hour)s? ago\b", lowered):
        return observed_date
    if "yesterday" in lowered:
        return date.fromordinal(observed_date.toordinal() - 1)
    relative = re.search(r"\b(\d+) days? ago\b", lowered)
    if relative:
        return date.fromordinal(observed_date.toordinal() - int(relative.group(1)))
    return None
