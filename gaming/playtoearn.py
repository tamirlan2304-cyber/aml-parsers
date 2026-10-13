"""Parse Ethereum and TRON game contracts from PlayToEarn into local Parquet.

The public, server-rendered HTML is sufficient; no login, browser profile or
database connection is used. Running this file creates two files beside it:

    playtoearn_ethereum.parquet
    playtoearn_tron.parquet
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, urljoin, urlsplit

import pyarrow as pa
import pyarrow.parquet as pq
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


LOGGER = logging.getLogger("playtoearn_gaming")
PROJECT_DIR = Path(__file__).resolve().parent
BASE_URL = "https://playtoearn.com"
LIST_URLS = {
    "Ethereum": (
        f"{BASE_URL}/blockchaingames/Ethereum/All-Genre/All-Status/"
        "All-Device/All-NFT/All-PlayToEarn/All-FreeToPlay"
    ),
    "Tron": (
        f"{BASE_URL}/blockchaingames/TRON/All-Genre/All-Status/"
        "All-Device/All-NFT/All-PlayToEarn/All-FreeToPlay"
    ),
}
OUTPUT_PATHS = {
    "Ethereum": PROJECT_DIR / "playtoearn_ethereum.parquet",
    "Tron": PROJECT_DIR / "playtoearn_tron.parquet",
}
OUTPUT_SCHEMA = pa.schema(
    [
        pa.field("address", pa.string(), nullable=False),
        pa.field("network", pa.string(), nullable=False),
        pa.field("game_name", pa.string(), nullable=False),
        pa.field("game_url", pa.string(), nullable=False),
        pa.field("status", pa.string(), nullable=False),
    ]
)

DEFAULT_WORKERS = 8
DEFAULT_TIMEOUT_SECONDS = 45
DEFAULT_RETRIES = 3
MAX_HTML_BYTES = 12 * 1024 * 1024
EXPECTED_PAGE_SIZE = 50
VALID_STATUSES = {"Live", "Presale", "Alpha", "Beta", "Development", "Cancelled"}
EVM_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
TRON_BASE58_RE = re.compile(r"T[1-9A-HJ-NP-Za-km-z]{33}")
TRON_HEX_RE = re.compile(r"41[0-9a-fA-F]{40}")
_THREAD_LOCAL = threading.local()


@dataclass(frozen=True)
class ListPage:
    active_page: int
    total_pages: int
    game_urls: tuple[str, ...]


@dataclass(frozen=True)
class GameDetail:
    url: str
    name: str
    status: str
    contracts: tuple[tuple[str, str], ...]


def _classes(attributes: dict[str, str | None]) -> set[str]:
    return set((attributes.get("class") or "").split())


def _clean_text(parts: Iterable[str]) -> str:
    return " ".join("".join(parts).split())


def _valid_game_url(value: str) -> bool:
    parts = urlsplit(value)
    path_parts = [part for part in parts.path.split("/") if part]
    return (
        parts.scheme == "https"
        and parts.netloc.casefold() == "playtoearn.com"
        and len(path_parts) == 2
        and path_parts[0] == "blockchaingame"
        and bool(path_parts[1])
        and not parts.query
        and not parts.fragment
    )


class _ListPageParser(HTMLParser):
    def __init__(self, expected_path: str) -> None:
        super().__init__(convert_charrefs=True)
        self.expected_path = expected_path.rstrip("/")
        self.game_urls: dict[str, None] = {}
        self.page_numbers: set[int] = {1}
        self.active_page: int | None = None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        classes = _classes(attributes)
        if tag == "a" and "dapp_detaillink" in classes:
            href = attributes.get("href")
            if href:
                url = urljoin(BASE_URL, href)
                if _valid_game_url(url):
                    self.game_urls.setdefault(url, None)
        if tag == "li" and "active-page" in classes:
            raw_page = attributes.get("data-page")
            if raw_page is not None and raw_page.isdigit():
                self.active_page = int(raw_page) + 1
        if tag == "a":
            href = attributes.get("href")
            if not href:
                return
            parts = urlsplit(urljoin(BASE_URL, href))
            if parts.path.rstrip("/") != self.expected_path:
                return
            values = parse_qs(parts.query).get("page", [])
            for value in values:
                if value.isdigit() and int(value) > 0:
                    self.page_numbers.add(int(value))


class _GameDetailParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.name = ""
        self.status = ""
        self.contracts: list[tuple[str, str]] = []
        self._capture_name = False
        self._capture_status = False
        self._capture_chain = False
        self._capture_address = False
        self._name_parts: list[str] = []
        self._status_parts: list[str] = []
        self._chain_parts: list[str] = []
        self._address_parts: list[str] = []
        self._insights_depth = 0
        self._in_contract_row = False

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        classes = _classes(attributes)

        if tag == "div":
            if attributes.get("id") == "gameInsightsBlock":
                self._insights_depth = 1
            elif self._insights_depth:
                self._insights_depth += 1

        if tag == "h1" and not self.name:
            self._capture_name = True
            self._name_parts = []

        if (
            tag == "span"
            and self._insights_depth
            and "__Builder_StatusBadge" in classes
            and not self.status
        ):
            self._capture_status = True
            self._status_parts = []

        if tag == "tr" and "ContractRow" in classes:
            self._in_contract_row = True
            self._chain_parts = []
            self._address_parts = []
        elif self._in_contract_row and tag == "td" and "__Chain" in classes:
            self._capture_chain = True
        elif self._in_contract_row and tag == "span" and "ContractAddress" in classes:
            self._capture_address = True

    def handle_data(self, data: str) -> None:
        if self._capture_name:
            self._name_parts.append(data)
        if self._capture_status:
            self._status_parts.append(data)
        if self._capture_chain:
            self._chain_parts.append(data)
        if self._capture_address:
            self._address_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "h1" and self._capture_name:
            self.name = _clean_text(self._name_parts)
            self._capture_name = False
        elif tag == "span" and self._capture_status:
            self.status = _clean_text(self._status_parts)
            self._capture_status = False
        elif tag == "td" and self._capture_chain:
            self._capture_chain = False
        elif tag == "span" and self._capture_address:
            self._capture_address = False
        elif tag == "tr" and self._in_contract_row:
            chain = _clean_text(self._chain_parts)
            address = _clean_text(self._address_parts)
            if chain and address:
                self.contracts.append((chain, address))
            self._in_contract_row = False

        if tag == "div" and self._insights_depth:
            self._insights_depth -= 1


def _new_session(retries: int) -> requests.Session:
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update(
        {
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": "Mozilla/5.0",
        }
    )
    return session


def _session(retries: int) -> requests.Session:
    session = getattr(_THREAD_LOCAL, "session", None)
    configured_retries = getattr(_THREAD_LOCAL, "retries", None)
    if session is None or configured_retries != retries:
        if session is not None:
            session.close()
        session = _new_session(retries)
        _THREAD_LOCAL.session = session
        _THREAD_LOCAL.retries = retries
    return session


def fetch_html(url: str, *, timeout: int, retries: int) -> str:
    if not _valid_playtoearn_url(url):
        raise ValueError(f"Refusing unexpected URL: {url}")
    with _session(retries).get(
        url,
        timeout=(10, timeout),
        stream=True,
        allow_redirects=True,
    ) as response:
        response.raise_for_status()
        if not _valid_playtoearn_url(response.url):
            raise RuntimeError(f"PlayToEarn redirected outside its site: {response.url}")
        content_type = response.headers.get("Content-Type", "").casefold()
        if "text/html" not in content_type:
            raise ValueError(f"Unexpected Content-Type for {url}: {content_type!r}")
        payload = bytearray()
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if len(payload) + len(chunk) > MAX_HTML_BYTES:
                raise ValueError(f"HTML response is too large: {url}")
            payload.extend(chunk)
    return bytes(payload).decode("utf-8", errors="replace")


def _valid_playtoearn_url(value: str) -> bool:
    parts = urlsplit(value)
    return (
        parts.scheme == "https"
        and parts.netloc.casefold() in {"playtoearn.com", "www.playtoearn.com"}
    )


def parse_list_page(html: str, list_url: str, requested_page: int) -> ListPage:
    parser = _ListPageParser(urlsplit(list_url).path)
    parser.feed(html)
    parser.close()
    active_page = parser.active_page or 1
    if active_page != requested_page:
        raise RuntimeError(
            f"PlayToEarn returned list page {active_page}, requested {requested_page}"
        )
    if not parser.game_urls:
        raise ValueError(f"PlayToEarn list page {requested_page} contains no game links")
    return ListPage(
        active_page=active_page,
        total_pages=max(parser.page_numbers),
        game_urls=tuple(parser.game_urls),
    )


def _list_page_url(list_url: str, page: int) -> str:
    # The default ranking can change between concurrent requests and shift a
    # game to another page. Name sorting is stable for a complete snapshot.
    return f"{list_url}?sort=name&direction=asc&page={page}"


def discover_game_urls(
    network: str,
    *,
    timeout: int,
    retries: int,
    workers: int,
) -> tuple[str, ...]:
    list_url = LIST_URLS[network]
    first = parse_list_page(
        fetch_html(_list_page_url(list_url, 1), timeout=timeout, retries=retries),
        list_url,
        1,
    )
    pages: dict[int, ListPage] = {1: first}
    if first.total_pages > 1:
        with ThreadPoolExecutor(max_workers=min(workers, first.total_pages - 1)) as executor:
            futures = {
                executor.submit(
                    fetch_html,
                    _list_page_url(list_url, page),
                    timeout=timeout,
                    retries=retries,
                ): page
                for page in range(2, first.total_pages + 1)
            }
            for future in as_completed(futures):
                page = futures[future]
                pages[page] = parse_list_page(future.result(), list_url, page)

    discovered: dict[str, None] = {}
    for page in range(1, first.total_pages + 1):
        result = pages[page]
        if result.total_pages != first.total_pages:
            raise RuntimeError(f"PlayToEarn {network} pagination changed during parsing")
        if page < first.total_pages and len(result.game_urls) != EXPECTED_PAGE_SIZE:
            raise RuntimeError(
                f"PlayToEarn {network} page {page} returned "
                f"{len(result.game_urls)} games instead of {EXPECTED_PAGE_SIZE}"
            )
        for url in result.game_urls:
            discovered.setdefault(url, None)
    LOGGER.info(
        "Discovered %d %s games on %d list page(s)",
        len(discovered),
        network,
        first.total_pages,
    )
    return tuple(discovered)


def parse_game_detail(html: str, url: str) -> GameDetail:
    if not _valid_game_url(url):
        raise ValueError(f"Invalid game URL: {url}")
    parser = _GameDetailParser()
    parser.feed(html)
    parser.close()
    if not parser.name:
        raise ValueError(f"PlayToEarn game page has no name: {url}")
    if parser.status not in VALID_STATUSES:
        raise ValueError(f"Unexpected or missing game status {parser.status!r}: {url}")
    unique_contracts = tuple(dict.fromkeys(parser.contracts))
    return GameDetail(url, parser.name, parser.status, unique_contracts)


def fetch_game_detail(url: str, *, timeout: int, retries: int) -> GameDetail:
    return parse_game_detail(fetch_html(url, timeout=timeout, retries=retries), url)


def canonical_contract(network: str, source_chain: str, address: str) -> str | None:
    value = address.strip()
    chain = " ".join(source_chain.split()).casefold()
    if network == "Ethereum":
        if chain != "ethereum" or not EVM_ADDRESS_RE.fullmatch(value):
            return None
        return value.casefold()
    if network == "Tron":
        if chain != "tron":
            return None
        if TRON_BASE58_RE.fullmatch(value):
            return value
        if TRON_HEX_RE.fullmatch(value):
            return value.casefold()
        return None
    raise ValueError(f"Unsupported network: {network}")


def rows_to_table(rows: Iterable[dict[str, str]], network: str) -> pa.Table:
    records: dict[tuple[str, str], dict[str, str]] = {}
    for row in rows:
        key = (row["game_url"], row["address"])
        records.setdefault(key, row)
    ordered = sorted(
        records.values(),
        key=lambda row: (row["game_name"].casefold(), row["address"]),
    )
    table = pa.Table.from_pylist(ordered, schema=OUTPUT_SCHEMA)
    validate_table(table, network)
    return table


def validate_table(table: pa.Table, network: str) -> None:
    if not table.schema.equals(OUTPUT_SCHEMA, check_metadata=False):
        raise ValueError(f"Unexpected {network} output schema")
    if table.num_rows == 0:
        raise ValueError(f"No valid {network} game contracts were found")
    if any(table[field.name].null_count for field in OUTPUT_SCHEMA):
        raise ValueError(f"NULL values found in {network} output")
    seen: set[tuple[str, str]] = set()
    for row in table.to_pylist():
        if row["network"] != network:
            raise ValueError(f"Wrong network in {network} output: {row}")
        if canonical_contract(network, network, row["address"]) != row["address"]:
            raise ValueError(f"Invalid {network} address: {row['address']!r}")
        if not row["game_name"].strip() or not _valid_game_url(row["game_url"]):
            raise ValueError(f"Invalid game metadata in {network} output: {row}")
        if row["status"] not in VALID_STATUSES:
            raise ValueError(f"Invalid game status in {network} output: {row['status']!r}")
        key = (row["game_url"], row["address"])
        if key in seen:
            raise ValueError(f"Duplicate game/address pair in {network} output: {key}")
        seen.add(key)


def build_tables(
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
    workers: int = DEFAULT_WORKERS,
    max_games_per_network: int | None = None,
) -> dict[str, pa.Table]:
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not 0 <= retries <= 8:
        raise ValueError("retries must be between 0 and 8")
    if workers <= 0 or workers > 32:
        raise ValueError("workers must be between 1 and 32")
    if max_games_per_network is not None and max_games_per_network <= 0:
        raise ValueError("max_games_per_network must be positive")

    memberships: dict[str, set[str]] = {}
    for network in LIST_URLS:
        urls = discover_game_urls(
            network,
            timeout=timeout,
            retries=retries,
            workers=workers,
        )
        if max_games_per_network is not None:
            urls = urls[:max_games_per_network]
        for url in urls:
            memberships.setdefault(url, set()).add(network)

    details: dict[str, GameDetail] = {}
    total_games = len(memberships)
    with ThreadPoolExecutor(max_workers=min(workers, total_games)) as executor:
        futures = {
            executor.submit(fetch_game_detail, url, timeout=timeout, retries=retries): url
            for url in memberships
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            url = futures[future]
            details[url] = future.result()
            if completed % 25 == 0 or completed == total_games:
                LOGGER.info("Parsed game pages: %d/%d", completed, total_games)

    rows: dict[str, list[dict[str, str]]] = {network: [] for network in LIST_URLS}
    games_with_contracts: dict[str, set[str]] = {network: set() for network in LIST_URLS}
    for url, networks in memberships.items():
        detail = details[url]
        for network in networks:
            for source_chain, source_address in detail.contracts:
                address = canonical_contract(network, source_chain, source_address)
                if address is None:
                    continue
                rows[network].append(
                    {
                        "address": address,
                        "network": network,
                        "game_name": detail.name,
                        "game_url": detail.url,
                        "status": detail.status,
                    }
                )
                games_with_contracts[network].add(detail.url)

    tables = {
        network: rows_to_table(network_rows, network)
        for network, network_rows in rows.items()
    }
    for network, table in tables.items():
        LOGGER.info(
            "%s result: games_with_contracts=%d, rows=%d, unique_addresses=%d",
            network,
            len(games_with_contracts[network]),
            table.num_rows,
            len(set(table["address"].to_pylist())),
        )
    return tables


def write_tables(tables: dict[str, pa.Table]) -> dict[str, Path]:
    if set(tables) != set(OUTPUT_PATHS):
        raise ValueError(f"Expected tables for {sorted(OUTPUT_PATHS)}, got {sorted(tables)}")
    PROJECT_DIR.mkdir(parents=True, exist_ok=True)
    temporary_paths: dict[str, Path] = {}
    try:
        for network, output_path in OUTPUT_PATHS.items():
            table = tables[network]
            validate_table(table, network)
            temporary_path = output_path.with_name(f".{output_path.name}.{os.getpid()}.tmp")
            temporary_paths[network] = temporary_path
            pq.write_table(table, temporary_path, compression="zstd")
            written = pq.read_table(temporary_path)
            validate_table(written, network)
        for network, output_path in OUTPUT_PATHS.items():
            os.replace(temporary_paths[network], output_path)
    finally:
        for temporary_path in temporary_paths.values():
            if temporary_path.exists():
                temporary_path.unlink()
    return dict(OUTPUT_PATHS)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Parse PlayToEarn Ethereum/TRON game contracts and create two local Parquet files"
        )
    )
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    arguments = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    try:
        tables = build_tables(
            timeout=arguments.timeout,
            retries=arguments.retries,
            workers=arguments.workers,
        )
        paths = write_tables(tables)
        for network, path in paths.items():
            print(f"{network}: {path} ({tables[network].num_rows} rows)")
    except KeyboardInterrupt:
        LOGGER.warning("PlayToEarn parsing interrupted; existing Parquet files were not changed")
        raise SystemExit(130)
    except (OSError, RuntimeError, ValueError, requests.RequestException, pa.ArrowException):
        LOGGER.exception("PlayToEarn parsing failed; existing Parquet files were not changed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
