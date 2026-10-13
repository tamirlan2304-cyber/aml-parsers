"""Conservative extraction of *documented* malicious roles, not all PoC addresses.

The GitHub repository is evidence for the attribution, not an on-chain oracle.
Only dated incident files and explicit introductory annotations are eligible.
Solidity is never executed. Code, transaction hashes and vm.prank are NOT
positive evidence. Unknown or contradictory roles are intentionally omitted.
"""
from __future__ import annotations

import argparse
import io
import logging
import os
import posixpath
import re
import subprocess
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote, unquote, urlsplit

import pyarrow as pa
import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


LOGGER = logging.getLogger("defihacklabs")
REPOSITORY = "SunWeb3Sec/DeFiHackLabs"
GITHUB_URL = f"https://github.com/{REPOSITORY}"
S3_KEY = "stolen_assets/defihacklabs.parquet"
ROLES = frozenset({
    "exploit_caller", "attacker", "exploit_contract", "profit_receiver",
    "consolidation", "laundering",
})
OUTPUT_SCHEMA = pa.schema([
    pa.field("address", pa.string(), nullable=False),
    pa.field("network", pa.string(), nullable=False),
    pa.field("incident_name", pa.string(), nullable=False),
    pa.field("role", pa.string(), nullable=False),
    pa.field("incident_date", pa.date32(), nullable=False),
    pa.field("source_url", pa.string(), nullable=False),
])

SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
ADDRESS_RE = re.compile(r"(?<![a-zA-Z0-9_])0[xX][a-fA-F0-9]{40}(?![a-zA-Z0-9_])")
INCIDENT_PATH_RE = re.compile(r"src/test/\d{4}-\d{2}/[^/]+\.sol\Z")
README_PATH_RE = re.compile(r"(?:README\.md|past/\d{4}/README\.md)\Z")
HEADING_RE = re.compile(r"^#{2,6}\s+(\d{8})\s+(.+?)\s*#*\s*$")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)")
# Strings are consumed before comments, so an import/string cannot inject a label.
SOLIDITY_TOKEN_RE = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/'
    r"|\b(?:contract|library|function)\b|[{}]", re.DOTALL,
)
COMMENT_OR_STRING_RE = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/', re.DOTALL,
)
EXCLUDED_WORDS_RE = re.compile(
    r"\b(?:victims?|vulnerable|vuln|target|token|tokens|pool|pools|liquidity|bridge|bridges|"
    r"router|routers|cex|exchange|exchanges|foundry|mock|testnet|placeholder|"
    r"dummy|burn|treasury|vault|vaults|protocol|protocols)\b", re.I,
)
UNCERTAIN_RE = re.compile(
    r"\b(?:possible|possibly|suspected|unconfirmed|unknown|hypothetical|example|"
    r"simulated|simulation|mock|placeholder|dummy|testnet|whitehat|white-hat)\b"
    r"|\b(?:not (?:the |an? )?attacker|test address|for testing|local test)\b", re.I,
)
NON_LIVE_INCIDENT_RE = re.compile(
    r"\b(?:pre-production|testnet|hypothetical|demonstration only)\b", re.I,
)
FORBIDDEN_ADDRESSES = frozenset({
    # Foundry cheatcode/console and default test deployment addresses.
    "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d",
    "0x000000000000000000636f6e736f6c652e6c6f67",
    "0x7fa9385be102ac3eac297483dd6233d62b3e1496",
    "0x1804c8ab1f12e6bbf3894d4083f33e07309d1f38",
})
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TEXT_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class Incident:
    name: str
    incident_date: date
    description: str


@dataclass(frozen=True)
class Evidence:
    address: str
    role: str
    line: int


def valid_address(value: str) -> bool:
    """20-byte EVM address; no hash fragments, placeholders or test constants."""
    value = value.lower()
    return bool(
        ADDRESS_RE.fullmatch(value)
        and int(value[2:], 16) > 0xFFFFFFFF
        and len(set(value[2:])) > 1
        and value not in FORBIDDEN_ADDRESSES
    )


def header_comments(source: str) -> list[tuple[int, str]]:
    """Read file-level introductions, also after interfaces, but never test bodies."""
    result: list[tuple[int, str]] = []
    last_line = 0
    depth = 0
    for token in SOLIDITY_TOKEN_RE.finditer(source):
        value = token.group()
        if value.startswith(('"', "'")):
            continue
        if value == "{":
            depth += 1
            continue
        if value == "}":
            depth = max(0, depth - 1)
            continue
        if not value.startswith(("//", "/*")):
            if depth == 0:
                break  # Stop before the first real contract/library/free function.
            continue
        if depth:
            continue  # Comments inside interfaces/structs are code documentation.
        line = source.count("\n", 0, token.start()) + 1
        # Reject comments attached to executable/top-level Solidity statements.
        prefix = source[source.rfind("\n", 0, token.start()) + 1:token.start()]
        if prefix.strip():
            continue
        if line > last_line + 1:
            result.append((line, ""))  # Blank/code lines terminate list inheritance.
        if value.startswith("//"):
            lines = [value[2:]]
        else:
            lines = value[2:-2].splitlines()
        for offset, text in enumerate(lines):
            result.append((line + offset, re.sub(r"^\s*\* ?", "", text).strip()))
        last_line = line + len(lines) - 1
    return result


def label_role(label: str) -> str | None:
    label = re.sub(r"\s+", " ", label.replace("_", " ")).strip().casefold()
    number = r"(?:\s*#?\s*(?:\d+|[a-z]))?"
    if re.fullmatch(
        r"(?:main )?(?:attack|attacker|exploit)(?: exploit)? contracts?" + number, label
    ):
        return "exploit_contract"
    if re.fullmatch(r"(?:attacker|exploiter)(?:s|\(s\))?(?: (?:wallets?|eoas?|addresses|address))?" + number, label):
        return "attacker"
    if re.fullmatch(r"(?:original (?:attack|attacking|exploit) (?:tx|transaction) (?:sender|from)|original exploit caller)", label):
        return "exploit_caller"
    if re.fullmatch(r"(?:final )?profit (?:receiver|recipient)(?: address| wallet)?s?", label):
        return "profit_receiver"
    if re.fullmatch(r"(?:confirmed )?(?:proceeds |stolen funds )?consolidation(?: address| wallet)?s?", label):
        return "consolidation"
    if re.fullmatch(r"(?:confirmed )?laundering (?:address|wallet)s?", label):
        return "laundering"
    return None


def field_parts(text: str) -> tuple[str, str]:
    """A colon-delimited field, or an exact known label followed by an address."""
    cleaned = text.strip().lstrip("- ")
    match = re.match(
        r"^((?:Attacker(?: EOA| exploit contract| contract)?|Exploiter|Attack Contract))\s+"
        r"((?:0x|https?://).+)$", cleaned, re.I,
    )
    if match:
        return match[1], match[2]
    match = re.match(r"^(.{1,180}?)(?<!https)(?<!http):\s*(.*)$", cleaned)
    return (match[1].strip(), match[2].strip()) if match else ("", cleaned)


def leading_addresses(value: str) -> list[str]:
    """Accept an address/list value, not arbitrary addresses in trailing prose.

    In 'Attacker: A funded by B', B must never inherit A's role.
    /tx/ and /token/ links are not address evidence even if they contain 20 bytes.
    """
    value = re.sub(r"\[[^\]]*\]\((https?://[^)]+)\)", r"\1", value)
    value = re.sub(r"^(?:[-*]\s*|\d+[.)]\s*)", "", value.strip())
    found: list[str] = []
    while value:
        value = value.lstrip(" `(<")
        if value.startswith(("https://", "http://")):
            url_match = re.match(r"https?://[^\s<>)`,;]+", value)
            assert url_match is not None
            parsed = urlsplit(url_match[0])
            address_match = re.fullmatch(r"/address/(0[xX][a-fA-F0-9]{40})/?", parsed.path)
            if not address_match:
                break
            address = address_match[1]
            end = url_match.end()
        else:
            address_match = ADDRESS_RE.match(value)
            if not address_match:
                break
            address = address_match[0]
            end = address_match.end()
        if valid_address(address):
            found.append(address.lower())
        rest = value[end:].lstrip(" `)>")
        separator = re.match(r"^(?:[,;]\s*|and\s+|&\s*)", rest, re.I)
        if not separator:
            break
        value = rest[separator.end():]
    return found


def code_exclusions(source: str) -> set[str]:
    """Code can only EXCLUDE, never establish a malicious role."""
    code = COMMENT_OR_STRING_RE.sub(lambda m: "\n" * m[0].count("\n"), source)
    excluded: set[str] = set()
    token_cast = re.compile(r"\bI(?:ERC|BEP)(?:20|721|1155)\s*\(\s*(0[xX][0-9a-fA-F]{40})\s*\)")
    excluded.update(m[1].lower() for m in token_cast.finditer(code))
    declarations = re.compile(
        r"\b(?:address|I\w+)\s+(?:(?:public|private|internal|constant|immutable|payable)\s+)*"
        r"([a-zA-Z_]\w*)\s*=\s*([^;]{1,500});", re.MULTILINE,
    )
    for declaration in declarations.finditer(code):
        name = re.sub(r"([a-z])([A-Z])", r"\1 \2", declaration[1]).replace("_", " ")
        # 'holderOfToken'/'tokenOwner' describe people, not the token contract.
        denotes_owner = re.search(r"\b(?:holder|owner|creator|creater|deployer|receiver|sender)\b", name, re.I)
        if not denotes_owner and (EXCLUDED_WORDS_RE.search(name) or re.search(r"\b(?:USDC|USDT|DAI|WETH|WBTC|WBNB|VM)\b", name, re.I)):
            excluded.update(m[0].lower() for m in ADDRESS_RE.finditer(declaration[2]))
    return excluded


def extract_evidence(source: str) -> tuple[list[Evidence], set[str]]:
    comments = header_comments(source)
    excluded = code_exclusions(source)
    # A rescue/test reproduction is not evidence of a malicious exploit contract.
    # Do not exclude a real hack merely because its description also mentions a rescue.
    if any(
        re.search(r"whitehat educational reproduction|whitehat fork reproduction|demonstration only", text, re.I)
        or (re.match(r"(?:Attacker|Exploiter)\b", text, re.I) and re.search(r"\bwhite[ -]?hat\b", text, re.I))
        for _, text in comments
    ):
        return [], excluded
    candidates: list[Evidence] = []
    active: str | None = None
    for line, text in comments:
        if not text:
            active = None
            continue
        label, value = field_parts(text)
        # Exclusion wins over a positive label. Never inherit past unknown headings.
        if label and EXCLUDED_WORDS_RE.search(label):
            # Wallet A (ETH vault) is an explicit sublabel ONLY within attacker EOAs.
            is_wallet_sublabel = active == "attacker" and bool(re.fullmatch(
                r"Wallet [A-Z0-9]+ \((?:ETH|USDC) vault\)", label, re.I
            ))
            if not is_wallet_sublabel:
                active = "exclude"
                excluded.update(m[0].lower() for m in ADDRESS_RE.finditer(value))
                continue
        if UNCERTAIN_RE.search(text) or "?" in label:
            active = None
            continue
        role = label_role(label) if label else None
        # Bounded, explicit plural sections used by newer incident writeups.
        if re.fullmatch(r"Two coordinated attacker EOAs \([^)]*\)", label, re.I):
            role = "attacker"
        elif re.fullmatch(r"Attack contracts \([^)]*\)", label, re.I):
            role = "exploit_contract"
        elif re.fullmatch(r"Proceeds consolidation \(everything converted to [^)]* and sent here\)", label, re.I):
            role = "consolidation"
        if role:
            plural = re.search(r"\b(?:contracts|attackers|exploiters|eoas|wallets|addresses)\b", label, re.I)
            active = role if not value or plural else None
            if not EXCLUDED_WORDS_RE.search(value):
                candidates.extend(Evidence(a, role, line) for a in leading_addresses(value))
            continue
        if active == "exclude":
            if label:
                active = None
            else:
                excluded.update(m[0].lower() for m in ADDRESS_RE.finditer(text))
            continue
        if active:
            sublabel = (
                active == "attacker" and re.fullmatch(r"Wallet [A-Z0-9]+(?: \((?:ETH|USDC) vault\))?", label, re.I)
            ) or (
                active == "exploit_contract" and re.fullmatch(r"Attack [A-Z0-9]+", label, re.I)
            )
            if label and not sublabel:
                active = None
                continue
            addresses = leading_addresses(value if sublabel else text)
            if not addresses or (not sublabel and EXCLUDED_WORDS_RE.search(text)):
                active = None
                continue
            candidates.extend(Evidence(a, active, line) for a in addresses)
    return candidates, excluded


def incident_index(files: Mapping[str, str]) -> dict[str, Incident]:
    incidents: dict[str, Incident] = {}
    conflicts: set[str] = set()
    for readme_path in sorted(p for p in files if README_PATH_RE.fullmatch(p)):
        current: Incident | None = None
        for line in files[readme_path].splitlines():
            heading = HEADING_RE.match(line)
            if heading:
                try:
                    incident_date = datetime.strptime(heading[1], "%Y%m%d").date()
                except ValueError:
                    current = None
                    continue
                description = heading[2].strip()
                name = re.split(r"\s+[-–—]\s+", description, maxsplit=1)[0].strip()
                current = Incident(name, incident_date, description)
            elif re.match(r"^#{1,2}\s", line):
                current = None
            if current is None:
                continue
            for link in LINK_RE.findall(line):
                parsed = urlsplit(link)
                if parsed.scheme or parsed.netloc:
                    continue
                path = posixpath.normpath(posixpath.join(posixpath.dirname(readme_path), unquote(parsed.path)))
                if not INCIDENT_PATH_RE.fullmatch(path) or path not in files:
                    continue
                existing = incidents.get(path)
                if existing and (existing.name, existing.incident_date) != (current.name, current.incident_date):
                    conflicts.add(path)
                else:
                    incidents[path] = current
    for path in sorted(conflicts):
        LOGGER.warning("Skipping file with contradictory README incident/date: %s", path)
        incidents.pop(path, None)
    if not incidents:
        raise RuntimeError("No dated DeFiHackLabs incident files found; check source layout")
    return incidents


def row_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    # Different incidents/roles remain separate. Git commit updates do NOT duplicate rows.
    return (str(row["address"]).lower(), row["network"], row["incident_name"],
            row["incident_date"], row["role"])


def rows_to_table(rows: Any) -> pa.Table:
    return pa.Table.from_pylist(sorted(rows, key=lambda r: (
        r["incident_date"], r["incident_name"], r["address"], r["role"], r["source_url"],
    )), schema=OUTPUT_SCHEMA)


def validate_table(table: pa.Table, source: str = "DeFiHackLabs") -> None:
    if not table.schema.equals(OUTPUT_SCHEMA, check_metadata=False):
        raise ValueError(f"Unexpected schema in {source}; expected {OUTPUT_SCHEMA}")
    if not table.num_rows:
        raise ValueError(f"Table is empty: {source}; refusing to upload")
    if any(table[name].null_count for name in OUTPUT_SCHEMA.names):
        raise ValueError(f"NULL values in {source}")
    seen: set[tuple[Any, ...]] = set()
    url_re = re.compile(re.escape(GITHUB_URL) + r"/blob/[0-9a-f]{40}/src/test/\d{4}-\d{2}/[^/]+\.sol#L[1-9]\d*\Z")
    for row in table.to_pylist():
        if not valid_address(row["address"]) or row["address"] != row["address"].lower():
            raise ValueError(f"Invalid/noncanonical address in {source}: {row['address']}")
        if row["network"] != "Ethereum" or row["role"] not in ROLES:
            raise ValueError(f"Invalid network/role in {source}")
        if not row["incident_name"].strip() or not url_re.fullmatch(row["source_url"]):
            raise ValueError(f"Missing incident or invalid evidence URL in {source}")
        key = row_key(row)
        if key in seen:
            raise ValueError(f"Duplicate address/incident/role in {source}: {key}")
        seen.add(key)


def parse_snapshot(files: Mapping[str, str], commit: str) -> pa.Table:
    if not SHA_RE.fullmatch(commit):
        raise ValueError("An exact 40-character Git commit SHA is required for evidence URLs")
    incidents = incident_index(files)
    parsed: list[tuple[str, Incident, list[Evidence], set[str]]] = []
    exclusions_by_incident: dict[tuple[str, date], set[str]] = {}
    skipped = Counter()
    for path, incident in sorted(incidents.items()):
        if NON_LIVE_INCIDENT_RE.search(incident.description):
            skipped["non_live_incident_files"] += 1
            continue
        candidates, exclusions = extract_evidence(files[path])
        exclusions_by_incident.setdefault((incident.name, incident.incident_date), set()).update(exclusions)
        parsed.append((path, incident, candidates, exclusions))
    records: dict[tuple[Any, ...], dict[str, Any]] = {}
    accepted_files = 0
    for index, (path, incident, candidates, _) in enumerate(parsed, 1):
        accepted = False
        for evidence in candidates:
            if evidence.address in exclusions_by_incident[(incident.name, incident.incident_date)]:
                skipped["contradictory_or_excluded_role"] += 1
                LOGGER.debug("Excluded %s in %s: contradictory/infrastructure role", evidence.address, path)
                continue
            row = {
                "address": evidence.address,
                "network": "Ethereum",  # Includes BSC, Base, Arbitrum and other EVMs.
                "incident_name": incident.name,
                "role": evidence.role,
                "incident_date": incident.incident_date,
                "source_url": f"{GITHUB_URL}/blob/{commit}/{quote(path, safe='/')}#L{evidence.line}",
            }
            records.setdefault(row_key(row), row)
            accepted = True
        if accepted:
            accepted_files += 1
        else:
            skipped["files_without_accepted_evidence"] += 1
            LOGGER.debug("No accepted explicit roles: %s", path)
        if index % 100 == 0:
            LOGGER.info("DeFiHackLabs files %d/%d; accepted rows=%d", index, len(parsed), len(records))
    table = rows_to_table(records.values())
    LOGGER.info(
        "DeFiHackLabs commit=%s; indexed files=%d; files with evidence=%d; rows=%d; unique addresses=%d; skipped=%s",
        commit, len(incidents), accepted_files, table.num_rows,
        len({r["address"] for r in records.values()}), dict(skipped),
    )
    LOGGER.info("DeFiHackLabs roles: %s", dict(Counter(r["role"] for r in records.values())))
    return table


def merge_with_existing(existing: pa.Table | None, current: pa.Table) -> tuple[pa.Table, int, int]:
    validate_table(current, "current DeFiHackLabs table")
    if existing is None:
        return current, current.num_rows, 0
    validate_table(existing, "existing DeFiHackLabs S3 table")
    records = {row_key(row): row for row in existing.to_pylist()}
    added = updated = 0
    for row in current.to_pylist():
        key = row_key(row)
        old = records.get(key)
        if old is None:
            added += 1
        elif old != row:
            updated += 1
        records[key] = row
    merged = rows_to_table(records.values())
    validate_table(merged, "merged DeFiHackLabs table")
    return merged, added, updated


def files_from_archive(payload: bytes, *, github_prefix: bool) -> dict[str, str]:
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise ValueError("DeFiHackLabs archive exceeds safety size limit")
    files: dict[str, str] = {}
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for item in archive.infolist():
                path = item.filename.split("/", 1)[-1] if github_prefix else item.filename
                if not (INCIDENT_PATH_RE.fullmatch(path) or README_PATH_RE.fullmatch(path)):
                    continue
                if item.file_size > MAX_FILE_BYTES or total + item.file_size > MAX_TEXT_BYTES:
                    raise ValueError(f"DeFiHackLabs text size limit exceeded: {path}")
                if path in files:
                    raise ValueError(f"Duplicate archive member: {path}")
                total += item.file_size
                files[path] = archive.read(item).decode("utf-8-sig")
    except (zipfile.BadZipFile, UnicodeDecodeError) as error:
        raise ValueError("Invalid DeFiHackLabs archive/text response") from error
    if "README.md" not in files:
        raise ValueError("Archive has no DeFiHackLabs README.md")
    return files


def download_snapshot(ref: str, timeout: int, retries: int) -> tuple[str, dict[str, str]]:
    if not ref.strip() or ref.startswith("-") or len(ref) > 200:
        raise ValueError("Invalid DEFIHACKLABS_REF")
    with requests.Session() as session:
        retry = Retry(total=retries, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504), allowed_methods=frozenset({"GET"}))
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.headers.update({"User-Agent": "stolen-assets-defihacklabs-parser/1.0", "Accept": "application/vnd.github+json"})
        if SHA_RE.fullmatch(ref):
            commit = ref
        else:
            response = session.get(f"https://api.github.com/repos/{REPOSITORY}/commits/{quote(ref, safe='')}", timeout=timeout)
            response.raise_for_status()
            commit = str(response.json().get("sha", ""))
            if not SHA_RE.fullmatch(commit):
                raise ValueError("GitHub did not return a commit SHA")
        LOGGER.info("Downloading public DeFiHackLabs snapshot %s (no Solidity execution)", commit)
        url = f"https://codeload.github.com/{REPOSITORY}/zip/{commit}"
        with session.get(url, timeout=timeout, stream=True, headers={"Accept": "application/zip"}) as response:
            response.raise_for_status()
            output = io.BytesIO()
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if output.tell() + len(chunk) > MAX_ARCHIVE_BYTES:
                    raise ValueError("DeFiHackLabs download exceeds safety size limit")
                output.write(chunk)
    return commit, files_from_archive(output.getvalue(), github_prefix=True)


def local_snapshot(repo_dir: Path) -> tuple[str, dict[str, str]]:
    """Read committed HEAD, ignoring uncommitted edits; never run repository code."""
    repo_dir = repo_dir.resolve(strict=True)
    try:
        commit = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "--verify", "HEAD"],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        if not SHA_RE.fullmatch(commit):
            raise ValueError("Local git repository returned an invalid commit")
        payload = subprocess.run(
            ["git", "-C", str(repo_dir), "archive", "--format=zip", commit, "README.md", "past", "src/test"],
            check=True, capture_output=True, timeout=120,
        ).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("Cannot read a committed DeFiHackLabs snapshot from local git") from error
    LOGGER.info("Reading committed DeFiHackLabs HEAD=%s from %s", commit, repo_dir)
    return commit, files_from_archive(payload, github_prefix=False)


def build_table(*, repo_dir: Path | None = None) -> pa.Table:
    if repo_dir is None:
        configured_dir = os.getenv("DEFIHACKLABS_REPO_DIR", "").strip()
        repo_dir = Path(configured_dir) if configured_dir else None
    if repo_dir:
        commit, files = local_snapshot(repo_dir)
    else:
        timeout = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "60"))
        retries = int(os.getenv("DEFIHACKLABS_MAX_RETRIES", "3"))
        if timeout <= 0 or not 0 <= retries <= 10:
            raise ValueError("Timeout must be positive; retries must be between 0 and 10")
        commit, files = download_snapshot(os.getenv("DEFIHACKLABS_REF", "main"), timeout, retries)
    table = parse_snapshot(files, commit)
    validate_table(table)
    return table


def main() -> None:
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
    parser = argparse.ArgumentParser(description="Parse documented DeFiHackLabs roles in memory; no S3 writes")
    parser.add_argument("--repo-dir", type=Path, help="Read a local clone's committed HEAD without network access")
    parser.add_argument("--verbose", action="store_true", help="Also log omitted files and contradictory addresses")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    table = build_table(repo_dir=args.repo_dir)
    print(table.schema)
    print(f"Rows: {table.num_rows}; unique addresses: {len(set(table['address'].to_pylist()))}")


if __name__ == "__main__":
    main()
