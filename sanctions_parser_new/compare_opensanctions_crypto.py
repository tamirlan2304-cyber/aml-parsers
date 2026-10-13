"""Compare crypto-wallet sanctions from several OpenSanctions source datasets.

The script downloads one normalized FollowTheMoney JSONL export per authority,
extracts wallet addresses, and writes one address-level Parquet file. UK and EU
records are also inspected for wallet addresses embedded in notes/descriptions:
those sources do not always publish them as standalone CryptoWallet entities.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import date
from pathlib import Path
from typing import Any, Iterable

import pyarrow as pa
import pyarrow.parquet as pq

if __package__:
    from .utils import (
        canonical_address,
        extract_crypto_addresses,
        network_for_address,
        open_url,
    )
else:
    from utils import (
        canonical_address,
        extract_crypto_addresses,
        network_for_address,
        open_url,
    )


DATASET_URL = (
    "https://data.opensanctions.org/datasets/latest/"
    "{dataset}/entities.ftm.json"
)
DATASETS = {
    "ofac": "us_ofac_sdn",
    "japan": "jp_mof_sanctions",
    "france": "fr_tresor_gels_avoir",
    "uk": "gb_fcdo_sanctions",
    "eu": "eu_fsf",
}
EMBEDDED_TEXT_SOURCES = {"uk", "eu"}
TEXT_PROPERTIES = {"description", "notes", "summary"}

OUTPUT_SCHEMA = pa.schema(
    [
        pa.field("wallet_address", pa.string(), nullable=False),
        pa.field("normalized_address", pa.string(), nullable=False),
        pa.field("network", pa.string(), nullable=False),
        pa.field("names", pa.string()),
        pa.field("source_datasets", pa.string(), nullable=False),
        pa.field("source_entity_ids", pa.string()),
        pa.field("extraction_methods", pa.string(), nullable=False),
        pa.field("source_count", pa.int8(), nullable=False),
        pa.field("in_ofac", pa.bool_(), nullable=False),
        pa.field("in_japan", pa.bool_(), nullable=False),
        pa.field("in_france", pa.bool_(), nullable=False),
        pa.field("in_uk", pa.bool_(), nullable=False),
        pa.field("in_eu", pa.bool_(), nullable=False),
        pa.field("intersects_ofac", pa.bool_(), nullable=False),
        pa.field("snapshot_date", pa.date32(), nullable=False),
    ]
)


def values(properties: dict[str, Any], key: str) -> list[str]:
    """Return scalar property values as clean strings."""
    raw = properties.get(key, [])
    if not isinstance(raw, list):
        raw = [raw]
    return [
        str(item).strip()
        for item in raw
        if item is not None and str(item).strip()
    ]


def entity_name(entity: dict[str, Any]) -> str | None:
    caption = str(entity.get("caption") or "").strip()
    if caption:
        return caption
    names = values(entity.get("properties") or {}, "name")
    return names[0] if names else None


def download_dataset(dataset: str, target: Path, refresh: bool) -> Path:
    """Download a dataset export atomically, or reuse its local cache."""
    if target.exists() and not refresh:
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    url = DATASET_URL.format(dataset=dataset)
    with open_url(url, "application/json,*/*;q=0.8") as response, partial.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
    os.replace(partial, target)
    return target


def iter_entities(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entity = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid JSON in {path}:{line_number}") from error
            if isinstance(entity, dict):
                yield entity


def add_observation(
    records: dict[str, dict[str, Any]],
    *,
    address: str,
    network: str,
    source: str,
    entity_id: str | None,
    name: str | None,
    method: str,
) -> None:
    key = canonical_address(address)
    record = records.setdefault(
        key,
        {
            "wallet_address": address.strip(),
            "network": network,
            "names": set(),
            "sources": set(),
            "entity_ids": set(),
            "methods": set(),
        },
    )
    if record["network"] == "Unknown" and network != "Unknown":
        record["network"] = network
    if name:
        record["names"].add(name)
    if entity_id:
        record["entity_ids"].add(entity_id)
    record["sources"].add(source)
    record["methods"].add(method)


def extract_dataset(
    path: Path,
    source: str,
    records: dict[str, dict[str, Any]],
) -> None:
    for entity in iter_entities(path):
        properties = entity.get("properties") or {}
        entity_id = str(entity.get("id") or "").strip() or None
        name = entity_name(entity)

        if entity.get("schema") == "CryptoWallet":
            currencies = values(properties, "currency")
            source_label = currencies[0] if currencies else None
            for address in values(properties, "address"):
                add_observation(
                    records,
                    address=address,
                    network=network_for_address(address, source_label),
                    source=source,
                    entity_id=entity_id,
                    name=name,
                    method="CryptoWallet",
                )

        if source not in EMBEDDED_TEXT_SOURCES:
            continue
        for property_name in TEXT_PROPERTIES:
            for text in values(properties, property_name):
                for address, network in extract_crypto_addresses(text):
                    add_observation(
                        records,
                        address=address,
                        network=network,
                        source=source,
                        entity_id=entity_id,
                        name=name,
                        method=f"embedded:{property_name}",
                    )


def output_rows(records: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    snapshot_date = date.today()
    for normalized_address in sorted(records):
        record = records[normalized_address]
        sources = record["sources"]
        rows.append(
            {
                "wallet_address": record["wallet_address"],
                "normalized_address": normalized_address,
                "network": record["network"],
                "names": " | ".join(sorted(record["names"])) or None,
                "source_datasets": " | ".join(sorted(sources)),
                "source_entity_ids": " | ".join(sorted(record["entity_ids"])) or None,
                "extraction_methods": " | ".join(sorted(record["methods"])),
                "source_count": len(sources),
                "in_ofac": "ofac" in sources,
                "in_japan": "japan" in sources,
                "in_france": "france" in sources,
                "in_uk": "uk" in sources,
                "in_eu": "eu" in sources,
                "intersects_ofac": "ofac" in sources and len(sources) > 1,
                "snapshot_date": snapshot_date,
            }
        )
    return rows


def comparison_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {
        source: sum(row[f"in_{source}"] for row in rows)
        for source in DATASETS
    }
    intersections = {
        source: sum(row["in_ofac"] and row[f"in_{source}"] for row in rows)
        for source in ("japan", "france", "uk", "eu")
    }
    return {
        "snapshot_date": date.today().isoformat(),
        "unique_wallets": len(rows),
        "source_counts": counts,
        "ofac_intersections": intersections,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("crypto_sanctions_comparison.parquet"),
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=Path("crypto_sanctions_comparison.json"),
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("opensanctions_cache"),
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Redownload OpenSanctions files even if cached files exist.",
    )
    arguments = parser.parse_args()

    records: dict[str, dict[str, Any]] = {}
    for source, dataset in DATASETS.items():
        path = download_dataset(
            dataset,
            arguments.cache_dir / f"{dataset}.entities.ftm.json",
            arguments.refresh,
        )
        extract_dataset(path, source, records)

    rows = output_rows(records)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(rows, schema=OUTPUT_SCHEMA)
    pq.write_table(table, arguments.output, compression="zstd")

    summary = comparison_summary(rows)
    summary["output_file"] = str(arguments.output.resolve())
    summary["columns"] = [field.name for field in OUTPUT_SCHEMA]
    arguments.summary.parent.mkdir(parents=True, exist_ok=True)
    arguments.summary.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
