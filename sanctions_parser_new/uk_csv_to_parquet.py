"""Stream the UK Sanctions List and export only sanctioned crypto addresses."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
from pathlib import Path
from typing import Any

if __package__:
    from .utils import (
        BASE_OUTPUT_SCHEMA,
        add_wallet_observation,
        clean,
        contains_crypto_data,
        extract_crypto_addresses,
        joined,
        open_url,
        parse_date,
        wallet_rows,
        write_parquet,
    )
else:
    from utils import (
        BASE_OUTPUT_SCHEMA,
        add_wallet_observation,
        clean,
        contains_crypto_data,
        extract_crypto_addresses,
        joined,
        open_url,
        parse_date,
        wallet_rows,
        write_parquet,
    )


UK_URL = os.getenv(
    "UK_URL",
    "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv",
).strip()
UK_DATE_FORMATS = ("%d/%m/%Y", "%Y-%m-%d", "%d-%b-%Y")


def empty_entity(entity_id: str) -> dict[str, Any]:
    return {
        "entity_id": entity_id,
        "_primary_names": {},
        "_all_names": {},
        "_dates": {},
        "_reasons": {},
        "_crypto_texts": {},
    }


def consume_row(entity: dict[str, Any], row: dict[str, str]) -> None:
    name = joined([clean(row.get(f"Name {index}")) for index in range(1, 7)], " ")
    if name:
        entity["_all_names"][name] = None
        if (clean(row.get("Name type")) or "").casefold() == "primary name":
            entity["_primary_names"][name] = None
    if value := parse_date(row.get("Date Designated"), UK_DATE_FORMATS):
        entity["_dates"][value] = None
    if reason := clean(row.get("UK Statement of Reasons")):
        entity["_reasons"][reason] = None
    for column in ("UK Statement of Reasons", "Other Information"):
        value = clean(row.get(column))
        if value and contains_crypto_data(value):
            entity["_crypto_texts"][value] = None


def read_rows() -> tuple[list[dict[str, Any]], str | None]:
    entities: dict[str, dict[str, Any]] = {}
    with open_url(UK_URL, "text/csv,*/*;q=0.8") as response:
        stream = io.TextIOWrapper(response, encoding="utf-8-sig", newline="")
        report_date = clean(next(stream, ""))
        reader = csv.DictReader(stream)
        required = {"Unique ID", "Name 6", "Date Designated", "Other Information"}
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"UK CSV is missing expected columns: {sorted(missing)}")
        for row in reader:
            entity_id = clean(row.get("Unique ID"))
            if entity_id:
                consume_row(entities.setdefault(entity_id, empty_entity(entity_id)), row)

    by_address: dict[str, dict[str, Any]] = {}
    for entity in entities.values():
        name = next(iter(entity["_primary_names"]), None) or next(
            iter(entity["_all_names"]), None
        )
        dates = list(entity["_dates"])
        designation_date = min(dates) if dates else None
        reason = joined(entity["_reasons"])
        for source_text in entity["_crypto_texts"]:
            for address, network in extract_crypto_addresses(source_text):
                add_wallet_observation(
                    by_address,
                    address=address,
                    network=network,
                    name=name,
                    designation_date=designation_date,
                    reason=reason,
                )
    return wallet_rows(by_address), report_date


def main() -> None:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--output", type=Path, required=True)
    arguments = argument_parser.parse_args()
    if arguments.output.suffix.lower() != ".parquet":
        raise ValueError("Output path must end with .parquet")

    rows, report_date = read_rows()
    if not rows:
        raise RuntimeError("UK source produced no crypto addresses")
    table = write_parquet(rows, arguments.output, BASE_OUTPUT_SCHEMA)
    print(
        json.dumps(
            {
                "source_url": UK_URL,
                "source_report_date": report_date,
                "output_file": str(arguments.output.resolve()),
                "rows": table.num_rows,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
