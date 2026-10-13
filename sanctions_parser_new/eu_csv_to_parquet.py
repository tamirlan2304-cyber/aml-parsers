from __future__ import annotations

import argparse
import csv
import io
import json
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode

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


EU_URL = os.getenv(
    "EU_URL",
    "https://webgate.ec.europa.eu/fsd/fsf/public/files/"
    "csvFullSanctionsList_1_1/content",
).strip()
EU_PUBLIC_TOKEN = os.getenv("EU_PUBLIC_TOKEN", "dG9rZW4tMjAxNw").strip()
EU_DATE_FORMATS = ("%Y-%m-%d", "%d/%m/%Y", "%d-%b-%Y")


def numeric_rank(value: str | None) -> int:
    try:
        return int(clean(value) or "")
    except ValueError:
        return 2**63 - 1


def open_eu_url():
    fallback_url = f"{EU_URL}?{urlencode({'token': EU_PUBLIC_TOKEN})}"
    last_error: Exception | None = None
    for url in (EU_URL, fallback_url):
        try:
            return open_url(url, "text/csv,*/*;q=0.8")
        except HTTPError as error:
            last_error = error
            if error.code not in {401, 403}:
                raise
    if last_error is not None:
        raise last_error
    raise RuntimeError("No EU download URL was attempted")


def empty_entity(entity_id: str) -> dict[str, Any]:
    return {
        "entity_id": entity_id,
        "_names": {},
        "_designation_dates": {},
        "_entry_dates": {},
        "_publication_dates": {},
        "_reasons": {},
        "_crypto_texts": {},
    }


def consume_row(entity: dict[str, Any], row: dict[str, str]) -> None:
    name = clean(row.get("NameAlias_WholeName")) or joined(
        [
            clean(row.get("NameAlias_FirstName")),
            clean(row.get("NameAlias_MiddleName")),
            clean(row.get("NameAlias_LastName")),
        ],
        " ",
    )
    if name:
        rank = numeric_rank(row.get("NameAlias_LogicalId"))
        entity["_names"][name] = min(rank, entity["_names"].get(name, rank))
    for column, target in (
        ("Entity_DesignationDate", "_designation_dates"),
        ("Entity_Regulation_EntryIntoForceDate", "_entry_dates"),
        ("Entity_Regulation_PublicationDate", "_publication_dates"),
    ):
        if value := parse_date(row.get(column), EU_DATE_FORMATS):
            entity[target][value] = None
    if reason := clean(row.get("Entity_DesignationDetails")):
        entity["_reasons"][reason] = None
    for column in (
        "Entity_DesignationDetails",
        "Entity_Remark",
        "NameAlias_Function",
        "NameAlias_Remark",
        "Address_ContactInfo",
        "Address_Remark",
        "BirthDate_Remark",
        "Identification_Remark",
        "Citizenship_Remark",
    ):
        value = clean(row.get(column))
        if value and contains_crypto_data(value):
            entity["_crypto_texts"][value] = None


def read_rows() -> tuple[list[dict[str, Any]], str | None]:
    entities: dict[str, dict[str, Any]] = {}
    generation_date: str | None = None
    with open_eu_url() as response:
        stream = io.TextIOWrapper(response, encoding="utf-8-sig", newline="")
        reader = csv.DictReader(stream, delimiter=";")
        required = {"Entity_LogicalId", "NameAlias_WholeName", "Entity_SubjectType"}
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"EU CSV is missing expected columns: {sorted(missing)}")
        for row in reader:
            entity_id = clean(row.get("Entity_LogicalId"))
            if not entity_id:
                continue
            if generation_date is None:
                generation_date = clean(row.get("fileGenerationDate"))
            consume_row(entities.setdefault(entity_id, empty_entity(entity_id)), row)

    by_address: dict[str, dict[str, Any]] = {}
    for entity in entities.values():
        ordered_names = sorted(entity["_names"], key=lambda item: (entity["_names"][item], item))
        name = ordered_names[0] if ordered_names else None
        dates = (
            list(entity["_designation_dates"])
            or list(entity["_entry_dates"])
            or list(entity["_publication_dates"])
        )
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
    return wallet_rows(by_address), generation_date


def main() -> None:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--output", type=Path, required=True)
    arguments = argument_parser.parse_args()
    if arguments.output.suffix.lower() != ".parquet":
        raise ValueError("Output path must end with .parquet")

    rows, generation_date = read_rows()
    if not rows:
        raise RuntimeError("EU source produced no crypto addresses")
    table = write_parquet(rows, arguments.output, BASE_OUTPUT_SCHEMA)
    print(
        json.dumps(
            {
                "source_url": EU_URL,
                "source_generation_date": generation_date,
                "output_file": str(arguments.output.resolve()),
                "rows": table.num_rows,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
