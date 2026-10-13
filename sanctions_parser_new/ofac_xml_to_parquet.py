"""Stream OFAC Advanced XML and export only sanctioned crypto addresses."""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import Any, BinaryIO
from xml.etree import ElementTree as ET

if __package__:
    from .utils import (
        OFAC_OUTPUT_SCHEMA,
        add_wallet_observation,
        joined,
        network_for_address,
        open_url,
        unique,
        wallet_rows,
        write_parquet,
    )
else:
    from utils import (
        OFAC_OUTPUT_SCHEMA,
        add_wallet_observation,
        joined,
        network_for_address,
        open_url,
        unique,
        wallet_rows,
        write_parquet,
    )


OFAC_URL = os.getenv(
    "OFAC_URL",
    "https://sanctionslistservice.ofac.treas.gov/"
    "api/PublicationPreview/exports/SDN_ADVANCED.XML",
).strip()


def tag_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def text(element: ET.Element | None) -> str | None:
    if element is None or element.text is None:
        return None
    value = " ".join(element.text.split())
    return value or None


def child(element: ET.Element, name: str) -> ET.Element | None:
    return next((item for item in element if tag_name(item) == name), None)


def children(element: ET.Element, name: str) -> list[ET.Element]:
    return [item for item in element if tag_name(item) == name]


def descendants(element: ET.Element, name: str) -> list[ET.Element]:
    return [item for item in element.iter() if tag_name(item) == name]


def date_text(element: ET.Element | None) -> str | None:
    if element is None:
        return None
    parts = {tag_name(item): text(item) for item in element}
    year, month, day = parts.get("Year"), parts.get("Month"), parts.get("Day")
    if not (year and month and day):
        return None
    try:
        return date(int(year), int(month), int(day)).isoformat()
    except ValueError:
        return None


def exact_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


class OfacCryptoParser:
    def __init__(self) -> None:
        self.references: dict[str, dict[str, str]] = defaultdict(dict)
        self.locations: dict[str, str] = {}
        self.parties: dict[str, dict[str, Any]] = {}
        self.sanctions: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def ref(self, type_name: str, identifier: str | None) -> str | None:
        if not identifier:
            return None
        return self.references.get(type_name, {}).get(identifier)

    def parse_references(self, element: ET.Element) -> None:
        for item in element.iter():
            identifier, value = item.attrib.get("ID"), text(item)
            if identifier and value:
                self.references[tag_name(item)][identifier] = value

    def parse_locations(self, element: ET.Element) -> None:
        for location in children(element, "Location"):
            location_id = location.attrib.get("ID")
            location_country = child(location, "LocationCountry")
            country = self.ref(
                "Country",
                location_country.attrib.get("CountryID")
                if location_country is not None
                else None,
            )
            if location_id and country:
                self.locations[location_id] = country

    def feature_values(self, version: ET.Element) -> list[str]:
        values: list[str | None] = []
        for detail in children(version, "VersionDetail"):
            values.append(
                text(detail)
                or self.ref("DetailReference", detail.attrib.get("DetailReferenceID"))
            )
        return unique(values)

    def parse_party(self, element: ET.Element) -> None:
        party_comment = text(child(element, "Comment"))
        for profile in children(element, "Profile"):
            profile_id = profile.attrib["ID"]
            names: list[tuple[str, bool]] = []
            wallets: list[dict[str, str]] = []
            country: str | None = None

            for identity in children(profile, "Identity"):
                for alias in children(identity, "Alias"):
                    name = " ".join(
                        value
                        for part in descendants(alias, "NamePartValue")
                        if (value := text(part))
                    ) or None
                    if name:
                        names.append((name, alias.attrib.get("Primary") == "true"))

            for feature in children(profile, "Feature"):
                feature_type = self.ref("FeatureType", feature.attrib.get("FeatureTypeID")) or ""
                prefix = "Digital Currency Address -"

                for version in children(feature, "FeatureVersion"):
                    if feature_type == "Location" and country is None:
                        for version_location in children(version, "VersionLocation"):
                            location_id = version_location.attrib.get("LocationID")
                            country = self.locations.get(location_id or "")
                            if country:
                                break
                    if not feature_type.startswith(prefix):
                        continue
                    source_code = feature_type.removeprefix(prefix).strip()
                    for address in self.feature_values(version):
                        address = address.strip()
                        if address:
                            wallets.append(
                                {
                                    "wallet_address": address,
                                    "network": network_for_address(address, source_code),
                                }
                            )

            if wallets:
                primary_name = next(
                    (name for name, primary in names if primary),
                    names[0][0] if names else None,
                )
                self.parties[profile_id] = {
                    "name": primary_name,
                    "wallets": wallets,
                    "country": country or "unknown",
                    "party_reason": party_comment,
                }

    def parse_sanctions_entry(self, element: ET.Element) -> None:
        profile_id = element.attrib.get("ProfileID")
        if not profile_id:
            return
        dates: list[str] = []
        reasons: list[str] = []
        for event in children(element, "EntryEvent"):
            if value := date_text(child(event, "Date")):
                dates.append(value)
            if comment := text(child(event, "Comment")):
                reasons.append(comment)
        for measure in children(element, "SanctionsMeasure"):
            measure_type = self.ref("SanctionsType", measure.attrib.get("SanctionsTypeID"))
            comment = text(child(measure, "Comment"))
            if measure_type != "Program" and comment:
                reasons.append(comment)
        self.sanctions[profile_id].append({"dates": dates, "reasons": reasons})

    def parse(self, source: BinaryIO) -> None:
        for _, element in ET.iterparse(source, events=("end",)):
            name = tag_name(element)
            if name == "ReferenceValueSets":
                self.parse_references(element)
                element.clear()
            elif name == "Locations":
                self.parse_locations(element)
                element.clear()
            elif name == "DistinctParty":
                self.parse_party(element)
                element.clear()
            elif name == "SanctionsEntry":
                self.parse_sanctions_entry(element)
                element.clear()

    def rows(self) -> list[dict[str, Any]]:
        by_address: dict[str, dict[str, Any]] = {}
        for profile_id, party in self.parties.items():
            sanction_rows = self.sanctions.get(profile_id, [])
            dates = [
                parsed
                for sanction in sanction_rows
                for value in sanction["dates"]
                if (parsed := exact_date(value)) is not None
            ]
            reason = joined(
                [party["party_reason"]]
                + [value for sanction in sanction_rows for value in sanction["reasons"]]
            )
            for wallet in party["wallets"]:
                add_wallet_observation(
                    by_address,
                    address=wallet["wallet_address"],
                    network=wallet["network"],
                    name=party["name"],
                    designation_date=min(dates) if dates else None,
                    reason=reason,
                    country=party["country"],
                )
        return wallet_rows(by_address, include_country=True)


def main() -> None:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--output", type=Path, required=True)
    arguments = argument_parser.parse_args()
    if arguments.output.suffix.lower() != ".parquet":
        raise ValueError("Output path must end with .parquet")

    parser = OfacCryptoParser()
    with open_url(OFAC_URL, "application/xml,*/*;q=0.8") as response:
        parser.parse(response)
    rows = parser.rows()
    if not rows:
        raise RuntimeError("OFAC source produced no crypto addresses")
    table = write_parquet(rows, arguments.output, OFAC_OUTPUT_SCHEMA)
    print(
        json.dumps(
            {
                "source_url": OFAC_URL,
                "output_file": str(arguments.output.resolve()),
                "rows": table.num_rows,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
