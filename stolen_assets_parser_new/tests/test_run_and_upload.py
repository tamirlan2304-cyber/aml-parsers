import unittest
from datetime import date

import pyarrow as pa
import pyarrow.parquet as pq

from run_and_upload import (
    SOURCE_NAMES,
    merge_with_existing,
    parquet_bytes,
    production_s3_key,
)
from telegram_investigations_parser import LEGACY_SCHEMA as OUTPUT_SCHEMA


ADDRESS_A = "0x1111111111111111111111111111111111111111"
ADDRESS_B = "0x2222222222222222222222222222222222222222"


def table_for(*rows: tuple[str, str]) -> pa.Table:
    return pa.Table.from_pylist(
        [
            {
                "wallet_address": address,
                "network": "Ethereum",
                "listed_date": date.fromisoformat(listed_date),
            }
            for address, listed_date in rows
        ],
        schema=OUTPUT_SCHEMA,
    )


class MergeTests(unittest.TestCase):
    def test_all_source_parsers_are_registered(self) -> None:
        self.assertEqual(
            SOURCE_NAMES,
            (
                "telegram_investigations",
                "slowmist_hacked",
                "defihacklabs",
                "sok_interop",
                "solidityscan_hack_analysis",
            ),
        )

    def test_adds_new_address_and_updates_earlier_date(self) -> None:
        existing = table_for((ADDRESS_A, "2026-08-20"))
        current = table_for(
            (ADDRESS_A, "2026-08-10"),
            (ADDRESS_B, "2026-08-15"),
        )

        merged, added, updated = merge_with_existing(existing, current)

        self.assertEqual((added, updated), (1, 1))
        self.assertEqual(merged.num_rows, 2)
        values = {row["wallet_address"]: row for row in merged.to_pylist()}
        self.assertEqual(values[ADDRESS_A]["listed_date"], date(2026, 8, 10))

    def test_parquet_round_trip_is_in_memory(self) -> None:
        table = table_for((ADDRESS_A, "2026-08-20"))

        restored = pq.read_table(pa.BufferReader(parquet_bytes(table)))

        self.assertEqual(restored.schema, OUTPUT_SCHEMA)
        self.assertEqual(restored.num_rows, 1)

    def test_production_key_is_fixed(self) -> None:
        self.assertEqual(
            production_s3_key(),
            "stolen_assets/stolen_assets.parquet",
        )


if __name__ == "__main__":
    unittest.main()
