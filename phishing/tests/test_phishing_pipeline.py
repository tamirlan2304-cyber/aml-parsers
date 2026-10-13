from __future__ import annotations

import unittest
import base64
import asyncio
from datetime import date, datetime, timezone
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import pyarrow as pa

from chainabuse_parser import (
    RecentReports,
    cursor_for_page,
    cursor_index,
    load_latest_checkpoint,
    parse_pagination,
    parse_reports_payload,
    rows_from_api_reports,
    rows_from_html_cards,
    save_checkpoint,
)
from chainabuse_incremental import (
    build_incremental_table_async,
    incremental_cutoff,
    normalize_existing_table,
)
from phishing_common import CHAINABUSE_SCHEMA, normalize_network, parse_html_report_date
from run_and_upload import SOURCES, merge_tables
from scamsniffer_parser import SCAMSNIFFER_SCHEMA, parse_source_payload


EVM = "0x1234567890abcdef1234567890abcdef12345678"
EVM_UPPER = "0x" + EVM[2:].upper()
TRON = "TYA3eVfYcLJ3bZ8Gx47hpjpr6GutvpTuFa"
OBSERVED = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
REPORT_ID_1 = "119d4882-dd34-454f-ab48-7e8927e61031"
REPORT_ID_2 = "8dcfcd9c-d5ca-4e93-9f0a-f17fb233f02c"


class PhishingPipelineTests(unittest.TestCase):
    def test_scamsniffer_has_no_domain_column(self) -> None:
        table = parse_source_payload(
            f'["{EVM}", "{EVM_UPPER}"]'.encode(),
            observed_at=OBSERVED,
            url="https://example.test/addresses.json",
        )
        self.assertEqual(table.schema, SCAMSNIFFER_SCHEMA)
        self.assertNotIn("domain", table.column_names)
        self.assertEqual(table.num_rows, 1)

    def test_chainabuse_html_fields_and_evm_normalization(self) -> None:
        cards = [
            {
                "reportId": REPORT_ID_1,
                "submitted": "Submitted by Anonymous on Mar 4, 2022",
                "domains": ["https://Phish.Example/path"],
                "addresses": [
                    {"address": EVM_UPPER, "chain": "Binance Smart Chain logo"},
                    {"address": TRON, "chain": "Tron logo"},
                ],
                "hiddenCount": 0,
            }
        ]
        rows = {row["wallet_address"]: row for row in rows_from_html_cards(cards, observed_at=OBSERVED)}
        self.assertEqual(rows[EVM]["network"], "Ethereum")
        self.assertEqual(rows[EVM]["domain"], "phish.example")
        self.assertEqual(rows[EVM]["report_date"], date(2022, 3, 4))
        self.assertEqual(rows[EVM]["report_id"], REPORT_ID_1)
        self.assertEqual(rows[EVM]["report_count"], 1)
        self.assertEqual(rows[TRON]["network"], "Tron")

    def test_chainabuse_api_report_contains_id_and_all_indicators(self) -> None:
        rows = rows_from_api_reports(
            [
                {
                    "id": REPORT_ID_1,
                    "createdAt": "2022-03-04T23:15:00.000Z",
                    "addresses": [
                        {"address": EVM_UPPER, "chain": "BSC", "domain": None},
                        {"address": TRON, "chain": "TRON", "domain": None},
                        {"address": None, "chain": None, "domain": "Phish.Example/path"},
                    ],
                }
            ]
        )
        by_address = {row["wallet_address"]: row for row in rows}
        self.assertEqual(set(by_address), {EVM, TRON})
        self.assertEqual(by_address[EVM]["report_id"], REPORT_ID_1)
        self.assertEqual(by_address[EVM]["report_count"], 1)
        self.assertEqual(by_address[EVM]["report_date"], date(2022, 3, 4))
        self.assertEqual(by_address[EVM]["domain"], "phish.example")

    def test_graphql_cursor_and_payload_validation(self) -> None:
        self.assertEqual(cursor_index(cursor_for_page(1)), 49)
        edge_cursor = base64.b64encode(b"arrayconnection:0").decode("ascii")
        page = parse_reports_payload(
            {
                "data": {
                    "reports": {
                        "totalCount": 1,
                        "edges": [
                            {
                                "cursor": edge_cursor,
                                "node": {
                                    "id": REPORT_ID_1,
                                    "createdAt": "2022-03-04T00:00:00Z",
                                    "addresses": [],
                                },
                            }
                        ],
                    }
                }
            },
            page_index=0,
        )
        self.assertEqual(page.report_ids, (REPORT_ID_1,))

    def test_displayed_relative_date(self) -> None:
        self.assertEqual(
            parse_html_report_date("Submitted by A 2 hours ago", OBSERVED),
            date(2026, 8, 25),
        )
        self.assertEqual(
            parse_html_report_date("Submitted by A 3 days ago", OBSERVED),
            date(2026, 8, 22),
        )

    def test_pagination_with_space_thousands_separator(self) -> None:
        self.assertEqual(
            parse_pagination("136 - 150 of 558 540 items"),
            (136, 150, 558540),
        )

    def test_all_evm_network_labels_map_to_ethereum(self) -> None:
        for label in (
            "Ethereum logo",
            "Binance Smart Chain logo",
            "Polygon logo",
            "Arbitrum logo",
            "Base logo",
            "Avalanche (0x) logo",
        ):
            self.assertEqual(normalize_network(label), "Ethereum")

    def test_chainabuse_merge_enriches_existing_row(self) -> None:
        spec = SOURCES["chainabuse"]
        existing = pa.Table.from_pylist(
            [
                {
                    "wallet_address": EVM,
                    "network": "Ethereum",
                    "domain": "",
                    "report_date": None,
                    "report_id": REPORT_ID_1,
                    "report_count": 1,
                }
            ],
            schema=CHAINABUSE_SCHEMA,
        )
        current = pa.Table.from_pylist(
            [
                {
                    "wallet_address": EVM,
                    "network": "Ethereum",
                    "domain": "phish.example",
                    "report_date": date(2022, 3, 4),
                    "report_id": REPORT_ID_1,
                    "report_count": 1,
                }
            ],
            schema=CHAINABUSE_SCHEMA,
        )
        merged, added, enriched = merge_tables(spec, existing, current)
        self.assertEqual((added, enriched), (0, 1))
        self.assertEqual(merged.to_pylist()[0]["domain"], "phish.example")

    def test_chainabuse_aggregates_same_address_from_different_reports(self) -> None:
        spec = SOURCES["chainabuse"]
        existing = pa.Table.from_pylist(
            [
                {
                    "wallet_address": EVM,
                    "network": "Ethereum",
                    "domain": "first.example",
                    "report_date": date(2022, 3, 4),
                    "report_id": REPORT_ID_1,
                    "report_count": 1,
                }
            ],
            schema=CHAINABUSE_SCHEMA,
        )
        current = pa.Table.from_pylist(
            [
                {
                    "wallet_address": EVM,
                    "network": "Ethereum",
                    "domain": "second.example",
                    "report_date": date(2023, 5, 6),
                    "report_id": REPORT_ID_2,
                    "report_count": 2,
                }
            ],
            schema=CHAINABUSE_SCHEMA,
        )
        merged, added, enriched = merge_tables(spec, existing, current)
        self.assertEqual((added, enriched), (0, 1))
        self.assertEqual(merged.num_rows, 1)
        self.assertEqual(merged.to_pylist()[0]["report_id"], REPORT_ID_1)
        self.assertEqual(merged.to_pylist()[0]["report_count"], 2)
        self.assertEqual(merged.to_pylist()[0]["report_date"], date(2023, 5, 6))

    def test_sources_have_different_schemas_and_keys(self) -> None:
        self.assertNotEqual(SOURCES["scamsniffer"].schema, SOURCES["chainabuse"].schema)
        self.assertEqual(SOURCES["scamsniffer"].key, "phishing/scamsniffer.parquet")
        self.assertEqual(SOURCES["chainabuse"].key, "phishing/chainabuse.parquet")

    def test_checkpoint_is_cumulative_and_resumable(self) -> None:
        base_url = "https://chainabuse.test/category/phishing"
        records = {
            EVM: {
                "wallet_address": EVM,
                "network": "Ethereum",
                "domain": "phish.example",
                "report_date": date(2022, 3, 4),
                "report_id": REPORT_ID_1,
                "report_count": 1,
            }
        }
        with TemporaryDirectory() as temporary_directory:
            with patch.dict(
                "os.environ",
                {"CHAINABUSE_CHECKPOINT_DIR": temporary_directory},
            ):
                older_path = save_checkpoint(
                    records,
                    base_url=base_url,
                    next_page_index=500,
                    item_first=1,
                    item_last=25000,
                    total_reports=558540,
                    complete=False,
                )
                path = save_checkpoint(
                    records,
                    base_url=base_url,
                    next_page_index=1500,
                    item_first=1,
                    item_last=75000,
                    total_reports=558540,
                    complete=False,
                )
                state = load_latest_checkpoint(base_url=base_url)

            self.assertEqual(
                path.name,
                "chainabuse_checkpoint_page_00001500_items_00000001-00075000.parquet",
            )
            self.assertIsNotNone(state)
            assert state is not None
            self.assertEqual(state.next_page_index, 1500)
            self.assertEqual(state.table.num_rows, 1)
            self.assertFalse(state.complete)
            self.assertFalse(older_path.exists())
            self.assertTrue(path.exists())

    def test_rows_use_address_key_and_keep_first_report_id(self) -> None:
        rows = rows_from_api_reports(
            [
                {
                    "id": REPORT_ID_1,
                    "createdAt": "2022-03-04T00:00:00Z",
                    "addresses": [{"address": EVM, "chain": "ETH", "domain": None}],
                },
                {
                    "id": REPORT_ID_2,
                    "createdAt": "2023-05-06T00:00:00Z",
                    "addresses": [
                        {"address": EVM_UPPER, "chain": "BSC", "domain": None},
                        {"address": EVM, "chain": "ETH", "domain": None},
                    ],
                },
            ]
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["report_id"], REPORT_ID_1)
        self.assertEqual(rows[0]["report_count"], 2)
        self.assertEqual(rows[0]["report_date"], date(2023, 5, 6))

    def test_incremental_parser_uses_overlap_without_double_counting(self) -> None:
        existing = pa.Table.from_pylist(
            [
                {
                    "wallet_address": EVM,
                    "network": "Ethereum",
                    "domain": "first.example",
                    "report_date": date(2023, 5, 6),
                    "report_id": REPORT_ID_1,
                    "report_count": 2,
                }
            ],
            schema=CHAINABUSE_SCHEMA,
        )
        old_report = {
            "id": REPORT_ID_1,
            "createdAt": "2023-05-06T00:00:00Z",
            "addresses": [{"address": EVM, "chain": "ETH", "domain": None}],
        }
        new_report = {
            "id": REPORT_ID_2,
            "createdAt": "2023-05-07T00:00:00Z",
            "addresses": [{"address": EVM, "chain": "ETH", "domain": "new.example"}],
        }
        recent = RecentReports(
            reports=[old_report, new_report],
            snapshot_total=2,
            newest_date=date(2023, 5, 7),
            cutoff_date=date(2023, 5, 1),
        )
        with patch(
            "chainabuse_incremental.fetch_recent_reports_async",
            new=AsyncMock(return_value=recent),
        ):
            first = asyncio.run(build_incremental_table_async(existing))
            second = asyncio.run(build_incremental_table_async(first))

        first_row = first.to_pylist()[0]
        second_row = second.to_pylist()[0]
        self.assertEqual(first_row["report_id"], REPORT_ID_1)
        self.assertEqual(first_row["report_count"], 3)
        self.assertEqual(first_row["report_date"], date(2023, 5, 7))
        self.assertEqual(first_row["domain"], "first.example; new.example")
        self.assertEqual(second_row["report_count"], 3)
        self.assertEqual(incremental_cutoff(second), date(2023, 5, 2))

    def test_legacy_report_rows_are_migrated_to_unique_addresses(self) -> None:
        legacy = pa.Table.from_pylist(
            [
                {
                    "wallet_address": EVM,
                    "network": "Ethereum",
                    "domain": "first.example",
                    "report_date": date(2022, 3, 4),
                    "report_id": REPORT_ID_1,
                },
                {
                    "wallet_address": EVM_UPPER,
                    "network": "Ethereum",
                    "domain": "second.example",
                    "report_date": date(2023, 5, 6),
                    "report_id": REPORT_ID_2,
                },
            ]
        )
        migrated = normalize_existing_table(legacy)
        row = migrated.to_pylist()[0]
        self.assertEqual(migrated.schema.names, CHAINABUSE_SCHEMA.names)
        self.assertEqual(migrated.num_rows, 1)
        self.assertEqual(row["report_id"], REPORT_ID_1)
        self.assertEqual(row["report_count"], 2)
        self.assertEqual(row["report_date"], date(2023, 5, 6))


if __name__ == "__main__":
    unittest.main()
