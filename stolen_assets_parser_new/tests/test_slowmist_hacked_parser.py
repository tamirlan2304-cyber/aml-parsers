import io
import unittest
from datetime import date
from unittest.mock import Mock, patch

import pyarrow as pa
import pyarrow.parquet as pq

import run_and_upload as pipeline
from debug_table import render_table

from slowmist_hacked_parser import (
    OUTPUT_SCHEMA,
    S3_KEY,
    SlowMistEvent,
    build_table_from_events,
    extract_addresses,
    merge_with_existing,
    page_url,
    parse_slowmist_page,
    validate_table,
)


EVM_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"
EVM_UPPER = "0x" + EVM_ADDRESS[2:].upper()
TRON_ADDRESS = "TYA3eVfYcLJ3bZ8Gx47hpjpr6GutvpTuFa"
TX_HASH = "0x" + "ab" * 32

PAGE_HTML = f"""
<html><body>
  <p><em>2</em> hack event(s)</p>
  <div class="case-content"><ul>
    <li>
      <span class="time">2026-08-23</span>
      <h3><em>Hacked target:</em> Example</h3>
      <p><em>Description of the event:</em>
        Ethereum attacker {EVM_UPPER}; transaction {TX_HASH}.
      </p>
      <p class="link-reference"><a href="https://etherscan.io/address/{EVM_ADDRESS}">Source</a></p>
    </li>
    <li>
      <span class="time">2026-08-22</span>
      <p>Tron recipient {TRON_ADDRESS}</p>
    </li>
  </ul></div>
  <ul class="pagination"><li><a>Page 1 of 1</a></li></ul>
</body></html>
"""


class SlowMistHackedParserTests(unittest.TestCase):
    def test_parses_events_dates_links_and_pagination(self) -> None:
        parsed = parse_slowmist_page(PAGE_HTML, expected_page=1)
        self.assertEqual(
            (parsed.page_number, parsed.total_pages, parsed.total_events),
            (1, 1, 2),
        )
        self.assertEqual(len(parsed.events), 2)
        self.assertEqual(parsed.events[0].listed_date, date(2026, 8, 23))
        self.assertIn("etherscan.io/address", parsed.events[0].links[0])
        self.assertEqual(parsed.events[0].hacked_target, "Example")
        self.assertIsNone(parsed.events[1].hacked_target)

    def test_target_handles_inline_markup_entities_and_whitespace(self) -> None:
        html = PAGE_HTML.replace(
            "<h3><em>Hacked target:</em> Example</h3>",
            "<h3>\n<em>Hacked&nbsp;target: </em>&nbsp;<a>warp.</a><b>green</b>\n</h3>",
        )
        self.assertEqual(parse_slowmist_page(html).events[0].hacked_target, "warp.green")

    def test_only_labelled_heading_is_used_not_description(self) -> None:
        html = PAGE_HTML.replace(
            "<h3><em>Hacked target:</em> Example</h3>",
            "<h3>Other heading</h3><p>Hacked target: Not the title</p>",
        )
        self.assertIsNone(parse_slowmist_page(html).events[0].hacked_target)

    def test_empty_target_is_null_and_never_leaks_between_events(self) -> None:
        html = PAGE_HTML.replace(
            f"<p>Tron recipient {TRON_ADDRESS}</p>",
            f"<h3><em>Hacked target:</em>&nbsp;</h3><p>Tron recipient {TRON_ADDRESS}</p>",
        )
        events = parse_slowmist_page(html).events
        self.assertEqual(events[0].hacked_target, "Example")
        self.assertIsNone(events[1].hacked_target)

    def test_target_preserves_unicode_and_is_applied_to_each_event_address(self) -> None:
        html = PAGE_HTML.replace("target:</em> Example", "target:</em> Проект &amp; DAO")
        html = html.replace("transaction " + TX_HASH, "Tron address " + TRON_ADDRESS)
        event = parse_slowmist_page(html).events[0]
        table = build_table_from_events([event])
        self.assertEqual(table["hacked_target"].to_pylist(), ["Проект & DAO"] * 2)

    def test_validates_addresses_and_rejects_transaction_hash(self) -> None:
        parsed = parse_slowmist_page(PAGE_HTML)
        addresses = dict(extract_addresses(parsed.events[0]))
        self.assertEqual(addresses, {EVM_ADDRESS: "Ethereum"})
        self.assertNotIn(TX_HASH, addresses)
        self.assertEqual(
            dict(extract_addresses(parsed.events[1])),
            {TRON_ADDRESS: "TRON"},
        )

    def test_deduplicates_and_keeps_earliest_date(self) -> None:
        later = SlowMistEvent(
            listed_date=date(2026, 8, 23),
            text=f"Ethereum address {EVM_ADDRESS}",
            links=(),
        )
        earlier = SlowMistEvent(
            listed_date=date(2026, 8, 20),
            text=f"Ethereum address {EVM_UPPER}",
            links=(),
        )
        table = build_table_from_events([later, earlier])
        self.assertEqual(table.num_rows, 1)
        self.assertEqual(
            table.to_pylist()[0],
            {
                "wallet_address": EVM_ADDRESS,
                "network": "Ethereum",
                "listed_date": date(2026, 8, 20),
                "hacked_target": None,
            },
        )

    def test_page_url_preserves_empty_category(self) -> None:
        self.assertEqual(
            page_url("https://hacked.slowmist.io/?c=&page=1", 12),
            "https://hacked.slowmist.io/?c=&page=12",
        )

    def test_earliest_date_and_target_stay_paired_in_either_input_order(self) -> None:
        later = SlowMistEvent(date(2026, 8, 23), EVM_ADDRESS, (), "Later incident")
        earlier = SlowMistEvent(date(2026, 8, 20), EVM_ADDRESS, (), "warp.green")
        for events in ([later, earlier], [earlier, later]):
            row = build_table_from_events(events).to_pylist()[0]
            self.assertEqual(row["listed_date"], earlier.listed_date)
            self.assertEqual(row["hacked_target"], "warp.green")

    def test_missing_earliest_target_is_not_borrowed_from_later_event(self) -> None:
        later = SlowMistEvent(date(2026, 8, 23), EVM_ADDRESS, (), "Later incident")
        earlier = SlowMistEvent(date(2026, 8, 20), EVM_ADDRESS, ())
        row = build_table_from_events([later, earlier]).to_pylist()[0]
        self.assertEqual(row["listed_date"], earlier.listed_date)
        self.assertIsNone(row["hacked_target"])

    def test_same_day_tie_is_deterministic_preferring_known_target(self) -> None:
        events = [
            SlowMistEvent(date(2026, 8, 20), EVM_ADDRESS, (), target)
            for target in (None, "Zulu", "Alpha")
        ]
        first = build_table_from_events(events)
        self.assertTrue(first.equals(build_table_from_events(reversed(events))))
        self.assertEqual(first["hacked_target"].to_pylist(), ["Alpha"])


def table_for(day: int = 20, target: str | None = "warp.green", address: str = EVM_ADDRESS) -> pa.Table:
    return build_table_from_events([SlowMistEvent(date(2026, 8, day), address, (), target)])


class SlowMistPipelineTests(unittest.TestCase):
    def test_parquet_round_trip_and_debug_keep_title_and_null(self) -> None:
        table = build_table_from_events(parse_slowmist_page(PAGE_HTML).events)
        restored = pq.read_table(pa.BufferReader(pipeline.parquet_bytes(table)))
        self.assertEqual(restored.schema, OUTPUT_SCHEMA)
        self.assertTrue(restored.equals(table))
        rendered = render_table(table, None)
        self.assertIn("hacked_target", rendered)
        self.assertIn("Example", rendered)
        self.assertNotIn("None", rendered)

    def test_schema_validation_allows_missing_title_but_rejects_bad_rows(self) -> None:
        table = table_for(target=None)
        validate_table(table)
        for changes in ({"hacked_target": " "}, {"listed_date": None}, {"wallet_address": ""}):
            invalid = pa.Table.from_pylist([{**table.to_pylist()[0], **changes}], schema=OUTPUT_SCHEMA)
            with self.assertRaises(ValueError):
                validate_table(invalid)
        with self.assertRaises(ValueError):
            validate_table(pa.concat_tables([table, table]))

    def test_merge_adds_addresses_and_updates_date_with_target(self) -> None:
        existing = table_for(23, "Later")
        current = pa.concat_tables([table_for(20, "Earlier"), table_for(21, "Tron incident", TRON_ADDRESS)])
        merged, added, updated = merge_with_existing(existing, current)
        self.assertEqual((added, updated), (1, 1))
        row = merged.to_pylist()[0]
        self.assertEqual((row["listed_date"], row["hacked_target"]), (date(2026, 8, 20), "Earlier"))
        self.assertEqual(merge_with_existing(merged, current)[1:], (0, 0))

    def test_merge_preserves_historical_rows_and_earlier_title(self) -> None:
        existing = pa.concat_tables([table_for(20, "Earlier"), table_for(21, None, TRON_ADDRESS)])
        merged, added, updated = merge_with_existing(existing, table_for(23, "Later"))
        self.assertTrue(merged.equals(existing))
        self.assertEqual((added, updated), (0, 0))

    def test_merge_earlier_event_with_missing_title_does_not_keep_later_title(self) -> None:
        merged, _, updated = merge_with_existing(table_for(23, "Later"), table_for(20, None))
        self.assertIsNone(merged.to_pylist()[0]["hacked_target"])
        self.assertEqual(updated, 1)

    def test_merge_can_fill_or_correct_title_for_same_date(self) -> None:
        current = table_for()
        for old_target in (None, "Old spelling"):
            merged, added, updated = merge_with_existing(table_for(target=old_target), current)
            self.assertTrue(merged.equals(current))
            self.assertEqual((added, updated), (0, 1))
        self.assertEqual(merge_with_existing(current, table_for(target=None))[1:], (0, 0))

    def test_merge_rejects_network_conflict(self) -> None:
        current = table_for()
        old = pa.Table.from_pylist([{**current.to_pylist()[0], "network": "Other"}], schema=OUTPUT_SCHEMA)
        with self.assertRaisesRegex(ValueError, "Conflicting networks"):
            merge_with_existing(old, current)

    def test_source_selection_preserves_title_and_legacy_projection_stays_three_columns(self) -> None:
        table = table_for()
        builder = Mock(return_value=table)
        with patch.object(pipeline, "SOURCE_BUILDERS", (("slowmist_hacked", builder),)):
            outputs = pipeline.build_output_tables("slowmist_hacked")
        builder.assert_called_once_with()
        self.assertEqual(outputs[0][0], "slowmist_hacked")
        self.assertTrue(outputs[0][1].equals(table))
        self.assertEqual(pipeline.output_s3_key("slowmist_hacked"), S3_KEY)
        legacy = pipeline.combine_source_tables(outputs)
        self.assertEqual(legacy.schema, pipeline.OUTPUT_SCHEMA)
        self.assertEqual(legacy.num_columns, 3)

    def test_s3_read_preserves_title_and_closes_body(self) -> None:
        table = table_for()
        client = Mock()
        body = io.BytesIO(pipeline.parquet_bytes(table))
        client.get_object.return_value = {"Body": body}
        restored = pipeline.read_s3(client, "test", S3_KEY, output_name="slowmist_hacked")
        self.assertTrue(restored.equals(table))
        self.assertTrue(body.closed)

    def test_s3_read_does_not_silently_assign_titles_to_old_mixed_data(self) -> None:
        legacy = table_for().select(pipeline.OUTPUT_SCHEMA.names)
        client = Mock()
        client.get_object.return_value = {"Body": io.BytesIO(pipeline.parquet_bytes(legacy))}
        with self.assertRaises((ValueError, pa.ArrowException)):
            pipeline.read_s3(client, "test", S3_KEY, output_name="slowmist_hacked")

    def test_cli_dry_run_never_creates_s3_client(self) -> None:
        with patch("sys.argv", ["run_and_upload.py", "--source", "slowmist_hacked", "--dry-run"]), \
                patch.object(pipeline, "build_output_tables", return_value=[("slowmist_hacked", table_for())]), \
                patch.object(pipeline, "create_s3_client") as client:
            pipeline.main()
        client.assert_not_called()

    def test_cli_uses_separate_object_and_skips_unchanged_upload(self) -> None:
        current = table_for()
        for existing in (None, current):
            with patch("sys.argv", ["run_and_upload.py", "--source", "slowmist_hacked"]), \
                    patch.object(pipeline, "build_output_tables", return_value=[("slowmist_hacked", current)]), \
                    patch.object(pipeline, "create_s3_client", return_value=Mock()), \
                    patch.object(pipeline, "required_setting", return_value="test-bucket"), \
                    patch.object(pipeline, "read_s3", return_value=existing) as read, \
                    patch.object(pipeline, "upload", return_value=123) as upload:
                pipeline.main()
            self.assertEqual(read.call_args.args[2], S3_KEY)
            if existing is None:
                self.assertEqual(upload.call_args.args[2], S3_KEY)
                self.assertTrue(upload.call_args.args[3].equals(current))
            else:
                upload.assert_not_called()


if __name__ == "__main__":
    unittest.main()
