import io
import json
import logging
import unittest
from datetime import date
from unittest.mock import MagicMock, Mock, patch

import pyarrow as pa
import pyarrow.parquet as pq
from botocore.exceptions import ClientError

import run_and_upload as pipeline
import solidityscan_hack_parser as parser
from debug_table import render_table


ATTACKER = "0x123456789012345678901234567890123456789a"
EXPLOIT = "0x234567890123456789012345678901234567890b"
STOLEN = "0x345678901234567890123456789012345678901c"
VICTIM = "0x456789012345678901234567890123456789012d"
UNLABELLED = "0x567890123456789012345678901234567890123e"
TX = "0x" + "ab" * 32


def setUpModule():
    logging.disable(logging.CRITICAL)


def tearDownModule():
    logging.disable(logging.NOTSET)


def content(when="April 26, 2026"):
    return f"""
    <h2>Overview</h2>
    <p>On {when}, Example Protocol on BSC suffered an exploit. An unrelated
       account was <code>{UNLABELLED}</code>.</p>
    <h2>Smart Contract Hack Overview</h2>
    <ul>
      <li><strong>Victim Contract:</strong>
          <a href="https://bscscan.com/address/{VICTIM}"><code>0x45678…</code></a></li>
      <li><strong>Attack Transaction:</strong>
          <a href="https://bscscan.com/tx/{TX}"><code>0xabab…</code></a></li>
      <li><strong>Attacker’s Address:</strong>
          <a href="https://bscscan.com/address/{ATTACKER}"><code>0x12345…</code></a></li>
      <li><strong>Exploit Contract:</strong> <code>{EXPLOIT}</code></li>
      <li><strong>Stolen Funds Parked At:</strong>
          <a href="https://etherscan.io/address/{STOLEN}"><code>0x34567…</code></a></li>
    </ul>
    <pre>address attacker = {VICTIM};</pre>
    """


def post(*, post_id=1, title="Example Protocol Hack Analysis", body=None):
    return parser.HackPost(
        post_id=post_id,
        published_date=date(2026, 4, 28),
        link=f"https://blog.solidityscan.com/example-{post_id}/",
        title=title,
        content=content() if body is None else body,
    )


def table_for(address=ATTACKER, name="Example Protocol", when=date(2026, 4, 26)):
    return parser.rows_to_table([{
        "address": address,
        "network": "Ethereum",
        "incident_date": when,
        "incident_name": name,
    }])


class ExtractionTests(unittest.TestCase):
    def test_extracts_only_explicit_malicious_roles_and_full_link_targets(self):
        self.assertEqual(
            set(parser.extract_addresses(content())),
            {(ATTACKER, "Ethereum"), (EXPLOIT, "Ethereum"), (STOLEN, "Ethereum")},
        )

    def test_excludes_victim_transaction_unlabelled_funder_and_placeholders(self):
        body = content() + f"""
        <p>Attacker Funded From: <a href="https://etherscan.io/address/{VICTIM}">{VICTIM}</a></p>
        <p>Attacker Address: 0x0000000000000000000000000000000000000000</p>
        """
        found = {address for address, _ in parser.extract_addresses(body)}
        self.assertNotIn(VICTIM, found)
        self.assertNotIn(UNLABELLED, found)
        self.assertEqual(found, {ATTACKER, EXPLOIT, STOLEN})

    def test_separate_label_and_address_blocks_are_supported_once(self):
        body = f"<p>Attacker Addresses:</p><p>{ATTACKER}, {EXPLOIT}</p><p>ordinary prose {STOLEN}</p>"
        self.assertEqual(
            set(parser.extract_addresses(body)),
            {(ATTACKER, "Ethereum"), (EXPLOIT, "Ethereum")},
        )

    def test_date_variants_and_title_normalization(self):
        cases = {
            "October 4, 2025": date(2025, 10, 4),
            "11th August 2025": date(2025, 8, 11),
            "31st Oct, 2023": date(2023, 10, 31),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(parser.incident_date(content(text)), expected)
        self.assertEqual(parser.incident_name("  Example &amp; DAO — Hack Analysis "), "Example & DAO")
        self.assertEqual(
            parser.incident_name("Sashimi Swap Hack Analysis — Improper Router Design"),
            "Sashimi Swap",
        )

    def test_invalid_or_late_dates_do_not_replace_incident_date(self):
        body = (
            "<p>Overview: On February 31, 2025 the incident occurred. "
            "On March 2, 2025 it was disclosed.</p><h2>Smart Contract Hack Overview</h2>"
        )
        self.assertEqual(parser.incident_date(body), date(2025, 3, 2))
        self.assertIsNone(parser.incident_date("<p>No exact incident day was published.</p>"))


class TableTests(unittest.TestCase):
    def test_schema_deduplication_and_rows(self):
        table = parser.build_table_from_posts([post(), post(post_id=2)])
        parser.validate_table(table)
        self.assertEqual(table.schema, parser.OUTPUT_SCHEMA)
        self.assertEqual(
            table.column_names,
            ["address", "network", "incident_date", "incident_name"],
        )
        self.assertEqual(table.num_rows, 3)
        self.assertEqual(set(table["network"].to_pylist()), {"Ethereum"})
        self.assertEqual(set(table["incident_name"].to_pylist()), {"Example Protocol"})

    def test_missing_date_or_addresses_is_skipped_and_all_empty_fails_closed(self):
        valid = post()
        no_date = post(post_id=2, body=content("not specified"))
        no_addresses = post(post_id=3, body="<p>On April 26, 2026, no addresses.</p>")
        self.assertEqual(parser.build_table_from_posts([valid, no_date, no_addresses]).num_rows, 3)
        with self.assertRaises(RuntimeError):
            parser.build_table_from_posts([no_date, no_addresses])

    def test_same_address_in_distinct_incidents_is_retained(self):
        second = post(
            post_id=2,
            title="Second Hack Analysis",
            body=content("April 27, 2026").replace(EXPLOIT, ATTACKER).replace(STOLEN, ATTACKER),
        )
        table = parser.build_table_from_posts([post(), second])
        self.assertEqual(sum(value == ATTACKER for value in table["address"].to_pylist()), 2)

    def test_validation_rejects_bad_schema_duplicate_network_and_address(self):
        valid = table_for()
        parser.validate_table(valid)
        invalid_rows = (
            {**valid.to_pylist()[0], "network": "BSC"},
            {**valid.to_pylist()[0], "address": "0x" + "0" * 40},
            {**valid.to_pylist()[0], "incident_name": " "},
        )
        for row in invalid_rows:
            with self.subTest(row=row):
                with self.assertRaises(ValueError):
                    parser.validate_table(parser.rows_to_table([row]))
        with self.assertRaises(ValueError):
            parser.validate_table(pa.concat_tables([valid, valid]))
        with self.assertRaises(ValueError):
            parser.validate_table(valid.drop(["incident_name"]))


class DownloadTests(unittest.TestCase):
    @staticmethod
    def response(values, total, pages):
        response = MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        response.headers = {"X-WP-Total": str(total), "X-WP-TotalPages": str(pages)}
        response.iter_content.return_value = [json.dumps(values).encode()]
        return response

    @staticmethod
    def api_value(post_id):
        return {
            "id": post_id,
            "date": "2026-04-28T07:02:09",
            "link": f"https://blog.solidityscan.com/example-{post_id}/",
            "title": {"rendered": "Example Hack Analysis"},
            "content": {"rendered": content()},
        }

    def test_fetches_every_api_page_and_checks_totals(self):
        first = self.response([self.api_value(1)], 2, 2)
        second = self.response([self.api_value(2)], 2, 2)
        with patch.object(parser.requests, "Session") as factory:
            session = factory.return_value.__enter__.return_value
            session.get.side_effect = [first, second]
            posts = parser.fetch_all_posts(timeout=10, retries=2)
        self.assertEqual([item.post_id for item in posts], [1, 2])
        self.assertEqual(session.get.call_count, 2)
        self.assertEqual(session.get.call_args_list[0].kwargs["params"]["categories"], parser.CATEGORY_ID)

    def test_incomplete_changed_duplicate_or_malformed_pages_fail_closed(self):
        cases = [
            [self.response([self.api_value(1)], 2, 1)],
            [self.response([self.api_value(1)], 2, 2), self.response([self.api_value(2)], 3, 2)],
            [self.response([self.api_value(1), self.api_value(1)], 2, 1)],
            [self.response([{"id": 1}], 1, 1)],
        ]
        for responses in cases:
            with self.subTest(case=len(responses)):
                with patch.object(parser.requests, "Session") as factory:
                    factory.return_value.__enter__.return_value.get.side_effect = responses
                    with self.assertRaises((RuntimeError, ValueError)):
                        parser.fetch_all_posts(timeout=10, retries=2)

    def test_invalid_configuration_fails_before_network(self):
        with patch.object(parser.requests, "Session") as factory:
            for timeout, retries in ((0, 1), (10, -1), (10, 6)):
                with self.subTest(timeout=timeout, retries=retries):
                    with self.assertRaises(ValueError):
                        parser.fetch_all_posts(timeout=timeout, retries=retries)
        factory.assert_not_called()


class PipelineTests(unittest.TestCase):
    def test_parquet_debug_merge_and_idempotence(self):
        current = table_for()
        payload = pipeline.parquet_bytes(current)
        self.assertTrue(pq.read_table(pa.BufferReader(payload)).equals(current))
        for column in parser.OUTPUT_SCHEMA.names:
            self.assertIn(column, render_table(current, None))
        self.assertEqual(parser.merge_with_existing(None, current)[1:], (1, 0))
        merged, added, updated = parser.merge_with_existing(current, table_for(EXPLOIT))
        self.assertEqual((merged.num_rows, added, updated), (2, 1, 0))
        self.assertEqual(parser.merge_with_existing(merged, table_for(EXPLOIT))[1:], (0, 0))

    def test_source_selection_key_s3_schema_and_closed_body(self):
        current = table_for()
        with patch.object(parser, "build_table", return_value=current) as build:
            outputs = pipeline.build_output_tables("solidityscan_hack_analysis")
        self.assertEqual(outputs, [("solidityscan_hack_analysis", current)])
        build.assert_called_once_with()
        self.assertEqual(pipeline.output_s3_key("solidityscan_hack_analysis"), parser.S3_KEY)

        body = io.BytesIO(pipeline.parquet_bytes(current))
        client = Mock()
        client.get_object.return_value = {"Body": body}
        restored = pipeline.read_s3(
            client, "test", parser.S3_KEY, output_name="solidityscan_hack_analysis"
        )
        self.assertTrue(restored.equals(current))
        self.assertTrue(body.closed)

    def test_cli_dry_run_and_unchanged_upload_behavior(self):
        current = table_for()
        with patch("sys.argv", [
            "run_and_upload.py", "--source", "solidityscan_hack_analysis", "--dry-run"
        ]), patch.object(parser, "build_table", return_value=current), \
                patch.object(pipeline, "create_s3_client") as client:
            pipeline.main()
        client.assert_not_called()

        with patch("sys.argv", [
            "run_and_upload.py", "--source", "solidityscan_hack_analysis"
        ]), patch.object(parser, "build_table", return_value=current), \
                patch.object(pipeline, "create_s3_client", return_value=Mock()), \
                patch.object(pipeline, "required_setting", return_value="test"), \
                patch.object(pipeline, "read_s3", return_value=current), \
                patch.object(pipeline, "upload") as upload:
            pipeline.main()
        upload.assert_not_called()

    def test_missing_object_is_not_confused_with_access_denied(self):
        client = Mock()
        client.get_object.side_effect = ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        self.assertIsNone(pipeline.read_s3(
            client, "test", parser.S3_KEY, output_name="solidityscan_hack_analysis"
        ))
        client.get_object.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetObject")
        with self.assertRaises(RuntimeError):
            pipeline.read_s3(
                client, "test", parser.S3_KEY, output_name="solidityscan_hack_analysis"
            )


if __name__ == "__main__":
    unittest.main()
