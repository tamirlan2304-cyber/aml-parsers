import io
import logging
import unittest
from datetime import date, datetime, timezone
from unittest.mock import Mock, patch

import pyarrow as pa
import pyarrow.parquet as pq
import requests
from botocore.exceptions import ClientError

import run_and_upload as pipeline
import sok_interop_parser as parser
from debug_table import render_table


A = "0x123456789012345678901234567890123456789a"
B = "0x234567890123456789012345678901234567890b"
TX = "0x" + "ab" * 32
BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
TRON = "TYA3eVfYcLJ3bZ8Gx47hpjpr6GutvpTuFa"
SHA = "a" * 40
SHA2 = "b" * 40


def setUpModule():
    logging.disable(logging.CRITICAL)


def tearDownModule():
    logging.disable(logging.NOTSET)


def post(day):
    timestamp = int(datetime.fromisoformat(day).replace(tzinfo=timezone.utc).timestamp() * 1000)
    return f"[Link](https://twitter.com/Example/status/{(timestamp - 1288834974657) << 22})"


def snapshot(rows=None, dates="Example,15/01/2022,100"):
    if rows is None:
        rows = [("Example", f"Attacker's address on Ethereum:<br>{A}", post("2022-01-16"))]
    return {
        parser.ADDRESS_FILE: "| Hacked Bridge | Transaction, Addresses and Other details |\n|---|---|\n"
        + "\n".join(f"| {name} | {details} |" for name, details, _ in rows),
        parser.RESPONSE_FILE: "| Hacked Bridge | First Transaction (Blockchain) | Public Announcement |\n|---|---|---|\n"
        + "\n".join(f"| {name} | not found | {announcement} |" for name, _, announcement in rows),
        parser.DATE_FILE: "bridge,date,value\n" + dates + "\n",
    }


def table_for(address=A, commit=SHA, when=date(2022, 1, 15)):
    return parser.rows_to_table([{
        "address": address, "network": "Ethereum", "hacked_bridge": "Example",
        "incident_date": when, "link": f"{parser.GITHUB_URL}/blob/{commit}/{parser.ADDRESS_FILE}#L3",
    }])


class AddressTests(unittest.TestCase):
    def test_reads_generic_and_attacker_sections_but_not_transaction_hashes(self):
        details = (
            f"Transactions on Ethereum:<br>{TX}<br><br>Addresses on Ethereum:<br>{B}"
            f"<br><br>Attacker addresses on BSC:<br>{A}"
        )
        self.assertEqual(parser.extract_addresses(details), [(B, "Ethereum"), (A, "Ethereum")])

    def test_deduplicates_all_evm_networks_and_case(self):
        details = f"Attacker's address on Ethereum:<br>{A.upper()}<br><br>Attacker's address on BSC:<br>{A}"
        self.assertEqual(parser.extract_addresses(details), [(A, "Ethereum")])

    def test_header_inline_values_markup_and_multiple_addresses(self):
        details = f"<strong>Attacker’s addresses on Ethereum:</strong> `{A}`<br/>{B}"
        self.assertEqual(parser.extract_addresses(details), [(A, "Ethereum"), (B, "Ethereum")])

    def test_bitcoin_and_tron_are_validated_before_network_assignment(self):
        details = f"Attacker addresses on Bitcoin:<br>{BTC}<br><br>Attacker addresses on Tron:<br>{TRON}"
        self.assertEqual(parser.extract_addresses(details), [(BTC, "Bitcoin"), (TRON, "TRON")])

    def test_invalid_addresses_and_transaction_hashes_are_rejected(self):
        for candidate in (TX, A[:-1], A + "a", BTC[:-1] + "b"):
            with self.subTest(candidate=candidate):
                self.assertEqual(parser.extract_addresses(f"Addresses:<br>{candidate}"), [])

    def test_role_labels_do_not_exclude_published_addresses(self):
        for role in ("Victim", "Token", "Pool", "Bridge", "CEX", "Router", "Foundry", "Testnet"):
            with self.subTest(role=role):
                details = f"Attacker addresses:<br>{A}<br><br>{role}:<br>{A}"
                self.assertEqual(parser.extract_addresses(details), [(A, "Ethereum")])
                details = f"Attacker addresses:<br>{A} ({role})"
                self.assertEqual(parser.extract_addresses(details), [(A, "Ethereum")])

    def test_uncertain_role_does_not_change_address_extraction(self):
        for text in (f"Possible attacker address: {A}", f"Attacker address: {A} (unconfirmed)"):
            self.assertEqual(parser.extract_addresses(text), [(A, "Ethereum")])

    def test_unknown_heading_or_blank_line_does_not_hide_addresses(self):
        for divider in ("<br><br>", "<br>Other accounts:<br>", "<br>More details:<br>"):
            details = f"Attacker addresses:<br>{A}{divider}{B}"
            self.assertEqual(parser.extract_addresses(details), [(A, "Ethereum"), (B, "Ethereum")])

    def test_includes_addresses_from_markdown_links_and_query_parameters(self):
        details = f"Attacker addresses:<br>[here](https://example.org/?address={A})<br>{B}"
        self.assertEqual(parser.extract_addresses(details), [(A, "Ethereum"), (B, "Ethereum")])
        details = f"Attacker addresses:<br>[{A}](https://example.org/?other={B})"
        self.assertEqual(parser.extract_addresses(details), [(A, "Ethereum"), (B, "Ethereum")])

    def test_free_text_and_no_space_after_label(self):
        self.assertEqual(parser.extract_addresses(f"The account is {A}; another address:{B}."), [(A, "Ethereum"), (B, "Ethereum")])

    def test_html_link_targets_and_percent_encoded_addresses(self):
        encoded = A.replace("0x", "%30%78")
        details = f'<a href="https://etherscan.io/txsInternal?a={encoded}&amp;other={B}">More</a>'
        self.assertEqual(parser.extract_addresses(details), [(A, "Ethereum"), (B, "Ethereum")])

    def test_hash_in_url_is_not_truncated_to_address(self):
        self.assertEqual(parser.extract_addresses(f"[Transaction](https://etherscan.io/tx/{TX})"), [])

    def test_legacy_function_name_is_an_alias_not_a_strict_filter(self):
        self.assertEqual(parser.extract_attacker_addresses(f"Addresses on Ethereum:<br>{A}"), [(A, "Ethereum")])

    def test_syntactically_valid_addresses_are_not_filtered_by_purpose(self):
        for address in ("0x" + "0" * 40, "0x" + "1" * 40, "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d"):
            self.assertEqual(parser.extract_addresses(address), [(address, "Ethereum")])

    def test_external_links_without_addresses_are_not_crawled(self):
        with patch.object(parser.requests, "Session") as session:
            self.assertEqual(parser.extract_addresses("List [here](https://pastebin.com/raw/bAquZVws)"), [])
        session.assert_not_called()


class SnapshotTests(unittest.TestCase):
    def test_schema_and_pinned_source_line(self):
        table = parser.parse_snapshot(snapshot(), SHA)
        parser.validate_table(table)
        self.assertEqual(table.schema, parser.OUTPUT_SCHEMA)
        self.assertEqual(table.column_names, ["address", "network", "hacked_bridge", "incident_date", "link"])
        self.assertTrue(table.equals(table_for()))

    def test_repeated_bridge_dates_not_mapped_by_csv_order(self):
        files = snapshot([
            ("Multichain", f"Attacker address:<br>{A}", post("2022-01-20")),
            ("Multichain", f"Attacker address:<br>{A}", post("2023-07-06")),
        ], "Multichain,07/07/2023,1\nMultichain,15/02/2023,2\nMultichain,19/01/2022,3")
        table = parser.parse_snapshot(files, SHA)
        self.assertEqual(table.num_rows, 2)
        self.assertEqual(table["incident_date"].to_pylist(), [date(2022, 1, 19), date(2023, 7, 7)])
        self.assertEqual(len(set(table["address"].to_pylist())), 1)

    def test_announcement_day_does_not_replace_csv_incident_day(self):
        self.assertEqual(parser.announcement_date("https://twitter.com/MultichainOrg/status/1484036449955553285"), date(2022, 1, 20))
        table = parser.parse_snapshot(snapshot(), SHA)
        self.assertEqual(table["incident_date"].to_pylist(), [date(2022, 1, 15)])

    def test_ambiguous_or_contradictory_dates_remain_null(self):
        for dates in ("Example,15/01/2022,1\nExample,18/01/2022,2", "Example,15/01/2021,1", "Other,15/01/2022,1"):
            table = parser.parse_snapshot(snapshot(dates=dates), SHA)
            parser.validate_table(table)
            self.assertEqual(table["incident_date"].to_pylist(), [None])

    def test_duplicate_csv_records_are_not_mistaken_for_one_incident(self):
        table = parser.parse_snapshot(snapshot(dates="Example,15/01/2022,1\nExample,15/01/2022,2"), SHA)
        self.assertEqual(table["incident_date"].null_count, 1)

    def test_missing_announcement_allows_only_unique_bridge_date(self):
        files = snapshot([("Example", f"Attacker address: {A}", "not found")])
        self.assertEqual(parser.parse_snapshot(files, SHA)["incident_date"].to_pylist(), [date(2022, 1, 15)])
        files = snapshot([
            ("Example", f"Attacker address: {A}", "not found"),
            ("Example", f"Attacker address: {B}", "not found"),
        ])
        self.assertEqual(parser.parse_snapshot(files, SHA)["incident_date"].null_count, 2)

    def test_aliases_and_numbered_incidents(self):
        self.assertEqual(parser.bridge_key("PolyNetwork"), parser.bridge_key("Poly Network"))
        self.assertEqual(parser.bridge_key("Boy x Highspeed"), "bxh")
        self.assertEqual(parser.bridge_key("Thorchain #2"), "thorchain")
        files = snapshot([("<b>PNetwork</b>", f"Attacker address: {A}", post("2021-09-19"))], "pNetwork,19/09/2021,1")
        self.assertEqual(parser.parse_snapshot(files, SHA)["incident_date"].to_pylist(), [date(2021, 9, 19)])

    def test_missing_changed_or_incomplete_tables_fail_closed(self):
        cases = []
        files = snapshot()
        files.pop(parser.DATE_FILE)
        cases.append(files)
        files = snapshot()
        files[parser.RESPONSE_FILE] = files[parser.RESPONSE_FILE].replace("| Example |", "| Wrong |")
        cases.append(files)
        files = snapshot()
        files[parser.RESPONSE_FILE] = "<html>Rate limit</html>"
        cases.append(files)
        files = snapshot()
        files[parser.ADDRESS_FILE] = files[parser.ADDRESS_FILE].replace("|---|---|", "|--|--|")
        cases.append(files)
        for files in cases:
            with self.assertRaises(ValueError):
                parser.parse_snapshot(files, SHA)

    def test_bad_csv_and_branch_instead_of_commit_are_rejected(self):
        for text in ("bridge,when,value\n", "bridge,date,value\nX,31/02/2022,1\n", "bridge,date,value\nX,01/02/2022\n"):
            with self.assertRaises(ValueError):
                parser.parse_dates(text)
        with self.assertRaises(ValueError):
            parser.parse_snapshot(snapshot(), "main")

    def test_source_without_attacker_labels_is_now_accepted(self):
        files = snapshot([("Example", f"Addresses on Ethereum:<br>{A}", "not found")])
        with patch.object(parser, "download_snapshot", return_value=(SHA, files)):
            self.assertEqual(parser.build_table()["address"].to_pylist(), [A])

    def test_source_with_only_transaction_hashes_cannot_be_uploaded(self):
        files = snapshot([("Example", f"Transactions on Ethereum:<br>{TX}", "not found")])
        with patch.object(parser, "download_snapshot", return_value=(SHA, files)):
            with self.assertRaisesRegex(ValueError, "empty"):
                parser.build_table()

    def test_secondary_table_address_has_its_own_evidence_link(self):
        files = snapshot()
        files[parser.RESPONSE_FILE] = files[parser.RESPONSE_FILE].replace("not found", B)
        table = parser.parse_snapshot(files, SHA)
        parser.validate_table(table)
        rows = {row["address"]: row for row in table.to_pylist()}
        self.assertEqual(len(rows), 2)
        self.assertIn(parser.ADDRESS_FILE, rows[A]["link"])
        self.assertIn(parser.RESPONSE_FILE, rows[B]["link"])

    def test_same_address_in_both_source_tables_is_not_duplicated(self):
        files = snapshot()
        files[parser.RESPONSE_FILE] = files[parser.RESPONSE_FILE].replace("not found", A)
        table = parser.parse_snapshot(files, SHA)
        self.assertEqual(table.num_rows, 1)
        self.assertIn(parser.ADDRESS_FILE, table["link"][0].as_py())

    def test_address_in_qubit_url_and_thorchain_text_keeps_both_incidents(self):
        files = snapshot([
            ("Qubit", f"More [here](https://etherscan.io/txsInternal?a={A})", "not found"),
            ("Thorchain #2", f"Address on Ethereum:<br>{A}", "not found"),
        ], "Qubit,28/01/2022,1\nThorchain,15/07/2021,2")
        table = parser.parse_snapshot(files, SHA)
        self.assertEqual(table.num_rows, 2)
        self.assertEqual(len(set(table["address"].to_pylist())), 1)

    def test_merge_adds_newly_included_unlabelled_addresses(self):
        files = snapshot([("Example", f"Attacker address: {A}<br>Other address: {B}", post("2022-01-16"))])
        current = parser.parse_snapshot(files, SHA)
        merged, added, updated = parser.merge_with_existing(table_for(), current)
        self.assertEqual((merged.num_rows, added, updated), (2, 1, 0))


class PipelineTests(unittest.TestCase):
    def test_parquet_roundtrip_and_debug_are_in_memory_and_keep_five_columns(self):
        table = table_for(when=None)
        payload = pipeline.parquet_bytes(table)
        restored = pq.read_table(pa.BufferReader(payload))
        self.assertTrue(table.equals(restored))
        output = render_table(table, None)
        for column in parser.OUTPUT_SCHEMA.names:
            self.assertIn(column, output)
        self.assertNotIn("None", output)

    def test_merge_missing_existing_new_address_changed_link_and_idempotence(self):
        current = table_for()
        self.assertEqual(parser.merge_with_existing(None, current)[1:], (1, 0))
        current = pa.concat_tables([table_for(commit=SHA2), table_for(B, SHA2)])
        merged, added, updated = parser.merge_with_existing(table_for(), current)
        self.assertEqual((added, updated), (1, 1))
        self.assertEqual(merged.num_rows, 2)
        self.assertEqual(parser.merge_with_existing(merged, current)[1:], (0, 0))

    def test_history_and_distinct_incidents_are_retained(self):
        merged, added, _ = parser.merge_with_existing(table_for(), table_for(when=date(2023, 7, 7)))
        self.assertEqual((merged.num_rows, added), (2, 1))

    def test_numbered_incidents_with_same_address_and_date_remain_distinct(self):
        rows = [{**table_for().to_pylist()[0], "hacked_bridge": name} for name in ("Thorchain #1", "Thorchain #2")]
        table = parser.rows_to_table(rows)
        parser.validate_table(table)
        self.assertEqual(parser.merge_with_existing(None, table)[1], 2)

    def test_validation_rejects_wrong_network_link_duplicate_and_empty(self):
        for changes in ({"network": "BSC"}, {"link": "https://example.org/"}, {"address": TX}, {"hacked_bridge": " "}):
            invalid = parser.rows_to_table([{**table_for().to_pylist()[0], **changes}])
            with self.assertRaises(ValueError):
                parser.validate_table(invalid)
        for invalid in (pa.concat_tables([table_for(), table_for()]), table_for().slice(0, 0), table_for().drop(["link"])):
            with self.assertRaises(ValueError):
                parser.validate_table(invalid)

    def test_source_selection_and_fixed_separate_key(self):
        with patch.object(parser, "build_table", return_value=table_for()) as build:
            outputs = pipeline.build_output_tables("sok_interop")
        self.assertEqual([name for name, _ in outputs], ["sok_interop"])
        self.assertEqual(outputs[0][1].num_columns, 5)
        self.assertEqual(pipeline.output_s3_key("sok_interop"), "stolen_assets/sok_interop.parquet")
        build.assert_called_once_with()

    def test_s3_read_validates_own_schema_and_closes_body(self):
        body = io.BytesIO(pipeline.parquet_bytes(table_for()))
        client = Mock()
        client.get_object.return_value = {"Body": body}
        table = pipeline.read_s3(client, "test", parser.S3_KEY, output_name="sok_interop")
        self.assertTrue(table.equals(table_for()))
        self.assertTrue(body.closed)

    def test_missing_s3_object_is_distinguished_from_access_denied(self):
        client = Mock()
        client.get_object.side_effect = ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        self.assertIsNone(pipeline.read_s3(client, "test", parser.S3_KEY, output_name="sok_interop"))
        client.get_object.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetObject")
        with self.assertRaises(RuntimeError):
            pipeline.read_s3(client, "test", parser.S3_KEY, output_name="sok_interop")

    def test_cli_dry_run_never_creates_s3_client(self):
        with patch("sys.argv", ["run_and_upload.py", "--source", "sok_interop", "--dry-run"]), \
                patch.object(parser, "build_table", return_value=table_for()), \
                patch.object(pipeline, "create_s3_client") as client:
            pipeline.main()
        client.assert_not_called()

    def test_cli_uses_only_own_object_and_skips_unchanged_upload(self):
        for existing in (None, table_for()):
            with patch("sys.argv", ["run_and_upload.py", "--source", "sok_interop"]), \
                    patch.object(parser, "build_table", return_value=table_for()), \
                    patch.object(pipeline, "create_s3_client", return_value=Mock()), \
                    patch.object(pipeline, "required_setting", return_value="test"), \
                    patch.object(pipeline, "read_s3", return_value=existing) as read, \
                    patch.object(pipeline, "upload", return_value=123) as upload:
                pipeline.main()
            self.assertEqual(read.call_args.args[2], parser.S3_KEY)
            self.assertEqual(upload.call_count, 1 if existing is None else 0)
            if upload.called:
                self.assertEqual(upload.call_args.args[2], parser.S3_KEY)
                self.assertEqual(upload.call_args.args[3].schema, parser.OUTPUT_SCHEMA)

    def test_source_error_prevents_any_s3_access(self):
        with patch("sys.argv", ["run_and_upload.py", "--source", "sok_interop"]), \
                patch.object(parser, "build_table", side_effect=ValueError("malformed table")), \
                patch.object(pipeline, "create_s3_client") as client:
            with self.assertRaises(SystemExit):
                pipeline.main()
        client.assert_not_called()


class DownloadTests(unittest.TestCase):
    def test_downloads_only_three_pinned_files_and_does_not_execute_code(self):
        session = Mock()
        response = Mock()
        response.json.return_value = {"sha": SHA}
        session.get.return_value = response
        with patch.object(parser.requests, "Session") as factory, \
                patch.object(parser, "_download_text", side_effect=lambda session, url, timeout: snapshot()[url.split(SHA + "/")[1]]) as download:
            factory.return_value.__enter__.return_value = session
            commit, files = parser.download_snapshot("main", 10, 0)
        self.assertEqual(commit, SHA)
        self.assertEqual(files, snapshot())
        self.assertEqual(download.call_count, 3)
        self.assertTrue(all(f"/{SHA}/" in call.args[1] for call in download.call_args_list))
        session.get.assert_called_once()

    def test_pinned_sha_needs_no_github_api_lookup(self):
        with patch.object(parser.requests, "Session") as factory, patch.object(parser, "_download_text", return_value="text"):
            parser.download_snapshot(SHA, 10, 0)
        factory.return_value.__enter__.return_value.get.assert_not_called()

    def test_size_limit_and_http_errors_do_not_return_partial_text(self):
        session = Mock()
        response = session.get.return_value.__enter__ = Mock(return_value=Mock())
        session.get.return_value.__exit__ = Mock(return_value=False)
        response.return_value.iter_content.return_value = [b"abcd"]
        with patch.object(parser, "MAX_FILE_BYTES", 3):
            with self.assertRaisesRegex(ValueError, "size limit"):
                parser._download_text(session, "https://example.org", 10)
        response.return_value.raise_for_status.side_effect = requests.HTTPError("500")
        with self.assertRaises(requests.HTTPError):
            parser._download_text(session, "https://example.org", 10)

    def test_invalid_configuration_fails_before_network(self):
        with patch.object(parser.requests, "Session") as factory:
            for args in (("", 10, 0), ("-bad", 10, 0), ("main", 0, 0), ("main", 10, 6)):
                with self.assertRaises(ValueError):
                    parser.download_snapshot(*args)
        factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
