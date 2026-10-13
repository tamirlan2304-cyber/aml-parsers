import io
import logging
import unittest
import zipfile
from datetime import date
from unittest.mock import Mock, patch

import pyarrow as pa
import pyarrow.parquet as pq
from botocore.exceptions import ClientError

import defihacklabs_parser as parser
import run_and_upload as pipeline
from debug_table import render_table


A = "0x123456789012345678901234567890123456789a"
B = "0x234567890123456789012345678901234567890b"
C = "0x345678901234567890123456789012345678901c"
D = "0x456789012345678901234567890123456789012d"
SHA = "a" * 40
PATH = "src/test/2024-01/Example_exp.sol"


def setUpModule():
    logging.disable(logging.CRITICAL)


def tearDownModule():
    logging.disable(logging.NOTSET)


def snapshot(header, *, name="Example - Access control", path=PATH, body="", when="20240115"):
    return {
        "README.md": f"### {when} {name}\n#### Contract\n[PoC]({path})\n",
        path: f'// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "test.sol";\n{header}\ncontract Test {{ {body} }}',
    }


def table_for(header=f"// Attacker: {A}"):
    return parser.parse_snapshot(snapshot(header), SHA)


class EvidenceTests(unittest.TestCase):
    def test_only_explicit_roles_not_code_or_victim(self):
        files = snapshot(
            f"// Attacker: https://etherscan.io/address/{A}\n"
            f"// Attack Contract: {B}\n// Vulnerable Contract: {C}",
            body=f"address attacker = {D}; // Attacker: {D}\nfunction test() public {{ vm.prank({D}); }}",
        )
        table = parser.parse_snapshot(files, SHA)
        parser.validate_table(table)
        rows = table.to_pylist()
        self.assertEqual({(r['address'], r['role']) for r in rows}, {(A, 'attacker'), (B, 'exploit_contract')})
        self.assertEqual({r['network'] for r in rows}, {'Ethereum'})
        self.assertEqual(rows[0]['incident_date'], date(2024, 1, 15))
        self.assertEqual(rows[0]['incident_name'], 'Example')
        self.assertEqual(rows[0]['source_url'], f'{parser.GITHUB_URL}/blob/{SHA}/{PATH}#L4')

    def test_all_six_roles_are_explicit_and_caller_is_not_inferred(self):
        labels = {
            "Original attack transaction sender": "exploit_caller",
            "Attacker": "attacker",
            "Attack Contract": "exploit_contract",
            "Final profit recipient": "profit_receiver",
            "Confirmed stolen funds consolidation address": "consolidation",
            "Confirmed laundering address": "laundering",
        }
        for label, role in labels.items():
            with self.subTest(label=label):
                self.assertEqual(table_for(f"// {label}: {A}")['role'].to_pylist(), [role])
        table = table_for(f"// Attacker EOA: {A}\n// Attack Tx: 0x{'b' * 64}")
        self.assertEqual(table['role'].to_pylist(), ['attacker'])

    def test_multiline_lists_stop_at_victim_unknown_and_blank(self):
        for stop in ('Victim contracts:', 'References:', ''):
            with self.subTest(stop=stop):
                table = table_for(f"// Attack Contracts:\n// - {A}\n// - {B}\n// {stop}\n// - {C}")
                self.assertEqual(set(table['address'].to_pylist()), {A, B})

    def test_narrative_sections_do_not_turn_funders_or_victims_into_attackers(self):
        table = table_for(
            "// Two coordinated attacker EOAs (both funded for gas via Tornado Cash, per Defimon):\n"
            f"// Wallet A (ETH vault): {A}\n// Wallet B (USDC vault): {B}\n"
            "// Attack contracts (deployed earlier, still live at the drain blocks, called with hardcoded data):\n"
            f"// Attack A: {C}\n"
            "// Proceeds consolidation (everything converted to ETH/DAI and sent here):\n"
            f"// {D}\n//\n// Victim contracts:\n// 0x567890123456789012345678901234567890123e"
        )
        self.assertEqual({(r['address'], r['role']) for r in table.to_pylist()}, {
            (A, 'attacker'), (B, 'attacker'), (C, 'exploit_contract'), (D, 'consolidation'),
        })

    def test_prose_does_not_label_every_address(self):
        self.assertEqual(table_for(f"// Attacker: {A} funded by {B}")['address'].to_pylist(), [A])
        self.assertEqual(table_for(f"// Attacker: {A}, {B}")['address'].to_pylist(), [A, B])
        self.assertEqual(table_for(f"// Funds Receiver: {A}").num_rows, 0)
        self.assertEqual(table_for(f"// Tx origin: {A}").num_rows, 0)
        self.assertEqual(table_for(f"// Tornado funding address: {A}").num_rows, 0)

    def test_direct_attacker_with_later_colon_and_inline_plural_list(self):
        self.assertEqual(table_for(f'// Attacker EOA {A} sends a CREATE (to == null):')['address'].to_pylist(), [A])
        table = table_for(f'// Attack Contracts: {A}\n// - {B}\n// Victim: {C}')
        self.assertEqual(set(table['address'].to_pylist()), {A, B})

    def test_hashes_malformed_and_placeholders_rejected(self):
        invalid = [
            '0x' + 'a' * 64, A + '00', '0xd9936EA91a461aA4B727a7e0x' + A[2:],
            '0x' + '0' * 40, '0x' + '0' * 36 + 'dead', '0x' + '1' * 40,
            '0x7109709ecfa91a80626ff3989d68f67f5b1dd12d', '0xcafebabe',
            f'https://etherscan.io/tx/{A}', f'https://etherscan.io/token/{A}',
        ]
        for value in invalid:
            with self.subTest(value=value):
                self.assertEqual(table_for(f'// Attacker: {value}').num_rows, 0)

    def test_conflicting_roles_and_token_code_casts_are_excluded(self):
        for label in ('Victim', 'Vulnerable Contract', 'Token', 'Liquidity pool', 'Bridge', 'Router', 'CEX', 'Foundry test address'):
            with self.subTest(label=label):
                self.assertEqual(table_for(f'// Attacker: {A}\n// {label}: {A}').num_rows, 0)
        files = snapshot(f'// Attack Contract: {A}\n// Attacker: {B}', body=f'IERC20 token = IERC20({A}); address router = {B};')
        self.assertEqual(parser.parse_snapshot(files, SHA).num_rows, 0)

    def test_uncertainty_and_test_addresses_do_not_pass(self):
        for label in ('Possible attacker', 'Attacker (suspected)', 'Attacker?', 'Attacker (test address)', 'Mock attacker'):
            with self.subTest(label=label):
                self.assertEqual(table_for(f'// {label}: {A}').num_rows, 0)
        self.assertEqual(table_for(f'// Attacker: {A} (unconfirmed)').num_rows, 0)
        files = snapshot(f'// Attacker: {A}', name='Example - pre-production deployment')
        self.assertEqual(parser.parse_snapshot(files, SHA).num_rows, 0)

    def test_block_comments_and_import_strings(self):
        source = f'pragma solidity ^0.8.0;\nimport "// Attacker: {D}";\n/*\n * Attacker: {A}\n * Attack Contract: {B}\n */\ncontract Test {{}}\n// Attacker: {C}\n'
        candidates, _ = parser.extract_evidence(source)
        self.assertEqual({e.address for e in candidates}, {A, B})
        self.assertEqual({e.line for e in candidates}, {4, 5})

    def test_metadata_after_interface_is_found_but_interface_comments_are_not(self):
        source = f'interface IToken {{\n// Attacker: {C}\nfunction transfer() external;\n}}\n// Attacker: {A}\n// Attack Contract: {B}\ncontract Exploit {{\n// Attacker: {D}\n}}'
        candidates, _ = parser.extract_evidence(source)
        self.assertEqual({e.address for e in candidates}, {A, B})
        self.assertEqual({e.line for e in candidates}, {5, 6})

    def test_whitehat_reproduction_does_not_label_rescue_contract_as_malicious(self):
        table = table_for(f'// Attacker: {A} (whitehat)\n// Attack Contract: {B}')
        self.assertEqual(table.num_rows, 0)
        table = table_for(f'// @KeyInfo: whitehat educational reproduction\n// Attack Contract: {B}')
        self.assertEqual(table.num_rows, 0)

    def test_token_holder_is_not_the_token(self):
        files = snapshot(f'// Attack Contract: {A}', body=f'address holderOfToken = {A};')
        self.assertEqual(parser.parse_snapshot(files, SHA).num_rows, 1)

    def test_excluded_role_in_another_poc_for_same_incident_wins(self):
        files = snapshot(f'// Attacker: {A}')
        other = 'src/test/2024-01/Example_second.sol'
        files['README.md'] += f'[PoC2]({other})'
        files[other] = f'// Vulnerable Contract: {A}\ncontract Exploit {{}}'
        self.assertEqual(parser.parse_snapshot(files, SHA).num_rows, 0)

    def test_dates_only_from_index_and_conflicts_are_skipped(self):
        files = snapshot(f'// Attacker: {A}')
        files['src/test/2024-01/Unindexed.sol'] = f'// Attacker: {B}'
        files['src/Poc-template.sol'] = f'// Attacker: {C}'
        self.assertEqual(parser.parse_snapshot(files, SHA)['address'].to_pylist(), [A])
        files['past/2024/README.md'] = f'### 20240116 Different\n[PoC](../../{PATH})'
        with self.assertRaisesRegex(RuntimeError, 'No dated'):
            parser.incident_index(files)

    def test_past_readme_relative_paths_and_multiple_roles(self):
        files = snapshot(f'// Attacker: {A}\n// Attack Contract: {A}')
        files['past/2024/README.md'] = files.pop('README.md').replace(f'({PATH})', f'(../../{PATH})')
        table = parser.parse_snapshot(files, SHA)
        self.assertEqual(table.num_rows, 2)
        parser.validate_table(table)

    def test_same_address_in_different_incidents_is_retained(self):
        files = snapshot(f'// Attacker: {A}')
        other = 'src/test/2024-02/Other_exp.sol'
        files['README.md'] += f'\n### 20240215 Other - Rounding\n[PoC]({other})'
        files[other] = f'// Attacker: {A}\ncontract Exploit {{}}'
        self.assertEqual(parser.parse_snapshot(files, SHA).num_rows, 2)


class ArchiveAndPipelineTests(unittest.TestCase):
    def test_archive_is_read_without_extracting_extra_files(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for path, data in snapshot(f'// Attacker: {A}').items():
                archive.writestr('root/' + path, data)
            archive.writestr('root/../../unsafe.py', 'ignored')
            archive.writestr('root/lib/token.sol', 'ignored')
        files = parser.files_from_archive(output.getvalue(), github_prefix=True)
        self.assertEqual(set(files), {'README.md', PATH})

    def test_sha_change_updates_provenance_not_duplicate_identity(self):
        existing = table_for()
        current = parser.parse_snapshot(snapshot(f'// Attacker: {A}\n// Attack Contract: {B}'), 'b' * 40)
        merged, added, updated = parser.merge_with_existing(existing, current)
        self.assertEqual((merged.num_rows, added, updated), (2, 1, 1))
        self.assertEqual(parser.merge_with_existing(merged, current)[1:], (0, 0))
        self.assertEqual(parser.merge_with_existing(None, current)[1:], (2, 0))

    def test_memory_parquet_has_exact_six_columns_and_date_type(self):
        table = table_for()
        restored = pq.read_table(pa.BufferReader(pipeline.parquet_bytes(table)))
        self.assertEqual(restored.schema, parser.OUTPUT_SCHEMA)
        self.assertEqual(restored.column_names, ['address', 'network', 'incident_name', 'role', 'incident_date', 'source_url'])
        self.assertEqual(render_table(table, 1).count(A), 1)
        self.assertIn('source_url', render_table(table, 1))
        self.assertIn('incident_date', render_table(table.slice(0, 0), 10))

    def test_validation_rejects_wrong_schema_and_duplicates(self):
        table = table_for()
        with self.assertRaises(ValueError):
            parser.validate_table(table.drop(['role']))
        with self.assertRaises(ValueError):
            parser.validate_table(pa.concat_tables([table, table]))
        with self.assertRaises(ValueError):
            parser.validate_table(table.slice(0, 0))

    def test_outputs_never_mix_schemas(self):
        old = pa.Table.from_pylist([{'wallet_address': A, 'network': 'Ethereum', 'listed_date': date(2024, 1, 15)}], schema=pipeline.OUTPUT_SCHEMA)
        new = table_for()
        telegram = pa.Table.from_pylist([{**old.to_pylist()[0], 'message_url': 'https://t.me/investigations/1'}], schema=pipeline.telegram_investigations_parser.OUTPUT_SCHEMA)
        slowmist = pa.Table.from_pylist([{**old.to_pylist()[0], 'hacked_target': 'warp.green'}], schema=pipeline.slowmist_hacked_parser.OUTPUT_SCHEMA)
        sok = pipeline.sok_interop_parser.rows_to_table([{
            'address': A, 'network': 'Ethereum', 'hacked_bridge': 'Example',
            'incident_date': date(2024, 1, 15),
            'link': f'{pipeline.sok_interop_parser.GITHUB_URL}/blob/{SHA}/{pipeline.sok_interop_parser.ADDRESS_FILE}#L3',
        }])
        solidityscan = pipeline.solidityscan_hack_parser.rows_to_table([{
            'address': A, 'network': 'Ethereum',
            'incident_date': date(2024, 1, 15), 'incident_name': 'Example',
        }])
        with patch.object(pipeline, '_build_legacy_inputs', return_value=[('telegram_investigations', telegram), ('slowmist_hacked', slowmist)]) as legacy, \
                patch.object(pipeline, 'build_current_table', side_effect=lambda source: {
                    'defihacklabs': new,
                    'sok_interop': sok,
                    'solidityscan_hack_analysis': solidityscan,
                }[source]) as build:
            outputs = pipeline.build_output_tables('all')
            self.assertEqual([name for name, _ in outputs], [
                'stolen_assets', 'telegram_investigations', 'slowmist_hacked',
                'defihacklabs', 'sok_interop', 'solidityscan_hack_analysis',
            ])
            self.assertEqual([t.num_columns for _, t in outputs], [3, 4, 4, 6, 5, 4])
            self.assertEqual([call.args[0] for call in build.call_args_list], [
                'defihacklabs', 'sok_interop', 'solidityscan_hack_analysis',
            ])
            legacy.assert_called_once_with('all')
        with patch.object(pipeline.defihacklabs_parser, 'build_table', return_value=new):
            outputs = pipeline.build_output_tables('defihacklabs')
            self.assertEqual(len(outputs), 1)
        self.assertEqual(pipeline.output_s3_key('defihacklabs'), 'stolen_assets/defihacklabs.parquet')
        self.assertEqual(pipeline.output_s3_key('stolen_assets'), 'stolen_assets/stolen_assets.parquet')

    def test_read_s3_new_object_missing_and_access_denied(self):
        client = Mock()
        table = table_for()
        client.get_object.return_value = {'Body': io.BytesIO(pipeline.parquet_bytes(table))}
        restored = pipeline.read_s3(client, 'test', parser.S3_KEY, output_name='defihacklabs')
        self.assertEqual(restored.schema, parser.OUTPUT_SCHEMA)
        client.get_object.side_effect = ClientError({'Error': {'Code': 'NoSuchKey'}}, 'GetObject')
        self.assertIsNone(pipeline.read_s3(client, 'test', parser.S3_KEY, output_name='defihacklabs'))
        client.get_object.side_effect = ClientError({'Error': {'Code': 'AccessDenied'}}, 'GetObject')
        with self.assertRaises(RuntimeError):
            pipeline.read_s3(client, 'test', parser.S3_KEY, output_name='defihacklabs')

    def test_cli_dry_run_does_not_create_s3_client(self):
        with patch('sys.argv', ['run_and_upload.py', '--source', 'defihacklabs', '--dry-run']), \
                patch.object(pipeline, 'build_output_tables', return_value=[('defihacklabs', table_for())]), \
                patch.object(pipeline, 'create_s3_client') as client:
            pipeline.main()
            client.assert_not_called()

    def test_cli_uploads_only_defihacklabs_without_writing_local_parquet(self):
        current = table_for()
        client = Mock()
        client.get_object.side_effect = ClientError({'Error': {'Code': 'NoSuchKey'}}, 'GetObject')
        client.head_object.return_value = {'ContentLength': len(pipeline.parquet_bytes(current))}
        with patch('sys.argv', ['run_and_upload.py', '--source', 'defihacklabs']), \
                patch.object(pipeline, 'build_output_tables', return_value=[('defihacklabs', current)]), \
                patch.object(pipeline, 'create_s3_client', return_value=client), \
                patch.object(pipeline, 'required_setting', return_value='test-bucket'):
            pipeline.main()
        self.assertEqual(client.put_object.call_count, 1)
        self.assertEqual(client.put_object.call_args.kwargs['Key'], parser.S3_KEY)
        self.assertIsInstance(client.put_object.call_args.kwargs['Body'], bytes)

    def test_cli_does_not_reupload_unchanged_s3_object(self):
        current = table_for()
        client = Mock()
        client.get_object.return_value = {'Body': io.BytesIO(pipeline.parquet_bytes(current))}
        with patch('sys.argv', ['run_and_upload.py', '--source', 'defihacklabs']), \
                patch.object(pipeline, 'build_output_tables', return_value=[('defihacklabs', current)]), \
                patch.object(pipeline, 'create_s3_client', return_value=client), \
                patch.object(pipeline, 'required_setting', return_value='test-bucket'):
            pipeline.main()
        client.put_object.assert_not_called()

    def test_cli_all_routes_each_schema_to_its_own_object(self):
        old = pa.Table.from_pylist([{'wallet_address': A, 'network': 'Ethereum', 'listed_date': date(2024, 1, 15)}], schema=pipeline.OUTPUT_SCHEMA)
        new = table_for()
        client = Mock()
        client.get_object.side_effect = ClientError({'Error': {'Code': 'NoSuchKey'}}, 'GetObject')
        with patch('sys.argv', ['run_and_upload.py']), \
                patch.object(pipeline, 'build_output_tables', return_value=[('stolen_assets', old), ('defihacklabs', new)]), \
                patch.object(pipeline, 'create_s3_client', return_value=client), \
                patch.object(pipeline, 'required_setting', return_value='test-bucket'), \
                patch.object(pipeline, 'upload', return_value=123) as upload:
            pipeline.main()
        self.assertEqual([c.args[2] for c in upload.call_args_list], [pipeline.PRODUCTION_S3_KEY, parser.S3_KEY])
        self.assertEqual([c.args[3].num_columns for c in upload.call_args_list], [3, 6])


if __name__ == '__main__':
    unittest.main()
