import io
import logging
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pyarrow as pa
import pyarrow.parquet as pq

import telegram_investigations_parser as parser
import run_and_upload as pipeline
from debug_table import render_table


A = "0xff575a22975cc413771825eb84c163189a4d5d22"
B = "0xc82f007bb4096a47d14ed0d46ee8143d37539d04"
C = "0x3297a41f528345c3b97af8c6ffe1401cc07b2527"
TRON = "TA6YHqB2xh5HhfmC7WoLQaWmqq7Vv4zCoQ"
SOLANA = "HwtbQBNnLERakdUDuCCLWmUs2oETLFQZeHUWeQdPads"
BTC = "bc1q5wnpn4k99wc587maaaa6eqnx27g4r6mduxg2s5"


def message(text, message_id=10, day=20, **kwargs):
    return parser.TelegramMessage(message_id, datetime(2026, 8, day, tzinfo=timezone.utc), text, kwargs.pop('links', ()), **kwargs)


def addresses(text):
    return {a for a, _ in parser.extract_addresses(message(text))}


def html_message(body, *, channel='investigations', post_id=10, extra=''):
    return f'<div data-post="{channel}/{post_id}"><div class="tgme_widget_message_text">{body}</div>{extra}<time datetime="2026-08-20T10:00:00Z"></time></div>'


class ContextTests(unittest.TestCase):
    def test_victim_before_and_after_address(self):
        for text in (f'Victim: {A}', f'victim {A}', f'{A} victim', f'{A} (victim)', f'{A} - victim', f'{A} is the victim', f'Жертва: {A}', f'{A} — пострадавший'):
            with self.subTest(text=text):
                self.assertEqual(addresses(text), set())

    def test_postfix_on_next_line_without_stealing_next_address_heading(self):
        self.assertEqual(addresses(f'{A}\nvictim'), set())
        self.assertEqual(addresses(f'{A}\n(victim)\nTheft address {B}'), {B})
        self.assertEqual(addresses(f'{A}\nVictim\n{B}'), {A})

    def test_generic_service_deposit_endpoints_are_excluded(self):
        self.assertEqual(addresses(f'Theft address {A}\nUnknownService deposit addresses\n{B}\n{C}'), {A})

    def test_every_requested_exclusion_type(self):
        for label in ('Victim', 'Protocol wallet', 'Liquidity pool', 'Token contract', 'Bridge address', 'CEX deposit address', 'Router', 'Foundry contract', 'Test address', 'Mock wallet', 'KuCoin deposit address', 'Binance wallet', 'EVM hot wallets', 'Пул ликвидности', 'Тестовый адрес', 'vm.prank'):
            with self.subTest(label=label):
                self.assertEqual(addresses(f'{label}: {A}'), set())

    def test_same_message_victim_and_attacker_do_not_contaminate_each_other(self):
        for text in (f'Victim: {A}\nTheft address: {B}', f'Victim: {A}; attacker: {B}', f'{A} (victim); {B} (attacker)', f'{A} - victim, {B} - attacker', f'Victim {A} Attacker {B}', f'Attacker {B} Victim {A}'):
            with self.subTest(text=text):
                self.assertEqual(addresses(text), {B})

    def test_sections_apply_to_entire_lists_and_stop_at_next_label(self):
        text = f'Victim addresses\n{A}\n\n{B}\nTheft addresses\n{C}\nKuCoin deposit addresses\n{TRON}'
        self.assertEqual(addresses(text), {C})

    def test_unknown_new_section_does_not_inherit_previous_label(self):
        text = f'Victim\n{A}\nAnother investigation without an attribution label\n{B}'
        self.assertEqual(addresses(text), {B})

    def test_victim_or_exchange_in_narrative_does_not_remove_theft_address(self):
        text = f'The victim lost funds which were later transferred to Binance.\n\nTheft address\n{A}'
        self.assertEqual(addresses(text), {A})
        self.assertEqual(addresses(f'Theft address {A} routed funds via Binance'), {A})

    def test_suffix_victim_does_not_leak_to_next_address(self):
        self.assertEqual(addresses(f'{A} (victim), {B}'), {B})

    def test_suffix_exclusion_wins_over_positive_prefix(self):
        self.assertEqual(addresses(f'Attacker address {A} (CEX deposit)'), set())

    def test_case_punctuation_and_zero_width_characters(self):
        self.assertEqual(addresses(f'VICTIM:{A.upper()}'), set())
        self.assertEqual(addresses(f'Victim {A[:20]}\u200b{A[20:]}'), set())
        self.assertEqual(addresses(f'Theft address {A[:20]}\u200b{A[20:]}'), {A})

    def test_all_evm_networks_remain_ethereum(self):
        for name in ('Base', 'BSC', 'Polygon', 'Arbitrum'):
            self.assertEqual(parser.extract_addresses(message(f'{name} theft address {A}')), [(A, 'Ethereum')])

    def test_non_evm_victims_are_filtered_after_validation(self):
        for address in (TRON, SOLANA, BTC):
            with self.subTest(address=address):
                self.assertEqual(addresses(f'Victim\n{address}\nTheft address\n{A}'), {A})

    def test_known_constants_and_zero_addresses_without_labels(self):
        for value in ('0x' + '0' * 40, '0x' + '0' * 36 + 'dead', '0x' + '1' * 40, '0x7109709ecfa91a80626ff3989d68f67f5b1dd12d', '0xdac17f958d2ee523a2206206994597c13d831ec7', '11111111111111111111111111111111'):
            with self.subTest(value=value):
                self.assertEqual(addresses(f'Theft address {value}'), set())

    def test_hash_and_malformed_address_are_not_address_fragments(self):
        for value in ('0x' + 'a' * 64, A + '00', 'abcd0x' + A[2:]):
            with self.subTest(value=value):
                self.assertEqual(addresses(f'Theft address {value}'), set())

    def test_unlabelled_repeat_cannot_resurrect_victim(self):
        result = addresses(f'Victim {A}\nTheft address {B}\nSee https://etherscan.io/address/{A}')
        self.assertEqual(result, {B})

    def test_exclusion_in_other_message_wins(self):
        table = parser.build_table_from_messages([message(f'Address {A}', 1, 10), message(f'Victim {A}\nTheft address {B}', 2, 20)])
        self.assertEqual(table['wallet_address'].to_pylist(), [B])


class HTMLAndProvenanceTests(unittest.TestCase):
    def test_html_keeps_newlines_and_hidden_link_role(self):
        html = html_message(f'Victim<br><a href="https://etherscan.io/address/{A}">0xff…d22</a><br><br>Theft addresses<br><code>{B}</code><br>{C}')
        msg = parser.parse_telegram_page(html, 'investigations')[0]
        self.assertIn('\n', msg.text)
        self.assertEqual({a for a, _ in parser.extract_addresses(msg)}, {B, C})
        self.assertEqual(msg.message_url, 'https://t.me/investigations/10')

    def test_link_label_after_address_is_used(self):
        html = html_message(f'<a href="https://etherscan.io/address/{A}">Address</a> (victim)<br>Theft address {B}')
        msg = parser.parse_telegram_page(html, 'investigations')[0]
        self.assertEqual({a for a, _ in parser.extract_addresses(msg)}, {B})

    def test_unrelated_navigation_links_do_not_add_addresses(self):
        html = html_message(f'Theft address {B}', extra=f'<a href="https://etherscan.io/address/{A}">Unrelated footer</a>')
        msg = parser.parse_telegram_page(html, 'investigations')[0]
        self.assertEqual({a for a, _ in parser.extract_addresses(msg)}, {B})

    def test_token_pool_and_transaction_links_are_not_wallet_evidence(self):
        for url in (f'https://etherscan.io/token/{A}', f'https://solscan.io/token/{SOLANA}', f'https://dexscreener.com/search?q={A}', f'https://etherscan.io/tx/{A}'):
            with self.subTest(url=url):
                html = html_message(f'<a href="{url}">Info</a><br>Theft address {B}')
                msg = parser.parse_telegram_page(html, 'investigations')[0]
                self.assertEqual({a for a, _ in parser.extract_addresses(msg)}, {B})

    def test_tronscan_address_transactions_page_is_allowed(self):
        html = html_message(f'Theft address <a href="https://tronscan.org/address/{TRON}/transactions">Tron account</a>')
        msg = parser.parse_telegram_page(html, 'investigations')[0]
        self.assertEqual(parser.extract_addresses(msg), [(TRON, 'TRON')])

    def test_grant_and_technical_transaction_query_are_not_address_evidence(self):
        for url in (f'https://explorer.gitcoin.co/#/round/10/{A}/42', f'https://basescan.org/txsInternal?a={A}'):
            self.assertEqual(addresses(url), set())
            self.assertEqual(addresses(f'Theft address {A}\n{url}'), {A})

    def test_wallet_tokens_tab_is_not_a_token_contract(self):
        self.assertEqual(addresses(f'Theft address https://etherscan.io/address/{A}/tokens'), {A})

    def test_album_links_point_to_caption_not_arbitrary_sibling(self):
        html = html_message(f'Theft address {A}', channel='some_channel', extra='<a href="https://t.me/some_channel/11?single">Image</a>')
        messages = parser.parse_telegram_page(html, 'some_channel')
        self.assertEqual([m.message_id for m in messages], [10, 11])
        self.assertEqual({m.message_url for m in messages}, {'https://t.me/some_channel/10'})
        self.assertEqual(parser.build_table_from_messages(messages)['message_url'].to_pylist(), ['https://t.me/some_channel/10'])

    def test_earliest_date_and_link_are_updated_together(self):
        later = message(f'Theft address {A}', 20, 20)
        earlier = message(f'Theft address {A.upper()}', 10, 10)
        for messages in ([later, earlier], [earlier, later]):
            row = parser.build_table_from_messages(messages).to_pylist()[0]
            self.assertEqual(row['listed_date'].isoformat(), '2026-08-10')
            self.assertEqual(row['message_url'], 'https://t.me/investigations/10')

    def test_schema_and_parquet_round_trip(self):
        table = parser.build_table_from_messages([message(f'Theft address {A}')])
        restored = pq.read_table(pa.BufferReader(pipeline.parquet_bytes(table)))
        self.assertEqual(restored.column_names, ['wallet_address', 'network', 'listed_date', 'message_url'])
        self.assertEqual(restored.schema, parser.OUTPUT_SCHEMA)
        self.assertIn('https://t.me/investigations/10', render_table(table, 20))


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.current = parser.build_table_from_messages([message(f'Theft address {B}')])

    def test_snapshot_update_removes_old_excluded_values(self):
        old = parser.build_table_from_messages([message(f'Addresses {A}\n{B}', 9)])
        merged, added, changes = parser.merge_with_existing(old, self.current)
        self.assertEqual(merged['wallet_address'].to_pylist(), [B])
        self.assertEqual(added, 0)
        self.assertGreater(changes, 0)
        self.assertEqual(parser.merge_with_existing(merged, self.current)[1:], (0, 0))

    def test_s3_read_uses_telegram_schema_and_closes_body(self):
        client = Mock()
        body = io.BytesIO(pipeline.parquet_bytes(self.current))
        client.get_object.return_value = {'Body': body}
        table = pipeline.read_s3(client, 'test', parser.S3_KEY, output_name='telegram_investigations')
        self.assertEqual(table.schema, parser.OUTPUT_SCHEMA)
        self.assertTrue(body.closed)

    def test_old_mixed_schema_is_not_silently_migrated_to_telegram(self):
        client = Mock()
        old = self.current.select(parser.LEGACY_SCHEMA.names).cast(parser.LEGACY_SCHEMA)
        client.get_object.return_value = {'Body': io.BytesIO(pipeline.parquet_bytes(old))}
        with self.assertRaises((ValueError, pa.ArrowException)):
            pipeline.read_s3(client, 'test', parser.S3_KEY, output_name='telegram_investigations')

    def test_source_selection_keeps_four_columns_and_separate_key(self):
        with patch.object(pipeline, '_build_legacy_inputs', return_value=[('telegram_investigations', self.current)]):
            outputs = pipeline.build_output_tables('telegram_investigations')
        self.assertEqual([n for n, _ in outputs], ['telegram_investigations'])
        self.assertEqual(outputs[0][1].num_columns, 4)
        self.assertEqual(pipeline.output_s3_key('telegram_investigations'), parser.S3_KEY)

    def test_production_telegram_does_not_touch_legacy_object(self):
        with patch('sys.argv', ['run_and_upload.py', '--source', 'telegram_investigations']), \
                patch.object(pipeline, 'build_output_tables', return_value=[('telegram_investigations', self.current)]), \
                patch.object(pipeline, 'create_s3_client', return_value=Mock()), \
                patch.object(pipeline, 'required_setting', return_value='test-bucket'), \
                patch.object(pipeline, 'read_s3', return_value=None) as read, \
                patch.object(pipeline, 'upload', return_value=123) as upload:
            pipeline.main()
        self.assertEqual(read.call_args.args[2], parser.S3_KEY)
        self.assertEqual(upload.call_args.args[2], parser.S3_KEY)

    def test_all_downloads_telegram_once_and_preserves_provenance(self):
        telegram_builder = Mock(return_value=self.current)
        slowmist = pa.Table.from_pylist(
            [{**row, 'hacked_target': 'warp.green'} for row in self.current.to_pylist()],
            schema=pipeline.slowmist_hacked_parser.OUTPUT_SCHEMA,
        )
        slowmist_builder = Mock(return_value=slowmist)
        with patch.object(pipeline, 'SOURCE_BUILDERS', (('telegram_investigations', telegram_builder), ('slowmist_hacked', slowmist_builder))), \
                patch.object(pipeline, 'build_current_table', return_value=pa.table({'placeholder': [1]})):
            outputs = pipeline.build_output_tables('all')
        telegram_builder.assert_called_once_with()
        slowmist_builder.assert_called_once_with()
        self.assertEqual(outputs[0][1].column_names, parser.LEGACY_SCHEMA.names)
        self.assertEqual(outputs[1][1].column_names, parser.OUTPUT_SCHEMA.names)
        self.assertTrue(outputs[2][1].equals(slowmist))

    def test_error_page_cannot_be_mistaken_for_completed_history(self):
        with patch.object(parser, '_get_page', return_value='<html>temporarily unavailable</html>'):
            with self.assertRaisesRegex(RuntimeError, 'channel-history'):
                parser.fetch_all_messages(Mock())

    def test_partial_history_followed_by_error_is_not_returned(self):
        good = '<section class="tgme_channel_history">' + html_message(f'Theft address {B}') + '</section>'
        with patch.object(parser, '_get_page', side_effect=[good, '<html>please sign in</html>']), \
                patch.object(parser.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'channel-history'):
                parser.fetch_all_messages(Mock())


if __name__ == '__main__':
    logging.disable(logging.CRITICAL)
    unittest.main()
