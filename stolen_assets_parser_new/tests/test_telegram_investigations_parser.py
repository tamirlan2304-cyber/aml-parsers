import unittest
from datetime import datetime, timezone

from telegram_investigations_parser import (
    TelegramMessage,
    build_table_from_messages,
    extract_addresses,
    parse_telegram_page,
    validated_network_codes,
)


EVM_ADDRESS = "0xff575a22975cc413771825eb84c163189a4d5d22"
EVM_TRANSACTION_HASH = (
    "0xd0eafd5c03b24c2f54c579745cacbffe4c6df2d19973e55d52a5f40aa1d089e0"
)
TRON_ADDRESS = "TA6YHqB2xh5HhfmC7WoLQaWmqq7Vv4zCoQ"
BITCOIN_ADDRESS = "bc1q5wnpn4k99wc587maaaa6eqnx27g4r6mduxg2s5"
SOLANA_ADDRESS = "HwtbQBNnLERakdUDuCCLWmUs2oETLFQZeHUWeQdPads"


class TelegramHTMLTests(unittest.TestCase):
    def test_extracts_message_text_links_and_utc_datetime(self) -> None:
        html = f"""
        <div class="tgme_widget_message" data-post="investigations/10">
          <div class="tgme_widget_message_text js-message_text">
            Theft address<br><code>{EVM_ADDRESS}</code>
          </div>
          <a href="https://etherscan.io/address/{EVM_ADDRESS}">Explorer</a>
          <a class="tgme_widget_message_date">
            <time datetime="2026-08-20T23:30:00+00:00"></time>
          </a>
        </div>
        """

        messages = parse_telegram_page(html, "investigations")

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].message_id, 10)
        self.assertIn(EVM_ADDRESS, messages[0].text)
        self.assertEqual(
            messages[0].posted_at,
            datetime(2026, 8, 20, 23, 30, tzinfo=timezone.utc),
        )
        self.assertEqual(len(messages[0].links), 1)

    def test_expands_grouped_media_message_ids(self) -> None:
        html = f"""
        <div class="tgme_widget_message" data-post="investigations/10">
          <div class="tgme_widget_message_text">Address {EVM_ADDRESS}</div>
          <a href="https://t.me/investigations/10?single">First image</a>
          <a href="https://t.me/investigations/11?single">Second image</a>
          <time datetime="2026-08-20T23:30:00+00:00"></time>
        </div>
        """

        messages = parse_telegram_page(html, "investigations")

        self.assertEqual([message.message_id for message in messages], [10, 11])
        self.assertEqual(messages[0].text, messages[1].text)


class AddressExtractionTests(unittest.TestCase):
    def message(self, text: str, day: int = 20) -> TelegramMessage:
        return TelegramMessage(
            message_id=day,
            posted_at=datetime(2026, 8, day, tzinfo=timezone.utc),
            text=text,
            links=(),
        )

    def test_validates_supported_addresses(self) -> None:
        self.assertEqual(validated_network_codes(EVM_ADDRESS), {"ETH"})
        self.assertEqual(validated_network_codes(TRON_ADDRESS), {"TRX"})
        self.assertEqual(validated_network_codes(BITCOIN_ADDRESS), {"BTC"})
        self.assertEqual(validated_network_codes(SOLANA_ADDRESS), {"SOL"})

    def test_rejects_evm_transaction_hash(self) -> None:
        message = self.message(
            f"Ethereum address {EVM_ADDRESS}; transaction {EVM_TRANSACTION_HASH}"
        )

        addresses = extract_addresses(message)

        self.assertEqual(addresses, [(EVM_ADDRESS, "Ethereum")])

    def test_deduplicates_and_keeps_earliest_message_date(self) -> None:
        later = self.message(f"Ethereum address {EVM_ADDRESS}", day=20)
        earlier = self.message(f"Same EVM address {EVM_ADDRESS.upper()}", day=10)

        table = build_table_from_messages([later, earlier])

        self.assertEqual(table.num_rows, 1)
        row = table.to_pylist()[0]
        self.assertEqual(row["wallet_address"], EVM_ADDRESS)
        self.assertEqual(row["network"], "Ethereum")
        self.assertEqual(row["listed_date"].isoformat(), "2026-08-10")


if __name__ == "__main__":
    unittest.main()
