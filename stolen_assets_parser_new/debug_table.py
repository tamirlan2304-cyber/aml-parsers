from __future__ import annotations

import argparse
import logging
from collections import Counter

import pyarrow as pa
import requests

from run_and_upload import SOURCE_NAMES, build_output_tables


def render_table(table: pa.Table, limit: int | None) -> str:
    rows = table.to_pylist() if limit is None else table.slice(0, limit).to_pylist()
    headers = table.column_names
    string_rows = [
        {header: "" if row[header] is None else str(row[header]) for header in headers}
        for row in rows
    ]
    widths = {
        header: max([len(header), *(len(row[header]) for row in string_rows)])
        for header in headers
    }
    separator = "+-" + "-+-".join("-" * widths[header] for header in headers) + "-+"
    header_line = "| " + " | ".join(
        header.ljust(widths[header]) for header in headers
    ) + " |"
    body_lines = [
        "| " + " | ".join(row[header].ljust(widths[header]) for header in headers) + " |"
        for row in string_rows
    ]
    return "\n".join([separator, header_line, separator, *body_lines, separator])


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    argument_parser = argparse.ArgumentParser(
        description="Print the current stolen-assets parsing result without S3 or local files"
    )
    argument_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Rows to print; use --all for the complete table",
    )
    argument_parser.add_argument(
        "--all",
        action="store_true",
        help="Print every parsed address",
    )
    argument_parser.add_argument(
        "--source",
        choices=("all", *SOURCE_NAMES),
        default="all",
        help="Source to display",
    )
    arguments = argument_parser.parse_args()
    if arguments.limit <= 0:
        argument_parser.error("--limit must be greater than zero")

    try:
        for output_name, table in build_output_tables(arguments.source):
            print(f"\nOutput: {output_name}")
            print(render_table(table, None if arguments.all else arguments.limit))
            address_column = "address" if "address" in table.column_names else "wallet_address"
            unique_addresses = len(set(table[address_column].to_pylist()))
            print(f"\nTotal rows: {table.num_rows}; unique addresses: {unique_addresses}")
            for column in ("network", "role"):
                if column not in table.column_names:
                    continue
                counts = Counter(str(value) for value in table[column].to_pylist())
                print(f"{column} (rows):")
                for value, count in sorted(counts.items()):
                    print(f"  {value}: {count}")
            if not arguments.all and table.num_rows > arguments.limit:
                print(
                    f"Displayed {arguments.limit} of {table.num_rows} rows; "
                    "run with --all to print everything."
                )
    except (
        OSError,
        RuntimeError,
        ValueError,
        requests.RequestException,
        pa.ArrowException,
    ):
        logging.exception("Debug parsing failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
