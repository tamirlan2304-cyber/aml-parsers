from __future__ import annotations

import argparse
import logging

import pyarrow as pa

from run_and_upload import build_source_tables


def render_table(table: pa.Table, limit: int | None) -> str:
    rows = table.to_pylist() if limit is None else table.slice(0, limit).to_pylist()
    if not rows:
        return "(no rows)"
    headers = table.column_names
    text_rows = []
    for row in rows:
        text_rows.append(
            {
                header: (
                    ""
                    if row[header] is None
                    else row[header].isoformat()
                    if hasattr(row[header], "isoformat")
                    else str(row[header])
                )
                for header in headers
            }
        )
    widths = {
        header: max(len(header), *(len(row[header]) for row in text_rows))
        for header in headers
    }
    separator = "+-" + "-+-".join("-" * widths[h] for h in headers) + "-+"
    lines = [
        separator,
        "| " + " | ".join(h.ljust(widths[h]) for h in headers) + " |",
        separator,
    ]
    lines.extend(
        "| " + " | ".join(row[h].ljust(widths[h]) for h in headers) + " |"
        for row in text_rows
    )
    lines.append(separator)
    return "\n".join(lines)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    parser = argparse.ArgumentParser(description="Print source tables without S3")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--all", action="store_true")
    parser.add_argument(
        "--source",
        choices=("all", "scamsniffer", "chainabuse"),
        default="all",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        help="Limit Chainabuse API pages (50 reports each) for debugging",
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Allow deliberately partial Chainabuse output for debugging",
    )
    arguments = parser.parse_args()
    if arguments.limit <= 0:
        parser.error("--limit must be greater than zero")
    try:
        for spec, table in build_source_tables(
            arguments.source,
            chainabuse_max_pages=arguments.max_pages,
            chainabuse_allow_partial=arguments.allow_partial,
        ):
            print(f"\n=== {spec.name} -> {spec.key} ===")
            print(render_table(table, None if arguments.all else arguments.limit))
            label = "Total unique addresses"
            print(f"{label}: {table.num_rows}")
            print("Schema:")
            print(table.schema)
    except KeyboardInterrupt:
        logging.warning(
            "Parsing paused safely. Run the same command later to resume from the latest checkpoint."
        )
        raise SystemExit(130)
    except (OSError, RuntimeError, ValueError, pa.ArrowException):
        logging.exception("Debug parsing failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
