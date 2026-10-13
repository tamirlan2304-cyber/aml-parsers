from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from run_and_upload import build_source_tables, validate_table


PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = PROJECT_DIR / "local_parquet"
LOGGER = logging.getLogger("phishing_local_parquet")


def save_table(table: pa.Table, output_path: Path) -> int:
    """Atomically replace a local Parquet file with the current source table."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.tmp")
    try:
        pq.write_table(table, temporary_path, compression="zstd")
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return output_path.stat().st_size


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    parser = argparse.ArgumentParser(
        description="Parse phishing sources and save separate local Parquet files"
    )
    parser.add_argument(
        "--source",
        choices=("all", "scamsniffer", "chainabuse"),
        default="all",
        help="Source to save; all creates one Parquet file per source",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        help="Limit Chainabuse API pages (50 reports each) for debugging",
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Allow a partial Chainabuse file for debugging only",
    )
    arguments = parser.parse_args()
    if arguments.max_pages is not None and arguments.max_pages <= 0:
        parser.error("--max-pages must be greater than zero")

    try:
        output_dir = arguments.output_dir.expanduser().resolve()
        source_tables = build_source_tables(
            arguments.source,
            chainabuse_max_pages=arguments.max_pages,
            chainabuse_allow_partial=arguments.allow_partial,
        )
        for spec, table in source_tables:
            validate_table(table, spec, f"local {spec.name}")
            output_path = output_dir / f"{spec.name}.parquet"
            size = save_table(table, output_path)
            LOGGER.info(
                "Saved %s: rows=%d, bytes=%d",
                output_path,
                table.num_rows,
                size,
            )
    except KeyboardInterrupt:
        LOGGER.warning(
            "Parsing paused safely. Run the same command later to resume from the latest checkpoint."
        )
        raise SystemExit(130)
    except (OSError, RuntimeError, ValueError, pa.ArrowException):
        LOGGER.exception("Local Parquet save failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
