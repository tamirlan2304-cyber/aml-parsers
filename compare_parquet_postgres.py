
from __future__ import annotations

import json
import logging
import re
import time
from collections import Counter
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from sqlalchemy import bindparam, create_engine, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.types import Text


IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LOG = logging.getLogger(__name__)

# ======================== CONFIGURATION =========================
# Fill in this section before starting the script.
# Use a read-only PostgreSQL account. Do not commit a real password to Git.
DATABASE_URL = (
    "postgresql+psycopg://readonly_user:password@postgres-host:5432/database_name"
    "?sslmode=require&connect_timeout=10&application_name=wallet-parquet-compare"
)

# Local input and result files. INPUT_FILE can be placed beside this script.
INPUT_FILE = Path(r"YOUR_ADDRESSES.parquet")
# JSON report is always created. Set this flag to False to create only the JSON report.
WRITE_PARQUET_OUTPUT = True
PARQUET_OUTPUT_FILE = Path(r"addresses_with_postgres_data.parquet")
JSON_REPORT_FILE = Path(r"addresses_postgres_comparison.report.json")

# Address column in the input Parquet and the indexed column in PostgreSQL.
INPUT_ADDRESS_COLUMN = "normalized_address"
POSTGRES_TABLE = "public.addresses"
POSTGRES_ADDRESS_COLUMN = "normalized_address"
POSTGRES_POPULATED_TAGS_COLUMN = "populatedtags"
POSTGRES_CATEGORY_COLUMN = "category"
POSTGRES_TAGS_COLUMN = "tags"

# Set to a network name such as "TRON" to process only that network.
# None disables filtering. If INPUT_CHAIN_COLUMN is None, the script first looks
# for a "chain" column and then for a "network" column in the input Parquet.
CHAIN_FILTER: str | None = None
INPUT_CHAIN_COLUMN: str | None = None

# False for Tron/Base58 addresses: uppercase and lowercase characters differ.
# True for EVM hexadecimal addresses: 0xAbC and 0xabc are treated as the same wallet.
CASE_INSENSITIVE_COMPARISON = False
BATCH_SIZE = 10_000
STATEMENT_TIMEOUT_SECONDS = 120  # Set to 0 to disable the per-query timeout.
OVERWRITE_OUTPUTS = False
# =================================================================


def quote_identifier(value: str) -> str:
    """Quote a simple SQL identifier after rejecting unsafe values."""
    if not IDENTIFIER.fullmatch(value):
        raise ValueError(
            f"Invalid SQL identifier {value!r}. Use letters, digits and underscores only."
        )
    return f'"{value}"'


def quote_table(value: str) -> str:
    parts = value.split(".")
    if len(parts) not in (1, 2):
        raise ValueError("POSTGRES_TABLE must be table or schema.table")
    return ".".join(quote_identifier(part) for part in parts)


def comparison_value(address: str) -> str:
    """Return the value used only for equality comparison, preserving the source row."""
    return address.lower() if CASE_INSENSITIVE_COMPARISON else address


def make_query(table: str, address_column: str):
    quoted_table = quote_table(table)
    quoted_address_column = quote_identifier(address_column)
    comparison_column = (
        f"LOWER({quoted_address_column})"
        if CASE_INSENSITIVE_COMPARISON
        else quoted_address_column
    )
    metadata_columns = {
        "populatedtags": quote_identifier(POSTGRES_POPULATED_TAGS_COLUMN),
        "category": quote_identifier(POSTGRES_CATEGORY_COLUMN),
        "tags": quote_identifier(POSTGRES_TAGS_COLUMN),
    }
    # The driver sends the batch as a PostgreSQL text array, not interpolated SQL.
    return text(
        f"SELECT {comparison_column} AS lookup_address, "
        f"{metadata_columns['populatedtags']} AS populatedtags, "
        f"{metadata_columns['category']} AS category, "
        f"{metadata_columns['tags']} AS tags "
        f"FROM {quoted_table} "
        f"WHERE {comparison_column} = ANY(:addresses)"
    ).bindparams(bindparam("addresses", type_=ARRAY(Text())))


def resolve_chain_column(column_names: list[str]) -> str | None:
    """Return the input network column, or fail only when filtering requires one."""
    if INPUT_CHAIN_COLUMN is not None:
        if INPUT_CHAIN_COLUMN not in column_names:
            raise SystemExit(
                f"Network column {INPUT_CHAIN_COLUMN!r} is absent. "
                f"Available: {column_names}"
            )
        return INPUT_CHAIN_COLUMN
    for candidate in ("chain", "network"):
        if candidate in column_names:
            return candidate
    if CHAIN_FILTER is not None:
        raise SystemExit(
            "CHAIN_FILTER is set, but neither 'chain' nor 'network' exists in the input. "
            f"Available: {column_names}"
        )
    return None


def matches_chain(value: object) -> bool:
    """Compare network labels without making the filter sensitive to letter case."""
    if CHAIN_FILTER is None:
        return True
    return value is not None and str(value).strip().casefold() == CHAIN_FILTER.strip().casefold()


def metadata_key(value: object) -> str:
    """Create a stable key for deduplicating PostgreSQL metadata values."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def merged_metadata(values: list[object]) -> object | None:
    """Keep one DB value as-is; retain every distinct value if a DB address is duplicated."""
    unique_values: list[object] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        key = metadata_key(value)
        if key not in seen:
            seen.add(key)
            unique_values.append(value)
    if not unique_values:
        return None
    return unique_values[0] if len(unique_values) == 1 else unique_values


def value_for_parquet(value: object | None) -> str | None:
    """Use text columns so PostgreSQL scalar, array, and JSON values write reliably."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def statistic_values(value: object | None):
    """Yield individual labels from a PostgreSQL scalar or array value."""
    if value is None:
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from statistic_values(item)
        return
    if isinstance(value, dict):
        yield json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        return
    yield str(value)


def counter_rows(counter: Counter[str], field_name: str) -> list[dict[str, object]]:
    """Return deterministic, JSON-friendly category/tag statistics."""
    return [
        {field_name: value, "count": count}
        for value, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    ]


def main() -> int:
    if BATCH_SIZE < 1:
        raise SystemExit("BATCH_SIZE must be positive.")
    if STATEMENT_TIMEOUT_SECONDS < 0:
        raise SystemExit("STATEMENT_TIMEOUT_SECONDS cannot be negative.")
    if not INPUT_FILE.is_file():
        raise SystemExit(f"Input Parquet was not found: {INPUT_FILE}")

    source = pq.ParquetFile(INPUT_FILE)
    if INPUT_ADDRESS_COLUMN not in source.schema_arrow.names:
        raise SystemExit(
            f"Column {INPUT_ADDRESS_COLUMN!r} is absent. Available: {source.schema_arrow.names}"
        )
    chain_column = resolve_chain_column(source.schema_arrow.names)

    enrichment_columns = ("populatedtags", "category", "tags")
    already_present = set(enrichment_columns) & set(source.schema_arrow.names)
    if already_present:
        raise SystemExit(
            "Input Parquet already has enrichment columns that would be ambiguous: "
            f"{sorted(already_present)}"
        )
    enriched_schema = source.schema_arrow
    for column in enrichment_columns:
        enriched_schema = enriched_schema.append(pa.field(column, pa.string(), nullable=True))

    JSON_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    if WRITE_PARQUET_OUTPUT:
        PARQUET_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    output_paths = [JSON_REPORT_FILE]
    if WRITE_PARQUET_OUTPUT:
        output_paths.append(PARQUET_OUTPUT_FILE)
    resolved_outputs = [path.resolve() for path in output_paths]
    if INPUT_FILE.resolve() in resolved_outputs:
        raise SystemExit("Input file cannot also be an output or report file.")
    if len(set(resolved_outputs)) != len(resolved_outputs):
        raise SystemExit("Output and report file paths must be different.")
    if not OVERWRITE_OUTPUTS:
        existing_output = next((path for path in output_paths if path.exists()), None)
        if existing_output:
            raise SystemExit(
                f"Refusing to replace existing file: {existing_output}. "
                "Set OVERWRITE_OUTPUTS = True if intended."
            )

    query = make_query(POSTGRES_TABLE, POSTGRES_ADDRESS_COLUMN)
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        connect_args={"options": "-c default_transaction_read_only=on"},
    )
    stats = {
        "input_file": str(INPUT_FILE.resolve()),
        "parquet_output_file": str(PARQUET_OUTPUT_FILE.resolve()) if WRITE_PARQUET_OUTPUT else None,
        "json_report_file": str(JSON_REPORT_FILE.resolve()),
        "input_rows": 0,
        "filtered_rows": 0,
        "matched_rows": 0,
        "unmatched_rows": 0,
        "empty_address_rows": 0,
        "batches": 0,
        "chain_filter": CHAIN_FILTER,
        "chain_column": chain_column,
        "case_insensitive_comparison": CASE_INSENSITIVE_COMPARISON,
        "table": POSTGRES_TABLE,
        "db_column": POSTGRES_ADDRESS_COLUMN,
    }
    category_counts: Counter[str] = Counter()
    tag_counts: Counter[str] = Counter()
    started = time.monotonic()

    try:
        with engine.connect() as connection:
            parquet_writer = (
                pq.ParquetWriter(PARQUET_OUTPUT_FILE, enriched_schema, compression="zstd")
                if WRITE_PARQUET_OUTPUT
                else None
            )
            try:
                # SET TRANSACTION must be the first statement in the transaction.
                connection.execute(text("SET TRANSACTION READ ONLY"))
                if STATEMENT_TIMEOUT_SECONDS:
                    timeout_ms = STATEMENT_TIMEOUT_SECONDS * 1000
                    connection.execute(text(f"SET LOCAL statement_timeout = {timeout_ms}"))

                for batch in source.iter_batches(batch_size=BATCH_SIZE):
                    stats["input_rows"] += batch.num_rows
                    if CHAIN_FILTER is not None:
                        assert chain_column is not None  # Checked by resolve_chain_column.
                        chain_values = batch.column(
                            batch.schema.get_field_index(chain_column)
                        ).to_pylist()
                        batch = batch.filter(pa.array([matches_chain(value) for value in chain_values]))
                    if batch.num_rows == 0:
                        continue

                    raw_values = batch.column(
                        batch.schema.get_field_index(INPUT_ADDRESS_COLUMN)
                    ).to_pylist()
                    comparison_values = [
                        comparison_value(value) if isinstance(value, str) and value else None
                        for value in raw_values
                    ]
                    query_values = list({value for value in comparison_values if value is not None})
                    postgres_rows: dict[str, dict[str, list[object]]] = {}
                    if query_values:
                        for row in connection.execute(query, {"addresses": query_values}).mappings():
                            lookup_address = row["lookup_address"]
                            postgres_rows.setdefault(
                                lookup_address,
                                {column: [] for column in enrichment_columns},
                            )
                            for column in enrichment_columns:
                                postgres_rows[lookup_address][column].append(row[column])

                    metadata_arrays = {column: [] for column in enrichment_columns}
                    matched_count = 0
                    for comparison in comparison_values:
                        metadata = postgres_rows.get(comparison) if comparison is not None else None
                        if metadata is None:
                            if comparison is None:
                                stats["empty_address_rows"] += 1
                            for column in enrichment_columns:
                                metadata_arrays[column].append(None)
                            continue

                        matched_count += 1
                        for column in enrichment_columns:
                            value = merged_metadata(metadata[column])
                            metadata_arrays[column].append(value_for_parquet(value))
                        for value in statistic_values(merged_metadata(metadata["category"])):
                            category_counts[value] += 1
                        for value in statistic_values(merged_metadata(metadata["tags"])):
                            tag_counts[value] += 1

                    if parquet_writer:
                        arrays = [batch.column(index) for index in range(batch.num_columns)]
                        arrays.extend(
                            pa.array(metadata_arrays[column], type=pa.string())
                            for column in enrichment_columns
                        )
                        parquet_writer.write_batch(
                            pa.RecordBatch.from_arrays(arrays, schema=enriched_schema)
                        )

                    stats["batches"] += 1
                    stats["filtered_rows"] += batch.num_rows
                    stats["matched_rows"] += matched_count
                    stats["unmatched_rows"] += batch.num_rows - matched_count
                    if stats["batches"] % 20 == 0:
                        LOG.info(
                            "batches=%d filtered=%d matched=%d",
                            stats["batches"], stats["filtered_rows"], stats["matched_rows"],
                        )
            finally:
                if parquet_writer:
                    parquet_writer.close()
    finally:
        engine.dispose()

    stats["elapsed_seconds"] = round(time.monotonic() - started, 2)
    stats["match_rate_percent"] = round(
        100 * stats["matched_rows"] / stats["filtered_rows"], 2
    ) if stats["filtered_rows"] else 0.0
    stats["matched_categories"] = counter_rows(category_counts, "category")
    stats["matched_tags"] = counter_rows(tag_counts, "tag")
    with JSON_REPORT_FILE.open("w", encoding="utf-8") as report_file:
        json.dump(stats, report_file, ensure_ascii=False, indent=2)
        report_file.write("\n")
    LOG.info("Finished: %s", json.dumps(stats, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        LOG.error("Interrupted")
        raise SystemExit(130)
