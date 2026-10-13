from __future__ import annotations

import argparse
import gc
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq


REQUIRED_COLUMNS = ("address", "chain", "label_type", "label_value", "source")

CATEGORY_SCORES = {
    "child_abuse": 100,
    "darknet": 100,
    "fraud": 100,
    "hacking": 100,
    "phishing": 100,
    "ransomware": 100,
    "sanctions_global": 100,
    "sanctions_russia": 100,
    "stolen_assets": 100,
    "terror_global": 100,
    "terror_russia": 100,
    "weapon": 100,
    "criminal_activity": 95,
    "extremism": 95,
    "illegal_service": 90,
    "private": 85,
    "countersanctions_russia": 85,
    "unlicensed_exchange": 75,
    "gambling": 70,
    "pornography": 70,
    "unlicensed_p2p": 70,
    "suspicious": 65,
    "bridges": 60,
    "dex": 55,
    "otc": 50,
    "cloud_mining": 45,
    "crypto_atm": 45,
    "lending_protocol": 45,
    "gaming": 40,
    "invest": 40,
    "crowdfunding": 40,
    "nft": 40,
    "payment_provider": 40,
    "online_marketplace": 35,
    "infrastructure_service": 30,
    "custodian": 25,
    "licensed_p2p": 25,
    "lending_centralized": 20,
    "licensed_exchange": 20,
    "crypto_faucet": 10,
    "mining_pool": 10,
    "smart_contract_platform": 10,
    "staking": 0,
    "government": 0,
    "smart_contract": 0,
    "treasury": 0,
    "validator": 0,
    "confiscation": 0,
    "individual_address": 0,
    "miner": 0,
    "other": 0,
}

# The score is always compared first. This priority is used only when scores tie.
CATEGORY_TIE_PRIORITY = {
    "terror_russia": 99,
    "terror_global": 98,
    "sanctions_russia": 97,
    "sanctions_global": 96,
    "stolen_assets": 95,
    "ransomware": 94,
    "hacking": 93,
    "phishing": 92,
    "fraud": 91,
    "child_abuse": 90,
    "darknet": 89,
    "weapon": 88,
    "criminal_activity": 87,
    "extremism": 86,
    "illegal_service": 85,
    "private": 84,
    "countersanctions_russia": 83,
    "unlicensed_exchange": 82,
    "gambling": 81,
    "pornography": 80,
    "unlicensed_p2p": 79,
    "suspicious": 78,
    "bridges": 77,
    "dex": 76,
    "otc": 75,
    "lending_protocol": 74,
    "cloud_mining": 73,
    "crypto_atm": 72,
    "invest": 71,
    "gaming": 70,
    "crowdfunding": 69,
    "nft": 68,
    "payment_provider": 67,
    "online_marketplace": 66,
    "infrastructure_service": 65,
    "custodian": 64,
    "licensed_p2p": 63,
    "licensed_exchange": 62,
    "lending_centralized": 61,
    "smart_contract_platform": 60,
    "crypto_faucet": 59,
    "mining_pool": 58,
    "confiscation": 57,
    "government": 56,
    "treasury": 55,
    "individual_address": 54,
    "smart_contract": 53,
    "staking": 52,
    "validator": 51,
    "miner": 50,
    "other": 0,
}

SUBCATEGORY_PRIORITY = {
    None: 0,
    "deposit_address": 1,
    "hot_wallet": 2,
    "cold_walelt": 3,
    "no_kyc_exchange": 4,
    "fund": 1,
    "yield": 2,
    "derivatives": 3,
}

CEX_TYPE_TO_ROLE = {
    "cex-deposit-address": "deposit_address",
    "cex-hot-wallet": "hot_wallet",
    "cex-cold-wallet": "cold_walelt",
    "cex-unknown-type": None,
}

NO_KYC_ENTITIES = {
    "alfacash",
    "changehero",
    "changenow",
    "crypto-bot",
    "fixedfloat",
}

# Entity-wide overrides are deliberately narrow. These names are known aliases of
# sanctioned entities, not merely exchanges that contain a few sanctioned deposits.
SANCTIONED_CEX_ENTITIES = {
    "garantex",
    "grinex",
    "grinex-io",
}

TERROR_MARKERS = (
    "terrorist-seizure",
    "hamas",
    "isil-khorasan",
    "ansarallah",
    "gaza-now",
)

DEX_CONTRACTS = {
    "justmoney",
    "mango",
    "tofuswap",
    "ton-swap",
    "uswap",
    "voidswap",
}

NO_KYC_CONTRACTS = {"alfacash", "changehero", "changenow", "fixedfloat"}

INVEST_CONTRACTS = {"alameda-research", "exness", "stusdt"}

HIGH_RISK_SECONDARY_THRESHOLD = 95

_CEX_SUFFIX_RE = re.compile(r"-(?:deposit|hot|cold|wallet)(?:-\d+)?$")


@dataclass(frozen=True)
class LabelMapping:
    category: str
    subcategory: str | None
    score: int
    rank: int
    default_tag: str
    entity: str | None = None
    wallet_role: str | None = None


def _rank(category: str, subcategory: str | None) -> int:
    return (
        CATEGORY_SCORES[category] * 10_000
        + CATEGORY_TIE_PRIORITY[category] * 100
        + SUBCATEGORY_PRIORITY.get(subcategory, 0)
    )


def _mapping(
    category: str,
    subcategory: str | None,
    tag: str,
    *,
    entity: str | None = None,
    wallet_role: str | None = None,
) -> LabelMapping:
    return LabelMapping(
        category=category,
        subcategory=subcategory,
        score=CATEGORY_SCORES[category],
        rank=_rank(category, subcategory),
        default_tag=tag,
        entity=entity,
        wallet_role=wallet_role,
    )


def normalize_cex_entity(label_value: str) -> str:
    return _CEX_SUFFIX_RE.sub("", label_value.strip().lower())


def contains_terror_marker(value: str) -> bool:
    value = value.lower()
    return any(marker in value for marker in TERROR_MARKERS)


def map_label(
    label_type: str,
    label_value: str,
    *,
    cex_entities: set[str],
) -> LabelMapping:
    label_type = label_type.strip().lower()
    label_value = label_value.strip().lower()

    if label_type in CEX_TYPE_TO_ROLE:
        role = CEX_TYPE_TO_ROLE[label_type]
        entity = normalize_cex_entity(label_value)

        if entity in SANCTIONED_CEX_ENTITIES:
            tag = "|".join(part for part in (entity, role) if part)
            return _mapping(
                "sanctions_global",
                None,
                tag,
                entity=entity,
                wallet_role=role,
            )

        if entity in NO_KYC_ENTITIES:
            tag = "|".join(part for part in (entity, role) if part)
            return _mapping(
                "unlicensed_exchange",
                "no_kyc_exchange",
                tag,
                entity=entity,
                wallet_role=role,
            )

        return _mapping(
            "licensed_exchange",
            role,
            entity,
            entity=entity,
            wallet_role=role,
        )

    if label_type == "sanctioned-entity":
        category = "terror_global" if contains_terror_marker(label_value) else "sanctions_global"
        return _mapping(category, None, label_value)

    if label_type == "scam":
        return _mapping("fraud", None, label_value)

    if label_type == "money-laundering":
        return _mapping("criminal_activity", None, label_value)

    if label_type == "no-kyc":
        return _mapping("unlicensed_exchange", "no_kyc_exchange", label_value)

    if label_type == "gambling":
        return _mapping("gambling", None, label_value)

    if label_type == "risk-flag":
        category = "terror_global" if contains_terror_marker(label_value) else "suspicious"
        return _mapping(category, None, label_value)

    if label_type in {"issuer-blocked-usdt", "issuer-blocked-usdc"}:
        return _mapping("suspicious", None, label_value)

    if label_type == "tainted":
        category = "stolen_assets" if "stolen" in label_value else "fraud"
        return _mapping(category, None, label_value)

    if label_type == "bridge":
        return _mapping("bridges", None, label_value)

    if label_type == "dex-router":
        return _mapping("dex", None, "route")

    if label_type == "dex-pool":
        return _mapping("dex", None, "pool")

    if label_type == "dex-aggregator":
        return _mapping("dex", None, "aggregator")

    if label_type == "otc-desk":
        return _mapping("otc", None, label_value)

    if label_type == "payment-processor":
        return _mapping("payment_provider", None, label_value)

    if label_type == "asset-manager":
        if label_value.startswith("chainup-custody") or label_value.startswith("ceffu"):
            return _mapping("custodian", None, label_value)
        return _mapping("invest", "fund", label_value)

    if label_type == "derivatives-protocol":
        return _mapping("invest", "derivatives", label_value)

    if label_type == "yield-aggregator":
        return _mapping("invest", "yield", label_value)

    if label_type == "rwa-protocol":
        return _mapping("invest", None, label_value)

    if label_type == "launchpad":
        return _mapping("crowdfunding", None, label_value)

    if label_type == "staking-protocol":
        return _mapping("staking", None, label_value)

    if label_type == "eoa-entity":
        return _mapping("individual_address", None, label_value)

    if label_type == "token-contract":
        return _mapping("smart_contract", None, label_value)

    if label_type == "team-wallet":
        return _mapping("treasury", None, label_value)

    if label_type == "government":
        category = "confiscation" if "seized" in label_value else "government"
        return _mapping(category, None, label_value)

    if label_type == "service":
        entity = normalize_cex_entity(label_value)
        if entity == "crypto-bot":
            return _mapping("unlicensed_exchange", "no_kyc_exchange", label_value)
        if entity in {"ceffu", "cobo"}:
            return _mapping("custodian", None, label_value)
        if entity == "debridge":
            return _mapping("bridges", None, label_value)
        return _mapping("infrastructure_service", None, label_value)

    if label_type == "contract":
        if label_value == "united-states-government":
            return _mapping("government", None, label_value)
        if label_value in NO_KYC_CONTRACTS:
            return _mapping("unlicensed_exchange", "no_kyc_exchange", label_value)
        if label_value in DEX_CONTRACTS:
            return _mapping("dex", None, label_value)
        if label_value == "hyperpay":
            return _mapping("payment_provider", None, label_value)
        if label_value == "huione-group":
            return _mapping("criminal_activity", None, label_value)
        if label_value == "swft-blockchain":
            return _mapping("bridges", None, label_value)
        if label_value in INVEST_CONTRACTS:
            subcategory = "fund" if label_value in {"alameda-research", "exness"} else None
            return _mapping("invest", subcategory, label_value)
        if label_value in cex_entities:
            if label_value in SANCTIONED_CEX_ENTITIES:
                return _mapping("sanctions_global", None, label_value)
            return _mapping("licensed_exchange", None, label_value)
        return _mapping("smart_contract", None, label_value)

    return _mapping("other", None, label_value or label_type)


def unique_in_order(values: Iterable[str | None]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        result.append(value)
        seen.add(value)
    return result


def compose_group_tag(
    label_types: list[str],
    label_values: list[str],
    *,
    final_mapping: LabelMapping,
    pair_mappings: dict[tuple[str, str], LabelMapping],
) -> str:
    mappings = [pair_mappings[(label_type, label_value)] for label_type, label_value in zip(label_types, label_values)]

    cex_mappings = [mapping for mapping in mappings if mapping.entity is not None]
    winner_mappings = [mapping for mapping in mappings if mapping.rank == final_mapping.rank]

    tokens: list[str | None] = []
    if cex_mappings:
        tokens.extend(mapping.entity for mapping in cex_mappings)

        cex_roles = unique_in_order(mapping.wallet_role for mapping in cex_mappings)
        if final_mapping.category == "licensed_exchange":
            tokens.extend(role for role in cex_roles if role != final_mapping.subcategory)
        else:
            tokens.extend(cex_roles)

        # Functional tags such as route/pool/aggregator remain useful when they win
        # over a lower-risk CEX attribution.
        tokens.extend(
            mapping.default_tag
            for mapping in winner_mappings
            if mapping.default_tag in {"route", "pool", "aggregator"}
        )
    else:
        tokens.extend(mapping.default_tag for mapping in winner_mappings)

    # Only other high-risk categories are preserved as secondary category tags.
    tokens.extend(
        mapping.category
        for mapping in mappings
        if mapping.score >= HIGH_RISK_SECONDARY_THRESHOLD
        and mapping.category != final_mapping.category
    )

    result = unique_in_order(tokens)
    if not result:
        result = unique_in_order(mapping.default_tag for mapping in winner_mappings)
    return "|".join(result)


def validate_input(parquet_file: pq.ParquetFile) -> None:
    missing = [column for column in REQUIRED_COLUMNS if column not in parquet_file.schema_arrow.names]
    if missing:
        raise ValueError(f"Input Parquet is missing required columns: {', '.join(missing)}")


def collect_pair_mappings(
    parquet_file: pq.ParquetFile,
) -> dict[tuple[str, str], LabelMapping]:
    labels = parquet_file.read(columns=["label_type", "label_value"])
    unique_pairs = labels.group_by(["label_type", "label_value"]).aggregate([([], "count_all")])

    pair_values = list(zip(unique_pairs["label_type"].to_pylist(), unique_pairs["label_value"].to_pylist()))
    cex_entities = {
        normalize_cex_entity(label_value)
        for label_type, label_value in pair_values
        if label_type in CEX_TYPE_TO_ROLE
    }

    result = {
        (label_type, label_value): map_label(
            label_type,
            label_value,
            cex_entities=cex_entities,
        )
        for label_type, label_value in pair_values
    }

    del labels, unique_pairs
    gc.collect()
    return result


def build_mapped_table(
    parquet_file: pq.ParquetFile,
    pair_mappings: dict[tuple[str, str], LabelMapping],
    *,
    batch_size: int,
) -> pa.Table:
    batches: list[pa.RecordBatch] = []
    for batch in parquet_file.iter_batches(columns=list(REQUIRED_COLUMNS), batch_size=batch_size):
        label_types = batch.column(batch.schema.get_field_index("label_type")).to_pylist()
        label_values = batch.column(batch.schema.get_field_index("label_value")).to_pylist()
        mappings = [pair_mappings[(label_type, label_value)] for label_type, label_value in zip(label_types, label_values)]

        batches.append(
            batch.append_column(
                "candidate_rank",
                pa.array((mapping.rank for mapping in mappings), type=pa.int32()),
            ).append_column(
                "default_tag",
                pa.array((mapping.default_tag for mapping in mappings), type=pa.string()),
            )
        )

    return pa.Table.from_batches(batches)


def aggregate_addresses(mapped_table: pa.Table) -> pa.Table:
    # list/first are ordered aggregations, so PyArrow requires a single-threaded
    # group-by execution for deterministic source ordering.
    return mapped_table.group_by(["address", "chain"], use_threads=False).aggregate(
        [
            ("candidate_rank", "max"),
            ([], "count_all"),
            ("default_tag", "first"),
            ("label_type", "list"),
            ("label_value", "list"),
            ("source", "list"),
        ]
    )


def rank_lookup_arrays(
    pair_mappings: dict[tuple[str, str], LabelMapping],
) -> tuple[pa.Array, pa.Array, pa.Array, dict[int, LabelMapping]]:
    by_rank: dict[int, LabelMapping] = {}
    for mapping in pair_mappings.values():
        by_rank[mapping.rank] = mapping

    ranks = sorted(by_rank)
    return (
        pa.array(ranks, type=pa.int32()),
        pa.array((by_rank[rank].category for rank in ranks), type=pa.string()),
        pa.array((by_rank[rank].subcategory for rank in ranks), type=pa.string()),
        by_rank,
    )


def make_bitquery_data(
    label_types: pa.ListArray,
    label_values: pa.ListArray,
    sources: pa.ListArray,
) -> pa.ListArray:
    offsets = label_types.offsets
    first_offset = offsets[0].as_py()
    if first_offset:
        offsets = pc.subtract(offsets, pa.scalar(first_offset, type=offsets.type))

    values = pa.StructArray.from_arrays(
        [
            pc.list_flatten(label_types),
            pc.list_flatten(label_values),
            pc.list_flatten(sources),
        ],
        names=["label_type", "label_value", "source"],
    )
    return pa.ListArray.from_arrays(offsets, values)


def write_output(
    grouped: pa.Table,
    output_path: Path,
    pair_mappings: dict[tuple[str, str], LabelMapping],
    *,
    output_batch_size: int,
) -> None:
    output_schema = pa.schema(
        [
            pa.field("address", pa.string(), nullable=False),
            pa.field("chain", pa.string(), nullable=False),
            pa.field("category", pa.string(), nullable=False),
            pa.field("subcategory", pa.string()),
            pa.field("tag", pa.string(), nullable=False),
            pa.field(
                "bitquery_data",
                pa.list_(
                    pa.struct(
                        [
                            pa.field("label_type", pa.string()),
                            pa.field("label_value", pa.string()),
                            pa.field("source", pa.string()),
                        ]
                    )
                ),
                nullable=False,
            ),
        ]
    )

    rank_values, categories, subcategories, by_rank = rank_lookup_arrays(pair_mappings)

    with pq.ParquetWriter(
        output_path,
        output_schema,
        compression="zstd",
        use_dictionary=True,
        write_statistics=True,
    ) as writer:
        for batch in grouped.to_batches(max_chunksize=output_batch_size):
            ranks = batch.column(batch.schema.get_field_index("candidate_rank_max"))
            rank_indices = pc.index_in(ranks, value_set=rank_values)
            category_array = pc.take(categories, rank_indices)
            subcategory_array = pc.take(subcategories, rank_indices)

            tags = batch.column(batch.schema.get_field_index("default_tag_first")).to_pylist()
            counts = batch.column(batch.schema.get_field_index("count_all")).to_pylist()
            label_types = batch.column(batch.schema.get_field_index("label_type_list"))
            label_values = batch.column(batch.schema.get_field_index("label_value_list"))
            sources = batch.column(batch.schema.get_field_index("source_list"))

            for index, count in enumerate(counts):
                if count <= 1:
                    continue
                rank = ranks[index].as_py()
                tags[index] = compose_group_tag(
                    label_types[index].as_py(),
                    label_values[index].as_py(),
                    final_mapping=by_rank[rank],
                    pair_mappings=pair_mappings,
                )

            output_batch = pa.RecordBatch.from_arrays(
                [
                    batch.column(batch.schema.get_field_index("address")),
                    batch.column(batch.schema.get_field_index("chain")),
                    category_array,
                    subcategory_array,
                    pa.array(tags, type=pa.string()),
                    make_bitquery_data(label_types, label_values, sources),
                ],
                schema=output_schema,
            )
            writer.write_batch(output_batch)


def map_parquet(
    input_path: Path,
    output_path: Path,
    *,
    overwrite: bool = False,
    batch_size: int = 250_000,
    output_batch_size: int = 100_000,
) -> None:
    input_path = input_path.resolve()
    output_path = output_path.resolve()

    if not input_path.is_file():
        raise FileNotFoundError(f"Input Parquet not found: {input_path}")
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output_path}. Use --overwrite to replace it.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.tmp")
    if temporary_path.exists():
        temporary_path.unlink()

    parquet_file = pq.ParquetFile(input_path)
    validate_input(parquet_file)
    pair_mappings = collect_pair_mappings(parquet_file)

    mapped_table = build_mapped_table(
        parquet_file,
        pair_mappings,
        batch_size=batch_size,
    )
    grouped = aggregate_addresses(mapped_table)
    del mapped_table
    gc.collect()

    try:
        write_output(
            grouped,
            temporary_path,
            pair_mappings,
            output_batch_size=output_batch_size,
        )
        temporary_path.replace(output_path)
    except Exception:
        if temporary_path.exists():
            temporary_path.unlink()
        raise


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Map Bitquery address labels to the project risk taxonomy.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path.home() / "Downloads" / "tron_labels.parquet",
        help="Source Bitquery Parquet file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=script_dir / "tron_labels_mapped.parquet",
        help="Destination Parquet file.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace the output file if it already exists.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    map_parquet(args.input, args.output, overwrite=args.overwrite)
    print(f"Mapped Parquet created: {args.output.resolve()}")


if __name__ == "__main__":
    main()
