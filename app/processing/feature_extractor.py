"""IP-based feature extraction for packet DataFrames."""

from pathlib import Path

import pandas as pd

from app.config import settings
from app.utils.logging import get_logger


logger = get_logger(__name__)

FEATURE_COLUMNS = [
    "src_ip",
    "total_packets",
    "total_bytes",
    "unique_dst_ips",
    "unique_dst_ports",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "avg_packet_size",
    "connection_rate",
    "first_seen",
    "last_seen",
]

REQUIRED_COLUMNS = {
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "packet_size",
}


def _empty_feature_frame() -> pd.DataFrame:
    """Return an empty feature DataFrame with the expected schema."""
    return pd.DataFrame(columns=FEATURE_COLUMNS)


def _validate_input(df: pd.DataFrame) -> None:
    """Validate that packet DataFrame has the expected pcap_reader schema."""
    missing_columns = REQUIRED_COLUMNS.difference(df.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise ValueError(f"Missing required packet columns: {missing}")


def _save_features(features: pd.DataFrame, output_path: Path) -> None:
    """Persist extracted features as CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    features.to_csv(output_path, index=False)
    logger.info("IP features saved: %s rows=%d", output_path, len(features))


def _resolve_output_path(output_path: str | Path | None) -> Path:
    """Resolve feature CSV output path."""
    return Path(output_path) if output_path else settings.processed_data_dir / "features.csv"


def _maybe_save_features(
    features: pd.DataFrame,
    save_to_csv: bool,
    output_path: str | Path | None,
) -> None:
    """Save features when requested."""
    if save_to_csv:
        _save_features(features, _resolve_output_path(output_path))


def extract_ip_features(
    df: pd.DataFrame,
    save_to_csv: bool = False,
    output_path: str | Path | None = None,
) -> pd.DataFrame:
    """Extract source-IP level traffic features from packet records.

    Args:
        df: Packet-level DataFrame produced by app.capture.pcap_reader.read_pcap.
        save_to_csv: When True, save extracted features to CSV.
        output_path: Optional CSV path. Defaults to data/processed/features.csv.

    Returns:
        Source-IP aggregated feature DataFrame.
    """
    if df.empty:
        logger.warning("Feature extraction skipped because packet DataFrame is empty.")
        features = _empty_feature_frame()
        _maybe_save_features(features, save_to_csv, output_path)
        return features

    _validate_input(df)

    working_df = df.copy()
    working_df = working_df[working_df["src_ip"].notna()].copy()

    if working_df.empty:
        logger.warning("Feature extraction produced no rows because src_ip is empty.")
        features = _empty_feature_frame()
        _maybe_save_features(features, save_to_csv, output_path)
        return features

    working_df["timestamp"] = pd.to_numeric(working_df["timestamp"], errors="coerce")
    working_df["packet_size"] = pd.to_numeric(working_df["packet_size"], errors="coerce").fillna(0)
    working_df["protocol"] = working_df["protocol"].fillna("OTHER").str.upper()

    grouped = working_df.groupby("src_ip", dropna=True)

    features = grouped.agg(
        total_packets=("src_ip", "size"),
        total_bytes=("packet_size", "sum"),
        unique_dst_ips=("dst_ip", "nunique"),
        unique_dst_ports=("dst_port", "nunique"),
        avg_packet_size=("packet_size", "mean"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
    ).reset_index()

    protocol_counts = (
        working_df.pivot_table(
            index="src_ip",
            columns="protocol",
            values="packet_size",
            aggfunc="size",
            fill_value=0,
        )
        .rename(columns={"TCP": "tcp_count", "UDP": "udp_count", "ICMP": "icmp_count"})
        .reset_index()
    )

    for column in ["tcp_count", "udp_count", "icmp_count"]:
        if column not in protocol_counts:
            protocol_counts[column] = 0

    features = features.merge(
        protocol_counts[["src_ip", "tcp_count", "udp_count", "icmp_count"]],
        on="src_ip",
        how="left",
    )

    duration = (features["last_seen"] - features["first_seen"]).clip(lower=0)
    features["connection_rate"] = features["total_packets"] / duration.where(duration > 0, 1)

    features = features[FEATURE_COLUMNS]

    count_columns = [
        "total_packets",
        "total_bytes",
        "unique_dst_ips",
        "unique_dst_ports",
        "tcp_count",
        "udp_count",
        "icmp_count",
    ]
    features[count_columns] = features[count_columns].fillna(0).astype(int)

    logger.info("IP feature extraction completed: rows=%d", len(features))

    _maybe_save_features(features, save_to_csv, output_path)

    return features
