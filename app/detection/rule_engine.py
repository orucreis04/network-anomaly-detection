"""Rule-based anomaly detection engine for IP-level traffic features."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from app.config import settings
from app.utils.logging import get_logger


logger = get_logger(__name__)

ANOMALY_COLUMNS = [
    "src_ip",
    "anomaly_type",
    "severity",
    "score",
    "description",
    "detected_at",
]

REQUIRED_FEATURE_COLUMNS = {
    "src_ip",
    "total_packets",
    "total_bytes",
    "unique_dst_ips",
    "unique_dst_ports",
    "connection_rate",
}

RuleHandler = Callable[[pd.Series, str], dict[str, object] | None]


@dataclass(frozen=True)
class DetectionRule:
    """Metadata and evaluator for one anomaly detection rule."""

    anomaly_type: str
    handler: RuleHandler


def _empty_anomaly_frame() -> pd.DataFrame:
    """Return an empty anomaly DataFrame with the expected schema."""
    return pd.DataFrame(columns=ANOMALY_COLUMNS)


def _validate_features(features_df: pd.DataFrame) -> None:
    """Validate feature DataFrame shape before rule evaluation."""
    missing_columns = REQUIRED_FEATURE_COLUMNS.difference(features_df.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise ValueError(f"Missing required feature columns: {missing}")


def _detected_at() -> str:
    """Return an ISO-8601 UTC detection timestamp."""
    return datetime.now(UTC).isoformat()


def _save_anomalies(anomalies: pd.DataFrame, output_path: Path) -> None:
    """Persist anomaly events as CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    anomalies.to_csv(output_path, index=False)
    logger.info("Anomalies saved: %s rows=%d", output_path, len(anomalies))


def _resolve_output_path(output_path: str | Path | None) -> Path:
    """Resolve anomaly CSV output path."""
    return Path(output_path) if output_path else settings.processed_data_dir / "anomalies.csv"


def _maybe_save_anomalies(
    anomalies: pd.DataFrame,
    save_to_csv: bool,
    output_path: str | Path | None,
) -> None:
    """Save anomalies when requested."""
    if save_to_csv:
        _save_anomalies(anomalies, _resolve_output_path(output_path))


def _ratio_score(value: float, threshold: float, cap: float = 100.0) -> float:
    """Convert a threshold breach into a bounded score."""
    if threshold <= 0:
        return cap
    return round(min((value / threshold) * 100.0, cap), 2)


def _severity_from_score(score: float) -> str:
    """Map numeric score to severity."""
    if score >= 95:
        return "critical"
    if score >= 80:
        return "high"
    if score >= 60:
        return "medium"
    return "low"


def _port_scan_rule(row: pd.Series, detected_at: str) -> dict[str, object] | None:
    unique_ports = float(row["unique_dst_ports"])
    threshold = settings.port_scan_unique_dst_ports_threshold
    if unique_ports < threshold:
        return None

    score = _ratio_score(unique_ports, threshold)
    return {
        "src_ip": row["src_ip"],
        "anomaly_type": "port_scan",
        "severity": _severity_from_score(score),
        "score": score,
        "description": (
            f"Source IP contacted {int(unique_ports)} unique destination ports "
            f"(threshold: {threshold})."
        ),
        "detected_at": detected_at,
    }


def _high_traffic_rule(row: pd.Series, detected_at: str) -> dict[str, object] | None:
    total_packets = float(row["total_packets"])
    total_bytes = float(row["total_bytes"])
    packet_threshold = settings.high_traffic_packets_threshold
    byte_threshold = settings.high_traffic_bytes_threshold

    if total_packets < packet_threshold and total_bytes < byte_threshold:
        return None

    packet_score = _ratio_score(total_packets, packet_threshold)
    byte_score = _ratio_score(total_bytes, byte_threshold)
    score = max(packet_score, byte_score)

    return {
        "src_ip": row["src_ip"],
        "anomaly_type": "high_traffic",
        "severity": _severity_from_score(score),
        "score": score,
        "description": (
            f"Source IP generated {int(total_packets)} packets and "
            f"{int(total_bytes)} bytes "
            f"(thresholds: {packet_threshold} packets or {byte_threshold} bytes)."
        ),
        "detected_at": detected_at,
    }


def _suspicious_rate_rule(row: pd.Series, detected_at: str) -> dict[str, object] | None:
    connection_rate = float(row["connection_rate"])
    threshold = settings.suspicious_connection_rate_threshold
    if connection_rate < threshold:
        return None

    score = _ratio_score(connection_rate, threshold)
    return {
        "src_ip": row["src_ip"],
        "anomaly_type": "suspicious_rate",
        "severity": _severity_from_score(score),
        "score": score,
        "description": (
            f"Source IP has connection rate {connection_rate:.2f} packets/second "
            f"(threshold: {threshold})."
        ),
        "detected_at": detected_at,
    }


def _multi_target_scan_rule(row: pd.Series, detected_at: str) -> dict[str, object] | None:
    unique_targets = float(row["unique_dst_ips"])
    threshold = settings.multi_target_unique_dst_ips_threshold
    if unique_targets < threshold:
        return None

    score = _ratio_score(unique_targets, threshold)
    return {
        "src_ip": row["src_ip"],
        "anomaly_type": "multi_target_scan",
        "severity": _severity_from_score(score),
        "score": score,
        "description": (
            f"Source IP contacted {int(unique_targets)} unique destination IPs "
            f"(threshold: {threshold})."
        ),
        "detected_at": detected_at,
    }


RULES = [
    DetectionRule("port_scan", _port_scan_rule),
    DetectionRule("high_traffic", _high_traffic_rule),
    DetectionRule("suspicious_rate", _suspicious_rate_rule),
    DetectionRule("multi_target_scan", _multi_target_scan_rule),
]


def detect_anomalies(
    features_df: pd.DataFrame,
    save_to_csv: bool = False,
    output_path: str | Path | None = None,
) -> pd.DataFrame:
    """Detect anomalies from IP-level traffic features.

    Args:
        features_df: DataFrame produced by extract_ip_features.
        save_to_csv: When True, save detected anomalies to CSV.
        output_path: Optional CSV path. Defaults to data/processed/anomalies.csv.

    Returns:
        Anomaly event DataFrame.
    """
    if features_df.empty:
        logger.warning("Rule engine skipped because feature DataFrame is empty.")
        anomalies = _empty_anomaly_frame()
        _maybe_save_anomalies(anomalies, save_to_csv, output_path)
        return anomalies

    _validate_features(features_df)

    detected_at = _detected_at()
    events: list[dict[str, object]] = []

    for _, row in features_df.iterrows():
        for rule in RULES:
            event = rule.handler(row, detected_at)
            if event is not None:
                events.append(event)

    anomalies = pd.DataFrame.from_records(events, columns=ANOMALY_COLUMNS)
    logger.info("Rule-based anomaly detection completed: rows=%d", len(anomalies))

    _maybe_save_anomalies(anomalies, save_to_csv, output_path)

    return anomalies
