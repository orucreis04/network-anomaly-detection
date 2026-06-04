"""Tests for rule-based anomaly detection."""

from pathlib import Path

import pandas as pd

from app.detection.rule_engine import ANOMALY_COLUMNS, detect_anomalies


def _base_feature_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "src_ip": "10.0.0.10",
        "total_packets": 10,
        "total_bytes": 1_000,
        "unique_dst_ips": 1,
        "unique_dst_ports": 1,
        "tcp_count": 10,
        "udp_count": 0,
        "icmp_count": 0,
        "avg_packet_size": 100.0,
        "connection_rate": 1.0,
        "first_seen": 1.0,
        "last_seen": 11.0,
    }
    row.update(overrides)
    return row


def test_detect_anomalies_detects_port_scan() -> None:
    features_df = pd.DataFrame([_base_feature_row(unique_dst_ports=20)])

    anomalies_df = detect_anomalies(features_df)

    assert "port_scan" in set(anomalies_df["anomaly_type"])
    port_scan = anomalies_df[anomalies_df["anomaly_type"] == "port_scan"].iloc[0]
    assert port_scan["src_ip"] == "10.0.0.10"
    assert port_scan["severity"] in {"low", "medium", "high", "critical"}
    assert port_scan["score"] >= 100


def test_detect_anomalies_detects_high_traffic() -> None:
    features_df = pd.DataFrame([_base_feature_row(total_packets=1_000)])

    anomalies_df = detect_anomalies(features_df)

    assert "high_traffic" in set(anomalies_df["anomaly_type"])
    high_traffic = anomalies_df[anomalies_df["anomaly_type"] == "high_traffic"].iloc[0]
    assert high_traffic["src_ip"] == "10.0.0.10"
    assert "1000 packets" in high_traffic["description"]


def test_detect_anomalies_handles_empty_dataframe(tmp_path: Path) -> None:
    output_path = tmp_path / "anomalies.csv"
    empty_features_df = pd.DataFrame(
        columns=[
            "src_ip",
            "total_packets",
            "total_bytes",
            "unique_dst_ips",
            "unique_dst_ports",
            "connection_rate",
        ]
    )

    anomalies_df = detect_anomalies(
        empty_features_df,
        save_to_csv=True,
        output_path=output_path,
    )

    assert anomalies_df.empty
    assert list(anomalies_df.columns) == ANOMALY_COLUMNS
    assert output_path.exists()
