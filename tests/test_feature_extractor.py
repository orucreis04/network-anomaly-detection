"""Tests for IP-based feature extraction."""

from pathlib import Path

import pandas as pd

from app.processing.feature_extractor import FEATURE_COLUMNS, extract_ip_features


def test_extract_ip_features_from_packet_dataframe() -> None:
    packets_df = pd.DataFrame(
        [
            {
                "timestamp": 10.0,
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.10",
                "src_port": 44444,
                "dst_port": 80,
                "protocol": "TCP",
                "packet_size": 100,
            },
            {
                "timestamp": 12.0,
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.11",
                "src_port": 44445,
                "dst_port": 443,
                "protocol": "UDP",
                "packet_size": 300,
            },
            {
                "timestamp": 14.0,
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.11",
                "src_port": None,
                "dst_port": None,
                "protocol": "ICMP",
                "packet_size": 200,
            },
        ]
    )

    features_df = extract_ip_features(packets_df)

    assert list(features_df.columns) == FEATURE_COLUMNS
    assert len(features_df) == 1

    row = features_df.iloc[0]
    assert row["src_ip"] == "10.0.0.1"
    assert row["total_packets"] == 3
    assert row["total_bytes"] == 600
    assert row["unique_dst_ips"] == 2
    assert row["unique_dst_ports"] == 2
    assert row["tcp_count"] == 1
    assert row["udp_count"] == 1
    assert row["icmp_count"] == 1
    assert row["avg_packet_size"] == 200
    assert row["first_seen"] == 10.0
    assert row["last_seen"] == 14.0
    assert row["connection_rate"] == 0.75


def test_extract_ip_features_handles_empty_dataframe(tmp_path: Path) -> None:
    output_path = tmp_path / "features.csv"
    empty_packets_df = pd.DataFrame(
        columns=["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "packet_size"]
    )

    features_df = extract_ip_features(
        empty_packets_df,
        save_to_csv=True,
        output_path=output_path,
    )

    assert features_df.empty
    assert list(features_df.columns) == FEATURE_COLUMNS
    assert output_path.exists()

