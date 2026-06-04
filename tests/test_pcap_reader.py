"""Tests for PCAP reader error handling."""

from pathlib import Path

import pytest

from app.capture.pcap_reader import PcapReadError, read_pcap


def test_read_pcap_raises_for_missing_file(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.pcap"

    with pytest.raises(PcapReadError, match="PCAP file not found"):
        read_pcap(str(missing_file))

