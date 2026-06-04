"""PCAP reading utilities."""

from pathlib import Path
from typing import Iterable

import pandas as pd
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet
from scapy.utils import PcapReader

from app.config import settings
from app.utils.logging import get_logger


logger = get_logger(__name__)


class PcapReadError(RuntimeError):
    """Raised when a PCAP file cannot be read safely."""


def _packet_to_record(packet: Packet) -> dict[str, object]:
    """Extract normalized fields from a Scapy packet."""
    src_ip = packet[IP].src if packet.haslayer(IP) else None
    dst_ip = packet[IP].dst if packet.haslayer(IP) else None
    src_port: int | None = None
    dst_port: int | None = None
    protocol = "OTHER"

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    return {
        "timestamp": float(packet.time) if packet.time is not None else None,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "packet_size": len(packet),
    }


def iter_packets(pcap_path: Path, limit: int | None = None) -> Iterable[Packet]:
    """Yield packets from a PCAP file with an optional packet limit."""
    if not pcap_path.exists():
        logger.error("PCAP file not found: %s", pcap_path)
        raise PcapReadError(f"PCAP file not found: {pcap_path}")

    max_packets = limit or settings.max_packets_per_pcap
    logger.info("Reading PCAP file: %s", pcap_path)

    try:
        with PcapReader(str(pcap_path)) as reader:
            for index, packet in enumerate(reader):
                if index >= max_packets:
                    logger.warning("Packet limit reached for %s", pcap_path)
                    break
                yield packet
    except Exception as exc:
        logger.exception("Unable to read PCAP file: %s", pcap_path)
        raise PcapReadError(f"Unable to read PCAP file: {pcap_path}") from exc


def read_pcap(file_path: str) -> pd.DataFrame:
    """Read a PCAP file and return packet-level features as a DataFrame.

    The returned DataFrame contains timestamp, src_ip, dst_ip, src_port,
    dst_port, protocol, and packet_size columns. Missing packet fields are
    represented with None.
    """
    pcap_path = Path(file_path)
    columns = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packet_size",
    ]

    try:
        records = [_packet_to_record(packet) for packet in iter_packets(pcap_path)]
    except PcapReadError:
        raise
    except Exception as exc:
        logger.exception("Unexpected error while processing PCAP file: %s", pcap_path)
        raise PcapReadError(f"Unable to process PCAP file: {pcap_path}") from exc

    dataframe = pd.DataFrame.from_records(records, columns=columns)
    logger.info("PCAP read completed: %s packets=%d", pcap_path, len(dataframe))
    return dataframe
