from datetime import datetime
from typing import Optional

from scapy.all import sniff, IP, TCP, UDP, ICMP  # type: ignore

from CS302_AdvancedEdition.database.db_utils import log_packet


def _get_protocol(pkt) -> str:
    """
    Return a simple protocol label based on the packet layers.
    We only care about high-level protocol for educational purposes.
    """
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def _handle_packet(pkt, counter: dict) -> None:
    """
    Callback used by scapy.sniff to log each packet into the database.
    Only packet *metadata* is stored (no payloads).
    """
    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    protocol = _get_protocol(pkt)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    length = len(pkt)

    log_packet(timestamp, src_ip, dst_ip, protocol, length)
    counter["count"] += 1


def capture_packets(
    iface: Optional[str] = None,
    duration_seconds: int = 5,
    packet_limit: Optional[int] = None,
) -> int:
    """
    Capture live packets for a fixed duration or until packet_limit is reached.

    Args:
        iface: Network interface name (or None for default).
        duration_seconds: How long to sniff for (timeout).
        packet_limit: Stop after this many packets (or None for no explicit limit).

    Returns:
        The number of packets logged to the database.
    """
    counter = {"count": 0}

    sniff(
        iface=iface,
        prn=lambda pkt: _handle_packet(pkt, counter),
        store=False,
        timeout=duration_seconds,
        count=packet_limit if packet_limit is not None else 0,
    )

    return counter["count"]


if __name__ == "__main__":
    print("Starting test capture for 5 seconds on default interface...")
    logged = capture_packets(duration_seconds=5)
    print(f"Capture completed. Logged {logged} packets to the database.")
