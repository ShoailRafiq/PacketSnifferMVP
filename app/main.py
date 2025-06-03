"""
Quick test harness for the Sniffer.
Run this file directly to see if packets are being captured.
"""

from app.sniffer import Sniffer


def print_row(row: list):
    """
    Simple callback to show rows in the terminal.
    Row format: [timestamp, src, dst, proto, length, info]
    """
    print(row)


if __name__ == "__main__":
    # Use the Npcap loopback adapter for a safe test
    iface = r"\Device\NPF_Loopback"
    bpf_filter = ""  # no filter, capture everything

    sniffer = Sniffer(iface=iface, bpf_filter=bpf_filter, on_row=print_row)

    print("Starting sniffer... Press Ctrl+C to stop.")
    sniffer.start()

    try:
        # Just idle here while packets are captured
        while True:
            pass
    except KeyboardInterrupt:
        print("Stopping sniffer...")
        sniffer.stop()
