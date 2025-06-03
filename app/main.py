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
    # Choose which interface to listen on.
    # Loopback is reliable for quick tests with localhost traffic.
    iface = r"\Device\NPF_Loopback"

    # BPF filter options (pick ONE and comment the rest):
    # bpf_filter = ""              # everything
    # bpf_filter = "icmp"          # only ping/ICMP
    # bpf_filter = "tcp"           # only TCP
    # bpf_filter = "udp"           # only UDP
    # bpf_filter = "port 53"       # only DNS
    # bpf_filter = "host 127.0.0.1"  # only loopback host
    bpf_filter = "icmp"  # ← example: only ICMP for ping tests

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

if __name__ == "__main__":
    from app.scanner import quick_scan
    print("Running quick scan of localhost (top ports)…")
    res = quick_scan("127.0.0.1", "top-100")
    for host, data in res.items():
        opens = [str(p) for p, st in data.get("tcp", {}).items() if st == "open"]
        print(f"{host} [{data.get('state','?')}] open: {', '.join(opens) or '—'}")
