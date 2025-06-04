"""
Quick test harness for the Packet Sniffer MVP.
Pick which test to run by toggling at the bottom.
"""

from app.sniffer import Sniffer
from app.scanner import quick_scan


def run_sniffer_test():
    """
    Test harness for the Sniffer.
    Captures packets and prints them to the console.
    """
    def print_row(row: list):
        print(row)

    iface = r"\Device\NPF_Loopback"
    bpf_filter = "icmp"   # change this if you want TCP/UDP/DNS

    sniffer = Sniffer(iface=iface, bpf_filter=bpf_filter, on_row=print_row)
    print("Starting sniffer... Press Ctrl+C to stop.")
    sniffer.start()
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Stopping sniffer...")
        sniffer.stop()


def run_scanner_test():
    """
    Test harness for the Scanner.
    Runs a quick scan of localhost and prints open ports.
    """
    print("Running quick scan of localhost (top ports)…")
    res = quick_scan("127.0.0.1", "top-100")
    for host, data in res.items():
        opens = [str(p) for p, st in data.get("tcp", {}).items() if st == "open"]
        print(f"{host} [{data.get('state','?')}] open: {', '.join(opens) or '—'}")


if __name__ == "__main__":
    import sys
    mode = "sniffer"  # default

    # allow calling: python -m app.main sniffer  OR python -m app.main scanner
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ("sniffer", "s"):
            mode = "sniffer"
        elif arg in ("scanner", "scan", "nmap"):
            mode = "scanner"
        else:
            print("Unknown mode:", arg)
            print("Usage: python -m app.main [sniffer|scanner]")
            sys.exit(1)

    if mode == "sniffer":
        run_sniffer_test()
    else:
        run_scanner_test()

# --------------------------------------------------------------------
# HOW TO USE THIS FILE (for students / new users):
#
# You can run this module from the project root with:
#
#   python -m app.main sniffer
#       → starts the Sniffer harness
#         (press Ctrl+C to stop, then try ping or curl.exe to generate traffic)
#
#   python -m app.main scanner
#       → runs the Scanner harness
#         (performs a quick Nmap scan of localhost and shows open ports)
#
# Default mode is "sniffer" if no argument is given.
# --------------------------------------------------------------------

