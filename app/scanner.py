# app/scanner.py
"""
Scanner module — thin wrapper around python-nmap for a 'Quick Scan' button.
Keeps the interface small and predictable for the GUI.
"""

import nmap

def quick_scan(target: str, ports: str = "top-100") -> dict:
    """
    Run a quick Nmap scan.
    :param target: IP/CIDR/hostname, e.g. "127.0.0.1" or "192.168.1.0/24"
    :param ports:  "top-100" (default) or explicit like "1-1024" or "22,80,443"
    :return: dict like { host: { "state": "...", "tcp": {port: "open"/"closed"/...} } }
    """
    nm = nmap.PortScanner()

    # -Pn = skip host discovery (safer in some networks), -F = fast scan (top ports)
    args = "-Pn -F" if ports.startswith("top-") else "-Pn"

    if ports and not ports.startswith("top-"):
        nm.scan(target, ports, arguments=args)
    else:
        nm.scan(target, arguments=args)  # -F is already in args for top-*

    results = {}
    for host in nm.all_hosts():
        host_data = {"state": nm[host].state(), "tcp": {}}
        if "tcp" in nm[host]:
            for p, pdata in nm[host]["tcp"].items():
                host_data["tcp"][p] = pdata.get("state", "unknown")
        results[host] = host_data
    return results
