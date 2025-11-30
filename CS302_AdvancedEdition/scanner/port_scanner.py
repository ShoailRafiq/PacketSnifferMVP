from datetime import datetime
from typing import List, Dict

import nmap  # python-nmap

from database.db_utils import log_scan_result

# Very simple vulnerability heuristic:
# These ports are commonly associated with older or high-risk services.
VULNERABLE_PORTS = {21, 23, 25, 110, 143, 3389}


def run_port_scan(
    target_host: str = "127.0.0.1",
    ports: str = "1-1024",
) -> List[Dict]:
    """
    Run a basic TCP SYN scan against the target_host.

    Args:
        target_host: The IP/hostname to scan.
        ports:       Port range string, e.g. "1-1024" or "22,80,443".

    Returns:
        A list of dictionaries describing each discovered port.
    """
    scanner = nmap.PortScanner()
    # -sS: TCP SYN scan, -T4: faster timing profile
    scanner.scan(target_host, ports, arguments="-sS -T4")

    results: List[Dict] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                state = scanner[host][proto][port]["state"]
                service = scanner[host][proto][port].get("name", "")

                vulnerable = int(port) in VULNERABLE_PORTS and state == "open"

                record = {
                    "timestamp": now,
                    "target_host": host,
                    "port": int(port),
                    "state": state,
                    "service": service,
                    "vulnerable": vulnerable,
                }
                results.append(record)

                # Persist to the database for later analysis and exports.
                log_scan_result(
                    timestamp=now,
                    target_host=host,
                    port=int(port),
                    state=state,
                    service=service,
                    vulnerable=vulnerable,
                )

    return results


if __name__ == "__main__":
    print("Running test scan against localhost (127.0.0.1, ports 1-1024)...")
    out = run_port_scan("127.0.0.1", "1-1024")
    print(f"Scan completed. Logged {len(out)} rows to DB.")
    if out:
        print("First few results:")
        for entry in out[:10]:
            print(entry)
