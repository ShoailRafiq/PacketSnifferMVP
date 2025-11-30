from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, request

from sniffer.capture_stub import simulate_packet_capture
from sniffer.live_capture import capture_packets
from scanner.port_scanner import run_port_scan
from database.db_utils import fetch_packets, fetch_scans

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = BASE_DIR / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


@app.route("/")
def home():
    """
    Basic status endpoint to confirm that the API is running.
    """
    return jsonify(
        {
            "status": "ok",
            "message": "Network Sniffer & Scanner – Advanced Educational Edition API",
        }
    )


@app.route("/health")
def health():
    """
    Simple health check endpoint.
    """
    return jsonify({"status": "healthy"})


@app.route("/start_capture_stub")
def start_capture_stub():
    """
    Original stubbed capture endpoint, kept for WIP/testing purposes.

    This calls simulate_packet_capture(), which logs a small number of
    dummy packets into the database. It matches the behaviour described
    in the CS302.2 WIP report.
    """
    simulate_packet_capture()
    return jsonify({"status": "stub_capture_completed", "logged_packets": 5})


@app.route("/start_capture", methods=["POST"])
def start_capture():
    """
    Start a live capture session using Scapy.

    Optional JSON body:
      {
        "duration_seconds": 5,
        "packet_limit": null,
        "iface": null
      }

    - duration_seconds: how long to sniff for (timeout).
    - packet_limit: stop after N packets (or null for no explicit limit).
    - iface: interface name, or null for default.
    """
    data = request.get_json(silent=True) or {}

    duration = int(data.get("duration_seconds", 5))
    packet_limit = data.get("packet_limit")
    iface = data.get("iface")

    if packet_limit is not None:
        try:
            packet_limit = int(packet_limit)
        except ValueError:
            packet_limit = None

    logged_count = capture_packets(
        iface=iface,
        duration_seconds=duration,
        packet_limit=packet_limit,
    )

    return jsonify(
        {
            "status": "live_capture_completed",
            "duration_seconds": duration,
            "packets_logged": logged_count,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    )


@app.route("/scan", methods=["POST"])
def scan():
    """
    Run a port scan using the python-nmap based scanner.

    JSON body:
      {
        "target_host": "127.0.0.1",
        "ports": "1-1024"
      }
    """
    data = request.get_json(silent=True) or {}
    target_host = data.get("target_host", "127.0.0.1")
    ports = data.get("ports", "1-1024")

    results = run_port_scan(target_host=target_host, ports=ports)

    return jsonify(
        {
            "status": "scan_completed",
            "target_host": target_host,
            "total_results": len(results),
            "results": results,
        }
    )


@app.route("/packets")
def list_packets():
    """
    Return recent packet metadata as JSON.
    """
    try:
        limit = int(request.args.get("limit", 200))
    except ValueError:
        limit = 200

    packets = fetch_packets(limit=limit)
    return jsonify({"count": len(packets), "packets": packets})


@app.route("/scans")
def list_scans():
    """
    Return recent port scan results as JSON.
    """
    try:
        limit = int(request.args.get("limit", 100))
    except ValueError:
        limit = 100

    scans = fetch_scans(limit=limit)
    return jsonify({"count": len(scans), "scans": scans})

@app.route("/export/packets")
def export_packets_csv():
    """
    Export all packets from the database to a CSV file and return it for download.
    """
    import csv
    packets = fetch_packets(limit=5000)  # big enough for our purposes

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = EVIDENCE_DIR / f"packets_export_{timestamp}.csv"

    with open(out_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "length"])

        for pkt in packets:
            writer.writerow([
                pkt.get("timestamp"),
                pkt.get("src_ip"),
                pkt.get("dst_ip"),
                pkt.get("protocol"),
                pkt.get("length"),
            ])

    return jsonify(
        {
            "status": "export_complete",
            "file": str(out_path),
            "records_exported": len(packets),
        }
    )


@app.route("/export/scans")
def export_scans_csv():
    """
    Export port scan results as a CSV file and return it for download.
    """
    import csv
    scans = fetch_scans(limit=5000)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = EVIDENCE_DIR / f"scans_export_{timestamp}.csv"

    with open(out_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "target_host", "port", "state", "service", "vulnerable"])

        for entry in scans:
            writer.writerow([
                entry.get("timestamp"),
                entry.get("target_host"),
                entry.get("port"),
                entry.get("state"),
                entry.get("service"),
                entry.get("vulnerable"),
            ])

    return jsonify(
        {
            "status": "export_complete",
            "file": str(out_path),
            "records_exported": len(scans),
        }
    )

if __name__ == "__main__":
    # You can change host to "0.0.0.0" if you want to access it from another device.
    app.run(host="127.0.0.1", port=5000, debug=True)

