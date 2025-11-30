from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, request

from sniffer.capture_stub import simulate_packet_capture
from sniffer.live_capture import capture_packets

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


if __name__ == "__main__":
    # You can change host to "0.0.0.0" if you want to access it from another device.
    app.run(host="127.0.0.1", port=5000, debug=True)
