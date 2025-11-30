from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict

import matplotlib.pyplot as plt

from database.db_utils import fetch_packets


def compute_timeline_distribution(limit: int = 2000, bucket: str = "minute") -> Dict[str, int]:
    """
    Group packets over time and return a mapping of time bucket -> count.

    bucket: "second", "minute", or "hour"
    """
    packets = fetch_packets(limit=limit)
    buckets = []

    for pkt in packets:
        ts_str = pkt.get("timestamp")
        if not ts_str:
            continue

        try:
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            # Skip malformed timestamps
            continue

        if bucket == "second":
            key = ts.strftime("%Y-%m-%d %H:%M:%S")
        elif bucket == "hour":
            key = ts.strftime("%Y-%m-%d %H:00")
        else:
            # default: minute
            key = ts.strftime("%Y-%m-%d %H:%M")

        buckets.append(key)

    counter = Counter(buckets)
    # Sort by time
    return dict(sorted(counter.items(), key=lambda x: x[0]))


def generate_timeline_chart(save_path: Path, limit: int = 2000, bucket: str = "minute") -> str:
    """
    Generate a simple line chart showing packets over time.
    Saves the PNG to save_path.
    """
    data = compute_timeline_distribution(limit=limit, bucket=bucket)

    if not data:
        raise ValueError("No packet data available for timeline visualisation.")

    labels = list(data.keys())
    counts = list(data.values())

    plt.figure(figsize=(12, 5))
    plt.plot(labels, counts, marker="o")
    plt.xticks(rotation=45, ha="right")
    plt.xlabel("Time")
    plt.ylabel("Packet count")
    plt.title(f"Packet Timeline ({bucket}-level buckets)")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()

    return str(save_path)
