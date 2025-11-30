from collections import Counter
from datetime import datetime
from typing import Dict

from database.db_utils import fetch_packets


def compute_timeline_distribution(limit: int = 1000, bucket: str = "minute") -> Dict[str, int]:
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
