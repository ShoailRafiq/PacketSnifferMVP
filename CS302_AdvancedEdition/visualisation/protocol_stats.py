import matplotlib.pyplot as plt
from pathlib import Path
from collections import Counter

from database.db_utils import fetch_packets


def compute_protocol_distribution(limit: int = 2000):
    """
    Return protocol counts as a dictionary.
    """
    packets = fetch_packets(limit=limit)
    protocols = [pkt.get("protocol", "UNKNOWN") for pkt in packets]
    return dict(Counter(protocols))


def generate_protocol_chart(save_path: Path, limit: int = 2000):
    """
    Generate both bar and pie charts showing the protocol distribution.
    Saves to the provided save_path (PNG file).
    """
    data = compute_protocol_distribution(limit)

    if not data:
        raise ValueError("No packet data available for visualisation.")

    protocols = list(data.keys())
    counts = list(data.values())

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Bar chart
    axes[0].bar(protocols, counts)
    axes[0].set_title("Protocol Distribution (Bar Chart)")
    axes[0].set_xlabel("Protocol")
    axes[0].set_ylabel("Count")

    # Pie chart
    axes[1].pie(counts, labels=protocols, autopct="%1.1f%%")
    axes[1].set_title("Protocol Distribution (Pie Chart)")

    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close(fig)

    return str(save_path)
