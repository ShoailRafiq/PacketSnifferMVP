# app/utils.py
"""
Helpers for the Packet Sniffer MVP.
Kept simple and readable (NZ English comments, teaching-first).

Includes:
- export_rows_to_csv(rows, path)
- PacketDB (small SQLite logger, optional) — added in later chunks
"""

from typing import List
import csv
import sqlite3
from pathlib import Path


def export_rows_to_csv(rows: List[List], path: str):
    """
    Save captured rows to a CSV file.

    :param rows: each row is [timestamp, src, dst, proto, length, info]
    :param path: where to write the CSV (folders are created if needed)
    """
    head = ["timestamp", "src", "dst", "proto", "length", "info"]
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)  # make folders if they don't exist
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(head)
        for r in rows:
            # be defensive about row shape (pad/trim to 6 columns)
            r = (list(r) + ["", "", "", "", "", ""])[:6]
            w.writerow(r)



