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

class PacketDB:
    """
    Tiny SQLite wrapper for saving packets.
    Not essential for MVP but handy if we want persistent logs.

    Table layout:
    packets(
        ts TEXT,
        src TEXT,
        dst TEXT,
        proto TEXT,
        length INT,
        info TEXT
    )
    """

    def __init__(self, db_path: str = "packets.db"):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS packets (
                ts TEXT,
                src TEXT,
                dst TEXT,
                proto TEXT,
                length INT,
                info TEXT
            )"""
        )
        self._conn.commit()

    def insert_row(self, row: list):
        """
        Insert a single packet row into the database.
        Row format must be [ts, src, dst, proto, length, info].
        """
        if not row or len(row) < 6:
            return  # ignore malformed rows

        self._conn.execute(
            "INSERT INTO packets (ts, src, dst, proto, length, info) VALUES (?, ?, ?, ?, ?, ?)",
            row[:6]
        )
        self._conn.commit()

    def fetch_recent(self, limit: int = 100) -> list:
        """
        Return the most recent 'limit' packet rows.
        Useful for a quick sanity-check or exporting a subset.
        """
        cur = self._conn.execute(
            "SELECT ts, src, dst, proto, length, info "
            "FROM packets ORDER BY rowid DESC LIMIT ?",
            (int(limit),)
        )
        return cur.fetchall()



