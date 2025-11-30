import sqlite3
from pathlib import Path
from typing import List, Dict

DB_PATH = Path(__file__).resolve().parent / "sniffer.db"


def _get_connection():
    """Return a new SQLite connection."""
    return sqlite3.connect(DB_PATH)


# ---------------------------------------------------------------------------
# PACKET LOGGING
# ---------------------------------------------------------------------------

def log_packet(timestamp: str, src_ip: str, dst_ip: str, protocol: str, length: int) -> None:
    """
    Save a single packet's metadata into the SQLite database.
    """
    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length)
        VALUES (?, ?, ?, ?, ?)
        """,
        (timestamp, src_ip, dst_ip, protocol, length),
    )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# SCAN LOGGING
# ---------------------------------------------------------------------------

def log_scan_result(
    timestamp: str,
    target_host: str,
    port: int,
    state: str,
    service: str,
    vulnerable: bool,
) -> None:
    """
    Save a single port scan result into the scans table.
    """
    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scans (timestamp, target_host, port, state, service, vulnerable)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (timestamp, target_host, port, state, service, int(vulnerable)),
    )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# FETCH FUNCTIONS
# ---------------------------------------------------------------------------

def fetch_packets(limit: int = 200) -> List[Dict]:
    """
    Retrieve recent packet logs from the database.
    """
    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, timestamp, src_ip, dst_ip, protocol, length
        FROM packets
        ORDER BY id DESC
        LIMIT ?;
        """,
        (limit,),
    )

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "src_ip": r[2],
            "dst_ip": r[3],
            "protocol": r[4],
            "length": r[5],
        }
        for r in rows
    ]


def fetch_scans(limit: int = 100) -> List[Dict]:
    """
    Retrieve recent port scan results from the database.
    """
    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, timestamp, target_host, port, state, service, vulnerable
        FROM scans
        ORDER BY id DESC
        LIMIT ?;
        """,
        (limit,),
    )

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "target_host": r[2],
            "port": r[3],
            "state": r[4],
            "service": r[5],
            "vulnerable": bool(r[6]),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# EXPORT FUNCTIONS
# ---------------------------------------------------------------------------

def export_packets_to_csv(csv_path: str) -> int:
    """
    Export all packets to a CSV file.
    Returns number of rows written.
    """
    import csv

    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT timestamp, src_ip, dst_ip, protocol, length
        FROM packets
        ORDER BY id ASC;
        """
    )

    rows = cursor.fetchall()
    conn.close()

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "length"])
        writer.writerows(rows)

    return len(rows)


def export_scans_to_csv(csv_path: str) -> int:
    """
    Export all scans to a CSV file.
    Returns number of rows written.
    """
    import csv

    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT timestamp, target_host, port, state, service, vulnerable
        FROM scans
        ORDER BY id ASC;
        """
    )

    rows = cursor.fetchall()
    conn.close()

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["timestamp", "target_host", "port", "state", "service", "vulnerable"]
        )
        writer.writerows(rows)

    return len(rows)
