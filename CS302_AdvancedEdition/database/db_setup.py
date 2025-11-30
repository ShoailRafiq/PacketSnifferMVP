import sqlite3
from pathlib import Path

# Path to where the database file will be stored.
DB_PATH = Path(__file__).resolve().parent / "sniffer.db"


def initialise_database():
    """
    Sets up the SQLite database for the upgraded sniffer.
    Creates the file if it doesn’t exist and sets up the main tables.

    - packets: stores packet *metadata* only (no payload).
    - scans:   stores basic port scan results and a simple vulnerability flag.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Packet metadata table (already used in CS302.2)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip    TEXT NOT NULL,
            dst_ip    TEXT NOT NULL,
            protocol  TEXT NOT NULL,
            length    INTEGER NOT NULL
        );
        """
    )

    # New scans table for CS302.3
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            target_host TEXT NOT NULL,
            port        INTEGER NOT NULL,
            state       TEXT NOT NULL,
            service     TEXT,
            vulnerable  INTEGER NOT NULL DEFAULT 0
        );
        """
    )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    initialise_database()
    print(f"Database initialised at: {DB_PATH}")

