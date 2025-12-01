import datetime
from database.db_utils import log_packet

def simulate_packet_capture(num_packets: int = 5) -> None:
    """
    Simulate a very basic packet capture for WIP testing.
    This just generates a handful of fake packets and logs them to SQLite.

    This lets me:
    - Test the database pipeline early
    - Make sure the Flask backend can call into the sniffer module
    - Show realistic CS302.2 progress without needing the full Scapy sniffer yet

    This will be replaced in CS302.3 with the proper Scapy-based capture.
    """
    for i in range(num_packets):
        # Timestamp in ISO format keeps things tidy and readable
        timestamp = datetime.datetime.now().isoformat(timespec="seconds")

        # These IPs are just placeholders for the WIP stage
        src_ip = f"192.168.1.{10 + i}"
        dst_ip = "8.8.8.8"
        protocol = "TCP"
        length = 60 + i  # Slight variation so it looks more natural

        # Save the record to SQLite
        log_packet(timestamp, src_ip, dst_ip, protocol, length)

    print(f"[WIP] Simulated capture: {num_packets} packets written to database.")

if __name__ == "__main__":
    # Quick manual test so I can run this file directly in PyCharm.
    simulate_packet_capture()
