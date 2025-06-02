# app/sniffer.py
"""
This is the first module that we will build, it's easier to build the sniffer part of the MVP
and then work on the scanner part before we build the GUI.

Sniffer module — this is the little engine that actually listens on a network interface
and turns packets into tidy rows for the GUI to display or save.

Design notes (kept simple on purpose):
- We run Scapy's sniff() in a background thread so the GUI doesn't freeze.
- We don’t store everything in here — we send rows back up via a callback.
- Rows are shaped like this: [timestamp, src, dst, proto, length, info]
"""

from threading import Thread, Event
from typing import Callable, Optional
from datetime import datetime

# Scapy imports — only what we need to recognise common IP protocols
from scapy.all import sniff, Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP

class Sniffer:
    """
    Small wrapper around scapy.sniff() so the rest of the app can just call start/stop
    and get back rows without worrying about threads or packet parsing details.
    """

    def __init__(self, iface: str, bpf_filter: str, on_row: Callable[[list], None]):
        """
        :param iface: The Npcap interface name, e.g. r"\\Device\\NPF_Loopback" or a Wi-Fi NPF GUID.
        :param bpf_filter: A Berkeley Packet Filter string, e.g. "tcp or udp" or "port 53".
                           Empty string is fine — we’ll treat it as no filter.
        :param on_row: A callback function that takes one list row:
                       [timestamp, src, dst, proto, length, info]
        """
        self.iface = iface
        self.bpf = (bpf_filter or "").strip() or None  # None = no filter
        self.on_row = on_row

        # Control bits for the background capture thread
        self._stop = Event()
        self._thread: Optional[Thread] = None

    def start(self):
        """
        Starts a background thread that runs scapy.sniff().
        If one is already running, we quietly ignore it.
        This stops the GUI from crashing if someone double-clicks Start.
        """
        if self._thread and self._thread.is_alive():
            # Already running — nothing more to do
            return

        self._stop.clear()  # reset the stop flag
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()

