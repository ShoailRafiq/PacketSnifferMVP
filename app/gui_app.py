# app/gui_app.py
"""
Simple Tkinter GUI for the Packet Sniffer MVP.
Focus: clear layout, easy to follow (NZ English comments).
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List
from datetime import datetime

from scapy.all import get_if_list
from app.sniffer import Sniffer
from app.utils import export_rows_to_csv


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Packet Sniffer MVP")
        self.geometry("980x560")

        # data model: we keep rows so we can export later
        self.rows: List[List] = []

        # sniffer handle (created on Start)
        self.sniffer: Sniffer | None = None

        # ---- UI layout ----
        self._build_toolbar()
        self._build_table()
        self._build_statusbar()

        self._set_status("Ready")

    # ---------- UI building ----------
    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=(8, 6))
        bar.pack(side=tk.TOP, fill=tk.X)

        # Interfaces dropdown (populate from scapy)
        ttk.Label(bar, text="Interface:").pack(side=tk.LEFT)
        self.if_var = tk.StringVar()
        self.if_combo = ttk.Combobox(bar, textvariable=self.if_var, width=50, state="readonly")
        self.if_combo.pack(side=tk.LEFT, padx=(6, 12))
        self._populate_interfaces()

        # BPF filter entry
        ttk.Label(bar, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar(value="")  # e.g. "icmp", "tcp", "port 53"
        ttk.Entry(bar, textvariable=self.filter_var, width=20).pack(side=tk.LEFT, padx=(6, 12))

        # Start / Stop buttons
        self.btn_start = ttk.Button(bar, text="Start", command=self.on_start)
        self.btn_stop = ttk.Button(bar, text="Stop", command=self.on_stop, state=tk.DISABLED)
        self.btn_start.pack(side=tk.LEFT)
        self.btn_stop.pack(side=tk.LEFT, padx=(6, 12))

        # Export button
        self.btn_export = ttk.Button(bar, text="Export CSV", command=self.on_export, state=tk.DISABLED)
        self.btn_export.pack(side=tk.LEFT)

    def _build_table(self):
        frame = ttk.Frame(self)
        frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=6)

        cols = ("timestamp", "src", "dst", "proto", "length", "info")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=18)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, anchor=tk.W, width=130 if c != "info" else 300)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        yscroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_statusbar(self):
        bar = ttk.Frame(self, relief=tk.SUNKEN)
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.status_var, padding=(8, 4)).pack(side=tk.LEFT)

    # ---------- helpers ----------
    def _set_status(self, msg: str):
        self.status_var.set(msg)

    def _populate_interfaces(self):
        ifs = get_if_list()
        self.if_combo["values"] = ifs
        # pick loopback by default if present
        default = next((i for i in ifs if "NPF_Loopback" in i), (ifs[0] if ifs else ""))
        self.if_var.set(default)

    def _append_row(self, row: List):
        """Append a row to the table and internal buffer."""
        self.rows.append(row)
        self.tree.insert("", tk.END, values=row)
        self._set_status(f"Captured: {len(self.rows)} rows")

    # ---------- actions ----------
    def on_start(self):
        iface = self.if_var.get().strip()
        bpf = self.filter_var.get().strip() or ""
        if not iface:
            messagebox.showwarning("No interface", "Please choose a network interface.")
            return
        if self.sniffer:
            # already running?
            return
        # clear previous rows
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.rows.clear()

        try:
            self.sniffer = Sniffer(iface=iface, bpf_filter=bpf, on_row=self._append_row)
            self.sniffer.start()
            self.btn_start.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.NORMAL)
            self.btn_export.config(state=tk.DISABLED)
            self._set_status(f"Capturing on: {iface}  (filter: {bpf or 'none'})")
        except Exception as e:
            self.sniffer = None
            messagebox.showerror("Error", f"Could not start sniffer: {e}")

    def on_stop(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
            self.btn_start.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.DISABLED)
            # enable export if we have rows
            self.btn_export.config(state=(tk.NORMAL if self.rows else tk.DISABLED))
            self._set_status(f"Stopped. Rows captured: {len(self.rows)}")

    def on_export(self):
        if not self.rows:
            messagebox.showinfo("Nothing to export", "No captured rows yet.")
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"capture_{ts}.csv"
        path = filedialog.asksaveasfilename(
            title="Export CSV",
            defaultextension=".csv",
            initialfile=default_name,
            filetypes=[("CSV files", "*.csv")],
        )
        if not path:
            return
        try:
            export_rows_to_csv(self.rows, path)
            messagebox.showinfo("Exported", f"Saved {len(self.rows)} rows to:\n{path}")
            self._set_status(f"Exported to {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))


def main():
    app = App()
    # Native look where possible
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)  # ignore if not on Windows
    except Exception:
        pass
    app.mainloop()


if __name__ == "__main__":
    main()
