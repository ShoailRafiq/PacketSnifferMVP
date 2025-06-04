# app/gui_app.py
"""
IDD-aligned GUI for the Packet Sniffer MVP.
Layout: toolbar (iface + filter + Start/Stop + Export), tabs (Sniffer/Scanner), status bar.
Sniffer tab is fully wired; Scanner tab UI is present (we’ll wire next).
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List
from datetime import datetime

from scapy.all import get_if_list
from app.sniffer import Sniffer
from app.utils import export_rows_to_csv
from app.scanner import quick_scan  # will be used in next chunk


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Packet Sniffer MVP")
        self.geometry("1024x600")

        # data model for sniffer
        self.rows: List[List] = []
        self.sniffer: Sniffer | None = None

        # build UI
        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()

        # populate interfaces & defaults
        self._populate_interfaces()
        self._set_status("Ready")

    # ---------- UI building ----------
    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=(8, 6))
        bar.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(bar, text="Interface:").pack(side=tk.LEFT)
        self.if_var = tk.StringVar()
        self.if_combo = ttk.Combobox(bar, textvariable=self.if_var, width=50, state="readonly")
        self.if_combo.pack(side=tk.LEFT, padx=(6, 12))

        ttk.Label(bar, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar(value="")  # e.g. icmp / tcp / udp / port 53
        ttk.Entry(bar, textvariable=self.filter_var, width=22).pack(side=tk.LEFT, padx=(6, 12))

        self.btn_start = ttk.Button(bar, text="Start", command=self.on_start)
        self.btn_stop = ttk.Button(bar, text="Stop", command=self.on_stop, state=tk.DISABLED)
        self.btn_export = ttk.Button(bar, text="Export CSV", command=self.on_export, state=tk.DISABLED)

        self.btn_start.pack(side=tk.LEFT)
        self.btn_stop.pack(side=tk.LEFT, padx=(6, 12))
        self.btn_export.pack(side=tk.LEFT)

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # --- Sniffer tab ---
        self.sniffer_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.sniffer_tab, text="Sniffer")

        cols = ("timestamp", "src", "dst", "proto", "length", "info")
        self.sniffer_tree = ttk.Treeview(self.sniffer_tab, columns=cols, show="headings")
        for c in cols:
            self.sniffer_tree.heading(c, text=c)
            self.sniffer_tree.column(c, width=130 if c != "info" else 360, anchor=tk.W)
        self.sniffer_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        yscroll = ttk.Scrollbar(self.sniffer_tab, orient="vertical", command=self.sniffer_tree.yview)
        self.sniffer_tree.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)

        # --- Scanner tab (UI only for now; wiring next) ---
        self.scanner_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_tab, text="Scanner")

        scan_bar = ttk.Frame(self.scanner_tab, padding=(6, 6))
        scan_bar.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(scan_bar, text="Target:").pack(side=tk.LEFT)
        self.scan_target = tk.StringVar(value="127.0.0.1")
        ttk.Entry(scan_bar, textvariable=self.scan_target, width=24).pack(side=tk.LEFT, padx=(6, 12))

        ttk.Label(scan_bar, text="Ports:").pack(side=tk.LEFT)
        self.scan_ports = tk.StringVar(value="top-100")
        ttk.Entry(scan_bar, textvariable=self.scan_ports, width=16).pack(side=tk.LEFT, padx=(6, 12))

        self.btn_quick_scan = ttk.Button(scan_bar, text="Quick Scan (Nmap)", state=tk.DISABLED)
        self.btn_quick_scan.pack(side=tk.LEFT)

        self.scan_output = tk.Text(self.scanner_tab, wrap="word", height=18)
        self.scan_output.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

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
        default = next((i for i in ifs if "NPF_Loopback" in i), (ifs[0] if ifs else ""))
        self.if_var.set(default)

    def _append_row(self, row: List):
        """Append a row to the table and internal buffer (Sniffer tab)."""
        self.rows.append(row)
        self.sniffer_tree.insert("", tk.END, values=row)
        self._set_status(f"Captured: {len(self.rows)} rows")

    def _clear_sniffer_table(self):
        for iid in self.sniffer_tree.get_children():
            self.sniffer_tree.delete(iid)
        self.rows.clear()

    # ---------- actions (Sniffer) ----------
    def on_start(self):
        iface = self.if_var.get().strip()
        bpf = self.filter_var.get().strip() or ""
        if not iface:
            messagebox.showwarning("No interface", "Please choose a network interface.")
            return
        if self.sniffer:
            return  # already running

        # clear previous capture
        self._clear_sniffer_table()

        try:
            self.sniffer = Sniffer(iface=iface, bpf_filter=bpf, on_row=self._append_row)
            self.sniffer.start()
            self.btn_start.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.NORMAL)
            self.btn_export.config(state=tk.DISABLED)
            self._set_status(f"Capturing on: {iface} (filter: {bpf or 'none'})")
        except Exception as e:
            self.sniffer = None
            messagebox.showerror("Error", f"Could not start sniffer: {e}")

    def on_stop(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        # enable export if there’s data
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
    # Optional: apply Windows DPI awareness
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app.mainloop()


if __name__ == "__main__":
    main()

