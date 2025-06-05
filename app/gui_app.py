# app/gui_app.py
"""
GUI aligned with the IDD:
- Home screen with 4 large buttons (Capture, Port Scanner, Settings, About)
- Separate screens for each feature (no tabs)
- Consent gate must be accepted before Capture/Scan
- CSV export for Capture and Scanner results
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List, Optional
from datetime import datetime

from scapy.all import get_if_list
from app.sniffer import Sniffer
from app.scanner import quick_scan
from app.utils import export_rows_to_csv


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Sniffer MVP")
        self.geometry("1060x620")

        # consent flag required by IDD (must accept before operations)
        self.user_consented: bool = False

        # shared state
        self.sniffer: Optional[Sniffer] = None
        self.capture_rows: List[List] = []
        self.scan_rows: List[List] = []  # each: [host, state, protocol, port]

        # screen container
        self.container = ttk.Frame(self)
        self.container.pack(fill=tk.BOTH, expand=True)

        # build all screens and show home
        self.screens = {}
        for Screen in (HomeScreen, CaptureScreen, ScannerScreen, SettingsScreen, AboutScreen):
            frame = Screen(self.container, self)
            self.screens[Screen.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show("HomeScreen")

        # show consent gate on first run (per IDD security)
        self.after(250, self.prompt_consent_if_needed)

    # ---- navigation ----
    def show(self, name: str):
        self.screens[name].tkraise()

    def prompt_consent_if_needed(self):
        if not self.user_consented:
            ok = messagebox.askyesno(
                "Consent required",
                "This educational tool captures network metadata and performs basic port scans.\n\n"
                "Only metadata (source IP, destination IP, protocol, length) is recorded. "
                "No payload content is captured or stored.\n\n"
                "Do you consent to proceed?",
            )
            self.user_consented = bool(ok)
            if not ok:
                # stay on Home; user can open Settings to review policy and accept later
                self.show("HomeScreen")

    # ---- capture helpers ----
    def start_capture(self, iface: str, bpf: str, on_row_cb):
        if not self.user_consented:
            messagebox.showwarning("Consent required", "Please accept consent in Settings before capturing.")
            return False
        if self.sniffer:
            return True  # already running
        # clear rows
        self.capture_rows.clear()
        try:
            self.sniffer = Sniffer(iface=iface, bpf_filter=bpf, on_row=on_row_cb)
            self.sniffer.start()
            return True
        except Exception as e:
            self.sniffer = None
            messagebox.showerror("Could not start capture", str(e))
            return False

    def stop_capture(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None

    # ---- scanner helpers ----
    def run_quick_scan(self, target: str, ports: str) -> List[List]:
        if not self.user_consented:
            messagebox.showwarning("Consent required", "Please accept consent in Settings before scanning.")
            return []
        results = quick_scan(target, ports)
        rows: List[List] = []
        for host, data in results.items():
            state = data.get("state", "?")
            if "tcp" in data:
                for p, st in data["tcp"].items():
                    rows.append([host, state, "tcp", p, st])
            else:
                rows.append([host, state, "tcp", "-", "no-tcp-data"])
        self.scan_rows = rows
        return rows


# -------------------- Home Screen --------------------
class HomeScreen(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=20)
        self.app = app

        title = ttk.Label(self, text="Network Sniffer MVP", font=("Segoe UI", 20, "bold"))
        title.pack(pady=(10, 20))

        grid = ttk.Frame(self)
        grid.pack()

        def big_button(text, cmd):
            btn = ttk.Button(grid, text=text, command=cmd)
            btn.config(width=24)
            return btn

        b1 = big_button("Packet Capture", lambda: app.show("CaptureScreen"))
        b2 = big_button("Port Scanner", lambda: app.show("ScannerScreen"))
        b3 = big_button("Settings", lambda: app.show("SettingsScreen"))
        b4 = big_button("About", lambda: app.show("AboutScreen"))

        # 2x2 layout
        b1.grid(row=0, column=0, padx=12, pady=12, ipady=18)
        b2.grid(row=0, column=1, padx=12, pady=12, ipady=18)
        b3.grid(row=1, column=0, padx=12, pady=12, ipady=18)
        b4.grid(row=1, column=1, padx=12, pady=12, ipady=18)


# -------------------- Capture Screen --------------------
class CaptureScreen(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=10)
        self.app = app

        # header
        hdr = ttk.Frame(self)
        hdr.pack(fill=tk.X)
        ttk.Button(hdr, text="← Home", command=lambda: app.show("HomeScreen")).pack(side=tk.LEFT)
        ttk.Label(hdr, text="Packet Capture", font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT, padx=12)

        # controls panel
        ctrl = ttk.Frame(self)
        ctrl.pack(fill=tk.X, pady=(10, 6))

        ttk.Label(ctrl, text="Interface:").pack(side=tk.LEFT)
        self.if_var = tk.StringVar()
        self.if_combo = ttk.Combobox(ctrl, textvariable=self.if_var, width=52, state="readonly")
        self.if_combo.pack(side=tk.LEFT, padx=(6, 16))

        ttk.Label(ctrl, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar(value="")
        ttk.Entry(ctrl, textvariable=self.filter_var, width=22).pack(side=tk.LEFT, padx=(6, 16))

        self.btn_start = ttk.Button(ctrl, text="Start", command=self.on_start)
        self.btn_stop = ttk.Button(ctrl, text="Stop", command=self.on_stop, state=tk.DISABLED)
        self.btn_export = ttk.Button(ctrl, text="Export CSV", command=self.on_export, state=tk.DISABLED)
        self.btn_start.pack(side=tk.LEFT)
        self.btn_stop.pack(side=tk.LEFT, padx=(8, 8))
        self.btn_export.pack(side=tk.LEFT)

        # table
        cols = ("timestamp", "src", "dst", "proto", "length", "info")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=18)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=140 if c != "info" else 400, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=(8, 8))

        yscroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        yscroll.place(relx=1.0, rely=0.28, relheight=0.62, anchor="ne")

        # footer/status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var).pack(anchor="w")

        # populate interfaces
        self._populate_interfaces()

    def _populate_interfaces(self):
        ifs = get_if_list()
        self.if_combo["values"] = ifs
        default = next((i for i in ifs if "NPF_Loopback" in i), (ifs[0] if ifs else ""))
        self.if_var.set(default)

    def _append_row(self, row: List):
        self.app.capture_rows.append(row)
        self.tree.insert("", tk.END, values=row)
        self.status_var.set(f"Rows captured: {len(self.app.capture_rows)}")

    def on_start(self):
        ok = self.app.start_capture(
            iface=self.if_var.get().strip(),
            bpf=self.filter_var.get().strip(),
            on_row_cb=self._append_row,
        )
        if ok:
            self.btn_start.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.NORMAL)
            self.btn_export.config(state=tk.DISABLED)
            # clear previous rows in table
            for iid in self.tree.get_children():
                self.tree.delete(iid)
            self.app.capture_rows.clear()
            self.status_var.set("Capturing…")

    def on_stop(self):
        self.app.stop_capture()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_export.config(state=(tk.NORMAL if self.app.capture_rows else tk.DISABLED))
        self.status_var.set(f"Stopped. Rows captured: {len(self.app.capture_rows)}")

    def on_export(self):
        if not self.app.capture_rows:
            messagebox.showinfo("Nothing to export", "No captured rows yet.")
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="Export capture to CSV",
            defaultextension=".csv",
            initialfile=f"capture_{ts}.csv",
            filetypes=[("CSV files", "*.csv")],
        )
        if not path:
            return
        try:
            export_rows_to_csv(self.app.capture_rows, path)
            messagebox.showinfo("Exported", f"Saved {len(self.app.capture_rows)} rows to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))


# -------------------- Scanner Screen --------------------
class ScannerScreen(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=10)
        self.app = app

        hdr = ttk.Frame(self)
        hdr.pack(fill=tk.X)
        ttk.Button(hdr, text="← Home", command=lambda: app.show("HomeScreen")).pack(side=tk.LEFT)
        ttk.Label(hdr, text="Port Scanner", font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT, padx=12)

        # controls
        ctrl = ttk.Frame(self)
        ctrl.pack(fill=tk.X, pady=(10, 6))
        ttk.Label(ctrl, text="Target:").pack(side=tk.LEFT)
        self.target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(ctrl, textvariable=self.target_var, width=24).pack(side=tk.LEFT, padx=(6, 16))
        ttk.Label(ctrl, text="Ports:").pack(side=tk.LEFT)
        self.ports_var = tk.StringVar(value="top-100")
        ttk.Entry(ctrl, textvariable=self.ports_var, width=16).pack(side=tk.LEFT, padx=(6, 16))

        ttk.Button(ctrl, text="Quick Scan (Nmap)", command=self.on_scan).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Button(ctrl, text="Export CSV", command=self.on_export).pack(side=tk.LEFT)

        # results table
        cols = ("host", "state", "proto", "port", "status")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=18)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=150 if c != "status" else 200, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=(8, 8))

    def on_scan(self):
        # clear
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.app.scan_rows.clear()

        rows = self.app.run_quick_scan(self.target_var.get().strip(), self.ports_var.get().strip())
        if not rows:
            return
        for r in rows:
            self.tree.insert("", tk.END, values=r)

    def on_export(self):
        if not self.app.scan_rows:
            messagebox.showinfo("Nothing to export", "No scan results yet.")
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="Export scan results to CSV",
            defaultextension=".csv",
            initialfile=f"scan_{ts}.csv",
            filetypes=[("CSV files", "*.csv")],
        )
        if not path:
            return
        try:
            # re-use the same helper (header won’t match, but OK for MVP teaching)
            export_rows_to_csv(self.app.scan_rows, path)
            messagebox.showinfo("Exported", f"Saved {len(self.app.scan_rows)} rows to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))


# -------------------- Settings Screen --------------------
class SettingsScreen(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=20)
        self.app = app

        hdr = ttk.Frame(self)
        hdr.pack(fill=tk.X)
        ttk.Button(hdr, text="← Home", command=lambda: app.show("HomeScreen")).pack(side=tk.LEFT)
        ttk.Label(hdr, text="Settings", font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT, padx=12)

        ttk.Separator(self).pack(fill=tk.X, pady=10)

        # consent toggle with brief policy text
        consent_row = ttk.Frame(self)
        consent_row.pack(anchor="w", pady=(8, 4))
        self.consent_var = tk.BooleanVar(value=app.user_consented)
        ttk.Checkbutton(
            consent_row,
            text="I consent to capturing network metadata and running basic port scans (no payloads).",
            variable=self.consent_var,
            command=self.on_toggle_consent
        ).pack(side=tk.LEFT)

        ttk.Label(
            self,
            text=("Note: Per course policy, only metadata (source/destination IP, protocol, length) is captured. "
                  "No payload contents are stored. Export is manual only."),
            wraplength=820, justify="left"
        ).pack(anchor="w", pady=(8, 0))

    def on_toggle_consent(self):
        self.app.user_consented = bool(self.consent_var.get())


# -------------------- About Screen --------------------
class AboutScreen(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=20)
        ttk.Button(self, text="← Home", command=lambda: app.show("HomeScreen")).pack(anchor="w")
        ttk.Label(self, text="About this MVP", font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(10, 6))
        ttk.Label(
            self,
            text=("A teaching-first packet sniffer and port scanner (CS301 MVP).\n"
                  "Built with Python, Scapy, and Nmap; simple UI via Tkinter.\n"
                  "Focuses on clarity and ethics: consent required; only metadata captured."),
            justify="left"
        ).pack(anchor="w")


def main():
    app = App()
    # Windows DPI awareness (no-op elsewhere)
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app.mainloop()


if __name__ == "__main__":
    main()

