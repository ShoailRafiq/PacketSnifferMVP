# app/gui_app.py
"""
GUI complete for MVP:
- Home (stacked tiles)
- Packet Capture (Start/Stop, table, Save/Export)
- Port Scanner (target, Start Scan, results, Save/Export)
- Settings (consent toggle, export all sessions, reset)
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List, Optional
from datetime import datetime
from pathlib import Path

from scapy.all import get_if_list
from app.sniffer import Sniffer
from app.utils import export_rows_to_csv
from app.scanner import quick_scan


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Sniffer MVP")
        self.geometry("1060x620")

        self._init_styles()
        self._build_menu()

        self.user_consented: bool = False

        self.sniffer: Optional[Sniffer] = None
        self.capture_rows: List[List] = []
        self.scan_rows: List[List] = []

        self.container = ttk.Frame(self)
        self.container.pack(fill=tk.BOTH, expand=True)

        self.screens = {}
        for Screen in (HomeScreen, CaptureScreen, ScannerScreen, SettingsScreen):
            frame = Screen(self.container, self)
            self.screens[Screen.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show("HomeScreen")
        self.after(250, self.prompt_consent_if_needed)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- base ----------
    def _init_styles(self):
        style = ttk.Style(self)
        style.configure(".", font=("Segoe UI", 11))
        style.configure("BigTitle.TLabel", font=("Segoe UI", 24, "bold"))
        style.configure("SectionTitle.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Tile.TButton", padding=(24, 16))
        style.configure("Big.TButton", padding=(22, 14))

    def _build_menu(self):
        m = tk.Menu(self)
        nav = tk.Menu(m, tearoff=0)
        nav.add_command(label="Home", command=lambda: self.show("HomeScreen"))
        nav.add_command(label="Packet Capture", command=lambda: self.show("CaptureScreen"))
        nav.add_command(label="Port Scanner", command=lambda: self.show("ScannerScreen"))
        nav.add_command(label="Settings", command=lambda: self.show("SettingsScreen"))
        m.add_cascade(label="Navigate", menu=nav)
        self.config(menu=m)

    def show(self, name: str):
        self.screens[name].tkraise()

    def _on_close(self):
        try:
            self.stop_capture()
        except Exception:
            pass
        self.destroy()

    # ---------- consent ----------
    def prompt_consent_if_needed(self):
        if not self.user_consented:
            ok = messagebox.askyesno(
                "Consent required",
                "This educational tool captures network metadata and runs basic port scans.\n"
                "Payloads are not stored. Do you consent to proceed?"
            )
            self.user_consented = bool(ok)

    # ---------- capture ----------
    def start_capture(self, iface: str, bpf: str, on_row_cb):
        if not self.user_consented:
            messagebox.showwarning("Consent required", "Enable consent to start capturing.")
            return False
        if not iface:
            messagebox.showerror("No interface", "Please select a network interface before starting capture.")
            return False
        if self.sniffer:
            return True
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

    # ---------- scanning ----------
    def run_quick_scan(self, target: str, ports: str) -> List[List]:
        if not self.user_consented:
            messagebox.showwarning("Consent required", "Enable consent to run scans.")
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


# -------------------- Home --------------------
class HomeScreen(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app
        shell = ttk.Frame(self, padding=32)
        shell.pack(fill=tk.BOTH, expand=True)
        header = ttk.Frame(shell, padding=16, relief=tk.GROOVE)
        header.pack(fill=tk.X, pady=(0, 20))
        ttk.Label(header, text="Network Sniffer", style="SectionTitle.TLabel").pack(side=tk.LEFT)
        ttk.Label(header, text="●", font=("Segoe UI", 28)).pack(side=tk.RIGHT)

        tiles = ttk.Frame(shell)
        tiles.pack(fill=tk.X, pady=8)

        def tile(text, cmd):
            b = ttk.Button(tiles, text=text, command=cmd, style="Tile.TButton")
            b.pack(fill=tk.X, pady=10, ipady=10)
            return b

        tile("Start Packet Capture", lambda: app.show("CaptureScreen"))
        tile("Port Scanner",        lambda: app.show("ScannerScreen"))
        tile("View Logs",           lambda: messagebox.showinfo("View Logs", "Planned for CS302."))
        tile("Settings",            lambda: app.show("SettingsScreen"))


# -------------------- Packet Capture --------------------
class CaptureScreen(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=20)
        self.app = app

        top = ttk.Frame(self, padding=16, relief=tk.GROOVE)
        top.pack(fill=tk.X)
        ttk.Button(top, text="← Home", command=lambda: app.show("HomeScreen")).pack(side=tk.LEFT)
        ttk.Label(top, text="Packet Capture", style="SectionTitle.TLabel").pack(side=tk.LEFT, padx=12)
        ttk.Label(top, text="●", font=("Segoe UI", 26)).pack(side=tk.RIGHT)

        ctrl = ttk.Frame(self)
        ctrl.pack(fill=tk.X, pady=16)
        self.if_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="")
        ttk.Label(ctrl, text="Interface:").pack(side=tk.LEFT)
        self.if_combo = ttk.Combobox(ctrl, textvariable=self.if_var, width=48, state="readonly")
        self.if_combo.pack(side=tk.LEFT, padx=(6, 16))
        ttk.Label(ctrl, text="Filter:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.filter_var, width=20).pack(side=tk.LEFT, padx=(6, 16))

        self.btn_start = ttk.Button(ctrl, text="Start Capture", style="Big.TButton", command=self.on_start)
        self.btn_stop  = ttk.Button(ctrl, text="Stop Capture",  style="Big.TButton",
                                    command=self.on_stop, state=tk.DISABLED)
        self.btn_start.pack(side=tk.LEFT, padx=8)
        self.btn_stop.pack(side=tk.LEFT, padx=8)

        cols = ("timestamp", "src", "dst", "proto", "length", "info")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=16)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=140 if c != "info" else 320, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=6)
        yscroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)


        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, pady=(10, 0))
        self.btn_save   = ttk.Button(bottom, text="Save Session", style="Big.TButton",
                                     command=self.on_save, state=tk.DISABLED)
        self.btn_export = ttk.Button(bottom, text="Export to File", style="Big.TButton",
                                     command=self.on_export, state=tk.DISABLED)
        self.btn_save.pack(side=tk.LEFT, padx=8)
        self.btn_export.pack(side=tk.RIGHT, padx=8)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var).pack(anchor="w", pady=(8, 0))

        self._populate_interfaces()

    def _populate_interfaces(self):
        ifs = get_if_list()
        self.if_combo["values"] = ifs
        default = next((i for i in ifs if "NPF_Loopback" in i), (ifs[0] if ifs else ""))
        self.if_var.set(default)

    def _append_row_ui(self, row: List):
        self.app.capture_rows.append(row)
        self.tree.insert("", tk.END, values=row)
        self.status_var.set(f"Rows captured: {len(self.app.capture_rows)}")

    def append_row(self, row: List):
        # Always schedule UI changes on the Tk main thread
        self.after(0, self._append_row_ui, row)

    def on_start(self):
        ok = self.app.start_capture(
            iface=self.if_var.get().strip(),
            bpf=self.filter_var.get().strip(),
            on_row_cb=self.append_row,
        )
        if ok:
            for iid in self.tree.get_children():
                self.tree.delete(iid)
            self.app.capture_rows.clear()
            self.btn_start.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.NORMAL)
            self.btn_export.config(state=tk.DISABLED)
            self.btn_save.config(state=tk.DISABLED)
            self.status_var.set("Capturing…")

    def on_stop(self):
        self.app.stop_capture()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        has = bool(self.app.capture_rows)
        self.btn_export.config(state=(tk.NORMAL if has else tk.DISABLED))
        self.btn_save.config(state=(tk.NORMAL if has else tk.DISABLED))
        self.status_var.set(f"Stopped. Rows captured: {len(self.app.capture_rows)}")

    def on_export(self):
        if not self.app.capture_rows:
            messagebox.showinfo("Nothing to export", "No captured rows yet.")
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="Export to CSV",
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

    def on_save(self):
        if not self.app.capture_rows:
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        Path("evidence").mkdir(exist_ok=True)
        try:
            export_rows_to_csv(self.app.capture_rows, f"evidence/capture_{ts}.csv")
            messagebox.showinfo("Saved", "Session saved into evidence/")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))


# -------------------- Port Scanner --------------------
class ScannerScreen(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=20)
        self.app = app

        top = ttk.Frame(self, padding=16, relief=tk.GROOVE)
        top.pack(fill=tk.X)
        ttk.Button(top, text="← Home", command=lambda: app.show("HomeScreen")).pack(side=tk.LEFT)
        ttk.Label(top, text="Port Scanner", style="SectionTitle.TLabel").pack(side=tk.LEFT, padx=12)
        ttk.Label(top, text="●", font=("Segoe UI", 26)).pack(side=tk.RIGHT)

        row = ttk.Frame(self)
        row.pack(fill=tk.X, pady=14)
        ttk.Label(row, text="Enter Target IP").pack(side=tk.LEFT)
        self.target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(row, textvariable=self.target_var, width=36).pack(side=tk.LEFT, padx=(12, 24))

        ttk.Button(self, text="Start Scan", style="Big.TButton", command=self.on_scan)\
            .pack(anchor="w", pady=(0, 8))

        cols = ("host", "open_ports")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=16)
        self.tree.heading("host", text="IP Address")
        self.tree.heading("open_ports", text="Open Ports")
        self.tree.column("host", width=260, anchor=tk.W)
        self.tree.column("open_ports", width=520, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=6)

        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, pady=(10, 0))
        self.btn_save   = ttk.Button(bottom, text="Save Results",  style="Big.TButton",
                                     command=self.on_save, state=tk.DISABLED)
        self.btn_export = ttk.Button(bottom, text="Export Report", style="Big.TButton",
                                     command=self.on_export, state=tk.DISABLED)
        self.btn_save.pack(side=tk.LEFT, padx=8)
        self.btn_export.pack(side=tk.RIGHT, padx=8)

    def on_scan(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.app.scan_rows.clear()

        rows = self.app.run_quick_scan(self.target_var.get().strip(), "top-100")
        if not rows:
            return

        by_host = {}
        for host, _state, _proto, port, status in rows:
            if status == "open":
                by_host.setdefault(host, []).append(str(port))
        for host, ports in by_host.items():
            self.tree.insert("", tk.END, values=[host, ", ".join(ports) or "—"])

        has = any(by_host.values())
        self.btn_save.config(state=(tk.NORMAL if has else tk.DISABLED))
        self.btn_export.config(state=(tk.NORMAL if has else tk.DISABLED))

    def on_export(self):
        if not self.app.scan_rows:
            messagebox.showinfo("Nothing to export", "No scan results yet.")
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="Export report (CSV)",
            defaultextension=".csv",
            initialfile=f"scan_{ts}.csv",
            filetypes=[("CSV files", "*.csv")],
        )
        if not path:
            return
        try:
            export_rows_to_csv(self.app.scan_rows, path)
            messagebox.showinfo("Exported", f"Saved raw scan rows to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def on_save(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        Path("evidence").mkdir(exist_ok=True)
        try:
            export_rows_to_csv(self.app.scan_rows, f"evidence/scan_{ts}.csv")
            messagebox.showinfo("Saved", "Scan rows saved into evidence/")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))


# -------------------- Settings --------------------
class SettingsScreen(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=24)
        self.app = app

        top = ttk.Frame(self, padding=16, relief=tk.GROOVE)
        top.pack(fill=tk.X)
        ttk.Button(top, text="← Home", command=lambda: app.show("HomeScreen")).pack(side=tk.LEFT)
        ttk.Label(top, text="Settings", style="SectionTitle.TLabel").pack(side=tk.LEFT, padx=12)
        ttk.Label(top, text="●", font=("Segoe UI", 24)).pack(side=tk.RIGHT)

        body = ttk.Frame(self)
        body.pack(fill=tk.BOTH, expand=True, pady=16)

        # consent toggle
        self.consent_var = tk.BooleanVar(value=app.user_consented)
        c1 = ttk.Checkbutton(
            body,
            text="I consent to packet capture and basic port scanning for this session",
            variable=self.consent_var,
            command=self.on_toggle_consent
        )
        c1.pack(fill=tk.X, pady=8, ipady=8)

        # filter settings (info only for MVP)
        ttk.Button(body, text="Packet Capture Filter Settings", style="Tile.TButton",
                   command=self.edit_filters).pack(fill=tk.X, pady=8, ipady=10)

        # export all sessions (current runtime only for MVP)
        ttk.Button(body, text="Export All Sessions", style="Tile.TButton",
                   command=self.export_all).pack(fill=tk.X, pady=8, ipady=10)

        # reset defaults
        ttk.Button(body, text="Reset to Default Settings", style="Tile.TButton",
                   command=self.reset_defaults).pack(fill=tk.X, pady=8, ipady=10)

    def on_toggle_consent(self):
        self.app.user_consented = bool(self.consent_var.get())

    def edit_filters(self):
        messagebox.showinfo(
            "Filters",
            "Enter BPF filters on the Packet Capture screen (e.g., icmp, tcp, udp, port 53).\n"
            "Presets and profiles planned for CS302."
        )

    def export_all(self):
        Path("evidence").mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        ok_any = False
        errors = []

        if self.app.capture_rows:
            try:
                export_rows_to_csv(self.app.capture_rows, f"evidence/all_captures_{ts}.csv")
                ok_any = True
            except Exception as e:
                errors.append(f"Captures: {e}")

        if self.app.scan_rows:
            try:
                export_rows_to_csv(self.app.scan_rows, f"evidence/all_scans_{ts}.csv")
                ok_any = True
            except Exception as e:
                errors.append(f"Scans: {e}")

        if ok_any and not errors:
            messagebox.showinfo("Exported", "Saved available sessions into evidence/")
        elif ok_any and errors:
            messagebox.showwarning("Partially exported", "\n".join(errors))
        else:
            messagebox.showinfo("Nothing to export", "No sessions available or export failed.")

    def reset_defaults(self):
        self.app.user_consented = False
        self.consent_var.set(False)
        messagebox.showinfo("Reset", "Settings reset. Consent disabled.")


def main():
    app = App()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app.mainloop()


if __name__ == "__main__":
    main()
