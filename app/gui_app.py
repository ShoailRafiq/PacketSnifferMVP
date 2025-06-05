# app/gui_app.py
"""
GUI with Home + Packet Capture.
Capture screen: header band, interface + filter, big Start/Stop,
live table, Save Session + Export to File.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List, Optional
from datetime import datetime
from pathlib import Path

from scapy.all import get_if_list
from app.sniffer import Sniffer
from app.utils import export_rows_to_csv


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Sniffer MVP")
        self.geometry("1060x620")

        self._init_styles()
        self._build_menu()

        # consent flag (can be toggled later in Settings; default off)
        self.user_consented: bool = False

        # shared capture state
        self.sniffer: Optional[Sniffer] = None
        self.capture_rows: List[List] = []

        self.container = ttk.Frame(self)
        self.container.pack(fill=tk.BOTH, expand=True)

        self.screens = {}
        for Screen in (HomeScreen, CaptureScreen):
            frame = Screen(self.container, self)
            self.screens[Screen.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show("HomeScreen")

        # First-run consent prompt (educational/ethical requirement)
        self.after(250, self.prompt_consent_if_needed)

    # ---------- base helpers ----------
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
        m.add_cascade(label="Navigate", menu=nav)
        self.config(menu=m)

    def show(self, name: str):
        self.screens[name].tkraise()

    # ---------- consent ----------
    def prompt_consent_if_needed(self):
        if not self.user_consented:
            ok = messagebox.askyesno(
                "Consent required",
                "This educational tool captures network metadata only (no payloads).\n"
                "Do you consent to proceed?"
            )
            self.user_consented = bool(ok)

    # ---------- capture helpers ----------
    def start_capture(self, iface: str, bpf: str, on_row_cb):
        if not self.user_consented:
            messagebox.showwarning("Consent required", "Enable consent to start capturing.")
            return False
        if self.sniffer:
            return True  # already running
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
        tile("Port Scanner",        lambda: messagebox.showinfo("Scanner", "Scanner screen coming next."))
        tile("View Logs",           lambda: messagebox.showinfo("View Logs", "Planned for CS302."))
        tile("Settings",            lambda: messagebox.showinfo("Settings", "Settings coming later."))


# -------------------- Packet Capture --------------------
class CaptureScreen(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=20)
        self.app = app

        # Header band
        top = ttk.Frame(self, padding=16, relief=tk.GROOVE)
        top.pack(fill=tk.X)
        ttk.Button(top, text="← Home", command=lambda: app.show("HomeScreen")).pack(side=tk.LEFT)
        ttk.Label(top, text="Packet Capture", style="SectionTitle.TLabel").pack(side=tk.LEFT, padx=12)
        ttk.Label(top, text="●", font=("Segoe UI", 26)).pack(side=tk.RIGHT)

        # Controls
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

        # Table
        cols = ("timestamp", "src", "dst", "proto", "length", "info")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=16)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=140 if c != "info" else 320, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=6)
        yscroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        yscroll.place(relx=1.0, rely=0.36, relheight=0.56, anchor="ne")

        # Bottom actions
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
            # clear previous
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
        path = f"evidence/capture_{ts}.csv"
        try:
            export_rows_to_csv(self.app.capture_rows, path)
            messagebox.showinfo("Saved", f"Session saved to {path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))


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
