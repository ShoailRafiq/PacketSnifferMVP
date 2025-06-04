# app/gui_app.py
"""
Tkinter GUI for Packet Sniffer MVP
Matches the IDD layout: toolbar, tabbed main area, status bar.
"""

import tkinter as tk
from tkinter import ttk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Packet Sniffer MVP")
        self.geometry("1024x600")

        # Build UI
        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()

    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=(8, 6))
        bar.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(bar, text="Interface:").pack(side=tk.LEFT)
        self.if_var = tk.StringVar()
        self.if_combo = ttk.Combobox(bar, textvariable=self.if_var, width=40, state="readonly")
        self.if_combo.pack(side=tk.LEFT, padx=(6, 12))

        ttk.Label(bar, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.filter_var, width=20).pack(side=tk.LEFT, padx=(6, 12))

        self.btn_start = ttk.Button(bar, text="Start")
        self.btn_stop = ttk.Button(bar, text="Stop", state=tk.DISABLED)
        self.btn_export = ttk.Button(bar, text="Export CSV", state=tk.DISABLED)

        self.btn_start.pack(side=tk.LEFT)
        self.btn_stop.pack(side=tk.LEFT, padx=(6, 12))
        self.btn_export.pack(side=tk.LEFT)

    def _build_tabs(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Sniffer tab
        self.sniffer_tab = ttk.Frame(notebook)
        notebook.add(self.sniffer_tab, text="Sniffer")

        cols = ("timestamp", "src", "dst", "proto", "length", "info")
        self.sniffer_tree = ttk.Treeview(self.sniffer_tab, columns=cols, show="headings")
        for c in cols:
            self.sniffer_tree.heading(c, text=c)
            self.sniffer_tree.column(c, width=130 if c != "info" else 300)
        self.sniffer_tree.pack(fill=tk.BOTH, expand=True)

        # Scanner tab
        self.scanner_tab = ttk.Frame(notebook)
        notebook.add(self.scanner_tab, text="Scanner")

        self.scan_output = tk.Text(self.scanner_tab, wrap="word", height=20)
        self.scan_output.pack(fill=tk.BOTH, expand=True)

    def _build_statusbar(self):
        bar = ttk.Frame(self, relief=tk.SUNKEN)
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.status_var, padding=(8, 4)).pack(side=tk.LEFT)


def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
