# app/gui_app.py
"""
GUI base for the Network Sniffer MVP (teaching-first).
This first chunk builds:
- App shell with styles
- Top-left 'Navigate' menu
- Simple Home screen placeholder
"""

import tkinter as tk
from tkinter import ttk


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Sniffer MVP")
        self.geometry("1060x620")

        self._init_styles()
        self._build_menu()

        # screen container
        self.container = ttk.Frame(self)
        self.container.pack(fill=tk.BOTH, expand=True)

        # register screens (we’ll fill these in later)
        self.screens = {}
        for Screen in (HomeScreen,):
            frame = Screen(self.container, self)
            self.screens[Screen.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show("HomeScreen")

    # ---------- styles & menu ----------
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
        # More pages will be added later (Capture, Scanner, Settings, About)
        m.add_cascade(label="Navigate", menu=nav)
        self.config(menu=m)

    # ---------- navigation ----------
    def show(self, name: str):
        self.screens[name].tkraise()


# -------------------- Home Screen (placeholder) --------------------
class HomeScreen(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        shell = ttk.Frame(self, padding=32)
        shell.pack(fill=tk.BOTH, expand=True)
        ttk.Label(shell, text="Network Sniffer", style="BigTitle.TLabel").pack()


def main():
    app = App()
    # Windows DPI awareness (safe to ignore elsewhere)
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app.mainloop()


if __name__ == "__main__":
    main()
