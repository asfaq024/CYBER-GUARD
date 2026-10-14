#!/usr/bin/env python3
"""
CyberGuard GUI - a fast, clean front end for cyber_guard_ai.py

Setup:  put this file in the SAME folder as cyber_guard_ai.py, then run
            python cyber_guard_gui.py
Needs:  Python 3.8+ with tkinter (included with the standard Windows/macOS
        installers; on Linux: sudo apt install python3-tk). No other packages.
"""
import contextlib
import io
import os
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import cyber_guard_ai as cg
except ImportError as exc:
    _r = tk.Tk()
    _r.withdraw()
    messagebox.showerror(
        "CyberGuard",
        "Could not load cyber_guard_ai.py.\n"
        "Put this file in the same folder as it.\n\n" + str(exc),
    )
    sys.exit(1)

# ------------------------------------------------------------- look & feel
BG, PANEL, CARD, BORDER = "#0f1419", "#151b23", "#1c2530", "#2a3441"
FG, MUTED = "#e6edf3", "#8b98a5"
ACCENT, ACCENT_DIM = "#3b82f6", "#1f3a63"
RED, AMBER, GREEN = "#ef4444", "#f59e0b", "#22c55e"

if sys.platform == "win32":
    FONT, MONO = "Segoe UI", "Consolas"
elif sys.platform == "darwin":
    FONT, MONO = "Helvetica Neue", "Menlo"
else:
    FONT, MONO = "DejaVu Sans", "DejaVu Sans Mono"

LEVEL_STYLE = {
    "DANGEROUS": ("\u26d4  DANGEROUS", RED),
    "SUSPICIOUS": ("\u26a0  SUSPICIOUS", AMBER),
    "LOW RISK": ("\u2714  LOW RISK", GREEN),
}
RANK = {"LOW RISK": 0, "SUSPICIOUS": 1, "DANGEROUS": 2}
DOWNLOADS = Path.home() / "Downloads"


def setup_style(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=FG, font=(FONT, 10))
    s.configure("TFrame", background=BG)
    s.configure("TLabel", background=BG, foreground=FG)
    s.configure("TButton", background=CARD, foreground=FG, bordercolor=BORDER,
                lightcolor=CARD, darkcolor=CARD, focuscolor=CARD,
                padding=(14, 7), relief="flat")
    s.map("TButton", background=[("active", "#2a3644"), ("disabled", PANEL)],
          foreground=[("disabled", MUTED)])
    s.configure("Accent.TButton", background=ACCENT, foreground="white",
                bordercolor=ACCENT, lightcolor=ACCENT, darkcolor=ACCENT,
                focuscolor=ACCENT, font=(FONT, 10, "bold"))
    s.map("Accent.TButton", background=[("active", "#2563eb"), ("disabled", "#27406b")],
          foreground=[("disabled", "#8aa4cf")])
    s.configure("TEntry", fieldbackground=CARD, foreground=FG, insertcolor=FG,
                bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER, padding=6)
    s.map("TEntry", bordercolor=[("focus", ACCENT)], lightcolor=[("focus", ACCENT)],
          darkcolor=[("focus", ACCENT)])
    s.configure("TCheckbutton", background=BG, foreground=FG)
    s.map("TCheckbutton", background=[("active", BG)], foreground=[("disabled", MUTED)])
    s.configure("TCombobox", fieldbackground=CARD, background=CARD, foreground=FG,
                arrowcolor=FG, bordercolor=BORDER, padding=5)
    s.map("TCombobox", fieldbackground=[("readonly", CARD)], foreground=[("readonly", FG)])
    root.option_add("*TCombobox*Listbox.background", CARD)
    root.option_add("*TCombobox*Listbox.foreground", FG)
    s.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=FG,
                rowheight=27, borderwidth=0)
    s.configure("Treeview.Heading", background=PANEL, foreground=MUTED,
                relief="flat", font=(FONT, 9, "bold"))
    s.map("Treeview", background=[("selected", "#2b4a7a")], foreground=[("selected", "white")])
    s.map("Treeview.Heading", background=[("active", PANEL)])
    s.configure("TProgressbar", troughcolor=CARD, background=ACCENT, bordercolor=CARD,
                lightcolor=ACCENT, darkcolor=ACCENT, thickness=6)
    s.configure("Vertical.TScrollbar", background=CARD, troughcolor=BG, bordercolor=BG,
                arrowcolor=MUTED, lightcolor=CARD, darkcolor=CARD)


# ----------------------------------------------------------------- helpers
def capture(fn, *args):
    """Run a function that print()s and return what it printed."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            fn(*args)
    except Exception as exc:  # show the problem instead of crashing the UI
        buf.write(f"\nCould not complete action: {exc}")
    return buf.getvalue().strip()


def open_folder(path):
    try:
        if sys.platform == "win32":
            os.startfile(str(path))  # noqa
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except OSError as exc:
        messagebox.showerror("CyberGuard", f"Could not open folder:\n{exc}")


def ro_text(parent, mono=False, height=8):
    t = tk.Text(parent, height=height, wrap="word", bg=CARD, fg=FG, relief="flat", bd=0,
                highlightthickness=0, padx=10, pady=6, state="disabled", cursor="arrow",
                font=(MONO if mono else FONT, 10 if mono else 11), spacing3=4)
    t.tag_configure("h", font=(FONT, 9, "bold"), foreground=MUTED, spacing1=10, spacing3=4)
    t.tag_configure("b", lmargin1=6, lmargin2=22)
    t.tag_configure("m", foreground=MUTED, font=(FONT, 9))
    t.tag_configure("bold", font=(FONT, 11, "bold"))
    t.bind("<1>", lambda e: t.focus_set())
    return t


def put(t, parts):
    t.configure(state="normal")
    t.delete("1.0", "end")
    for text, tag in parts:
        t.insert("end", text, tag)
    t.configure(state="disabled")


def make_tree(parent, columns, height=8):
    wrap = tk.Frame(parent, bg=BG)
    tree = ttk.Treeview(wrap, columns=[c[0] for c in columns], show="headings",
                        height=height, selectmode="browse")
    for cid, title, width, stretch in columns:
        tree.heading(cid, text=title, anchor="w")
        tree.column(cid, width=width, stretch=stretch, anchor="w")
    sb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    for level, (_, color) in LEVEL_STYLE.items():
        tree.tag_configure(level, foreground=color)
    return wrap, tree


def text_input(parent, height=6):
    return tk.Text(parent, height=height, wrap="word", bg=CARD, fg=FG, insertbackground=FG,
                   relief="flat", padx=12, pady=10, font=(FONT, 11),
                   highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT)


def clipboard_text(widget):
    try:
        return widget.clipboard_get()
    except tk.TclError:
        return ""


# ------------------------------------------------------------ result panel
class ResultPanel(tk.Frame):
    """Big colored verdict + plain-language reasons."""

    def __init__(self, parent):
        super().__init__(parent, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        self.stripe = tk.Frame(self, bg=BORDER, width=6)
        self.stripe.pack(side="left", fill="y")
        inner = tk.Frame(self, bg=CARD)
        inner.pack(side="left", fill="both", expand=True)
        self.badge = tk.Label(inner, font=(FONT, 18, "bold"), bg=CARD, fg=MUTED, anchor="w")
        self.badge.pack(fill="x", padx=18, pady=(14, 0))
        self.sub = tk.Label(inner, font=(FONT, 10), bg=CARD, fg=MUTED, anchor="w")
        self.sub.pack(fill="x", padx=18)
        self.text = ro_text(inner)
        self.text.pack(fill="both", expand=True, padx=8, pady=(4, 10))
        self.reset()

    def reset(self, msg="Result will appear here"):
        self.stripe.configure(bg=BORDER)
        self.badge.configure(text=msg, fg=MUTED)
        self.sub.configure(text="")
        put(self.text, [])

    def busy(self, msg="Checking\u2026"):
        self.reset(msg)

    def show(self, level, score, reasons, advice=(), notes=(), caption=""):
        # The backend may return descriptive verdicts such as
        # "NO STRONG SIGNALS" rather than one of the GUI's three risk levels.
        # Normalize common variants and safely handle unknown values.
        level_text = str(level or "").strip().upper().replace("_", " ").replace("-", " ")
        if level_text in {"DANGEROUS", "HIGH", "HIGH RISK", "CRITICAL", "MALICIOUS"}:
            level = "DANGEROUS"
        elif level_text in {"SUSPICIOUS", "MEDIUM", "MEDIUM RISK", "WARNING", "MODERATE RISK"}:
            level = "SUSPICIOUS"
        elif level_text in {"LOW RISK", "LOW", "SAFE", "NO STRONG SIGNALS", "NO STRONG SIGNAL", "CLEAN", "BENIGN", "NORMAL"}:
            level = "LOW RISK"
        else:
            # Unknown backend labels should not crash the Tkinter callback.
            # Keep the display conservative by treating them as suspicious.
            level = "SUSPICIOUS"
        label, color = LEVEL_STYLE[level]
        self.stripe.configure(bg=color)
        self.badge.configure(text=label, fg=color)
        self.sub.configure(text=f"Risk score {score}" + (f"   \u00b7   {caption}" if caption else ""))
        parts = [("WHY", "h")]
        if reasons:
            parts += [(f"\u2022  {r}\n", "b") for r in reasons]
        else:
            parts.append(("\u2022  Nothing suspicious found\n", "b"))
        if notes:
            parts.append(("NOTES", "h"))
            parts += [(f"\u2022  {n}\n", "b") for n in notes]
        if advice:
            parts.append(("WHAT TO DO", "h"))
            parts += [(f"\u2022  {a}\n", "b") for a in advice]
        parts.append(("\nHeuristic screening \u2014 a clean result is not a guarantee of safety.", "m"))
        put(self.text, parts)


# -------------------------------------------------------------- page base
class Page(tk.Frame):
    title = ""
    subtitle = ""

    def __init__(self, parent, app):
        super().__init__(parent, bg=BG)
        self.app = app
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=28, pady=(22, 6))
        tk.Label(head, text=self.title, font=(FONT, 20, "bold"), bg=BG, fg=FG).pack(anchor="w")
        tk.Label(head, text=self.subtitle, font=(FONT, 10), bg=BG, fg=MUTED,
                 wraplength=720, justify="left").pack(anchor="w", pady=(2, 0))
        self.body = tk.Frame(self, bg=BG)
        self.body.pack(fill="both", expand=True, padx=28, pady=(8, 20))
        self.build()

    def build(self):
        pass

    def on_show(self):
        pass

    def run_with(self, value):
        pass


def row(parent, pady=(10, 0)):
    f = tk.Frame(parent, bg=BG)
    f.pack(fill="x", pady=pady)
    return f


# ------------------------------------------------------------------- pages
def check_message(text):
    s, reasons = cg.analyze_text(text)
    c = cg.classify_message(text)
    level = cg.verdict(s)
    # Convert backend verdict text to the GUI's canonical level names.
    verdict_text = str(level or "").strip().upper().replace("_", " ").replace("-", " ")
    if verdict_text in {"DANGEROUS", "HIGH", "HIGH RISK", "CRITICAL", "MALICIOUS"}:
        level = "DANGEROUS"
    elif verdict_text in {"SUSPICIOUS", "MEDIUM", "MEDIUM RISK", "WARNING", "MODERATE RISK"}:
        level = "SUSPICIOUS"
    else:
        level = "LOW RISK"
    c_level = {"HIGH": "DANGEROUS", "MEDIUM": "SUSPICIOUS"}.get(str(c.get("risk", "")).upper(), "LOW RISK")
    if RANK[c_level] > RANK[level]:
        level = c_level
    # Evidence formats can differ between backend versions. Do not assume
    # every evidence item is a dictionary containing the "feature" key.
    extra = []
    for evidence in c.get("evidence", []):
        if isinstance(evidence, dict):
            feature = (
                evidence.get("feature")
                or evidence.get("reason")
                or evidence.get("description")
                or evidence.get("indicator")
            )
        elif isinstance(evidence, str):
            feature = evidence
        else:
            feature = None

        if feature:
            feature = str(feature)
            if not feature.startswith("URL:"):
                extra.append(feature)

    reasons = list(dict.fromkeys(list(reasons) + extra))
    return level, max(s, c["score"]), reasons, c["advice"], c["protective_context"]


class MessagePage(Page):
    title = "Check a message"
    subtitle = "Paste an SMS, WhatsApp or chat message to look for scam and phishing signs."

    def build(self):
        self.box = text_input(self.body)
        self.box.pack(fill="x")
        self.box.bind("<Control-Return>", lambda e: (self.run(), "break")[1])
        r = row(self.body)
        ttk.Button(r, text="Analyze   (Ctrl+Enter)", style="Accent.TButton",
                   command=self.run).pack(side="left")
        ttk.Button(r, text="Paste", command=self.paste).pack(side="left", padx=8)
        ttk.Button(r, text="Clear", command=self.clear).pack(side="left")
        self.result = ResultPanel(self.body)
        self.result.pack(fill="both", expand=True, pady=(14, 0))

    def on_show(self):
        self.box.focus_set()

    def paste(self):
        self.box.delete("1.0", "end")
        self.box.insert("1.0", clipboard_text(self))
        self.run()

    def clear(self):
        self.box.delete("1.0", "end")
        self.result.reset()

    def run_with(self, value):
        self.box.delete("1.0", "end")
        self.box.insert("1.0", value)
        self.run()

    def run(self):
        text = self.box.get("1.0", "end").strip()
        if not text:
            self.result.reset("Paste a message first")
            return
        level, score, reasons, advice, notes = check_message(text)
        self.result.show(level, score, reasons, advice if level != "LOW RISK" else (), notes)


class LinkPage(Page):
    title = "Check a link"
    subtitle = "Analyzes the web address only. The link is never opened or fetched."

    def build(self):
        self.var = tk.StringVar()
        r = row(self.body, (0, 0))
        self.entry = ttk.Entry(r, textvariable=self.var, font=(FONT, 11))
        self.entry.pack(side="left", fill="x", expand=True, ipady=3)
        self.entry.bind("<Return>", lambda e: self.run())
        ttk.Button(r, text="Check", style="Accent.TButton", command=self.run).pack(side="left", padx=(8, 0))
        ttk.Button(r, text="Paste", command=self.paste).pack(side="left", padx=(8, 0))
        self.result = ResultPanel(self.body)
        self.result.pack(fill="both", expand=True, pady=(14, 0))

    def on_show(self):
        self.entry.focus_set()

    def paste(self):
        self.var.set(clipboard_text(self).strip())
        self.run()

    def run_with(self, value):
        self.var.set(value)
        self.run()

    def run(self):
        url = self.var.get().strip()
        if not url:
            self.result.reset("Enter a link first")
            return
        res = cg.inspect_url(url)
        self.result.show(res["risk"], res["score"], res["reasons"], res["advice"],
                         caption=res["host"] or "")


class EmailPage(Page):
    title = "Check an email"
    subtitle = "Open a saved .eml file to look for spoofing, fake links and dangerous attachments."

    def build(self):
        self.var = tk.StringVar()
        r = row(self.body, (0, 0))
        self.entry = ttk.Entry(r, textvariable=self.var, font=(FONT, 11))
        self.entry.pack(side="left", fill="x", expand=True, ipady=3)
        self.entry.bind("<Return>", lambda e: self.run())
        ttk.Button(r, text="Browse\u2026", command=self.browse).pack(side="left", padx=(8, 0))
        ttk.Button(r, text="Analyze", style="Accent.TButton", command=self.run).pack(side="left", padx=(8, 0))
        self.result = ResultPanel(self.body)
        self.result.pack(fill="both", expand=True, pady=(14, 0))

    def browse(self):
        p = filedialog.askopenfilename(title="Choose an email", filetypes=[("Email", "*.eml"), ("All files", "*.*")])
        if p:
            self.var.set(p)
            self.run()

    def run_with(self, value):
        self.var.set(value)
        self.run()

    def run(self):
        p = self.var.get().strip().strip('"')
        if not p:
            self.result.reset("Choose an .eml file first")
            return
        try:
            score, reasons = cg.analyze_email(p)
        except (OSError, ValueError) as exc:
            self.result.reset(f"Could not read file: {exc}")
            return
        level = cg.verdict(score)
        advice = ["Don't click links or open attachments.",
                  "Visit the company's site by typing its address yourself.",
                  "Report the email as phishing in your mail app."] if level != "LOW RISK" else ()
        self.result.show(level, score, reasons, advice, caption=Path(p).name)


class PhonePage(Page):
    title = "Check a phone number"
    subtitle = "Include the country code (for example +91\u2026). Spots callback scams and spoofed numbers."

    def build(self):
        self.var = tk.StringVar()
        self.mine = tk.StringVar()
        r = row(self.body, (0, 0))
        self.entry = ttk.Entry(r, textvariable=self.var, font=(FONT, 11))
        self.entry.pack(side="left", fill="x", expand=True, ipady=3)
        self.entry.bind("<Return>", lambda e: self.run())
        ttk.Button(r, text="Check", style="Accent.TButton", command=self.run).pack(side="left", padx=(8, 0))
        ttk.Button(r, text="Add to blocklist", command=self.block).pack(side="left", padx=(8, 0))
        r2 = row(self.body, (8, 0))
        tk.Label(r2, text="Your own number (optional, detects spoofing):", bg=BG, fg=MUTED,
                 font=(FONT, 9)).pack(side="left")
        ttk.Entry(r2, textvariable=self.mine, width=20).pack(side="left", padx=8)
        self.note = tk.Label(self.body, text="", bg=BG, fg=GREEN, font=(FONT, 9), anchor="w")
        self.note.pack(fill="x", pady=(6, 0))
        self.result = ResultPanel(self.body)
        self.result.pack(fill="both", expand=True, pady=(8, 0))

    def on_show(self):
        self.entry.focus_set()

    def run_with(self, value):
        self.var.set(value)
        self.run()

    def run(self):
        n = self.var.get().strip()
        if not n:
            self.result.reset("Enter a number first")
            return
        self.note.configure(text="")
        score, reasons = cg.analyze_number(n, self.mine.get().strip() or None)
        level = cg.verdict(score)
        advice = ["Don't call back unknown international numbers.",
                  "Block and report it using your phone's built-in tools."] if level != "LOW RISK" else ()
        self.result.show(level, score, reasons, advice, caption=cg.normalize_number(n))

    def block(self):
        n = self.var.get().strip()
        if not n:
            return
        capture(cg.block_number, n)
        self.note.configure(
            text=f"\u2714 Added {cg.normalize_number(n)} to your blocklist. Also block it in your phone's dialer.")


class FilePage(Page):
    title = "Scan files"
    subtitle = "Scan a file or a whole folder for malware signs. Only suspicious files are listed."

    def build(self):
        self.path = tk.StringVar()
        self.q_var = tk.BooleanVar(value=False)
        self.d_var = tk.BooleanVar(value=False)
        self.rows = {}
        self.total = 0
        self.flagged = 0
        self.cancel_evt = threading.Event()

        r = row(self.body, (0, 0))
        e = ttk.Entry(r, textvariable=self.path, font=(FONT, 11))
        e.pack(side="left", fill="x", expand=True, ipady=3)
        e.bind("<Return>", lambda ev: self.start())
        ttk.Button(r, text="File\u2026", command=self.pick_file).pack(side="left", padx=(8, 0))
        ttk.Button(r, text="Folder\u2026", command=self.pick_folder).pack(side="left", padx=(8, 0))

        o = row(self.body, (10, 0))
        ttk.Checkbutton(o, text="Quarantine dangerous files automatically", variable=self.q_var).pack(side="left")
        self.def_chk = ttk.Checkbutton(o, text="Ask Windows Defender too (slower)", variable=self.d_var)
        self.def_chk.pack(side="left", padx=(16, 0))
        if sys.platform != "win32":
            self.def_chk.state(["disabled"])
        self.stop_btn = ttk.Button(o, text="Cancel", command=lambda: self.cancel_evt.set())
        self.stop_btn.pack(side="right")
        self.stop_btn.state(["disabled"])
        self.go = ttk.Button(o, text="Scan", style="Accent.TButton", command=self.start)
        self.go.pack(side="right", padx=(0, 8))

        self.progress = ttk.Progressbar(self.body, mode="determinate")
        self.progress.pack(fill="x", pady=(12, 0))
        self.status = tk.Label(self.body, text="Ready", bg=BG, fg=MUTED, font=(FONT, 9), anchor="w")
        self.status.pack(fill="x", pady=(4, 6))

        wrap, self.tree = make_tree(self.body, [("v", "Verdict", 110, False), ("s", "Score", 60, False),
                                                ("f", "File", 560, True)], height=7)
        wrap.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        d = tk.Frame(self.body, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        d.pack(fill="x", pady=(10, 0))
        self.detail = ro_text(d, height=5)
        self.detail.pack(fill="x")
        self.q_btn = ttk.Button(self.body, text="Quarantine selected file", command=self.quarantine_selected)
        self.q_btn.pack(anchor="e", pady=(8, 0))
        self.q_btn.state(["disabled"])

    def pick_file(self):
        p = filedialog.askopenfilename(title="Choose a file to scan")
        if p:
            self.path.set(p)
            self.start()

    def pick_folder(self):
        p = filedialog.askdirectory(title="Choose a folder to scan")
        if p:
            self.path.set(p)
            self.start()

    def run_with(self, value):
        self.path.set(value)
        self.start()

    # --- scanning
    def start(self):
        target = self.path.get().strip().strip('"')
        if not target or not Path(target).exists():
            messagebox.showinfo("CyberGuard", "Choose an existing file or folder first.")
            return
        if str(self.go.cget("state")) == "disabled":
            return
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        put(self.detail, [])
        self.flagged = 0
        self.cancel_evt = threading.Event()
        self.go.state(["disabled"])
        self.stop_btn.state(["!disabled"])
        self.q_btn.state(["disabled"])
        self.status.configure(text="Collecting files\u2026")
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        threading.Thread(target=self._worker, daemon=True,
                         args=(Path(target), self.q_var.get(), self.d_var.get(), self.cancel_evt)).start()

    def _worker(self, target, quar, defender, cancel):
        post = self.app.post
        files = []
        if target.is_file():
            files = [target]
        else:
            try:
                for p in target.rglob("*"):
                    if cancel.is_set():
                        break
                    try:
                        if p.is_file():
                            files.append(p)
                    except OSError:
                        pass
            except OSError:
                pass
        post(lambda n=len(files): self._on_total(n))
        show_all = target.is_file()
        last = 0.0
        i = 0
        for i, f in enumerate(files, 1):
            if cancel.is_set():
                break
            try:
                score, reasons = cg.scan_file(f, defender)
            except Exception as exc:
                score, reasons = 0, [f"Could not scan: {exc}"]
            level = cg.verdict(score)
            moved = None
            if quar and level == "DANGEROUS":
                try:
                    moved = cg.quarantine(f)
                except OSError as exc:
                    reasons = list(reasons) + [f"Could not quarantine: {exc}"]
            if level != "LOW RISK" or show_all:
                post(lambda a=(f, score, reasons, level, moved): self._on_hit(*a))
            now = time.time()
            if now - last > 0.1:
                last = now
                post(lambda k=i: self._on_progress(k))
        post(lambda k=i, c=cancel.is_set(): self._on_done(k, c))

    def _on_total(self, n):
        self.total = n
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=max(n, 1), value=0)
        self.status.configure(text=f"Scanning {n} file(s)\u2026")

    def _on_progress(self, i):
        self.progress.configure(value=i)
        self.status.configure(text=f"Scanning {i}/{self.total}   \u00b7   {self.flagged} flagged")

    def _on_hit(self, f, score, reasons, level, moved):
        if level != "LOW RISK":
            self.flagged += 1
        shown = f"(quarantined)  {f}" if moved else str(f)
        iid = self.tree.insert("", "end", values=(level, score, shown), tags=(level,))
        self.rows[iid] = dict(path=f, score=score, reasons=reasons, level=level, moved=moved)
        if len(self.rows) == 1:
            self.tree.selection_set(iid)

    def _on_done(self, i, cancelled):
        self.progress.stop()
        self.progress.configure(mode="determinate", value=self.progress["maximum"] if not cancelled else i)
        self.go.state(["!disabled"])
        self.stop_btn.state(["disabled"])
        word = "Cancelled" if cancelled else "Done"
        self.status.configure(text=f"{word}.  {self.flagged} flagged out of {self.total} file(s).",
                              fg=RED if self.flagged else GREEN)
        if not self.rows and not cancelled:
            put(self.detail, [("\u2714  No suspicious files found.", "bold")])

    def on_select(self, _=None):
        sel = self.tree.selection()
        if not sel:
            return
        r = self.rows[sel[0]]
        parts = [(f"{r['level']}  (score {r['score']})\n", "bold"), (f"{r['path']}\n", "m")]
        parts += [(f"\u2022  {x}\n", "b") for x in r["reasons"]] or [("\u2022  Nothing suspicious found\n", "b")]
        if r["moved"]:
            parts.append((f"Moved to quarantine: {r['moved']}\n", "m"))
        put(self.detail, parts)
        can = Path(r["path"]).exists() and not r["moved"]
        self.q_btn.state(["!disabled"] if can else ["disabled"])

    def quarantine_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        r = self.rows[sel[0]]
        if not messagebox.askyesno("Quarantine", f"Move this file to quarantine?\n\n{r['path']}"):
            return
        try:
            r["moved"] = cg.quarantine(r["path"])
        except OSError as exc:
            messagebox.showerror("CyberGuard", f"Could not quarantine:\n{exc}")
            return
        self.tree.set(sel[0], "f", f"(quarantined)  {r['path']}")
        self.on_select()


class WatchPage(Page):
    title = "Watch a folder"
    subtitle = "Checks every new file that appears in a folder (Downloads by default) and warns you."

    def build(self):
        self.folder = tk.StringVar(value=str(DOWNLOADS))
        self.auto = tk.BooleanVar(value=False)
        self.stop_evt = None
        self.rows = {}

        r = row(self.body, (0, 0))
        ttk.Entry(r, textvariable=self.folder, font=(FONT, 11)).pack(side="left", fill="x", expand=True, ipady=3)
        ttk.Button(r, text="Browse\u2026", command=self.browse).pack(side="left", padx=(8, 0))

        o = row(self.body, (10, 0))
        ttk.Checkbutton(o, text="Auto-quarantine dangerous files", variable=self.auto).pack(side="left")
        self.btn = ttk.Button(o, text="Start watching", style="Accent.TButton", command=self.toggle)
        self.btn.pack(side="right")
        self.state_lbl = tk.Label(self.body, text="\u25cf Not watching", bg=BG, fg=MUTED,
                                  font=(FONT, 11, "bold"), anchor="w")
        self.state_lbl.pack(fill="x", pady=(12, 6))

        wrap, self.tree = make_tree(self.body, [("t", "Time", 80, False), ("v", "Verdict", 110, False),
                                                ("f", "New file", 560, True)], height=8)
        wrap.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        d = tk.Frame(self.body, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        d.pack(fill="x", pady=(10, 0))
        self.detail = ro_text(d, height=5)
        self.detail.pack(fill="x")

    def browse(self):
        p = filedialog.askdirectory(title="Folder to watch", initialdir=self.folder.get() or str(Path.home()))
        if p:
            self.folder.set(p)

    def toggle(self):
        if self.stop_evt and not self.stop_evt.is_set():
            self.stop_evt.set()
            self.btn.configure(text="Start watching", style="Accent.TButton")
            self.state_lbl.configure(text="\u25cf Not watching", fg=MUTED)
            return
        folder = Path(self.folder.get().strip().strip('"'))
        if not folder.is_dir():
            messagebox.showinfo("CyberGuard", "Choose an existing folder to watch.")
            return
        self.stop_evt = threading.Event()
        threading.Thread(target=self._loop, daemon=True,
                         args=(folder, self.auto.get(), self.stop_evt)).start()
        self.btn.configure(text="Stop watching", style="TButton")
        self.state_lbl.configure(text=f"\u25cf Watching {folder}", fg=GREEN)

    def _loop(self, folder, auto, stop):
        post = self.app.post
        try:
            seen = set(folder.iterdir())
        except OSError:
            seen = set()
        while not stop.is_set():
            try:
                for p in list(folder.iterdir()):
                    if stop.is_set():
                        break
                    if p in seen or not p.is_file() or p.suffix.lower() in {".crdownload", ".part", ".tmp"}:
                        continue
                    size = p.stat().st_size
                    if stop.wait(1):
                        break
                    if not p.exists() or p.stat().st_size != size:
                        continue  # still downloading; check next round
                    seen.add(p)
                    score, reasons = cg.scan_file(p)
                    level = cg.verdict(score)
                    moved = None
                    if level != "LOW RISK":
                        cg.alert(level, f"New download: {p.name}\n\n" + "\n".join("- " + r for r in reasons[:8]))
                    if auto and level == "DANGEROUS":
                        try:
                            moved = cg.quarantine(p)
                        except OSError:
                            pass
                    post(lambda a=(p, score, reasons, level, moved): self._on_event(*a))
            except OSError:
                pass
            stop.wait(3)

    def _on_event(self, p, score, reasons, level, moved):
        shown = f"(quarantined)  {p.name}" if moved else p.name
        iid = self.tree.insert("", 0, values=(datetime.now().strftime("%H:%M:%S"), level, shown), tags=(level,))
        self.rows[iid] = dict(path=p, score=score, reasons=reasons, level=level, moved=moved)
        self.tree.selection_set(iid)
        if level != "LOW RISK":
            self.app.bell()
            self.state_lbl.configure(text=f"\u26a0 {level}: {p.name}", fg=RED if level == "DANGEROUS" else AMBER)

    def on_select(self, _=None):
        sel = self.tree.selection()
        if not sel:
            return
        r = self.rows[sel[0]]
        parts = [(f"{r['level']}  (score {r['score']})\n", "bold"), (f"{r['path']}\n", "m")]
        parts += [(f"\u2022  {x}\n", "b") for x in r["reasons"]] or [("\u2022  Nothing suspicious found\n", "b")]
        if r["moved"]:
            parts.append((f"Moved to quarantine: {r['moved']}\n", "m"))
        put(self.detail, parts)


class PasswordPage(Page):
    title = "Password check"
    subtitle = "Checked in memory only \u2014 never saved, logged or sent anywhere."
    COLORS = {"WEAK": (RED, 0.25), "MODERATE": (AMBER, 0.62), "STRONGER": (GREEN, 1.0)}

    def build(self):
        self.var = tk.StringVar()
        self.show_var = tk.BooleanVar(value=False)
        r = row(self.body, (0, 0))
        self.entry = ttk.Entry(r, textvariable=self.var, show="\u2022", font=(FONT, 12))
        self.entry.pack(side="left", fill="x", expand=True, ipady=4)
        ttk.Checkbutton(r, text="Show", variable=self.show_var, command=self.toggle_show).pack(side="left", padx=(10, 0))
        self.var.trace_add("write", lambda *a: self.update_view())
        self.bar = tk.Canvas(self.body, height=10, bg=CARD, highlightthickness=0)
        self.bar.pack(fill="x", pady=(14, 0))
        self.bar.bind("<Configure>", lambda e: self.draw())
        self.frac, self.color = 0, BORDER
        self.rating = tk.Label(self.body, text="Type a password to check it", font=(FONT, 16, "bold"),
                               bg=BG, fg=MUTED, anchor="w")
        self.rating.pack(fill="x", pady=(10, 0))
        box = tk.Frame(self.body, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        box.pack(fill="both", expand=True, pady=(8, 0))
        self.text = ro_text(box)
        self.text.pack(fill="both", expand=True, padx=8, pady=6)

    def on_show(self):
        self.entry.focus_set()

    def toggle_show(self):
        self.entry.configure(show="" if self.show_var.get() else "\u2022")

    def draw(self):
        self.bar.delete("all")
        w = self.bar.winfo_width()
        self.bar.create_rectangle(0, 0, int(w * self.frac), 10, fill=self.color, width=0)

    def update_view(self):
        pw = self.var.get()
        if not pw:
            self.frac, self.color = 0, BORDER
            self.rating.configure(text="Type a password to check it", fg=MUTED)
            put(self.text, [])
            self.draw()
            return
        res = cg.password_audit(pw)
        self.color, self.frac = self.COLORS[res["rating"]]
        self.rating.configure(text=res["rating"], fg=self.color)
        parts = [(f"{res['length']} characters   \u00b7   \u2248 {res['estimated_entropy_bits']} bits (upper estimate)\n", "m")]
        if res["issues"]:
            parts.append(("TO IMPROVE", "h"))
            parts += [(f"\u2022  {i}\n", "b") for i in res["issues"]]
        parts.append(("TIPS", "h"))
        parts += [(f"\u2022  {t}\n", "b") for t in res["recommendations"]]
        put(self.text, parts)
        self.draw()


class ToolsPage(Page):
    title = "More tools"
    subtitle = "Audit, integrity checks, duplicates, reports, checklists and help."

    def build(self):
        g = tk.Frame(self.body, bg=BG)
        g.pack(fill="x")
        items = [
            ("System audit", lambda: self.run(cg.command_audit)),
            ("Self-test", lambda: self.run(cg.run_self_tests)),
            ("Security tips", lambda: self.run(cg.show_tips)),
            ("Config & privacy", lambda: self.run(cg.show_configuration)),
            ("Log summary", lambda: self.run(cg.command_log_summary, str(cg.LOG_FILE))),
            ("Export report", lambda: self.run(cg.command_report)),
            ("Create integrity baseline\u2026", self.integrity_create),
            ("Check against baseline", lambda: self.run(cg.command_integrity_check)),
            ("Find duplicates\u2026", self.duplicates),
        ]
        for i, (label, cmd) in enumerate(items):
            ttk.Button(g, text=label, command=cmd).grid(row=i // 3, column=i % 3, sticky="ew", padx=4, pady=4)
        for c in range(3):
            g.columnconfigure(c, weight=1, uniform="b")

        r = row(self.body, (8, 0))
        tk.Label(r, text="Incident checklist:", bg=BG, fg=MUTED, font=(FONT, 10)).pack(side="left")
        self.kind = ttk.Combobox(r, values=["phishing", "money", "malware", "account", "phone"],
                                 state="readonly", width=12)
        self.kind.set("phishing")
        self.kind.pack(side="left", padx=8)
        ttk.Button(r, text="Show", command=lambda: self.run(cg.command_incident, self.kind.get())).pack(side="left")
        for label, p in (("Data folder", cg.HOME), ("Quarantine", cg.QUARANTINE), ("Reports", cg.REPORT_DIR)):
            ttk.Button(r, text=label, command=lambda p=p: open_folder(p)).pack(side="right", padx=(6, 0))

        box = tk.Frame(self.body, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        box.pack(fill="both", expand=True, pady=(12, 0))
        sb = ttk.Scrollbar(box, orient="vertical")
        self.out = ro_text(box, mono=True, height=12)
        self.out.configure(yscrollcommand=sb.set)
        sb.configure(command=self.out.yview)
        sb.pack(side="right", fill="y")
        self.out.pack(side="left", fill="both", expand=True, padx=4, pady=4)

    def run(self, fn, *args):
        put(self.out, [("Running\u2026", "m")])

        def work():
            result = capture(fn, *args) or "(no output)"
            self.app.post(lambda: put(self.out, [(result, "")]))

        threading.Thread(target=work, daemon=True).start()

    def integrity_create(self):
        p = filedialog.askdirectory(title="Folder to fingerprint")
        if p:
            self.run(cg.command_integrity_create, p)

    def duplicates(self):
        p = filedialog.askdirectory(title="Folder to search for duplicates")
        if p:
            self.run(cg.command_duplicates, p)


# -------------------------------------------------------------------- home
def detect(value):
    """Guess which check fits what the user pasted."""
    v = value.strip().strip('"')
    try:
        p = Path(v)
        if p.exists():
            return "email" if p.suffix.lower() == ".eml" else "files"
    except (OSError, ValueError):
        pass
    digits = re.sub(r"\D", "", v)
    if re.fullmatch(r"[+\d][\d\s\-().]{5,}", v) and 7 <= len(digits) <= 15:
        return "phone"
    if " " not in v and (v.lower().startswith(("http://", "https://", "www.")) or re.search(r"\.[a-z]{2,}(/|$)", v, re.I)):
        return "link"
    return "message"


class HomePage(Page):
    title = "CyberGuard"
    subtitle = "Paste anything suspicious \u2014 a message, link, phone number or file path \u2014 and the right check runs automatically."

    def build(self):
        self.var = tk.StringVar()
        r = row(self.body, (0, 0))
        self.entry = ttk.Entry(r, textvariable=self.var, font=(FONT, 13))
        self.entry.pack(side="left", fill="x", expand=True, ipady=8)
        self.entry.bind("<Return>", lambda e: self.go())
        ttk.Button(r, text="Quick check", style="Accent.TButton", command=self.go).pack(side="left", padx=(8, 0), ipady=4)
        ttk.Button(r, text="Paste & check", command=self.paste).pack(side="left", padx=(8, 0), ipady=4)

        tk.Label(self.body, text="TOOLS", bg=BG, fg=MUTED, font=(FONT, 9, "bold")).pack(anchor="w", pady=(22, 6))
        grid = tk.Frame(self.body, bg=BG)
        grid.pack(fill="both", expand=True)
        for c in range(3):
            grid.columnconfigure(c, weight=1, uniform="card")
        for i, (key, label, desc) in enumerate(CARDS):
            card = tk.Frame(grid, bg=CARD, highlightthickness=1, highlightbackground=BORDER, cursor="hand2")
            card.grid(row=i // 3, column=i % 3, sticky="nsew", padx=5, pady=5, ipady=6)
            t1 = tk.Label(card, text=label, bg=CARD, fg=FG, font=(FONT, 12, "bold"), anchor="w")
            t1.pack(fill="x", padx=14, pady=(10, 0))
            t2 = tk.Label(card, text=desc, bg=CARD, fg=MUTED, font=(FONT, 9), anchor="w",
                          justify="left", wraplength=190)
            t2.pack(fill="x", padx=14, pady=(2, 8))
            for w in (card, t1, t2):
                w.bind("<Button-1>", lambda e, k=key: self.app.show_page(k))
                w.bind("<Enter>", lambda e, c=card: c.configure(highlightbackground=ACCENT))
                w.bind("<Leave>", lambda e, c=card: c.configure(highlightbackground=BORDER))
        for rr in range(3):
            grid.rowconfigure(rr, weight=1)
        tk.Label(self.body, text="Heuristic helper \u2014 not a replacement for a real antivirus. Keep Windows Defender on.",
                 bg=BG, fg=MUTED, font=(FONT, 9)).pack(anchor="w", pady=(8, 0))

    def on_show(self):
        self.entry.focus_set()

    def paste(self):
        self.var.set(clipboard_text(self).strip())
        self.go()

    def go(self):
        v = self.var.get().strip()
        if not v:
            return
        kind = detect(v)
        self.app.show_page(kind)
        self.app.pages[kind].run_with(v.strip('"') if kind in ("files", "email") else v)
        self.var.set("")


CARDS = [
    ("message", "Message", "Scam & phishing check for SMS / chat text"),
    ("link", "Link", "Inspect a URL without opening it"),
    ("email", "Email", "Analyze a saved .eml file"),
    ("phone", "Phone number", "Spam & callback-scam patterns, blocklist"),
    ("files", "Scan files", "Check a file or folder, quarantine threats"),
    ("watch", "Watch folder", "Warn about dangerous new downloads"),
    ("password", "Password", "Live strength check, nothing stored"),
    ("tools", "More tools", "Audit, integrity, duplicates, reports"),
]

PAGES = [
    ("home", "Home", HomePage),
    ("message", "Message", MessagePage),
    ("link", "Link", LinkPage),
    ("email", "Email", EmailPage),
    ("phone", "Phone number", PhonePage),
    ("files", "Scan files", FilePage),
    ("watch", "Watch folder", WatchPage),
    ("password", "Password", PasswordPage),
    ("tools", "More tools", ToolsPage),
]


# --------------------------------------------------------------------- app
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberGuard")
        self.geometry("1040x700")
        self.minsize(900, 600)
        self.configure(bg=BG)
        setup_style(self)
        self._q = queue.Queue()

        side = tk.Frame(self, bg=PANEL, width=210)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Label(side, text="\U0001f6e1  CyberGuard", bg=PANEL, fg=FG,
                 font=(FONT, 15, "bold")).pack(anchor="w", padx=18, pady=(22, 2))
        tk.Label(side, text=f"AI+  v{getattr(cg, 'APP_VERSION', '')}", bg=PANEL, fg=MUTED,
                 font=(FONT, 9)).pack(anchor="w", padx=20, pady=(0, 18))

        self.container = tk.Frame(self, bg=BG)
        self.container.pack(side="right", fill="both", expand=True)

        self.pages, self.nav, self.current = {}, {}, None
        for key, label, cls in PAGES:
            page = cls(self.container, self)
            page.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.pages[key] = page
            b = tk.Label(side, text=f"   {label}", bg=PANEL, fg=MUTED, font=(FONT, 11),
                         anchor="w", padx=6, pady=9, cursor="hand2")
            b.pack(fill="x", padx=10, pady=1)
            b.bind("<Button-1>", lambda e, k=key: self.show_page(k))
            b.bind("<Enter>", lambda e, k=key: self._hover(k, True))
            b.bind("<Leave>", lambda e, k=key: self._hover(k, False))
            self.nav[key] = b

        self.show_page("home")
        self.after(40, self._drain)

    def _hover(self, key, on):
        if key != self.current:
            self.nav[key].configure(bg="#1c2530" if on else PANEL)

    def show_page(self, key):
        self.current = key
        for k, b in self.nav.items():
            b.configure(bg=ACCENT_DIM if k == key else PANEL, fg="white" if k == key else MUTED)
        self.pages[key].lift()
        self.pages[key].on_show()

    # thread-safe way for workers to update the UI
    def post(self, fn):
        self._q.put(fn)

    def _drain(self):
        for _ in range(400):
            try:
                fn = self._q.get_nowait()
            except queue.Empty:
                break
            try:
                fn()
            except tk.TclError:
                pass
        self.after(40, self._drain)


def main():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # crisp text on high-DPI screens
        except Exception:
            pass
    App().mainloop()


if __name__ == "__main__":
    main()
