#!/usr/bin/env python3
"""
CyberGuard AI+ Enhanced - defensive security toolkit with phone scam intelligence (standard library only).

What it does
  scan     Scan files/folders for malware signs (hashes, disguised files,
           suspicious script code, optional VirusTotal + Windows Defender)
  watch    Watch your Downloads folder and warn about dangerous new files
  message  Check an SMS / WhatsApp / chat message for scam or phishing signs
  email    Check a saved .eml email for phishing, spoofing, bad attachments
  number   Check a phone number for known spam / scam-call patterns
  block    Add a number to your personal blocklist\n  phone-patterns    Summarize local scam report patterns\n  phone-investigate Export a JSON phone investigation report

What it can NOT do
  * It cannot block calls or read SMS by itself (PCs don't receive them).
    Paste the number/text into CyberGuard, or use your phone's built-in
    spam protection for real-time blocking.
  * It is a heuristic helper, NOT a replacement for a real antivirus.
    Keep Windows Defender (or another AV) turned on.

Optional: set the environment variable VT_API_KEY (free VirusTotal key)
to look up file hashes online.

Usage examples
  python cyber_guard.py scan C:\\Users\\me\\Downloads --quarantine
  python cyber_guard.py watch --auto-quarantine
  python cyber_guard.py message "Your account is blocked. Share OTP now"
  python cyber_guard.py email suspicious.eml
  python cyber_guard.py number +2241234567
  python cyber_guard.py            (no arguments = simple menu)
"""

import argparse
import email
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path

# ---------------------------------------------------------------- setup
HOME = Path.home() / "CyberGuard"
QUARANTINE = HOME / "quarantine"
LOG_FILE = HOME / "guard.log"
BAD_HASHES_FILE = HOME / "bad_hashes.txt"        # one SHA-256 per line
BLOCKED_FILE = HOME / "blocked_numbers.txt"      # one number per line
TRUSTED_FILE = HOME / "trusted_numbers.txt"      # your real contacts
HISTORY_FILE = HOME / "number_history.json"
for d in (HOME, QUARANTINE):
    d.mkdir(parents=True, exist_ok=True)
os.system("")  # enables ANSI colours in Windows terminals

COLORS = {"DANGEROUS": "\033[91m", "SUSPICIOUS": "\033[93m", "LOW RISK": "\033[92m"}


def verdict(score):
    return "DANGEROUS" if score >= 6 else "SUSPICIOUS" if score >= 3 else "LOW RISK"


def log(line):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} | {line}\n")


def alert(title, body):
    """Console + log + (on Windows) a pop-up warning window."""
    log(f"{title} | {body}")
    if sys.platform == "win32":
        import ctypes
        threading.Thread(
            target=lambda: ctypes.windll.user32.MessageBoxW(0, body[:600], f"CyberGuard: {title}", 0x30 | 0x1000),
            daemon=True,
        ).start()


def show(title, score, reasons, popup=True):
    v = verdict(score)
    print(f"{COLORS[v]}[{v}] {title}  (risk score {score}){chr(27)}[0m")
    for r in reasons:
        print("   -", r)
    if not reasons:
        print("   - nothing suspicious found")
    if popup and v != "LOW RISK":
        alert(v, f"{title}\n\n" + "\n".join("- " + r for r in reasons[:8]))
    print()
    return v


# ------------------------------------------------------- URL analysis
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "tiny.cc"}
BAD_TLDS = {"zip", "xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga", "icu", "buzz", "support", "monster", "rest"}
SECOND_LEVEL = {"co.uk", "com.au", "co.in", "com.br", "co.jp", "org.uk", "net.in", "gov.in", "ac.in", "com.sg"}
BRANDS = {
    "paypal": {"paypal.com"}, "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com"},
    "google": {"google.com", "gmail.com", "googleapis.com", "googleusercontent.com", "google.co.in"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"}, "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"}, "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"}, "linkedin": {"linkedin.com"},
    "paytm": {"paytm.com"}, "hdfcbank": {"hdfcbank.com"}, "icicibank": {"icicibank.com"},
    "dhl": {"dhl.com"}, "fedex": {"fedex.com"},
}
LOOKALIKE_MAPS = [str.maketrans("0135", "oles"), str.maketrans("1", "i")]
URL_RE = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\"')]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|in|xyz|top|click|info|co|link|me|ly|app|support)(?:/[^\s<>\"')]*)?"
)


def registered_domain(host):
    parts = host.strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def analyze_url(url):
    score, reasons = 0, []
    try:
        p = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        host = (p.hostname or "").lower()
    except ValueError:
        return 2, [f"Malformed link: {url[:60]}"]
    if not host:
        return 0, []
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 3; reasons.append(f"Link uses a raw IP address ({host})")
    if host in SHORTENERS:
        score += 2; reasons.append(f"Shortened link hides the real site ({host})")
    if host.startswith("xn--") or ".xn--" in host:
        score += 3; reasons.append(f"Look-alike (punycode) domain: {host}")
    if host.rsplit(".", 1)[-1] in BAD_TLDS:
        score += 2; reasons.append(f"Domain ending often abused by scammers: {host}")
    if "@" in p.netloc:
        score += 3; reasons.append("Link contains '@' (hides real destination)")
    if host.count(".") >= 4 or host.count("-") >= 3:
        score += 1; reasons.append(f"Overly complex domain: {host}")
    if p.scheme == "http":
        score += 1; reasons.append(f"Not HTTPS: {host}")
    reg = registered_domain(host)
    for brand, legit in BRANDS.items():
        if reg in legit:
            continue
        if brand in host:
            score += 3; reasons.append(f"Pretends to be {brand.title()} but domain is {reg}"); break
        if any(brand in host.translate(m) for m in LOOKALIKE_MAPS):
            score += 3; reasons.append(f"Misspelled look-alike of {brand.title()}: {reg}"); break
    return score, reasons


# ----------------------------------------------- message / text analysis
TEXT_RULES = [
    (r"\b(urgent|immediately|act now|final notice|last warning|expires? (today|soon)|within \d+ (hours|hrs|minutes))\b", 1, "Creates urgency/pressure"),
    (r"\b(account|card|sim|number|service)\b.{0,40}\b(blocked|suspended|deactivated|closed|expire[sd]?)\b", 2, "Threatens to shut down your account/service"),
    (r"\b(you('ve| have)? won|lottery|lucky draw|prize|congratulations|claim (your|now))\b", 2, "Prize / lottery bait"),
    (r"\b(share|send|tell|give|enter|confirm|provide)\b.{0,25}\b(otp|pin|password|cvv|passcode)\b", 3, "Asks you for an OTP / PIN / password"),
    (r"\b(kyc|pan card|aadhaar)\b.{0,40}\b(update|verify|expire|suspend|block)", 2, "Fake KYC / ID update"),
    (r"\b(arrest|warrant|legal action|police|court|customs|narcotics)\b", 2, "Legal / police threat (common scam)"),
    (r"\b(gift ?cards?|bitcoin|crypto|wire transfer|western union|processing fee|advance fee)\b", 2, "Unusual payment method / fee request"),
    (r"\b(anydesk|teamviewer|quicksupport|remote access|install .{0,20}(app|apk))\b", 3, "Asks you to install a remote-access or unknown app"),
    (r"\b(refund|cashback|reward points?)\b.{0,40}\b(click|link|claim|expire)", 2, "Refund / reward bait"),
    (r"\b(package|parcel|delivery)\b.{0,50}\b(fee|held|failed|address|reschedule|link)\b", 2, "Fake delivery notice"),
    (r"\bdear (customer|user|sir|madam|account holder)\b", 1, "Generic greeting (not your name)"),
    (r"\b(work from home|part[- ]time|job offer)\b.{0,50}\b(per day|daily|weekly|earn)\b", 2, "Too-good-to-be-true job offer"),
]


def analyze_text(text):
    score, reasons = 0, []
    for pattern, pts, why in TEXT_RULES:
        if re.search(pattern, text, re.I | re.S):
            score += pts; reasons.append(why)
    seen = []
    for url in URL_RE.findall(text):
        url = url.rstrip(".,;")
        if url in seen or len(seen) >= 10:
            continue
        seen.append(url)
        s, r = analyze_url(url)
        score += s; reasons += r
    return score, reasons


# ------------------------------------------------------- email analysis
RISKY_EXT = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".hta", ".jar", ".msi", ".lnk", ".dll", ".reg", ".iso", ".img"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".xlam"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".rtf"}


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.links = []; self._href = None; self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href"); self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip())); self._href = None


def addr_domain(addr):
    return parseaddr(addr)[1].split("@")[-1].lower()


def analyze_email(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    score, reasons = 0, []
    sender = str(msg.get("From", ""))
    name, address = parseaddr(sender)
    from_dom = addr_domain(sender)

    for hdr, pts in (("Reply-To", 2), ("Return-Path", 1)):
        other = str(msg.get(hdr, ""))
        if other and addr_domain(other) and registered_domain(addr_domain(other)) != registered_domain(from_dom):
            score += pts; reasons.append(f"{hdr} domain ({addr_domain(other)}) differs from sender ({from_dom})")

    for brand, legit in BRANDS.items():
        if brand in name.lower() and registered_domain(from_dom) not in legit:
            score += 3; reasons.append(f"Display name says '{name}' but address is {address}"); break

    auth = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []) + (msg.get_all("Received-SPF") or []))
    if not auth:
        score += 1; reasons.append("No SPF/DKIM/DMARC results found in headers")
    for proto, result in re.findall(r"\b(spf|dkim|dmarc)=(fail|softfail|permerror)", auth, re.I):
        pts = 1 if result.lower() == "softfail" else 2
        score += pts; reasons.append(f"{proto.upper()} check {result.lower()} (sender may be forged)")

    body = msg.get_body(preferencelist=("plain", "html"))
    html_body = ""
    text = ""
    if body is not None:
        content = body.get_content()
        if body.get_content_type() == "text/html":
            html_body = content; text = re.sub(r"<[^>]+>", " ", content)
        else:
            text = content
    subject = str(msg.get("Subject", ""))
    s, r = analyze_text(subject + "\n" + text)
    score += s; reasons += r

    if html_body:
        parser = LinkParser(); parser.feed(html_body)
        for href, shown in parser.links[:30]:
            if URL_RE.search(shown) and href.startswith("http"):
                shown_host = urllib.parse.urlparse(shown if "://" in shown else "http://" + shown).hostname or ""
                real_host = urllib.parse.urlparse(href).hostname or ""
                if shown_host and registered_domain(shown_host) != registered_domain(real_host):
                    score += 4; reasons.append(f"Link text shows {shown_host} but goes to {real_host}")
            if href.startswith("http"):
                s, r = analyze_url(href)
                score += s; reasons += r

    for att in msg.iter_attachments():
        fname = (att.get_filename() or "").lower()
        ext = Path(fname).suffix
        if ext in RISKY_EXT:
            score += 4; reasons.append(f"Dangerous attachment type: {fname}")
        elif ext in MACRO_EXT:
            score += 3; reasons.append(f"Macro-enabled document: {fname}")
        if len(Path(fname).suffixes) >= 2 and ext in RISKY_EXT | MACRO_EXT:
            score += 3; reasons.append(f"Double extension trick: {fname}")

    return score, list(dict.fromkeys(reasons))


# --------------------------------------------------------- file scanning
BAD_STRINGS = [
    b"eicar-standard-antivirus-test-file", b"powershell -enc", b"-encodedcommand", b"certutil -urlcache",
    b"frombase64string", b"invoke-expression", b"downloadstring", b"vssadmin delete shadows",
    b"bcdedit /set", b"mimikatz", b"regsvr32 /s /u /i:http", b"wscript.shell",
]


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_lines(path):
    if not path.exists():
        return set()
    return {ln.split()[0].lower() for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if ln.strip() and not ln.startswith("#")}


def virustotal_lookup(sha):
    key = os.environ.get("VT_API_KEY")
    if not key:
        return None
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            stats = json.load(resp)["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0), stats.get("suspicious", 0)
    except urllib.error.HTTPError as e:
        return None if e.code == 404 else None
    except Exception:
        return None


def defender_scan(path):
    """Ask Windows Defender to scan the path; True if it logged a detection."""
    if sys.platform != "win32":
        return False
    ps = (f"Start-MpScan -ScanType CustomScan -ScanPath '{path}'; "
          f"(Get-MpThreatDetection | Where-Object {{ $_.Resources -like '*{Path(path).name}*' }}).Count")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=300)
        return out.stdout.strip().splitlines()[-1].strip() not in ("", "0")
    except Exception:
        return False


def scan_file(path, use_defender=False):
    path = Path(path)
    score, reasons = 0, []
    ext = path.suffix.lower()
    try:
        sha = sha256_of(path)
        with open(path, "rb") as f:
            head = f.read(5 * 1024 * 1024)
    except (PermissionError, OSError) as e:
        return 0, [f"Could not read file ({e.__class__.__name__})"]

    if sha in load_lines(BAD_HASHES_FILE):
        score += 10; reasons.append("Hash matches your known-bad list")
    vt = virustotal_lookup(sha)
    if vt and vt[0] > 0:
        score += 10 if vt[0] >= 3 else 5; reasons.append(f"VirusTotal: {vt[0]} engines flag it malicious")
    if head[:2] == b"MZ" and ext in DOC_EXT:
        score += 8; reasons.append(f"Program disguised as a {ext} file")
    if ext in RISKY_EXT:
        score += 1; reasons.append(f"Executable/script file type ({ext})")
    if len(path.suffixes) >= 2 and ext in RISKY_EXT and path.suffixes[-2].lower() in DOC_EXT:
        score += 5; reasons.append(f"Double extension trick: {path.name}")
    low = head.lower()
    hits = [s.decode() for s in BAD_STRINGS if s in low]
    if hits:
        score += min(8, 3 * len(hits)); reasons.append("Suspicious code/strings: " + ", ".join(hits[:4]))
    if use_defender and defender_scan(path):
        score += 10; reasons.append("Windows Defender reported a threat")
    return score, reasons


def quarantine(path):
    path = Path(path)
    dest = QUARANTINE / f"{datetime.now():%Y%m%d_%H%M%S}_{path.name}.quarantined"
    shutil.move(str(path), dest)
    log(f"QUARANTINED {path} -> {dest}")
    return dest


def scan_path(target, do_quarantine=False, use_defender=False):
    target = Path(target)
    files = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()]
    flagged = 0
    print(f"Scanning {len(files)} file(s)...\n")
    for f in files:
        score, reasons = scan_file(f, use_defender)
        if verdict(score) == "LOW RISK" and len(files) > 1:
            continue  # keep folder scans readable
        v = show(str(f), score, reasons)
        if v != "LOW RISK":
            flagged += 1
        if do_quarantine and v == "DANGEROUS":
            print("   Moved to quarantine:", quarantine(f), "\n")
    print(f"Done. {flagged} file(s) flagged out of {len(files)}.")


def watch(folder, auto_quarantine=False, interval=3):
    folder = Path(folder)
    seen = {p for p in folder.iterdir()} if folder.exists() else set()
    print(f"Watching {folder}  (Ctrl+C to stop)")
    try:
        while True:
            for p in list(folder.iterdir()):
                if p in seen or not p.is_file() or p.suffix.lower() in {".crdownload", ".part", ".tmp"}:
                    continue
                size = p.stat().st_size
                time.sleep(1)
                if not p.exists() or p.stat().st_size != size:
                    continue  # still downloading, check next round
                seen.add(p)
                score, reasons = scan_file(p)
                v = show(f"New download: {p.name}", score, reasons)
                if auto_quarantine and v == "DANGEROUS":
                    print("   Moved to quarantine:", quarantine(p), "\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped watching.")


# ------------------------------------------------------ phone numbers
# Offline phone-risk triage. Number patterns alone cannot prove fraud.
WANGIRI = ("+224", "+225", "+232", "+216", "+222", "+252", "+257", "+375", "+592", "+599")
CARIBBEAN_AREA = {"809", "829", "849", "284", "876", "473", "649", "767", "664"}
PHONE_REPORT_FILE = HOME / "phone_reports.json"
COMMUNITY_PHONE_REPORT_FILE = HOME / "community_phone_reports.json"

def normalize_number(n):
    """Normalize common formatting while preserving a leading international +."""
    raw = str(n).strip()
    if not raw:
        raise ValueError("Phone number cannot be empty.")
    # Permit only common visual separators; reject letters and extensions.
    if re.search(r"[A-Za-z]", raw):
        raise ValueError("Enter digits, an optional leading +, and common separators only.")
    cleaned = re.sub(r"[\s().-]", "", raw)
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    if cleaned.count("+") > 1 or ("+" in cleaned and not cleaned.startswith("+")):
        raise ValueError("The + symbol is allowed only once, at the beginning.")
    if not re.fullmatch(r"\+?\d{5,15}", cleaned):
        raise ValueError("Enter 5–15 digits, optionally starting with + and including country code.")
    # Bare 10-digit Indian mobile (starts 6-9) or 0-prefixed: assume +91 so prefix rules can work.
    if not cleaned.startswith("+"):
        if re.fullmatch(r"[6-9]\d{9}", cleaned):
            cleaned = "+91" + cleaned
        elif re.fullmatch(r"0[6-9]\d{9}", cleaned):
            cleaned = "+91" + cleaned[1:]
        elif re.fullmatch(r"91[6-9]\d{9}", cleaned):
            cleaned = "+" + cleaned
        elif re.fullmatch(r"140\d{7}", cleaned):
            cleaned = "+91" + cleaned
    return cleaned

def _read_phone_history():
    data = _safe_json(PHONE_REPORT_FILE, {})
    return data if isinstance(data, dict) else {}

def _phone_risk_band(score):
    """Map the phone scam risk score, which is measured from 0 to 10."""
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "NO STRONG SIGNALS"

def analyze_number(number, my_number=None, indicators=None, save_check=True):
    """
    Explainable offline phone scam screening.
    indicators is a dict of caller behaviors reported by the user.
    It does not identify the subscriber or query a live scam-number database.
    """
    num = normalize_number(number)
    trusted = {normalize_number(x) for x in load_lines(TRUSTED_FILE)}
    blocked = {normalize_number(x) for x in load_lines(BLOCKED_FILE)}
    if num in trusted:
        return 0, ["Number is in your trusted contacts (still verify unexpected requests)."]

    score, reasons = 0, []
    digits = num.lstrip("+")
    if num in blocked:
        score += 10
        reasons.append("Number is on your personal blocklist.")
    if num.startswith(WANGIRI):
        score += 2
        reasons.append("International prefix has been associated with some one-ring callback scams; country code alone is not proof.")
    if num.startswith("+1") and len(digits) >= 4 and digits[1:4] in CARIBBEAN_AREA:
        score += 2
        reasons.append("Area code has appeared in callback-scam warnings; verify before calling back.")
    if num.startswith(("+1900", "+449", "+4470", "1900")):
        score += 2
        reasons.append("Prefix may involve premium-rate or costly callback services; charges depend on carrier and destination.")
    # India: 140 is a telemarketing series, not itself evidence of a scam.
    if digits.startswith("91140") or digits.startswith("140"):
        score += 3
        reasons.append("Indian 140-series (telemarketing/promotional) number; often used for unsolicited sales or fraud calls (+3).")
    if digits.startswith("91") and not digits.startswith("91140") and len(digits) == 12 and digits[2] in "12345":
        score += 1
        reasons.append("Indian number whose first digit after +91 is not 6-9, so it is not a normal mobile number (+1).")
    if re.search(r"(\d{2,3})\1{3,}", digits[-8:]):
        score += 1
        reasons.append("Ends in a repeating digit block (weak signal).")
    if re.search(r"(?:0123|1234|2345|3456|4567|5678|6789|9876|8765|7654)", digits[-6:]):
        score += 1
        reasons.append("Ends in a sequential digit run, common in fake/bulk numbers (weak signal).")
    if re.search(r"(\d)\1{5,}", digits):
        score += 1
        reasons.append("Contains a long repeated-digit pattern (weak signal only).")
    if len(digits) < 7 or len(digits) > 15:
        score += 2
        reasons.append("Unusual international number length.")
    if num.startswith("+91") and len(digits) != 12:
        score += 2
        reasons.append("+91 should be followed by 10 digits; this number has a nonstandard length (+2).")
    if my_number:
        mine = normalize_number(my_number).lstrip("+")
        if digits != mine and len(digits) == len(mine) and len(digits) > 4 and digits[:-4] == mine[:-4]:
            score += 2
            reasons.append("Number resembles yours except for the last four digits; possible neighbour spoofing, but not proof.")

    # These are behavioral indicators, so they are stronger than number shape.
    indicator_rules = [
        ("asked_otp", 5, "Caller requested an OTP, PIN, password, or CVV."),
        ("urgent_money", 4, "Caller pressured you to transfer money immediately."),
        ("remote_access", 5, "Caller asked you to install a remote-access app or share your screen."),
        ("threatened", 3, "Caller used threats (arrest, account closure, or legal action) to force compliance."),
        ("unknown_link", 3, "Caller sent an unexpected link or APK and urged you to open/install it."),
        ("impersonation", 4, "Caller claimed to represent a bank, government agency, delivery service, or support team but could not be independently verified."),
        ("missed_one_ring", 2, "Unexpected one-ring/missed call from an unfamiliar number."),
        ("asked_upi_pin", 5, "Caller asked for a UPI PIN or told you to enter it to receive money."),
    ]
    for key, points, description in indicator_rules:
        if indicators and indicators.get(key):
            score += points
            reasons.append(f"{description} (+{points})")

    # Count checks separately from reported call events; repeated checking alone
    # must not be misrepresented as proof that the person repeatedly called.
    history = _read_phone_history()
    record = history.get(num, {})
    if not isinstance(record, dict):
        record = {"checks": int(record) if str(record).isdigit() else 0}
    record["checks"] = int(record.get("checks", 0)) + (1 if save_check else 0)
    record.setdefault("first_checked", datetime.now().isoformat(timespec="seconds"))
    record["last_checked"] = datetime.now().isoformat(timespec="seconds")
    record["last_score"] = min(score, 10)
    record["last_reasons"] = reasons
    history[num] = record
    if save_check:
        try:
            PHONE_REPORT_FILE.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError:
            reasons.append("Could not save local phone-check history.")

    return min(score, 10), list(dict.fromkeys(reasons))

def command_number_check(number=None):
    """Interactive, behavior-aware phone scam check for the CyberGuard menu."""
    number = number or input("Phone number (include country code, e.g. +919876543210): ").strip()
    indicators = {}
    print("\nAnswer y/n based on what actually happened. These signals improve the assessment:")
    questions = [
        ("asked_otp", "Did they ask for an OTP, PIN, password, or CVV? "),
        ("urgent_money", "Did they pressure you to send money immediately? "),
        ("remote_access", "Did they ask you to install AnyDesk/remote access or share your screen? "),
        ("threatened", "Did they threaten arrest, account blocking, or legal action? "),
        ("unknown_link", "Did they send a suspicious link or APK? "),
        ("impersonation", "Did they claim to be a bank/government/support agent without verification? "),
        ("missed_one_ring", "Was it an unexpected one-ring missed call from an unfamiliar international number? "),
        ("asked_upi_pin", "Did they ask for your UPI PIN to receive money? "),
    ]
    for key, prompt in questions:
        indicators[key] = input(prompt).strip().lower() in {"y", "yes"}
    mine = input("Your own number for neighbour-spoofing comparison (optional; Enter to skip): ").strip()
    score, reasons = analyze_number(number, mine or None, indicators)
    band = _phone_risk_band(score)
    print("\n" + "=" * 62)
    print("CYBERGUARD — PHONE SCAM RISK ASSESSMENT")
    print(f"Number: {normalize_number(number)}")
    confidence, confidence_note = _phone_confidence(
        score, reasons, indicators, sum(1 for row in _phone_report_rows()
                                        if isinstance(row, dict) and row.get("number") == normalize_number(number))
    )
    print(f"Risk: {band} | Score: {_phone_gauge(score)}")
    print(f"Evidence confidence: {confidence} — {confidence_note}")
    print("Evidence:")
    if reasons:
        for reason in reasons:
            print(" •", reason)
    else:
        print(" • No configured warning signal was found.")
    print("\nRecommended action:")
    if indicators.get("asked_otp") or indicators.get("asked_upi_pin") or indicators.get("remote_access") or indicators.get("urgent_money"):
        print(" • Treat the interaction as high risk. End the call; do not share codes, enter a UPI PIN to receive money, or install remote-control apps.")
    elif score >= 7:
        print(" • Do not call back or share information. Block/report it if unwanted and verify any claimed organization independently.")
    elif score >= 4:
        print(" • Do not trust the caller ID alone. Verify through the organization's official app or published number.")
    else:
        print(" • No strong signals were detected, but this does not prove the number is safe.")
    print(" • Caller ID can be spoofed; this tool cannot identify the real caller.")
    print(" • If money was lost in India, contact your bank immediately and call 1930 / report at cybercrime.gov.in.")
    print("=" * 62 + "\n")


def analyze_phone_message(text):
    """Offline analysis of a suspicious call transcript, SMS, or chat message."""
    message = str(text or "").strip()
    if not message:
        raise ValueError("Message cannot be empty.")
    patterns = [
        (r"\b(otp|one[- ]time password|verification code|cvv|upi pin|atm pin|password)\b", 5,
         "Requests a secret code, PIN, password, or CVV."),
        (r"\b(send|transfer|pay|deposit)\b.{0,45}\b(now|immediately|urgent|today|right away|asap)\b|\b(urgent|immediately|right now)\b.{0,45}\b(money|payment|transfer|pay)\b", 3,
         "Pressures you to make an urgent payment or transfer."),
        (r"\b(account|bank account|sim|card)\b.{0,45}\b(block(ed)?|suspend(ed)?|freeze|close(d)?)\b|\b(arrest|police|court case|warrant)\b", 2,
         "Uses account-closure or legal-threat language to create fear."),
        (r"\b(anydesk|teamviewer|remote access|screen share|share your screen|install this app|download this apk)\b", 4,
         "Requests remote access, screen sharing, or installing an app/APK."),
        (r"\b(kyc|update your account|verify your account|bank officer|customs|courier|delivery agent|customer support)\b", 2,
         "Claims an account-verification or official/support context that should be independently verified."),
        (r"https?://|\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl)/?", 2,
         "Contains a link; inspect it independently and do not open unexpected links."),
        (r"\b(receive money|refund|cashback|prize|lottery|you have won)\b.{0,55}\b(pin|otp|fee|pay|payment|claim)\b", 3,
         "Combines a reward/refund claim with a request for sensitive information or payment."),
    ]
    reasons=[]
    score=0
    for pattern, points, description in patterns:
        if re.search(pattern, message, re.IGNORECASE | re.DOTALL):
            score += points
            reasons.append(f"{description} (+{points})")
    score=min(10, score)
    return score, reasons


def command_phone_message_check():
    print("\nPaste the suspicious SMS, WhatsApp message, or call transcript. Finish with a blank line:")
    lines=[]
    while True:
        try:
            line=input()
        except EOFError:
            break
        if not line.strip():
            break
        lines.append(line)
    text="\n".join(lines).strip()
    score, reasons=analyze_phone_message(text)
    print("\nCYBERGUARD — MESSAGE / CALL TRANSCRIPT ANALYSIS")
    confidence, confidence_note = _phone_confidence(score, reasons)
    print(f"Risk: {_phone_risk_band(score)} | Score: {_phone_gauge(score)}")
    print(f"Evidence confidence: {confidence} — {confidence_note}")
    if reasons:
        for reason in reasons:
            print(" •", reason)
    else:
        print(" • No configured warning pattern was detected.")
    print("Recommended action: Never share OTPs, PINs, passwords, or CVV. Verify claims using an official app or independently published number.")
    print("Note: This is a rule-based text check; wording alone cannot prove a scam.")
    if input("Save a community report about this interaction (without saving message text)? (y/n): ").strip().lower() in {"y","yes"}:
        number=input("Phone number (optional; Enter to skip): ").strip()
        category=input("Category (otp/payment/impersonation/link/threat/remote-access/other): ").strip().lower() or "other"
        save_community_phone_report(number, category, f"Message analyzer score {score}/10")


def save_community_phone_report(number, category, note=""):
    """Save a user-submitted allegation locally; reports are not verified facts."""
    normalized = ""
    if str(number or "").strip():
        normalized = normalize_number(number)
    allowed = {"otp", "payment", "impersonation", "link", "threat", "remote-access", "one-ring", "other"}
    category = str(category or "other").strip().lower()
    if category not in allowed:
        category = "other"
    note = re.sub(r"\\s+", " ", str(note or "").strip())[:240]
    data = _safe_json(COMMUNITY_PHONE_REPORT_FILE, [])
    if not isinstance(data, list):
        data = []
    now = datetime.now()
    # Collapse likely same-number/same-category reports within 24 hours.
    for existing in data:
        if not isinstance(existing, dict):
            continue
        try:
            prior = datetime.fromisoformat(str(existing.get("reported_at", "")))
        except (ValueError, TypeError):
            continue
        same_number = bool(normalized) and existing.get("number") == normalized
        same_category = str(existing.get("category", "other")).lower() == category
        if same_number and same_category and now - prior <= timedelta(hours=24):
            existing["duplicate_submissions"] = int(existing.get("duplicate_submissions", 1) or 1) + 1
            existing["last_duplicate_at"] = now.isoformat(timespec="seconds")
            if note and not existing.get("note"):
                existing["note"] = note
            COMMUNITY_PHONE_REPORT_FILE.write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            print("Likely duplicate report detected within 24 hours; existing report counter updated.")
            print("This remains an unverified local user report; it is not shared online.")
            return
    data.append({
        "number": normalized,
        "category": category,
        "note": note,
        "reported_at": now.isoformat(timespec="seconds"),
        "duplicate_submissions": 1,
        "status": "unverified_user_report",
    })
    COMMUNITY_PHONE_REPORT_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Saved locally to {COMMUNITY_PHONE_REPORT_FILE}. This report is unverified and is not shared online.")

def command_phone_community_report():
    number=input("Suspicious phone number (optional): ").strip()
    category=input("Category (otp/payment/impersonation/link/threat/remote-access/one-ring/other): ").strip().lower()
    note=input("Short note (do not include OTPs, passwords, or private details): ").strip()
    save_community_phone_report(number, category, note)


def _phone_gauge(score):
    score = max(0, min(10, int(score)))
    return "[" + "#" * score + "-" * (10 - score) + f"] {score}/10"


def _phone_confidence(score, reasons=None, indicators=None, report_count=0):
    """Evidence-strength label separate from risk; not a probability of fraud."""
    reasons = reasons or []
    indicators = indicators or {}
    strong = any(indicators.get(k) for k in (
        "asked_otp", "urgent_money", "remote_access", "threatened",
        "unknown_link", "impersonation", "asked_upi_pin"
    ))
    if strong and len(reasons) >= 2:
        return "HIGH", "Multiple behavior-based warning signals were reported."
    if strong or report_count >= 3:
        return "MEDIUM", "Some meaningful evidence exists, but reports are not independently verified."
    if score >= 4 or len(reasons) >= 2:
        return "MEDIUM", "Several heuristic signals exist; caller identity remains unverified."
    return "LOW", "Limited evidence is available; low confidence does not mean the caller is safe."


def _phone_report_rows():
    rows = _safe_json(COMMUNITY_PHONE_REPORT_FILE, [])
    return rows if isinstance(rows, list) else []


def command_phone_pattern_intelligence():
    """Summarize recurring categories and descriptions in local, unverified reports."""
    reports = [r for r in _phone_report_rows() if isinstance(r, dict)]
    now = datetime.now()
    categories, weekly = {}, {}
    descriptions = {}
    for row in reports:
        cat = str(row.get("category", "other")).strip().lower() or "other"
        categories[cat] = categories.get(cat, 0) + int(row.get("duplicate_submissions", 1) or 1)
        note = re.sub(r"[^a-z0-9 ]+", " ", str(row.get("note", "")).lower())
        note = re.sub(r"\\s+", " ", note).strip()
        if len(note) >= 18:
            descriptions.setdefault(note, []).append(row)
        try:
            stamp = datetime.fromisoformat(str(row.get("reported_at", "")))
            if now - stamp <= timedelta(days=7):
                weekly[cat] = weekly.get(cat, 0) + 1
        except (ValueError, TypeError):
            pass
    print("\\nCYBERGUARD — SCAM PATTERN INTELLIGENCE")
    print(f"Local reports: {len(reports)} (all unverified)")
    print("\\nCategories:")
    for cat, count in sorted(categories.items(), key=lambda x: (-x[1], x[0])):
        print(f" • {cat}: {count}")
    if not categories:
        print(" • No reports yet")
    print("\\nReports submitted in the last 7 days:")
    for cat, count in sorted(weekly.items(), key=lambda x: (-x[1], x[0])):
        print(f" • {cat}: {count}")
    if not weekly:
        print(" • No recent reports")
    repeated = [(note, rows) for note, rows in descriptions.items() if len(rows) >= 2]
    print("\\nRepeated descriptions:")
    for note, rows in sorted(repeated, key=lambda x: len(x[1]), reverse=True)[:10]:
        nums = {r.get("number") or "(number not supplied)" for r in rows}
        print(f" • {len(rows)} report(s), {len(nums)} number(s): {note[:110]}")
    if not repeated:
        print(" • No repeated descriptions found")
    print("These are local pattern clues, not proof of fraud or verified threat intelligence.")


def command_phone_investigation_report(number_arg=None):
    """Export a JSON case report for a number using locally stored evidence."""
    raw = number_arg if number_arg is not None else input("Phone number to investigate (with country code): ").strip()
    number = normalize_number(raw)
    history = _read_phone_history()
    check = history.get(number, {})
    if not isinstance(check, dict):
        check = {"checks": int(check) if str(check).isdigit() else 0}
    reports = [r for r in _phone_report_rows() if isinstance(r, dict) and r.get("number") == number]
    score = max(0, min(10, int(check.get("last_score", 0) or 0)))
    reasons = check.get("last_reasons", [])
    if not isinstance(reasons, list):
        reasons = []
    confidence, confidence_note = _phone_confidence(score, reasons, report_count=len(reports))
    trusted = {normalize_number(x) for x in load_lines(TRUSTED_FILE)}
    blocked = {normalize_number(x) for x in load_lines(BLOCKED_FILE)}
    case = {
        "report_type": "CyberGuard AI+ phone investigation",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "number": number,
        "risk_score_out_of_10": score,
        "risk_band": _phone_risk_band(score),
        "risk_gauge": _phone_gauge(score),
        "evidence_confidence": confidence,
        "confidence_explanation": confidence_note,
        "last_assessment_reasons": reasons,
        "routine_checks": check.get("checks", 0),
        "first_checked": check.get("first_checked"),
        "last_checked": check.get("last_checked"),
        "community_reports": reports,
        "trusted_contact": number in trusted,
        "blocked_contact": number in blocked,
        "limitations": [
            "Offline heuristic assessment; no live verified scam-number database was queried.",
            "Community reports are user-submitted and unverified.",
            "Caller ID can be spoofed; this report does not identify the real caller.",
            "Risk score is not a probability of fraud."
        ]
    }
    digits = re.sub(r"[^0-9]", "", number)
    destination = HOME / f"phone_investigation_{digits}_{datetime.now():%Y%m%d_%H%M%S}.json"
    destination.write_text(json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\\nCYBERGUARD — PHONE INVESTIGATION REPORT")
    print(f"Number: {number}")
    print(f"Risk: {case['risk_band']} | {case['risk_gauge']}")
    print(f"Evidence confidence: {confidence} — {confidence_note}")
    print(f"Local reports: {len(reports)} (unverified)")
    print(f"JSON report saved: {destination}")
    print("Review for personal information before sharing.")
    return destination


def command_phone_dashboard():
    history=_read_phone_history()
    reports=_safe_json(COMMUNITY_PHONE_REPORT_FILE, [])
    if not isinstance(reports, list): reports=[]
    checked=sum(int(v.get("checks", 0)) for v in history.values() if isinstance(v, dict))
    high=sum(1 for v in history.values() if isinstance(v, dict) and int(v.get("last_score",0)) >= 7)
    medium=sum(1 for v in history.values() if isinstance(v, dict) and 4 <= int(v.get("last_score",0)) <= 6)
    categories={}
    for report in reports:
        if isinstance(report, dict):
            cat=str(report.get("category", "other"))
            categories[cat]=categories.get(cat,0)+1
    print("\nCYBERGUARD — PHONE SAFETY DASHBOARD")
    print(f"Unique numbers checked: {len(history)}")
    print(f"Total checks recorded: {checked}")
    print(f"Latest checks rated high (7–10): {high}")
    print(f"Latest checks rated medium (4–6): {medium}")
    print(f"Local community reports: {len(reports)} (unverified)")
    print(f"Trusted contacts: {len(load_lines(TRUSTED_FILE))}")
    print(f"Blocked contacts: {len(load_lines(BLOCKED_FILE))}")
    cutoff = datetime.now() - timedelta(days=7)
    weekly_count = 0
    for row in reports:
        if isinstance(row, dict):
            try:
                if datetime.fromisoformat(str(row.get("reported_at", ""))) >= cutoff:
                    weekly_count += 1
            except (ValueError, TypeError):
                pass
    print(f"Community reports in last 7 days: {weekly_count}")
    print("Report categories:")
    if categories:
        for cat, count in sorted(categories.items(), key=lambda item: (-item[1], item[0])):
            print(f" • {cat}: {count}")
    else:
        print(" • No reports yet")
    recent=sorted((r for r in reports if isinstance(r,dict)), key=lambda r:r.get("reported_at",""), reverse=True)[:5]
    if recent:
        print("Recent reports (all unverified):")
        for r in recent:
            number=r.get("number") or "number not provided"
            print(f" • {r.get('reported_at','unknown time')} | {number} | {r.get('category','other')}")
    print("Privacy: history and reports are stored locally on this computer; they are not automatically shared.")


def block_number(number):
    num = normalize_number(number)
    blocked = {normalize_number(x) for x in load_lines(BLOCKED_FILE)}
    if num in blocked:
        print(f"{num} is already in your personal blocklist.")
        return
    with open(BLOCKED_FILE, "a", encoding="utf-8") as f:
        f.write(num + "\n")
    print(f"Added {num} to your CyberGuard blocklist. Also block/report it in your phone's dialer.")
# ----------------------------------------------------------------- CLI
def menu():
    options = """
 CyberGuard
 1) Scan a file or folder
 2) Watch Downloads folder
 3) Check a message (SMS / WhatsApp / chat)
 4) Check an email (.eml file)
 5) Check a phone number
 6) Block a number
 0) Exit
"""
    while True:
        print(options)
        choice = input("Choose: ").strip()
        try:
            if choice == "1":
                scan_path(input("Path: ").strip('" '), do_quarantine=input("Quarantine dangerous files? (y/n) ").lower() == "y")
            elif choice == "2":
                watch(Path.home() / "Downloads", auto_quarantine=input("Auto-quarantine? (y/n) ").lower() == "y")
            elif choice == "3":
                t = input("Paste the message: ")
                show("Message check", *analyze_text(t))
            elif choice == "4":
                show("Email check", *analyze_email(input("Path to .eml: ").strip('" ')))
            elif choice == "5":
                show("Number check", *analyze_number(input("Number (with country code): ")))
            elif choice == "6":
                block_number(input("Number to block: "))
            elif choice == "0":
                return
        except FileNotFoundError:
            print("File or folder not found.")


def main():
    ap = argparse.ArgumentParser(description="CyberGuard defensive toolkit")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("scan"); p.add_argument("path"); p.add_argument("--quarantine", action="store_true"); p.add_argument("--defender", action="store_true")
    p = sub.add_parser("watch"); p.add_argument("folder", nargs="?", default=str(Path.home() / "Downloads")); p.add_argument("--auto-quarantine", action="store_true")
    p = sub.add_parser("message"); p.add_argument("text")
    p = sub.add_parser("email"); p.add_argument("file")
    p = sub.add_parser("number"); p.add_argument("number"); p.add_argument("--my-number")
    p = sub.add_parser("block"); p.add_argument("number")
    a = ap.parse_args()

    if a.cmd == "scan":
        scan_path(a.path, a.quarantine, a.defender)
    elif a.cmd == "watch":
        watch(a.folder, a.auto_quarantine)
    elif a.cmd == "message":
        show("Message check", *analyze_text(a.text))
    elif a.cmd == "email":
        show("Email check", *analyze_email(a.file))
    elif a.cmd == "number":
        show(f"Number check: {a.number}", *analyze_number(a.number, a.my_number))
    elif a.cmd == "block":
        block_number(a.number)
    else:
        menu()




# =====================================================================
# CyberGuard AI+ feature layer
# Explainable local heuristics; no claim of a trained/deep-learning model.
# =====================================================================

import csv
import difflib
import math
import platform
import socket
import statistics
import getpass
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


APP_VERSION = "2.0"
REPORT_DIR = HOME / "reports"
BASELINE_FILE = HOME / "integrity_baseline.json"
ALLOWLIST_FILE = HOME / "trusted_hashes.txt"
FEEDBACK_FILE = HOME / "feedback.json"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class Finding:
    """One explainable security finding."""
    category: str
    severity: str
    title: str
    detail: str
    recommendation: str
    score: int = 0

    def to_dict(self):
        return asdict(self)


def _safe_read_text(path: Path, limit: int = 2_000_000) -> str:
    """Read bounded text without allowing an unexpectedly huge file into RAM."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except (OSError, ValueError):
        return ""


def _safe_json(path: Path, default):
    try:
        return json.loads(_safe_read_text(path))
    except (json.JSONDecodeError, TypeError):
        return default


def severity_for_score(score: int) -> str:
    """Map a heuristic score to a human-readable risk band."""
    if score >= 8:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "INFO"


def confidence_label(signal_count: int) -> str:
    """Confidence describes evidence quantity, not certainty that an item is bad."""
    if signal_count >= 5:
        return "more evidence"
    if signal_count >= 2:
        return "some evidence"
    return "limited evidence"


def explain_score(title: str, score: int, reasons: Sequence[str]) -> Dict[str, Any]:
    """Create a structured, explainable result suitable for a report."""
    return {
        "title": title,
        "score": int(score),
        "risk": verdict(score),
        "evidence_count": len(reasons),
        "evidence_strength": confidence_label(len(reasons)),
        "reasons": list(reasons),
        "limitations": [
            "This is a heuristic screening result, not a proof of malware or fraud.",
            "A clean result does not guarantee safety; verify through trusted channels.",
        ],
    }


def print_explanation(result: Dict[str, Any]) -> None:
    """Print the same structured findings in a readable terminal format."""
    print("=" * 68)
    print(result["title"])
    print(f"Risk: {result['risk']} | Score: {result['score']}")
    print(f"Evidence: {result['evidence_strength']} ({result['evidence_count']} signal(s))")
    for reason in result["reasons"]:
        print(f"  • {reason}")
    if not result["reasons"]:
        print("  • No configured heuristic triggered.")
    print("Note: heuristic results can produce false positives and false negatives.")
    print("=" * 68)


# ---------------------------------------------------------------------
# 1. Explainable text classifier
# ---------------------------------------------------------------------

PHISHING_FEATURES = [
    (r"\b(otp|one[- ]time password|verification code)\b", 3, "Mentions an OTP or verification code"),
    (r"\b(password|passcode|cvv|pin)\b", 2, "Mentions a secret credential"),
    (r"\b(click here|tap here|open this link|verify now)\b", 2, "Pressures the reader to follow a link"),
    (r"\b(account.{0,20}(locked|blocked|suspended)|suspended.{0,20}account)\b", 3, "Threatens account access"),
    (r"\b(urgent|immediately|within \d+ hours|last warning)\b", 1, "Uses urgency or pressure"),
    (r"\b(prize|lottery|winner|cashback|free gift)\b", 2, "Uses a prize or reward lure"),
    (r"\b(pay.{0,20}fee|processing fee|advance payment)\b", 2, "Requests an advance payment"),
    (r"\b(aadhaar|pan|kyc)\b.{0,35}\b(update|verify|block|expire)\b", 2, "Requests identity/KYC action"),
    (r"\b(remote access|anydesk|teamviewer|screen share)\b", 3, "Mentions remote-access software"),
    (r"\b(bank|upi|wallet)\b.{0,35}\b(refund|credit|debit|blocked)\b", 1, "Mentions a financial account action"),
    (r"\b(send|share|tell|provide|enter)\b.{0,20}\b(otp|pin|password|cvv)\b", 4, "Explicitly asks for a secret"),
    (r"\b(install|download)\b.{0,25}\b(apk|application|app)\b", 2, "Requests an app installation"),
    (r"\b(police|arrest|warrant|legal action)\b", 2, "Uses a threat of legal consequences"),
    (r"\b(work from home|part[- ]time job)\b.{0,45}\b(earn|daily income|guaranteed)\b", 2, "Promises easy income"),
    (r"\b(delivery|parcel|courier)\b.{0,35}\b(failed|fee|address|reschedule)\b", 2, "May imitate a delivery notice"),
]

BENIGN_CONTEXT_FEATURES = [
    (r"\b(security awareness|phishing simulation|training exercise)\b", 2,
     "Text may be discussing security training"),
    (r"\b(do not share|never share|don't share)\b.{0,30}\b(otp|password|pin)\b", 2,
     "Contains protective advice about credentials"),
]


def classify_message(text: str) -> Dict[str, Any]:
    """
    Local, explainable phishing triage.
    This is a rules-based scoring system rather than a trained neural network.
    """
    score = 0
    evidence = []
    protective_context = []
    for pattern, points, description in PHISHING_FEATURES:
        if re.search(pattern, text, re.I | re.S):
            score += points
            evidence.append({"feature": description, "points": points})
    for pattern, points, description in BENIGN_CONTEXT_FEATURES:
        if re.search(pattern, text, re.I | re.S):
            score -= points
            protective_context.append(description)
    url_score, url_reasons = analyze_text(text)
    # The existing analyzer also scores message patterns. Only use URL signals
    # here to avoid counting the same text rules twice.
    for url in URL_RE.findall(text):
        points, reasons = analyze_url(url.rstrip(".,;"))
        if points:
            score += points
            evidence.append({"feature": "URL: " + "; ".join(reasons), "points": points})
    score = max(0, min(score, 30))
    if score >= 9:
        label = "LIKELY SCAM / PHISHING"
    elif score >= 4:
        label = "SUSPICIOUS — VERIFY"
    else:
        label = "NO STRONG SIGNALS FOUND"
    return {
        "label": label,
        "score": score,
        "risk": severity_for_score(score),
        "evidence": evidence,
        "protective_context": protective_context,
        "advice": [
            "Do not share OTPs, PINs, passwords, or CVV codes.",
            "Do not use links in unexpected messages; open the official app or type the known website yourself.",
            "Contact the organization using a phone number printed on its official card or website.",
            "If money was lost in India, contact your bank promptly and report cyber fraud via 1930 or cybercrime.gov.in.",
        ],
        "model_note": "Explainable local rules; not a trained AI model and not a guarantee.",
    }


def command_classify(text: str) -> None:
    result = classify_message(text)
    print(f"\nClassification: {result['label']}")
    print(f"Risk band: {result['risk']} | score: {result['score']}/30")
    print("\nSignals:")
    if result["evidence"]:
        for item in result["evidence"]:
            print(f"  +{item['points']}: {item['feature']}")
    else:
        print("  No configured signal triggered.")
    if result["protective_context"]:
        print("\nProtective context:")
        for item in result["protective_context"]:
            print("  -", item)
    print("\nRecommended next steps:")
    for item in result["advice"]:
        print("  -", item)
    print("\nLimit:", result["model_note"])


# ---------------------------------------------------------------------
# 2. Password quality checker (does not store the password)
# ---------------------------------------------------------------------

COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "qwerty",
    "admin", "admin123", "letmein", "welcome", "iloveyou",
    "india123", "changeme", "pass@123", "12345678",
}


def password_audit(password: str) -> Dict[str, Any]:
    """Estimate password strength locally; never persist or log the input."""
    issues = []
    length = len(password)
    alphabet_size = 0
    alphabet_size += 26 if re.search(r"[a-z]", password) else 0
    alphabet_size += 26 if re.search(r"[A-Z]", password) else 0
    alphabet_size += 10 if re.search(r"\d", password) else 0
    alphabet_size += 32 if re.search(r"[^A-Za-z0-9]", password) else 0
    if length < 12:
        issues.append("Use at least 12 characters; longer is generally better.")
    if not re.search(r"[a-z]", password):
        issues.append("Add lowercase letters or use a long passphrase.")
    if not re.search(r"[A-Z]", password):
        issues.append("Consider uppercase letters.")
    if not re.search(r"\d", password):
        issues.append("Consider adding numbers.")
    if not re.search(r"[^A-Za-z0-9]", password):
        issues.append("Consider punctuation or use a longer passphrase.")
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is a commonly used password.")
    if re.search(r"(.)\1{3,}", password):
        issues.append("Avoid long runs of the same character.")
    if re.search(r"1234|abcd|qwerty|password", password, re.I):
        issues.append("Avoid common sequences and predictable words.")
    if length and len(set(password)) <= 3:
        issues.append("Too few distinct characters.")
    # Shannon-style upper-bound estimate, not a crack-time promise.
    entropy = length * math.log2(alphabet_size) if alphabet_size > 1 else 0
    if length >= 16 and len(set(password)) >= 8 and not issues:
        rating = "STRONGER"
    elif length >= 12 and entropy >= 60 and len(issues) <= 2:
        rating = "MODERATE"
    else:
        rating = "WEAK"
    return {
        "rating": rating,
        "length": length,
        "estimated_entropy_bits": round(entropy, 1),
        "issues": issues,
        "privacy": "Password was checked in memory only and is not saved by this feature.",
        "recommendations": [
            "Use a unique password for every account.",
            "Prefer a long passphrase or a password manager-generated password.",
            "Enable multifactor authentication where available.",
        ],
    }


def command_password() -> None:
    password = getpass.getpass("Password to check (hidden; not stored): ")
    result = password_audit(password)
    print(f"\nRating: {result['rating']}")
    print(f"Length: {result['length']} characters")
    print(f"Rough entropy upper-bound: {result['estimated_entropy_bits']} bits")
    for issue in result["issues"]:
        print(" -", issue)
    for advice in result["recommendations"]:
        print(" •", advice)
    print(result["privacy"])
    # Best-effort removal of the local reference.
    password = ""


# ---------------------------------------------------------------------
# 3. File integrity baseline
# ---------------------------------------------------------------------

def build_integrity_baseline(root: str) -> Dict[str, Any]:
    """Hash files under a folder; skip unreadable files and this app's data."""
    base = Path(root).expanduser().resolve()
    if not base.exists() or not base.is_dir():
        raise ValueError("Baseline target must be an existing directory.")
    entries = {}
    errors = []
    for path in base.rglob("*"):
        try:
            if not path.is_file():
                continue
            resolved = path.resolve()
            if HOME == resolved or HOME in resolved.parents:
                continue
            entries[str(path.relative_to(base))] = {
                "sha256": sha256_of(path),
                "size": path.stat().st_size,
            }
        except (OSError, PermissionError) as exc:
            errors.append(f"{path}: {type(exc).__name__}")
    return {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(base),
        "files": entries,
        "errors": errors,
    }


def save_integrity_baseline(root: str) -> Path:
    baseline = build_integrity_baseline(root)
    BASELINE_FILE.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    log(f"Integrity baseline created for {baseline['root']} ({len(baseline['files'])} files)")
    return BASELINE_FILE


def compare_integrity_baseline() -> Dict[str, Any]:
    baseline = _safe_json(BASELINE_FILE, {})
    if not baseline or "root" not in baseline:
        raise FileNotFoundError("No baseline found. Run: integrity-create FOLDER")
    root = Path(baseline["root"])
    if not root.exists():
        raise FileNotFoundError(f"Baseline folder is missing: {root}")
    previous = baseline.get("files", {})
    current = {}
    errors = []
    for path in root.rglob("*"):
        try:
            if path.is_file():
                current[str(path.relative_to(root))] = {
                    "sha256": sha256_of(path),
                    "size": path.stat().st_size,
                }
        except OSError as exc:
            errors.append(f"{path}: {type(exc).__name__}")
    added = sorted(set(current) - set(previous))
    removed = sorted(set(previous) - set(current))
    changed = sorted(name for name in set(current) & set(previous)
                     if current[name]["sha256"] != previous[name].get("sha256"))
    return {
        "root": str(root),
        "added": added,
        "removed": removed,
        "changed": changed,
        "errors": errors,
        "checked_at": datetime.now().isoformat(timespec="seconds"),
    }


def command_integrity_create(folder: str) -> None:
    path = save_integrity_baseline(folder)
    baseline = _safe_json(BASELINE_FILE, {})
    print(f"Baseline saved: {path}")
    print(f"Files fingerprinted: {len(baseline.get('files', {}))}")
    if baseline.get("errors"):
        print(f"Unreadable files: {len(baseline['errors'])}")


def command_integrity_check() -> None:
    result = compare_integrity_baseline()
    print(f"Integrity check: {result['root']}")
    for key in ("added", "removed", "changed"):
        print(f"\n{key.title()} ({len(result[key])}):")
        for item in result[key][:100]:
            print("  -", item)
        if len(result[key]) > 100:
            print(f"  ... {len(result[key]) - 100} more")
    if result["errors"]:
        print(f"\nUnreadable: {len(result['errors'])}")
    if not (result["added"] or result["removed"] or result["changed"]):
        print("\nNo changes detected. This does not prove the folder is safe.")


# ---------------------------------------------------------------------
# 4. Local system security posture checklist
# ---------------------------------------------------------------------

def system_audit() -> List[Finding]:
    """A cautious local checklist; it does not attempt privilege escalation."""
    findings = []
    system = platform.system()
    findings.append(Finding(
        "system", "INFO", "Operating system",
        f"{platform.platform()}",
        "Keep the operating system and browser updated.", 0
    ))
    if system == "Windows":
        defender = shutil.which("powershell")
        if defender:
            try:
                cmd = [
                    "powershell", "-NoProfile", "-Command",
                    "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                value = result.stdout.strip().lower()
                if value == "true":
                    findings.append(Finding(
                        "antivirus", "INFO", "Microsoft Defender reports enabled",
                        "PowerShell status query returned True.",
                        "Keep real-time protection enabled and signatures updated.", 0
                    ))
                elif value == "false":
                    findings.append(Finding(
                        "antivirus", "HIGH", "Microsoft Defender may be disabled",
                        "PowerShell status query returned False or protection is unavailable.",
                        "Open Windows Security and verify antivirus protection.", 8
                    ))
                else:
                    findings.append(Finding(
                        "antivirus", "LOW", "Defender status could not be confirmed",
                        "The status query returned no clear True/False value.",
                        "Check Windows Security manually.", 1
                    ))
            except (OSError, subprocess.TimeoutExpired):
                findings.append(Finding(
                    "antivirus", "LOW", "Defender status check failed",
                    "The command was unavailable or timed out.",
                    "Check Windows Security manually.", 1
                ))
    else:
        findings.append(Finding(
            "antivirus", "INFO", "Antivirus status not queried",
            "Automatic antivirus status query is only implemented for Windows.",
            "Use the security tools supported by your operating system.", 0
        ))
    if not os.environ.get("VT_API_KEY"):
        findings.append(Finding(
            "reputation", "INFO", "VirusTotal integration not configured",
            "No VT_API_KEY environment variable was found.",
            "Optional: configure an API key if you understand third-party hash lookups.", 0
        ))
    findings.append(Finding(
        "backup", "LOW", "Backup status requires manual confirmation",
        "This program cannot verify that your personal files have restorable backups.",
        "Keep an offline or versioned backup and test restoring a file.", 1
    ))
    findings.append(Finding(
        "account", "LOW", "Account protection requires manual confirmation",
        "MFA and recovery settings are not exposed to this local script.",
        "Enable MFA and review account recovery options.", 1
    ))
    return findings


def command_audit() -> None:
    print(f"CyberGuard system audit — {datetime.now():%Y-%m-%d %H:%M:%S}")
    for finding in system_audit():
        print(f"\n[{finding.severity}] {finding.title}")
        print("  ", finding.detail)
        print("  Recommended:", finding.recommendation)


# ---------------------------------------------------------------------
# 5. Safe duplicate-file inventory
# ---------------------------------------------------------------------

def duplicate_files(folder: str) -> Dict[str, List[str]]:
    """Find byte-identical files by SHA-256; never delete or modify them."""
    root = Path(folder).expanduser()
    if not root.is_dir():
        raise ValueError("Provide an existing directory.")
    by_hash: Dict[str, List[str]] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            digest = sha256_of(path)
            by_hash.setdefault(digest, []).append(str(path))
        except OSError:
            continue
    return {digest: paths for digest, paths in by_hash.items() if len(paths) > 1}


def command_duplicates(folder: str) -> None:
    groups = duplicate_files(folder)
    print(f"Duplicate groups found: {len(groups)}")
    for digest, paths in groups.items():
        print(f"\nSHA-256: {digest}")
        for path in paths:
            print("  -", path)
    print("\nNo files were deleted or changed.")


# ---------------------------------------------------------------------
# 6. Local event-log summaries
# ---------------------------------------------------------------------

def summarize_log(path: str) -> Dict[str, Any]:
    """Summarize CyberGuard's own log without claiming intrusion detection."""
    target = Path(path).expanduser()
    lines = _safe_read_text(target).splitlines()
    levels = Counter()
    for line in lines:
        upper = line.upper()
        if "DANGEROUS" in upper or "THREAT" in upper:
            levels["high_signal"] += 1
        elif "SUSPICIOUS" in upper or "QUARANTINED" in upper:
            levels["medium_signal"] += 1
        else:
            levels["other"] += 1
    return {
        "path": str(target),
        "line_count": len(lines),
        "counts": dict(levels),
        "recent_lines": lines[-20:],
        "note": "This summarizes logged events only; it is not a full forensic analysis.",
    }


def command_log_summary(path: str) -> None:
    result = summarize_log(path)
    print(f"Log: {result['path']}")
    print(f"Lines: {result['line_count']}")
    for key, value in result["counts"].items():
        print(f"{key}: {value}")
    print("\nRecent entries:")
    for line in result["recent_lines"]:
        print(line)
    print("\n", result["note"])


# ---------------------------------------------------------------------
# 7. Structured report export
# ---------------------------------------------------------------------

def write_report(report_type: str, data: Any) -> Path:
    """Write JSON report using a timestamped filename."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_type = re.sub(r"[^a-zA-Z0-9_-]", "_", report_type)[:40]
    target = REPORT_DIR / f"{stamp}_{safe_type}.json"
    payload = {
        "application": "CyberGuard",
        "version": APP_VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "report_type": report_type,
        "data": data,
        "disclaimer": "Heuristic screening is not a guarantee of safety.",
    }
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"REPORT {target.name}")
    return target


def command_report(path: Optional[str] = None) -> None:
    if path:
        target = Path(path)
        if not target.exists():
            raise FileNotFoundError(path)
        data = {
            "file": str(target),
            "size": target.stat().st_size,
            "sha256": sha256_of(target) if target.is_file() else None,
        }
        report = write_report("file_metadata", data)
    else:
        report = write_report("system_audit", [asdict(x) for x in system_audit()])
    print("Report saved:", report)


# ---------------------------------------------------------------------
# 8. Safe URL inspection with explicit no-fetch behavior
# ---------------------------------------------------------------------

def inspect_url(url: str) -> Dict[str, Any]:
    """Analyze a URL string without visiting it or downloading content."""
    score, reasons = analyze_url(url.strip())
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""
    return {
        "url": url,
        "host": host,
        "scheme": parsed.scheme,
        "score": score,
        "risk": verdict(score),
        "reasons": reasons,
        "network_access": False,
        "advice": [
            "Do not open an unexpected link just to test it.",
            "A domain name and HTTPS lock do not prove that a page is legitimate.",
            "Navigate to the service through its official app or a saved bookmark.",
        ],
    }


def command_url(url: str) -> None:
    result = inspect_url(url)
    print(f"URL: {result['url']}")
    print(f"Host: {result['host'] or '(not parsed)'}")
    print(f"Risk: {result['risk']} (score {result['score']})")
    for reason in result["reasons"]:
        print(" -", reason)
    for advice in result["advice"]:
        print(" •", advice)
    print("The URL was not opened or fetched.")


# ---------------------------------------------------------------------
# 9. Security education and guided incident response
# ---------------------------------------------------------------------

SECURITY_TIPS = [
    "Never disclose an OTP to a caller, even if they claim to be bank staff.",
    "A caller ID or sender name can be spoofed; verify through an official channel.",
    "Use a password manager and unique passwords for important accounts.",
    "Turn on multifactor authentication for email, banking, and developer accounts.",
    "Keep your browser, operating system, and apps updated.",
    "Back up important files and periodically test that restoration works.",
    "Do not enable macros or run scripts from unexpected attachments.",
    "Use a separate standard account for everyday computer use when practical.",
    "Review account sessions and revoke sessions you do not recognize.",
    "Avoid entering credentials after following links in unexpected messages.",
    "Treat QR codes as links: inspect the destination before signing in or paying.",
    "If you suspect fraud, contact your bank using its official app or card number.",
    "Do not pay a person who promises to recover money in exchange for an advance fee.",
    "Download software from official publisher sites or trusted stores.",
    "Keep recovery codes offline in a secure place.",
    "Do not install remote-control apps at the request of an unsolicited caller.",
    "Use screen lock and device encryption where supported.",
    "Review app permissions and remove apps you no longer use.",
    "Be cautious with public Wi-Fi; avoid sensitive work on untrusted networks.",
    "Report suspicious messages using your phone or email provider's reporting option.",
]


def show_tips() -> None:
    print("CyberGuard Security Tips")
    for index, tip in enumerate(SECURITY_TIPS, 1):
        print(f"{index:02d}. {tip}")


def incident_response(kind: str) -> List[str]:
    """Provide conservative first-response advice, not automated remediation."""
    common = [
        "Stop interacting with the suspicious message, caller, or website.",
        "Do not delete relevant evidence; keep screenshots, timestamps, and transaction IDs.",
        "Use a separate trusted device to access important accounts if compromise is suspected.",
    ]
    playbooks = {
        "phishing": [
            "Do not click further links or open attachments.",
            "Report the message to the mail, messaging, or social platform.",
            "If you entered a password, change it from the official site and revoke other sessions.",
        ],
        "money": [
            "Contact your bank/payment provider immediately using an official channel.",
            "In India, call 1930 promptly for cyber financial fraud and submit details at cybercrime.gov.in.",
            "Preserve UPI IDs, transaction references, screenshots, and bank notifications.",
        ],
        "malware": [
            "Disconnect the affected device from networks if active compromise is suspected.",
            "Do not run the suspicious file again; scan with updated trusted security software.",
            "Use a clean device to change important passwords if credentials may have been exposed.",
        ],
        "account": [
            "Change the password from the official site and enable MFA.",
            "Review recovery email/phone, active sessions, app passwords, and forwarding rules.",
            "Check recent activity and contact the service provider if access is lost.",
        ],
        "phone": [
            "Do not call back an unexpected missed international number.",
            "Block and report the caller using your phone's built-in tools.",
            "Contact your telecom provider if repeated spoofing or harassment occurs.",
        ],
    }
    return common + playbooks.get(kind, [
        "Contact the relevant service provider through a verified official channel.",
        "If money or personal safety is at immediate risk, contact appropriate local authorities.",
    ])


def command_incident(kind: str) -> None:
    print(f"First-response checklist: {kind}")
    for index, step in enumerate(incident_response(kind), 1):
        print(f"{index}. {step}")
    print("\nDo not share passwords, OTPs, or full payment credentials in this tool.")


# ---------------------------------------------------------------------
# 10. Small offline self-test suite
# ---------------------------------------------------------------------

def run_self_tests() -> Tuple[int, int]:
    """Smoke tests for core defensive heuristics; no network access required."""
    tests = [
        ("obvious OTP scam", lambda: analyze_text("Share OTP immediately or account blocked")[0] >= 3),
        ("shortener URL", lambda: analyze_url("https://bit.ly/example")[0] >= 2),
        ("password length", lambda: password_audit("x")["rating"] == "WEAK"),
        ("safe URL parsing", lambda: inspect_url("https://example.com")["host"] == "example.com"),
        ("bare domain recognition", lambda: any(u.startswith("example.com") for u in _extract_urls("Check example.com/path"))),
        ("message link recognition", lambda: len(_extract_urls("Hi, open https://example.com and www.google.com")) == 2),
        ("URL score not multiplied by reasons", lambda: classify_message("https://bit.ly/abc")["score"] <= 10),
        ("message result shape", lambda: "advice" in classify_message("hello")),
        ("incident playbook", lambda: len(incident_response("money")) >= 4),
        ("score severity", lambda: severity_for_score(9) == "HIGH"),
        ("duplicate result type", lambda: isinstance(duplicate_files(str(HOME)), dict)),
    ]
    passed = 0
    for name, check in tests:
        try:
            ok = bool(check())
        except Exception as exc:
            ok = False
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"{'PASS' if ok else 'FAIL'} {name}")
        passed += int(ok)
    print(f"\nSelf-tests: {passed}/{len(tests)} passed")
    return passed, len(tests)


# ---------------------------------------------------------------------
# 11. Configuration and privacy information
# ---------------------------------------------------------------------

def show_configuration() -> None:
    print("CyberGuard configuration")
    print("Version:", APP_VERSION)
    print("Data directory:", HOME)
    print("Quarantine:", QUARANTINE)
    print("Log file:", LOG_FILE)
    print("Reports:", REPORT_DIR)
    print("Integrity baseline:", BASELINE_FILE)
    print("VirusTotal key configured:", bool(os.environ.get("VT_API_KEY")))
    print("\nPrivacy notes:")
    print("- Message and password checks are performed locally by this feature layer.")
    print("- VirusTotal hash lookup can send a file hash to a third-party service when enabled.")
    print("- The password checker does not write the entered password to disk.")
    print("- Logs can contain file paths; review them before sharing.")
    print("- Do not upload confidential files or messages to public analysis services.")


# ---------------------------------------------------------------------
# 12. Extended interactive menu
# ---------------------------------------------------------------------

def enhanced_menu() -> None:
    menu_text = """
 CyberGuard AI+ — defensive security toolkit
  1) Scan a file or folder
  2) Watch a folder for new files
  3) Check a message (SMS / chat)
  4) Check a saved email (.eml)
  5) Check a phone number
  6) Add a number to personal blocklist
  7) Explainable phishing triage
  8) Inspect a URL (without opening it)
  9) Password strength check (hidden input)
 10) Create file-integrity baseline
 11) Compare files to saved baseline
 12) Local system security audit
 13) Find duplicate files (read-only)
 14) Summarize CyberGuard log
 15) Export JSON report
 16) Incident-response checklist
 17) Security tips
 18) Run offline self-tests
 19) Show configuration and privacy notes
 20) Analyze suspicious call message / transcript
 21) Submit a local community scam report
 22) Phone scam dashboard and trends
 23) Scam pattern intelligence (local reports)
 24) Generate phone investigation report (JSON)
  0) Exit
"""
    while True:
        print(menu_text)
        choice = input("Choose: ").strip()
        try:
            if choice == "1":
                folder = input("File/folder path: ").strip('" ')
                scan_path(folder, do_quarantine=input("Quarantine dangerous files? (y/n) ").lower() == "y")
            elif choice == "2":
                folder = input(f"Folder to watch [{Path.home() / 'Downloads'}]: ").strip('" ')
                watch(folder or str(Path.home() / "Downloads"),
                      auto_quarantine=input("Auto-quarantine dangerous files? (y/n) ").lower() == "y")
            elif choice == "3":
                show("Message check", *analyze_text(input("Paste message: ")))
            elif choice == "4":
                show("Email check", *analyze_email(input("Path to .eml: ").strip('" ')))
            elif choice == "5":
                command_number_check()
            elif choice == "6":
                block_number(input("Number to block: "))
            elif choice == "7":
                command_classify(input("Paste message: "))
            elif choice == "8":
                command_url(input("URL: "))
            elif choice == "9":
                command_password()
            elif choice == "10":
                command_integrity_create(input("Folder to baseline: ").strip('" '))
            elif choice == "11":
                command_integrity_check()
            elif choice == "12":
                command_audit()
            elif choice == "13":
                command_duplicates(input("Folder: ").strip('" '))
            elif choice == "14":
                command_log_summary(str(LOG_FILE))
            elif choice == "15":
                command_report()
            elif choice == "16":
                kind = input("Incident type (phishing/money/malware/account/phone): ").strip().lower()
                command_incident(kind)
            elif choice == "17":
                show_tips()
            elif choice == "18":
                run_self_tests()
            elif choice == "19":
                show_configuration()
            elif choice == "20":
                command_phone_message_check()
            elif choice == "21":
                command_phone_community_report()
            elif choice == "22":
                command_phone_dashboard()
            elif choice == "23":
                command_phone_pattern_intelligence()
            elif choice == "24":
                command_phone_investigation_report()
            elif choice == "0":
                print("CyberGuard closed.")
                return
            else:
                print("Choose one of the listed options.")
        except (OSError, ValueError, FileNotFoundError) as exc:
            print(f"Could not complete action: {exc}")
        except KeyboardInterrupt:
            print("\nAction cancelled.")


# ---------------------------------------------------------------------
# 13. Expanded command-line interface
# ---------------------------------------------------------------------

def enhanced_main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberGuard AI+ defensive security toolkit",
        epilog="Heuristic tool only. Keep your operating system's antivirus enabled.",
    )
    sub = parser.add_subparsers(dest="cmd")
    p = sub.add_parser("scan", help="scan a file or folder")
    p.add_argument("path")
    p.add_argument("--quarantine", action="store_true")
    p.add_argument("--defender", action="store_true")

    p = sub.add_parser("watch", help="watch a folder for new files")
    p.add_argument("folder", nargs="?", default=str(Path.home() / "Downloads"))
    p.add_argument("--auto-quarantine", action="store_true")

    p = sub.add_parser("message", help="check a message with existing rules")
    p.add_argument("text")
    p = sub.add_parser("classify", help="explainable phishing triage")
    p.add_argument("text")
    p = sub.add_parser("url", help="inspect a URL string without visiting it")
    p.add_argument("url")
    sub.add_parser("password", help="check password strength with hidden input")

    p = sub.add_parser("email", help="analyze a saved .eml file")
    p.add_argument("file")
    p = sub.add_parser("number", help="check a phone number")
    p.add_argument("number")
    p.add_argument("--my-number")
    p.add_argument("--quick", action="store_true", help="skip the y/n questions (number pattern only)")
    p = sub.add_parser("block", help="add a number to personal blocklist")
    p.add_argument("number")
    sub.add_parser("phone-patterns", help="summarize local scam-report patterns")
    p = sub.add_parser("phone-investigate", help="export a JSON phone investigation report")
    p.add_argument("number")

    p = sub.add_parser("integrity-create", help="create a SHA-256 folder baseline")
    p.add_argument("folder")
    sub.add_parser("integrity-check", help="compare folder against saved baseline")
    sub.add_parser("audit", help="run local security posture checklist")
    p = sub.add_parser("duplicates", help="find duplicate files without deleting them")
    p.add_argument("folder")
    p = sub.add_parser("log-summary", help="summarize CyberGuard log")
    p.add_argument("--file", default=str(LOG_FILE))
    p = sub.add_parser("report", help="export a JSON report")
    p.add_argument("--file", default=None)
    p = sub.add_parser("incident", help="show first-response checklist")
    p.add_argument("kind", choices=["phishing", "money", "malware", "account", "phone"])
    sub.add_parser("tips", help="show security tips")
    sub.add_parser("self-test", help="run offline smoke tests")
    sub.add_parser("config", help="show configuration and privacy notes")

    args = parser.parse_args()
    if not args.cmd:
        enhanced_menu()
        return

    try:
        if args.cmd == "scan":
            scan_path(args.path, args.quarantine, args.defender)
        elif args.cmd == "watch":
            watch(args.folder, args.auto_quarantine)
        elif args.cmd == "message":
            show("Message check", *analyze_text(args.text))
        elif args.cmd == "classify":
            command_classify(args.text)
        elif args.cmd == "url":
            command_url(args.url)
        elif args.cmd == "password":
            command_password()
        elif args.cmd == "email":
            show("Email check", *analyze_email(args.file))
        elif args.cmd == "number":
            if not getattr(args, "quick", False):
                command_number_check(args.number)
                return
            number_score, number_reasons = analyze_number(args.number, args.my_number)
            print(f"Phone risk: {_phone_risk_band(number_score)} | score {number_score}/10")
            for reason in number_reasons:
                print(" -", reason)
            if not number_reasons:
                print(" - No configured warning signal was found.")
            print("Note: caller ID can be spoofed; this offline check cannot prove identity or safety.")
        elif args.cmd == "block":
            block_number(args.number)
        elif args.cmd == "phone-patterns":
            command_phone_pattern_intelligence()
        elif args.cmd == "phone-investigate":
            command_phone_investigation_report(args.number)
        elif args.cmd == "integrity-create":
            command_integrity_create(args.folder)
        elif args.cmd == "integrity-check":
            command_integrity_check()
        elif args.cmd == "audit":
            command_audit()
        elif args.cmd == "duplicates":
            command_duplicates(args.folder)
        elif args.cmd == "log-summary":
            command_log_summary(args.file)
        elif args.cmd == "report":
            command_report(args.file)
        elif args.cmd == "incident":
            command_incident(args.kind)
        elif args.cmd == "tips":
            show_tips()
        elif args.cmd == "self-test":
            passed, total = run_self_tests()
            raise SystemExit(0 if passed == total else 1)
        elif args.cmd == "config":
            show_configuration()
    except (OSError, ValueError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(2)


# Keep original functions above for backwards compatibility, but route execution
# through the expanded CLI.


# ---------------------------------------------------------------------
# PhishProof enhancement layer (v2.1)
# Focus: consistent, explainable message and URL triage.
# ---------------------------------------------------------------------
from dataclasses import dataclass as _dataclass
from typing import Optional as _Optional

@dataclass
class Evidence:
    category: str
    description: str
    points: int
    matched_text: str = ""

@dataclass
class PhishResult:
    label: str
    score: int
    evidence: list
    protective_context: list
    advice: list
    limitation: str = "Heuristic screening only; this is not proof and cannot guarantee safety."


def _extract_urls(text: str) -> list:
    """Find URLs in pasted text, including www links and bare domains."""
    if not text:
        return []
    pattern = re.compile(
        r"""(?i)(?:https?://|ftp://|www\.)[^\s<>"'`]+"""
        r"""|(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"""
        r"""(?:com|net|org|in|co|uk|gov|edu|io|app|info|biz|xyz|top|click|me|ly|dev|ai|support)"""
        r"""(?:/[^\s<>"'`]*)?"""
    )
    found = []
    for match in pattern.findall(str(text)[:20000]):
        candidate = match.rstrip(".,;:!?)]}")
        if candidate and candidate not in found:
            found.append(candidate)
        if len(found) >= 20:
            break
    return found

def _url_host(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
        return (parsed.hostname or "").lower().rstrip(".")
    except (ValueError, UnicodeError):
        return ""


def analyze_url(url):
    """Return URL risk points and explicit evidence without fetching it."""
    score, reasons = 0, []
    url = (url or "").strip()
    if not url or len(url) > 4096:
        return 2, ["Empty or unusually long URL; could not assess reliably"]
    try:
        parsed = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except (ValueError, UnicodeError):
        return 2, ["Malformed URL; inspect only through a trusted channel"]
    if not host:
        return 2, ["URL has no recognizable hostname"]
    try:
        host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError:
        host_ascii = host
    if host_ascii.startswith("xn--") or ".xn--" in host_ascii:
        score += 3; reasons.append(f"Internationalized/punycode hostname: {host_ascii}")
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        score += 3; reasons.append("Uses a numeric IP address instead of a recognizable domain")
    if host_ascii in SHORTENERS:
        score += 2; reasons.append(f"URL shortener hides the eventual destination ({host_ascii})")
    tld = host_ascii.rsplit(".", 1)[-1] if "." in host_ascii else ""
    if tld in BAD_TLDS:
        score += 1; reasons.append(f"Uncommon/high-abuse domain ending .{tld}; not proof of fraud")
    if "@" in parsed.netloc:
        score += 3; reasons.append("URL contains user-info ('@'), which can obscure the actual host")
    if len(host_ascii) > 55 or host_ascii.count("-") >= 4 or host_ascii.count(".") >= 5:
        score += 1; reasons.append("Hostname has unusually complex structure")
    if parsed.scheme.lower() == "http":
        score += 1; reasons.append("Uses HTTP rather than HTTPS (this alone does not indicate phishing)")
    if port not in (None, 80, 443):
        score += 1; reasons.append(f"Uses a non-standard web port ({port})")
    # Compare brand-like hostname text against an explicit allowlist of registered domains.
    reg = registered_domain(host_ascii)
    for brand, legitimate_domains in BRANDS.items():
        if reg in legitimate_domains:
            continue
        compact = re.sub(r"[^a-z0-9]", "", host_ascii)
        # Catch common one-character substitutions/typos such as paypai-login.
        close_match = any(
            difflib.SequenceMatcher(None, brand, label).ratio() >= 0.80
            for label in re.findall(r"[a-z0-9]+", host_ascii)
        )
        if brand in compact or close_match:
            score += 3
            reasons.append(f"Hostname resembles or mentions {brand.title()} but uses {reg}")
            break
    return score, reasons


def analyze_text(text):
    """Unified legacy-compatible message analysis: (score, unique reasons)."""
    score, reasons = 0, []
    text = text or ""
    for pattern, points, description in TEXT_RULES:
        if re.search(pattern, text, re.I | re.S):
            score += points; reasons.append(description)
    for url in _extract_urls(text):
        points, why = analyze_url(url)
        score += points
        reasons.extend([f"URL {url}: {item}" for item in why])
    return score, list(dict.fromkeys(reasons))


def classify_message(text: str) -> Dict[str, Any]:
    """One consistent, explainable phishing triage result, checked locally."""
    text = (text or "")[:20000]
    evidence = []
    score = 0
    protective_context = []
    for pattern, points, description in PHISHING_FEATURES:
        match = re.search(pattern, text, re.I | re.S)
        if match:
            score += points
            evidence.append(Evidence("message", description, points, match.group(0)[:100]))
    for pattern, points, description in BENIGN_CONTEXT_FEATURES:
        match = re.search(pattern, text, re.I | re.S)
        if match:
            score -= points
            protective_context.append(description)
    # URL signals are analyzed once; retain each explanation as a separate item.
    for url in _extract_urls(text):
        points, reasons = analyze_url(url)
        if reasons:
            score += points
            for reason in reasons:
                evidence.append(Evidence("url", f"{url}: {reason}", points, url[:160]))
    score = max(0, min(score, 40))
    if score >= 9:
        label = "LIKELY PHISHING — DO NOT INTERACT"
    elif score >= 4:
        label = "SUSPICIOUS — VERIFY INDEPENDENTLY"
    else:
        label = "NO STRONG SIGNALS FOUND — NOT A SAFETY GUARANTEE"
    advice = [
        "Do not share an OTP, PIN, password, or CVV in response to an unexpected message.",
        "Do not open an unexpected link; open the organization’s official app or type its known address yourself.",
        "Contact the organization using a number or contact method you already trust.",
    ]
    return {
        "label": label,
        "score": score,
        "risk": "HIGH" if score >= 9 else "MEDIUM" if score >= 4 else "LOW SIGNAL",
        "evidence": [e.__dict__ for e in evidence],
        "protective_context": protective_context,
        "advice": advice,
        "model_note": "Local heuristic rules; score is not a probability and cannot prove safety or fraud.",
        "network_access": False,
    }


def inspect_url(url: str) -> Dict[str, Any]:
    """Inspect URL text locally; never resolve, open, or fetch it."""
    score, reasons = analyze_url(url)
    host = _url_host(url)
    return {
        "url": url,
        "host": host,
        "score": score,
        "risk": "HIGH" if score >= 6 else "SUSPICIOUS" if score >= 2 else "NO STRONG SIGNALS",
        "reasons": reasons,
        "network_access": False,
        "advice": ["Do not open an unexpected link to test it.", "Visit the official service through its app or a known bookmark."],
        "limitation": "No threat-intelligence lookup is performed; no warning does not mean safe.",
    }


def command_classify(text: str) -> None:
    result = classify_message(text)
    print(f"\n{result['label']}")
    print(f"Heuristic signal score: {result['score']} | {result['risk']}")
    print("\nEvidence:")
    if result["evidence"]:
        for item in result["evidence"]:
            excerpt = f" | matched: {item['matched_text']}" if item.get("matched_text") else ""
            print(f" +{item['points']} [{item['category']}] {item['description']}{excerpt}")
    else:
        print(" No configured indicators triggered.")
    if result["protective_context"]:
        print("\nProtective context:")
        for item in result["protective_context"]:
            print(" -", item)
    print("\nSafer next steps:")
    for item in result["advice"]:
        print(" -", item)
    print("\nLimit:", result["model_note"])


def command_url(url: str) -> None:
    """Recognize and assess one URL or links pasted inside a message."""
    raw = (url or "").strip()
    if not raw:
        print("No input provided. Paste a URL or a message containing a link.")
        return

    links = _extract_urls(raw)
    # Accept a direct URL even if it uses a less-common TLD not in the extractor.
    if not links and ("://" in raw or re.fullmatch(r"[^\s/]+\.[^\s/]+(?:/[^\s]*)?", raw)):
        links = [raw]

    if not links:
        print("No recognizable link found in the input.")
        print("Try pasting a full link such as https://example.com or a message containing it.")
        print("No network request was made.")
        return

    print(f"Recognized {len(links)} link(s). Links are inspected locally; they are NOT opened.\n")
    for index, link in enumerate(links, 1):
        result = inspect_url(link)
        print(f"[{index}] URL: {result['url']}")
        print(f"    Host: {result['host'] or '(unrecognized)'}")
        print(f"    Result: {result['risk']} (heuristic score {result['score']})")
        if result["reasons"]:
            for reason in result["reasons"]:
                print(f"    - {reason}")
        else:
            print("    - No configured URL warning patterns triggered.")
        print("    Advice: do not open unexpected links; verify through the official app/site.")
        print()
    print("Important: this offline check does not contact a live reputation database.")
    print("A low-risk result does not prove a link is safe.")


if __name__ == "__main__":
    enhanced_main()
