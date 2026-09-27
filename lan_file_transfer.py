#!/usr/bin/env python3
"""
Beam - LAN File Transfer (v2.0)
===============================
Share the drives on this PC with any web browser on your home network.

HOW TO USE
  1. Double-click "Start File Transfer.bat" on the PC with the drives.
  2. On your other PC, open the "Bookmark" address it shows and favourite it.
  3. Choose which drives are shared in Settings (sliders icon, top right).

SAFETY
  - Beam never deletes or overwrites anything. An upload with a name that
    already exists is saved as "name (1).ext".
  - Only the drives/folders ticked in Settings can be reached.
  - Without a password, anyone on your home network can browse the shared
    drives while Beam is running. Set a password in Settings if that matters.
  - Settings can only be changed on this PC, unless a password is set.

Files kept next to this script: beam_settings.json (settings), beam.log (log).
Requires Python 3.8+ (standard library only - nothing else to install).
"""

from __future__ import annotations

import copy
import email.utils
import hashlib
import hmac
import html
import http.cookies
import http.server
import ipaddress
import json
import logging
import logging.handlers
import os
import re
import secrets
import shutil
import socket
import socketserver
import stat
import sys
import threading
import time
import unicodedata
import urllib.parse
import webbrowser
import zipfile
from pathlib import Path

if sys.version_info < (3, 8):
    sys.exit("Beam needs Python 3.8 or newer: https://www.python.org/downloads/")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
APP = "Beam"
VERSION = "2.0"
IS_WINDOWS = os.name == "nt"
APP_DIR = Path(__file__).resolve().parent
SETTINGS_PATH = APP_DIR / "beam_settings.json"
LOG_PATH = APP_DIR / "beam.log"
HOSTNAME = socket.gethostname() or "localhost"
DEFAULT_PORT = 8000
CHUNK = 1024 * 1024
MAX_FORM_BYTES = 64 * 1024
MAX_DEPTH = 64
REINDEX_SECONDS = 60 * 60
SESSION_SECONDS = 30 * 24 * 3600
PBKDF2_ROUNDS = 240_000
SPACE_RESERVE = 16 * 1024 * 1024
TEMP_PREFIX = ".beam-"

SKIP_NAMES = {
    "$recycle.bin", "system volume information", "recycler", "config.msi",
    "$windows.~bt", "$windows.~ws", "msocache", "found.000",
}
LOCAL_SUFFIXES = ("local", "lan", "home", "localdomain", "home.arpa",
                  "internal", "router", "station", "gateway")

VIDEO_EXT = {"mp4", "mkv", "avi", "mov", "wmv", "m4v", "webm", "ts", "m2ts",
             "mpg", "mpeg", "flv", "vob", "3gp"}
AUDIO_EXT = {"mp3", "flac", "wav", "aac", "m4a", "ogg", "oga", "opus", "wma",
             "alac", "aiff"}
IMAGE_EXT = {"jpg", "jpeg", "png", "gif", "bmp", "webp", "heic", "tif",
             "tiff", "avif", "svg"}
ARCHIVE_EXT = {"zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso", "cab"}

# Types a browser can safely show itself. Anything else is always downloaded
# (never rendered), so a shared .html/.svg file can't run script on Beam's page.
INLINE_MIME = {
    "mp4": "video/mp4", "m4v": "video/mp4", "webm": "video/webm",
    "mp3": "audio/mpeg", "m4a": "audio/mp4", "aac": "audio/aac",
    "wav": "audio/wav", "ogg": "audio/ogg", "oga": "audio/ogg",
    "opus": "audio/ogg", "flac": "audio/flac",
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "gif": "image/gif", "webp": "image/webp", "bmp": "image/bmp",
    "avif": "image/avif", "pdf": "application/pdf",
}
for _ext in ("txt", "log", "md", "srt", "vtt", "nfo", "csv", "json", "ini", "cfg"):
    INLINE_MIME[_ext] = "text/plain; charset=utf-8"

PAGE_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "media-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'")

log = logging.getLogger("beam")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def setup_logging() -> None:
    log.setLevel(logging.INFO)
    log.propagate = False
    try:
        fh = logging.handlers.RotatingFileHandler(
            LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s %(message)s"))
        log.addHandler(fh)
    except OSError:
        pass
    if sys.stderr is not None:  # None when started hidden (pythonw)
        ch = logging.StreamHandler(sys.stderr)
        ch.setFormatter(logging.Formatter("  %(message)s"))
        log.addHandler(ch)


def say(msg: str = "") -> None:
    if sys.stdout is None:
        return
    try:
        print(msg, flush=True)
    except Exception:
        pass


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def human_size(n) -> str:
    if n is None:
        return ""
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def fmt_time(ts) -> str:
    try:
        return time.strftime("%d %b %Y, %H:%M", time.localtime(ts))
    except (OverflowError, OSError, ValueError):
        return ""


def natural_key(s: str):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s.casefold())]


def quote_path(rel: str) -> str:
    return urllib.parse.quote(rel, safe="/")


def normkey(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))


def share_id(path: str) -> str:
    return hashlib.sha1(normkey(path).encode("utf-8", "surrogatepass")).hexdigest()[:10]


def clean_parts(rel: str):
    return [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]


def ext_of(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def icon_for(name: str) -> str:
    e = ext_of(name)
    if e in VIDEO_EXT:
        return "video"
    if e in AUDIO_EXT:
        return "audio"
    if e in IMAGE_EXT:
        return "image"
    if e in ARCHIVE_EXT:
        return "archive"
    return "file"


_INVALID_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}


def clean_component(name: str):
    """Make one uploaded file/folder name safe for Windows. None = reject."""
    name = unicodedata.normalize("NFC", name)
    name = _INVALID_CHARS.sub("_", name).strip().rstrip(". ")
    if not name or name in (".", ".."):
        return None
    if name.split(".")[0].lower() in _RESERVED:
        name = "_" + name
    if len(name) > 200:
        stem, dot, ext = name.rpartition(".")
        name = (stem[: 200 - len(ext) - 1] + "." + ext) if dot and len(ext) < 20 else name[:200]
    return name


def unique_path(p: Path) -> Path:
    if not p.exists():
        return p
    stem, suffix = p.stem, p.suffix
    for i in range(1, 10000):
        cand = p.with_name(f"{stem} ({i}){suffix}")
        if not cand.exists():
            return cand
    raise OSError("No free file name available")


def content_disposition(name: str, inline: bool = False) -> str:
    kind = "inline" if inline else "attachment"
    fallback = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    fallback = re.sub(r'[^\x20-\x7e]|["\\]', "_", fallback).strip() or "download"
    return f"{kind}; filename=\"{fallback}\"; filename*=UTF-8''{urllib.parse.quote(name, safe='')}"


def capacity(path: str):
    try:
        du = shutil.disk_usage(path)
        return du.total, du.free
    except OSError:
        return None


def is_reparse(st) -> bool:
    if IS_WINDOWS:
        return bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    return stat.S_ISLNK(st.st_mode)


def skip_entry(entry: os.DirEntry, show_hidden: bool) -> bool:
    name = entry.name
    if name.lower() in SKIP_NAMES or name.startswith(TEMP_PREFIX):
        return True
    if show_hidden:
        return False
    if name.startswith("."):
        return True
    if IS_WINDOWS:
        try:
            attrs = entry.stat(follow_symlinks=False).st_file_attributes
        except OSError:
            return True
        return bool(attrs & (stat.FILE_ATTRIBUTE_HIDDEN | stat.FILE_ATTRIBUTE_SYSTEM))
    return False


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def primary_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))  # no packet is sent; just picks the LAN interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


_ip_cache = {"at": 0.0, "ips": set()}
_ip_lock = threading.Lock()


def local_ips() -> set:
    with _ip_lock:
        if time.time() - _ip_cache["at"] < 60:
            return _ip_cache["ips"]
        ips = {"127.0.0.1", "::1", primary_ip()}
        try:
            for info in socket.getaddrinfo(HOSTNAME, None):
                ips.add(norm_ip(info[4][0]))
        except OSError:
            pass
        _ip_cache.update(at=time.time(), ips=ips)
        return ips


def norm_ip(ip: str) -> str:
    ip = ip.split("%", 1)[0]
    if ip.lower().startswith("::ffff:") and "." in ip:
        ip = ip[7:]
    return ip


# ---------------------------------------------------------------------------
# Drives (auto-detected - no config editing)
# ---------------------------------------------------------------------------
def detect_drives():
    drives = []
    if not IS_WINDOWS:
        return drives
    import ctypes
    k32 = ctypes.windll.kernel32
    mask = k32.GetLogicalDrives()
    system_drive = os.environ.get("SystemDrive", "C:").upper().rstrip("\\")
    kinds = {2: "USB drive", 3: "Local disk", 4: "Network drive"}
    for i in range(26):
        if not mask & (1 << i):
            continue
        letter = chr(65 + i)
        root = f"{letter}:\\"
        dtype = k32.GetDriveTypeW(ctypes.c_wchar_p(root))
        if dtype not in kinds:
            continue
        label = ""
        if dtype in (2, 3):
            buf = ctypes.create_unicode_buffer(261)
            ok = k32.GetVolumeInformationW(ctypes.c_wchar_p(root), buf, 261, None, None, None, None, 0)
            if not ok:
                continue  # e.g. an empty card-reader slot
            label = buf.value
        label = label or kinds[dtype]
        drives.append({
            "path": root,
            "display": f"{label} ({letter}:)",
            "kind": kinds[dtype],
            "system": f"{letter}:" == system_drive,
        })
    return drives


# ---------------------------------------------------------------------------
# Settings (beam_settings.json)
# ---------------------------------------------------------------------------
class Settings:
    DEFAULTS = {"port": DEFAULT_PORT, "shares": [], "allow_uploads": True,
                "show_hidden": False, "password": None, "secret": ""}

    def __init__(self):
        self._lock = threading.RLock()
        self._data = copy.deepcopy(self.DEFAULTS)
        self.first_run = False

    def load(self) -> None:
        raw = None
        existed = SETTINGS_PATH.exists()
        if existed:
            try:
                raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
                if not isinstance(raw, dict):
                    raise ValueError("settings file is not a JSON object")
            except (OSError, ValueError) as exc:
                backup = SETTINGS_PATH.with_name("beam_settings.corrupt.json")
                log.error("Settings file unreadable (%s). Backed up to %s; using defaults.", exc, backup.name)
                try:
                    os.replace(SETTINGS_PATH, backup)
                except OSError:
                    pass
                raw = None
        with self._lock:
            d = self._data
            if raw is None:
                self.first_run = not existed
                d["shares"] = [{"path": x["path"], "name": x["display"]} for x in detect_drives()
                               if not x["system"] and x["kind"] != "Network drive"]
            else:
                port = raw.get("port")
                if isinstance(port, int) and not isinstance(port, bool) and 1024 <= port <= 65535:
                    d["port"] = port
                for key in ("allow_uploads", "show_hidden"):
                    if isinstance(raw.get(key), bool):
                        d[key] = raw[key]
                shares, seen = [], set()
                for s in raw.get("shares") if isinstance(raw.get("shares"), list) else []:
                    if isinstance(s, dict) and isinstance(s.get("path"), str) and s["path"].strip():
                        k = normkey(s["path"])
                        if k not in seen:
                            seen.add(k)
                            shares.append({"path": s["path"], "name": str(s.get("name") or s["path"])[:80]})
                d["shares"] = shares
                pw = raw.get("password")
                if (isinstance(pw, dict) and isinstance(pw.get("salt"), str)
                        and isinstance(pw.get("hash"), str) and isinstance(pw.get("rounds"), int)):
                    d["password"] = {"salt": pw["salt"], "hash": pw["hash"], "rounds": pw["rounds"]}
                if isinstance(raw.get("secret"), str) and len(raw["secret"]) >= 32:
                    d["secret"] = raw["secret"]
            if not d["secret"]:
                d["secret"] = secrets.token_hex(32)
            self.save()

    def save(self) -> None:
        with self._lock:
            tmp = SETTINGS_PATH.with_name("beam_settings.tmp")
            try:
                tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
                os.replace(tmp, SETTINGS_PATH)
            except OSError as exc:
                log.error("Couldn't save settings: %s", exc)

    def get(self, key):
        with self._lock:
            return copy.deepcopy(self._data[key])

    def set(self, **kwargs) -> None:
        with self._lock:
            self._data.update(kwargs)
            self.save()

    def shares(self):
        with self._lock:
            return [{"id": share_id(s["path"]), "path": s["path"], "name": s["name"]}
                    for s in self._data["shares"]]


settings = Settings()


def find_share(sid: str):
    for s in settings.shares():
        if s["id"] == sid:
            return s
    return None


def resolve_in_share(share, rel: str):
    """Real path inside the share, or None. Blocks '..', ':' (Windows
    alternate data streams) and symlinks/junctions leading outside."""
    parts = clean_parts(rel)
    if any(p == ".." or ":" in p or "\x00" in p for p in parts):
        return None
    try:
        root = Path(share["path"]).resolve(strict=True)
        target = root.joinpath(*parts).resolve(strict=True) if parts else root
    except (OSError, RuntimeError, ValueError):
        return None
    if target != root and root not in target.parents:
        return None
    return target


# ---------------------------------------------------------------------------
# Passwords & sessions
# ---------------------------------------------------------------------------
def hash_password(pw: str) -> dict:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return {"salt": salt.hex(), "hash": digest.hex(), "rounds": PBKDF2_ROUNDS}


def check_password(pw: str, rec) -> bool:
    if not rec:
        return False
    try:
        digest = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(rec["salt"]), int(rec["rounds"]))
    except (ValueError, KeyError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), rec["hash"])


def _session_key() -> bytes:
    pw = settings.get("password")
    return (settings.get("secret") + (pw["hash"] if pw else "")).encode()


def make_session() -> str:
    msg = f"{int(time.time()) + SESSION_SECONDS}.{secrets.token_hex(8)}"
    sig = hmac.new(_session_key(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{msg}.{sig}"


def valid_session(token: str) -> bool:
    try:
        exp, nonce, sig = token.split(".")
    except ValueError:
        return False
    good = hmac.new(_session_key(), f"{exp}.{nonce}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(good, sig) and exp.isdigit() and int(exp) > time.time()


def session_cookie(token: str) -> str:
    return f"beam_session={token}; Path=/; Max-Age={SESSION_SECONDS}; HttpOnly; SameSite=Strict"


CLEAR_SESSION = "beam_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"

_fails = {}
_fails_lock = threading.Lock()


def login_blocked(ip: str) -> bool:
    with _fails_lock:
        return _fails.get(ip, (0, 0.0))[1] > time.time()


def login_failed(ip: str) -> None:
    with _fails_lock:
        count, _ = _fails.get(ip, (0, 0.0))
        count += 1
        _fails[ip] = (0, time.time() + 60) if count >= 5 else (count, 0.0)


def login_ok(ip: str) -> None:
    with _fails_lock:
        _fails.pop(ip, None)


def safe_next(n: str) -> str:
    return n if n.startswith("/") and not n.startswith("//") and "\\" not in n else "/"


# ---------------------------------------------------------------------------
# Start with Windows
# ---------------------------------------------------------------------------
def startup_file():
    appdata = os.environ.get("APPDATA")
    if not IS_WINDOWS or not appdata:
        return None
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "Beam LAN File Transfer.cmd"


def autostart_enabled() -> bool:
    f = startup_file()
    return bool(f and f.exists())


def set_autostart(on: bool) -> None:
    f = startup_file()
    if f is None:
        raise OSError("Start-with-Windows is only available on Windows")
    if on:
        exe = Path(sys.executable)
        hidden = exe.with_name("pythonw.exe")  # runs without a console window
        exe = hidden if hidden.exists() else exe
        f.parent.mkdir(parents=True, exist_ok=True)
        with open(f, "w", encoding="utf-8", newline="\r\n") as out:
            out.write("@echo off\nchcp 65001 >nul\n"
                      f'cd /d "{APP_DIR}"\n'
                      f'start "" "{exe}" "{Path(__file__).resolve()}"\n')
    else:
        f.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Search index: inverted index + typo-tolerant token matching
# ---------------------------------------------------------------------------
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def fold(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s.casefold().replace("'", "").replace("\u2019", "")


def tokens(s: str):
    return _TOKEN_RE.findall(fold(s))


def osa_distance(a: str, b: str, maxd: int) -> int:
    """Edit distance counting swapped letters as one typo; stops early past maxd."""
    la, lb = len(a), len(b)
    if abs(la - lb) > maxd:
        return maxd + 1
    prev2 = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        row_min = i
        ai = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ai == b[j - 1] else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ai == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, prev2[j - 2] + 1)
            cur[j] = v
            if v < row_min:
                row_min = v
        if row_min > maxd:
            return maxd + 1
        prev2, prev = prev, cur
    return prev[lb]


def match_token(qt: str, vocab):
    n = len(qt)
    maxd = 0 if qt.isdigit() or n < 4 else (1 if n <= 6 else 2)
    qset = set(qt)
    out = []
    for vt, vset, vdigit in vocab:
        if vt == qt:
            out.append((vt, 1.0))
        elif vt.startswith(qt):
            out.append((vt, 0.9 if n > 1 else 0.6))
        elif n >= 3 and qt in vt:
            out.append((vt, 0.75))
        elif maxd and not vdigit and len(qset - vset) <= maxd:
            lv = len(vt)
            if abs(lv - n) <= maxd and osa_distance(qt, vt, maxd) <= maxd:
                out.append((vt, 0.7 if osa_distance(qt, vt, 1) <= 1 else 0.55))
            elif lv > n and osa_distance(qt, vt[:n], 1) <= 1:
                out.append((vt, 0.6))  # typo in a half-typed word
    return out


class SearchIndex:
    def __init__(self):
        self._lock = threading.Lock()
        self._build_lock = threading.Lock()
        self._rerun = False
        self._timer = None
        self.entries = []      # (kind 'd'/'f', share_id, rel_posix, name, size, mtime)
        self.name_post = {}    # token -> [entry index]  (token is in the name)
        self.path_post = {}    # token -> [entry index]  (token is in a parent folder name)
        self.vocab = []
        self.state = "idle"
        self.progress = 0
        self.built_at = None

    def status(self) -> dict:
        with self._lock:
            building = self.state == "building"
            return {"state": self.state,
                    "count": self.progress if building else len(self.entries),
                    "built_at": self.built_at}

    def schedule(self, delay: float = 5.0) -> None:
        with self._lock:
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(delay, self.build)
            self._timer.daemon = True
            self._timer.start()

    def build(self) -> None:
        if not self._build_lock.acquire(blocking=False):
            self._rerun = True
            return
        try:
            self._rerun = False
            self._build_once()
        finally:
            self._build_lock.release()
        if self._rerun:
            self.schedule(1.0)

    def _build_once(self) -> None:
        with self._lock:
            self.state, self.progress = "building", 0
        started = time.time()
        entries, name_post, path_post = [], {}, {}
        show_hidden = settings.get("show_hidden")
        try:
            for share in settings.shares():
                if not os.path.isdir(share["path"]):
                    continue
                stack = [(share["path"], "", frozenset(), frozenset())]
                while stack:
                    folder, rel, dir_toks, parent_toks = stack.pop()
                    ancestors = dir_toks | parent_toks
                    try:
                        it = os.scandir(folder)
                    except OSError:
                        continue
                    with it:
                        for e in it:
                            try:
                                if skip_entry(e, show_hidden):
                                    continue
                                is_dir = e.is_dir(follow_symlinks=False)
                                if not is_dir and not e.is_file(follow_symlinks=False):
                                    continue
                                st = e.stat(follow_symlinks=False)
                            except OSError:
                                continue
                            erel = f"{rel}/{e.name}" if rel else e.name
                            idx = len(entries)
                            entries.append(("d" if is_dir else "f", share["id"], erel, e.name,
                                            None if is_dir else st.st_size, st.st_mtime))
                            ntoks = frozenset(tokens(e.name))
                            for t in ntoks:
                                name_post.setdefault(t, []).append(idx)
                            for t in ancestors - ntoks:
                                path_post.setdefault(t, []).append(idx)
                            if idx % 2000 == 0:
                                self.progress = idx
                            if is_dir and not is_reparse(st) and erel.count("/") < MAX_DEPTH:
                                stack.append((e.path, erel, ntoks, dir_toks))
            vocab = [(t, frozenset(t), t.isdigit()) for t in set(name_post) | set(path_post)]
            with self._lock:
                self.entries, self.name_post, self.path_post, self.vocab = entries, name_post, path_post, vocab
                self.built_at = time.time()
            log.info("Search index ready: %s items in %.1fs", f"{len(entries):,}", time.time() - started)
        except Exception:
            log.exception("Indexing failed")
        finally:
            with self._lock:
                self.state = "idle"

    def search(self, query: str, limit: int = 100):
        """Returns ([(score, entry)], total_matches, closest_only)."""
        qts = list(dict.fromkeys(tokens(query)))[:8]
        with self._lock:
            entries, npost, ppost, vocab = self.entries, self.name_post, self.path_post, self.vocab
        if not qts or not entries:
            return [], 0, False
        counts, totals = {}, {}
        for qt in qts:
            best = {}
            for vt, s in match_token(qt, vocab):
                for i in npost.get(vt, ()):
                    if best.get(i, 0.0) < s:
                        best[i] = s
                ps = s * 0.55  # matched a parent folder, not the name itself
                for i in ppost.get(vt, ()):
                    if best.get(i, 0.0) < ps:
                        best[i] = ps
            for i, s in best.items():
                counts[i] = counts.get(i, 0) + 1
                totals[i] = totals.get(i, 0.0) + s
        if not counts:
            return [], 0, False
        top = max(counts.values())
        cands = [i for i, c in counts.items() if c == top]
        cands.sort(key=lambda i: totals[i], reverse=True)
        n, phrase = len(qts), " ".join(qts)

        def final_score(i):
            kind, _sid, _rel, name, _size, _mtime = entries[i]
            stem = name.rsplit(".", 1)[0] if kind == "f" and "." in name else name
            stem_toks = " ".join(tokens(stem))
            score = totals[i] / n
            if stem_toks == phrase:
                score += 0.35
            elif stem_toks.startswith(phrase):
                score += 0.15
            if kind == "d":
                score += 0.03
            return score - min(len(name), 200) / 5000

        scored = sorted(((round(final_score(i), 4), i) for i in cands[: max(limit * 5, 500)]),
                        key=lambda x: (-x[0], natural_key(entries[x[1]][2])))  # ties: natural order (E01, E02...)
        return [(s, entries[i]) for s, i in scored[:limit]], len(cands), top < n


index = SearchIndex()


# ---------------------------------------------------------------------------
# Look & feel
# ---------------------------------------------------------------------------
LIGHT_VARS = ("--bg:#e8eaef;--glow:radial-gradient(1100px 520px at 85% -12%,rgba(226,0,116,.10),transparent 62%);"
              "--panel:linear-gradient(180deg,#ffffff,#f2f3f6);--solid:#ffffff;--line:#d4d7de;--line-hi:#bfc3cc;"
              "--text:#16161b;--muted:#5b5e6a;--link:#b3005c;--hot:#b3005c;--row-hi:#fcebf4;--input:#ffffff;"
              "--bar:linear-gradient(180deg,#ffffff 0%,#eef0f3 49%,#dfe2e8 50%,#eceef2 100%);--bar-edge:#c3c7cf;"
              "--shadow:0 12px 30px -16px rgba(30,30,60,.35);--gloss:rgba(255,255,255,.9);"
              "--tile:linear-gradient(180deg,#ffffff,#e9ebf0);color-scheme:light;")

CSS = r"""
:root,[data-theme=dark]{--m:#e20074;--m-lo:#8e0049;--bg:#000;--glow:radial-gradient(1100px 520px at 85% -12%,rgba(226,0,116,.18),transparent 62%),radial-gradient(800px 460px at -10% 115%,rgba(226,0,116,.08),transparent 60%);
--panel:linear-gradient(180deg,#17171c,#0c0c10);--solid:#101014;--line:#23232a;--line-hi:#34343d;--text:#f4f4f7;--muted:#9c9ca9;--link:#ff4fa6;--hot:#ff3d9a;--row-hi:#19191f;--input:#07070a;
--bar:linear-gradient(180deg,#2d2d35 0%,#15151a 49%,#030304 50%,#0c0c10 100%);--bar-edge:#000;--shadow:0 14px 34px -16px rgba(0,0,0,.9);--gloss:rgba(255,255,255,.07);--tile:linear-gradient(180deg,#2a2a33,#0d0d11);color-scheme:dark}
[data-theme=light]{/*LIGHT*/}
@media (prefers-color-scheme:light){[data-theme=system]{/*LIGHT*/}}
*{box-sizing:border-box}
html,body{margin:0}
body{font:15px/1.5 "Segoe UI","Segoe UI Variable",Tahoma,system-ui,-apple-system,sans-serif;background-color:var(--bg);background-image:var(--glow);background-attachment:fixed;color:var(--text);min-height:100vh;display:flex;flex-direction:column;-webkit-font-smoothing:antialiased}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--hot);outline-offset:2px}
button{font-family:inherit}
code{font-family:Consolas,"Cascadia Mono",monospace;font-size:13.5px;color:var(--hot);word-break:break-all}
kbd{font-family:inherit;font-size:12px;padding:1px 7px;border-radius:6px;border:1px solid var(--line-hi);background:var(--solid)}
.ic{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
.ic.big{width:44px;height:44px;color:var(--hot)}
.topbar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:18px;padding:10px 22px;background:var(--bar);border-bottom:1px solid var(--bar-edge);box-shadow:0 1px 0 var(--m),0 10px 28px -12px rgba(226,0,116,.6)}
.brand{display:flex;align-items:center;gap:11px;color:var(--text);text-decoration:none!important;flex:none}
.orb{position:relative;display:inline-block;width:34px;height:34px;border-radius:50%;flex:none;background:radial-gradient(circle at 50% 118%,#ff79c0 0%,var(--m) 46%,#52002b 100%);box-shadow:0 0 0 1px rgba(0,0,0,.55),0 0 20px rgba(226,0,116,.6),inset 0 -3px 7px rgba(0,0,0,.35)}
.orb::after{content:"";position:absolute;left:18%;right:18%;top:7%;height:44%;border-radius:50%;background:linear-gradient(180deg,rgba(255,255,255,.9),rgba(255,255,255,.06))}
.orb.big{width:72px;height:72px;margin-bottom:14px}
.brand b{display:block;font-size:20px;font-weight:300;letter-spacing:.6px;line-height:1.1}
.brand small{display:block;font-size:11.5px;color:var(--muted)}
.search{position:relative;flex:1;max-width:640px;margin:0 auto;display:flex;align-items:center}
.search>.ic{position:absolute;left:15px;color:var(--muted);pointer-events:none}
.search input{width:100%;height:42px;padding:0 18px 0 44px;border-radius:21px;border:1px solid var(--line-hi);background:var(--input);color:var(--text);font:inherit;box-shadow:inset 0 2px 5px rgba(0,0,0,.35)}
.search input:focus{outline:none;border-color:var(--m);box-shadow:inset 0 2px 5px rgba(0,0,0,.35),0 0 0 3px rgba(226,0,116,.3)}
.tools{display:flex;gap:8px;flex:none}
.iconbtn{display:inline-grid;place-items:center;width:42px;height:42px;border-radius:50%;border:1px solid var(--line-hi);background:linear-gradient(180deg,var(--gloss),transparent 55%),var(--solid);color:var(--text);cursor:pointer}
.iconbtn:hover{border-color:var(--m);color:var(--hot);text-decoration:none}
.moon{display:none}
[data-theme=light] .sun{display:none}[data-theme=light] .moon{display:block}
@media (prefers-color-scheme:light){[data-theme=system] .sun{display:none}[data-theme=system] .moon{display:block}}
.live{position:absolute;top:48px;left:0;right:0;max-height:440px;overflow:auto;padding:6px;background:var(--solid);border:1px solid var(--line-hi);border-radius:16px;box-shadow:var(--shadow),0 0 0 1px rgba(226,0,116,.15)}
.live a{display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:11px;color:var(--text)}
.live a:hover,.live a[aria-selected=true]{background:var(--row-hi);text-decoration:none}
.live a .ic{color:var(--muted)}
.live .more{justify-content:center;color:var(--link);font-weight:600}
.hint{padding:10px 12px;color:var(--muted);font-size:13.5px}
.t{display:flex;flex-direction:column;min-width:0}
.t .n{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.t small{color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.wrap{width:100%;max-width:1120px;margin:0 auto;padding:28px 22px 48px;flex:1}
.foot{display:flex;flex-wrap:wrap;justify-content:space-between;gap:8px 20px;padding:12px 22px;font-size:12.5px;color:var(--muted);border-top:1px solid var(--line)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow),inset 0 1px 0 var(--gloss)}
.head{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:14px;margin-bottom:18px}
.title{font-size:30px;font-weight:300;letter-spacing:.2px;margin:0;line-height:1.2;overflow-wrap:anywhere}
.meta{color:var(--muted);font-size:13.5px;margin-top:4px}
.crumbs{display:flex;flex-wrap:wrap;align-items:center;gap:7px;font-size:13.5px;margin-bottom:4px}
.crumbs a{color:var(--muted)}.crumbs a:hover{color:var(--hot)}
.crumbs .sep{color:var(--m)}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:8px;height:38px;padding:0 18px;border-radius:19px;border:1px solid var(--m-lo);background:linear-gradient(180deg,#ff4aa8 0%,#e8047c 48%,#c5006a 52%,#d8007a 100%);color:#fff;font-size:14px;font-weight:600;cursor:pointer;white-space:nowrap;text-shadow:0 -1px 0 rgba(0,0,0,.25);box-shadow:inset 0 1px 0 rgba(255,255,255,.5),0 5px 16px -7px rgba(226,0,116,.9)}
.btn:hover{filter:brightness(1.08);text-decoration:none}
.btn:active{filter:brightness(.94);transform:translateY(1px)}
.btn .ic{width:18px;height:18px}
.btn.ghost{border-color:var(--line-hi);background:linear-gradient(180deg,var(--gloss),transparent 55%),var(--solid);color:var(--text);text-shadow:none;box-shadow:inset 0 1px 0 var(--gloss)}
.btn.ghost:hover{border-color:var(--m);color:var(--hot)}
.btn.sm{height:30px;padding:0 13px;font-size:12.5px}
.btn.wide{width:100%;justify-content:center}
fieldset[disabled] .btn,.btn:disabled{opacity:.45;cursor:not-allowed;filter:none}
.drives{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:16px}
.drive{display:flex;flex-direction:column;gap:14px;padding:18px 18px 16px;color:var(--text);text-decoration:none!important}
a.drive:hover{border-color:var(--m);box-shadow:var(--shadow),inset 0 1px 0 var(--gloss),0 0 0 1px var(--m),0 0 24px -6px rgba(226,0,116,.6)}
.drive .top{display:flex;align-items:center;gap:13px;min-width:0}
.dicon{width:46px;height:46px;border-radius:13px;display:grid;place-items:center;flex:none;background:radial-gradient(circle at 50% 0%,rgba(255,255,255,.2),transparent 62%),var(--tile);color:var(--hot);border:1px solid var(--line-hi)}
.drive .name{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sub{font-size:12.5px;color:var(--muted)}
.drive.off{opacity:.55}
.meter{height:9px;border-radius:5px;background:var(--input);border:1px solid var(--line);overflow:hidden}
.meter i{display:block;height:100%;width:0;background:linear-gradient(180deg,#ff66b5 0%,var(--m) 48%,#b30062 52%,#d4007a 100%);box-shadow:0 0 12px rgba(226,0,116,.65);transition:width .2s}
.list{overflow:hidden}
.lh,.row{display:grid;grid-template-columns:minmax(0,1fr) 104px 170px 116px;align-items:center;gap:12px;padding:0 16px}
.lh{height:40px;font-size:12.5px;color:var(--muted);border-bottom:1px solid var(--line);background:linear-gradient(180deg,var(--gloss),transparent)}
.lh a{color:var(--muted)}.lh a.on{color:var(--hot)}
.row{min-height:50px;border-bottom:1px solid var(--line);position:relative}
.row:last-child{border-bottom:0}
.row:hover{background:var(--row-hi)}
.row:hover::before{content:"";position:absolute;left:0;top:9px;bottom:9px;width:3px;border-radius:0 3px 3px 0;background:var(--m);box-shadow:0 0 10px var(--m)}
.nm{display:flex;align-items:center;gap:12px;min-width:0;color:var(--text);padding:8px 0}
.nm:hover{text-decoration:none}.nm:hover .n{text-decoration:underline}
.nm .ic{color:var(--muted)}
.row.dir .nm .ic{color:var(--hot)}
.row.dir .n{font-weight:600}
.num{font-size:13px;color:var(--muted);text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.ra{display:flex;justify-content:flex-end;gap:2px}
.mini{width:34px;height:34px;display:inline-grid;place-items:center;border-radius:50%;color:var(--muted);border:1px solid transparent}
.mini:hover{color:var(--hot);border-color:var(--line-hi);background:var(--solid)}
.mini .ic{width:18px;height:18px}
.empty{padding:52px 20px;text-align:center;color:var(--muted)}
.hero{padding:56px 24px;text-align:center}
.hero p{color:var(--muted);max-width:46ch;margin:10px auto 22px}
.drop{position:fixed;inset:0;z-index:50;display:none;place-items:center;background:rgba(0,0,0,.72)}
.drop.on{display:grid}
.drop>div{padding:38px 56px;border:2px dashed var(--m);border-radius:22px;background:var(--solid);text-align:center;font-size:18px;box-shadow:0 0 50px rgba(226,0,116,.45)}
.drop p{margin:12px 0 0}
.xfer{position:fixed;right:20px;bottom:20px;z-index:40;width:min(390px,calc(100vw - 40px));padding:16px 18px;display:none}
.xfer.on{display:block}
.xfer h3{margin:0 0 3px;font-size:15px;font-weight:600}
.xfer p{margin:0 0 10px;font-size:13px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.xrow{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-top:10px;font-size:12.5px;color:var(--muted)}
.toast{position:fixed;left:50%;bottom:26px;z-index:60;transform:translate(-50%,16px);opacity:0;pointer-events:none;max-width:calc(100vw - 40px);padding:10px 18px;border-radius:20px;background:#0d0d11;color:#fff;border:1px solid var(--m);box-shadow:0 0 22px rgba(226,0,116,.45);transition:opacity .18s,transform .18s;font-size:14px}
.toast.on{opacity:1;transform:translate(-50%,0)}
.toast.err{border-color:#ff5a5a;box-shadow:0 0 22px rgba(255,80,80,.4)}
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,440px),1fr));gap:18px;align-items:start}
.sect{padding:22px 24px}
.sect h2{font-size:18px;font-weight:400;margin:0 0 4px;display:flex;align-items:center;gap:10px}
.sect h2::before{content:"";width:9px;height:9px;border-radius:50%;background:var(--m);box-shadow:0 0 9px var(--m)}
.note{margin:0 0 14px;color:var(--muted);font-size:13.5px}
fieldset{border:0;margin:0;padding:0;min-width:0}
.check{display:flex;align-items:center;gap:14px;padding:11px 0;border-bottom:1px solid var(--line);cursor:pointer}
.check:last-of-type{border-bottom:0}
.grow{flex:1;min-width:0}
.check b{font-weight:600}
.check small{display:block;color:var(--muted);font-size:12.5px;overflow-wrap:anywhere}
.sw{appearance:none;-webkit-appearance:none;width:46px;height:26px;margin:0;border-radius:13px;background:var(--input);border:1px solid var(--line-hi);position:relative;cursor:pointer;flex:none;box-shadow:inset 0 2px 4px rgba(0,0,0,.35);transition:background .15s}
.sw::after{content:"";position:absolute;top:2px;left:2px;width:20px;height:20px;border-radius:50%;background:linear-gradient(180deg,#fff,#c9ccd4);box-shadow:0 1px 3px rgba(0,0,0,.5);transition:left .15s}
.sw:checked{background:linear-gradient(180deg,#ff4aa8,#e8047c 48%,#c5006a 52%,#d8007a);border-color:var(--m-lo)}
.sw:checked::after{left:22px}
.sw:disabled{opacity:.5;cursor:not-allowed}
.field{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:14px}
.field input[type=text],.field input[type=password],.field input[type=number]{flex:1;min-width:180px;height:40px;padding:0 14px;border-radius:11px;border:1px solid var(--line-hi);background:var(--input);color:var(--text);font:inherit;box-shadow:inset 0 2px 4px rgba(0,0,0,.3)}
.field input:focus{outline:none;border-color:var(--m);box-shadow:0 0 0 3px rgba(226,0,116,.28)}
.field input[type=number]{flex:0 0 130px;min-width:0}
.seg{display:inline-flex;border:1px solid var(--line-hi);border-radius:20px;overflow:hidden;background:var(--solid)}
.seg label{position:relative;cursor:pointer}
.seg input{position:absolute;opacity:0;pointer-events:none}
.seg span{display:block;padding:8px 18px;font-size:14px;border-right:1px solid var(--line)}
.seg label:last-child span{border-right:0}
.seg input:checked+span{color:#fff;background:linear-gradient(180deg,#ff4aa8,#e8047c 48%,#c5006a 52%,#d8007a);text-shadow:0 -1px 0 rgba(0,0,0,.25)}
.seg input:focus-visible+span{outline:2px solid var(--hot);outline-offset:-3px}
.kv{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:12px 14px;border-radius:12px;background:var(--input);border:1px solid var(--line)}
.flash{padding:12px 16px;border-radius:12px;margin-bottom:18px;border:1px solid var(--m);background:rgba(226,0,116,.12)}
.flash.err{border-color:#ff5a5a;background:rgba(255,90,90,.12)}
.badge{font-size:11.5px;padding:2px 9px;border-radius:10px;border:1px solid var(--line-hi);color:var(--muted);white-space:nowrap}
.login{max-width:400px;margin:60px auto;padding:34px 30px;text-align:center}
@media (max-width:760px){
 .topbar{flex-wrap:wrap;gap:10px 12px;padding:10px 14px}
 .brand small{display:none}
 .search{order:3;flex-basis:100%;max-width:none}
 .tools{margin-left:auto}
 .wrap{padding:20px 14px 40px}
 .lh,.row{grid-template-columns:minmax(0,1fr) 84px;padding:0 12px}
 .c-size,.c-date{display:none}
 .title{font-size:25px}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
""".replace("/*LIGHT*/", LIGHT_VARS)

_ICONS = {
    "folder": '<path d="M3 7.5A1.5 1.5 0 0 1 4.5 6h4.3l2 2h8.7A1.5 1.5 0 0 1 21 9.5v8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z"/>',
    "file": '<path d="M6.5 3h7l5 5v12a1 1 0 0 1-1 1h-11a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M13.5 3v5h5"/>',
    "video": '<rect x="3" y="6" width="13" height="12" rx="2"/><path d="M16 10.5l5-3v9l-5-3"/>',
    "audio": '<path d="M9 18V5l11-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="17" cy="16" r="3"/>',
    "image": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 16l5-5 4 4 3-3 6 6"/><circle cx="15.5" cy="8.5" r="1.5"/>',
    "archive": '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9"/><path d="M10 13h4"/>',
    "drive": '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M5 13l2.5-8h9L19 13"/><path d="M7 16.5h.01M10 16.5h.01"/>',
    "download": '<path d="M12 4v11"/><path d="M7 10l5 5 5-5"/><path d="M5 20h14"/>',
    "upload": '<path d="M12 20V9"/><path d="M7 14l5-5 5 5"/><path d="M5 4h14"/>',
    "search": '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>',
    "settings": '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    "moon": '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
    "eye": '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "lock": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3"/>',
}
SPRITE = ('<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false"><defs>'
          + "".join(f'<symbol id="i-{k}" viewBox="0 0 24 24">{v}</symbol>' for k, v in _ICONS.items())
          + "</defs></svg>")

FAVICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs>'
           '<radialGradient id="g" cx="50%" cy="100%" r="95%"><stop offset="0" stop-color="#ff79c0"/>'
           '<stop offset=".5" stop-color="#e20074"/><stop offset="1" stop-color="#52002b"/></radialGradient>'
           '<linearGradient id="h" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".9"/>'
           '<stop offset="1" stop-color="#fff" stop-opacity=".05"/></linearGradient></defs>'
           '<circle cx="32" cy="32" r="30" fill="url(#g)"/><ellipse cx="32" cy="19" rx="19" ry="12" fill="url(#h)"/></svg>')

JS = r"""
(() => {
"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt = n => { if (n == null) return ""; const u = ["B","KB","MB","GB","TB"]; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return (i ? n.toFixed(1) : Math.round(n)) + " " + u[i]; };
const body = document.body, root = document.documentElement;

const toastEl = $("#toast"); let toastTimer = 0;
function toast(msg, err) {
  toastEl.textContent = msg; toastEl.className = "toast on" + (err ? " err" : "");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { toastEl.className = "toast"; }, err ? 7000 : 3200);
}

/* Theme: remembered per browser */
function setTheme(t) {
  root.dataset.theme = t;
  document.cookie = "beam_theme=" + t + "; path=/; max-age=31536000; samesite=lax";
  $$("input[data-set-theme]").forEach(r => { r.checked = r.value === t; });
}
function effectiveTheme() {
  const t = root.dataset.theme;
  return t === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : t;
}
const tt = $("#themeToggle");
if (tt) tt.addEventListener("click", () => setTheme(effectiveTheme() === "dark" ? "light" : "dark"));
$$("input[data-set-theme]").forEach(r => r.addEventListener("change", () => { if (r.checked) setTheme(r.value); }));

$$("form[data-confirm]").forEach(f => f.addEventListener("submit", e => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));
$$("[data-copy]").forEach(b => b.addEventListener("click", async () => {
  const t = b.dataset.copy;
  try { await navigator.clipboard.writeText(t); }
  catch (_) {
    const a = document.createElement("textarea"); a.value = t; a.style.position = "fixed"; a.style.opacity = "0";
    document.body.appendChild(a); a.select(); try { document.execCommand("copy"); } catch (__) {} a.remove();
  }
  toast("Copied " + t);
}));

/* Live search */
const q = $("#q"), live = $("#live");
if (q && live) {
  let timer = 0, ctl = null, sel = -1;
  const hide = () => { live.hidden = true; sel = -1; q.setAttribute("aria-expanded", "false"); };
  const render = (d, v) => {
    let h = "";
    if (!d.results.length) {
      h = d.indexing ? '<div class="hint">Still indexing your drives (' + d.count.toLocaleString() + ' items so far)…</div>'
                     : '<div class="hint">No matches for “' + esc(v) + '”. Try fewer words.</div>';
    } else {
      if (d.closest) h += '<div class="hint">No exact match. Closest results:</div>';
      for (const r of d.results) {
        h += '<a role="option" href="' + esc(r.url) + '"' + (r.kind === "f" ? " download" : "") + '><svg class="ic"><use href="#i-' + esc(r.icon) +
             '"/></svg><span class="t"><span class="n">' + esc(r.name) + '</span><small>' + esc(r.where) + '</small></span></a>';
      }
      h += '<a class="more" href="/search?q=' + encodeURIComponent(v) + '">See all ' + d.total.toLocaleString() + ' result' + (d.total === 1 ? "" : "s") + '</a>';
    }
    live.innerHTML = h; live.hidden = false; sel = -1; q.setAttribute("aria-expanded", "true");
  };
  const run = async () => {
    const v = q.value.trim();
    if (!v) { hide(); return; }
    if (ctl) ctl.abort();
    ctl = new AbortController();
    try {
      const r = await fetch("/api/search?limit=12&q=" + encodeURIComponent(v), { signal: ctl.signal });
      if (r.status === 401) { location.href = "/login"; return; }
      if (!r.ok) throw new Error("HTTP " + r.status);
      render(await r.json(), v);
    } catch (e) {
      if (e.name !== "AbortError") { live.innerHTML = '<div class="hint">Search isn’t responding. Is Beam still running?</div>'; live.hidden = false; }
    }
  };
  q.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(run, 150); });
  q.addEventListener("focus", () => { if (q.value.trim() && live.innerHTML) live.hidden = false; });
  q.addEventListener("keydown", e => {
    if (e.key === "Escape") { hide(); return; }
    const items = $$("a", live);
    if (live.hidden || !items.length) return;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      sel = (sel + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
      items.forEach((a, i) => a.setAttribute("aria-selected", String(i === sel)));
      items[sel].scrollIntoView({ block: "nearest" });
    } else if (e.key === "Enter" && sel >= 0) { e.preventDefault(); items[sel].click(); }
  });
  document.addEventListener("click", e => { if (!e.target.closest(".search")) hide(); });
  document.addEventListener("keydown", e => {
    const tag = document.activeElement ? document.activeElement.tagName : "";
    if (e.key === "/" && tag !== "INPUT" && tag !== "TEXTAREA" && !e.ctrlKey && !e.metaKey && !e.altKey) { e.preventDefault(); q.focus(); q.select(); }
  });
}

/* Drag a file out of the browser onto the desktop / File Explorer (Chrome & Edge) */
let dragOut = false;
document.addEventListener("dragstart", e => {
  const a = e.target && e.target.closest ? e.target.closest("[data-dl]") : null;
  if (!a) return;
  dragOut = true;
  const url = new URL(a.getAttribute("data-dl"), location.href).href;
  try { e.dataTransfer.setData("DownloadURL", (a.dataset.mime || "application/octet-stream") + ":" + a.dataset.name + ":" + url); } catch (_) {}
  e.dataTransfer.effectAllowed = "copy";
});
document.addEventListener("dragend", () => { dragOut = false; });

/* Uploads: drop files/folders anywhere, or use the buttons */
const upBase = body.dataset.upload;
if (upBase) {
  const drop = $("#drop"), xfer = $("#xfer"), xname = $("#xname"), xbar = $("#xbar"), xstat = $("#xstat");
  $("#dropName").textContent = body.dataset.folder || "this folder";
  const queue = [];
  let busy = false, cur = null, done = 0, failed = 0, cancelled = false, bytesDone = 0, bytesTotal = 0, depth = 0;
  const isFileDrag = e => !dragOut && e.dataTransfer && Array.from(e.dataTransfer.types || []).includes("Files");

  const readAll = reader => new Promise((res, rej) => {
    const out = [];
    const more = () => reader.readEntries(b => { if (!b.length) res(out); else { out.push(...b); more(); } }, rej);
    more();
  });
  const fileOf = entry => new Promise((res, rej) => entry.file(res, rej));
  async function collect(entries) {
    const out = [], stack = entries.map(e => [e, ""]);
    while (stack.length) {
      const [e, base] = stack.pop();
      const p = base ? base + "/" + e.name : e.name;
      try {
        if (e.isFile) out.push({ file: await fileOf(e), path: p });
        else if (e.isDirectory) for (const c of await readAll(e.createReader())) stack.push([c, p]);
      } catch (_) { toast("Couldn't read " + p + " from your PC", true); }
    }
    return out;
  }

  function paint(it, rate) {
    const pct = bytesTotal ? Math.min(100, bytesDone / bytesTotal * 100) : 100;
    xname.textContent = it ? it.path : "";
    xbar.style.width = pct.toFixed(1) + "%";
    let s = Math.floor(pct) + "%, " + fmt(bytesDone) + " of " + fmt(bytesTotal);
    if (rate) s += ", " + fmt(rate) + "/s";
    if (queue.length) s += ", " + queue.length + " to go";
    xstat.textContent = s;
  }
  function finish() {
    busy = false; cur = null;
    const bits = [];
    if (done) bits.push(done + " uploaded");
    if (failed) bits.push(failed + " failed");
    if (cancelled) bits.push("cancelled");
    xstat.textContent = bits.join(", ") || "Nothing uploaded";
    if (done) { toast(done + " file" + (done === 1 ? "" : "s") + " uploaded"); setTimeout(() => location.reload(), 900); }
    else setTimeout(() => xfer.classList.remove("on"), 2500);
  }
  function next() {
    const it = queue.shift();
    if (!it) { finish(); return; }
    busy = true;
    const xhr = new XMLHttpRequest(); cur = xhr;
    const t0 = performance.now(); let sent = 0;
    const settle = () => { bytesDone += it.file.size - sent; sent = it.file.size; };
    xhr.open("PUT", upBase + "?path=" + encodeURIComponent(it.path) + "&mtime=" + (it.file.lastModified || ""));
    xhr.setRequestHeader("X-Beam", "1");
    xhr.upload.onprogress = ev => {
      bytesDone += ev.loaded - sent; sent = ev.loaded;
      const secs = (performance.now() - t0) / 1000;
      paint(it, secs > 0.4 ? ev.loaded / secs : 0);
    };
    xhr.onload = () => {
      settle();
      if (xhr.status >= 200 && xhr.status < 300) done++;
      else {
        failed++;
        let m = ""; try { m = JSON.parse(xhr.responseText).error || ""; } catch (_) {}
        toast("Couldn't upload " + it.path + ": " + (m || "error " + xhr.status), true);
      }
      next();
    };
    xhr.onerror = () => { settle(); failed++; toast("Upload of " + it.path + " failed. The connection dropped, the drive may be full, or uploads are switched off.", true); next(); };
    xhr.onabort = () => { settle(); next(); };
    paint(it, 0);
    xhr.send(it.file);
  }
  function enqueue(list) {
    if (!list.length) { toast("Nothing to upload. Empty folders are skipped.", true); return; }
    if (!busy) { done = failed = bytesDone = bytesTotal = 0; cancelled = false; }
    for (const it of list) { queue.push(it); bytesTotal += it.file.size; }
    xfer.classList.add("on");
    if (!busy) next();
  }

  window.addEventListener("dragenter", e => { if (!isFileDrag(e)) return; e.preventDefault(); depth++; drop.classList.add("on"); });
  window.addEventListener("dragover", e => { if (!isFileDrag(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = "copy"; });
  window.addEventListener("dragleave", e => { if (!isFileDrag(e)) return; depth = Math.max(0, depth - 1); if (!depth) drop.classList.remove("on"); });
  window.addEventListener("drop", e => {
    if (!isFileDrag(e)) return;
    e.preventDefault(); depth = 0; drop.classList.remove("on");
    const entries = Array.from(e.dataTransfer.items || []).filter(i => i.kind === "file")
      .map(i => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null)).filter(Boolean);
    if (entries.length) collect(entries).then(enqueue);
    else enqueue(Array.from(e.dataTransfer.files).map(f => ({ file: f, path: f.name })));
  });
  const wire = (inputId, btnId) => {
    const input = $(inputId), btn = $(btnId);
    if (!input || !btn) return;
    btn.addEventListener("click", () => input.click());
    input.addEventListener("change", () => {
      enqueue(Array.from(input.files).map(f => ({ file: f, path: f.webkitRelativePath || f.name })));
      input.value = "";
    });
  };
  wire("#picker", "#upFiles");
  wire("#fpicker", "#upFolder");
  $("#xcancel").addEventListener("click", () => { cancelled = true; queue.length = 0; if (cur) cur.abort(); else finish(); });
  window.addEventListener("beforeunload", e => { if (busy) { e.preventDefault(); e.returnValue = ""; } });
}

/* Index progress in the footer */
if (body.dataset.indexing === "1") {
  const idx = $("#idx");
  const poll = async () => {
    try {
      const d = await (await fetch("/api/status")).json();
      idx.textContent = d.state === "building" ? "Indexing… " + d.count.toLocaleString() + " items" : d.count.toLocaleString() + " items indexed";
      if (d.state === "building") setTimeout(poll, 2500);
    } catch (_) {}
  };
  setTimeout(poll, 2500);
}
})();
"""

BASE_HTML = """<!DOCTYPE html>
<html lang="en-GB" data-theme="%%THEME%%">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>%%TITLE%% | Beam</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>%%CSS%%</style>
</head>
<body%%BODYATTRS%%>
%%SPRITE%%
<header class="topbar">
  <a class="brand" href="/" aria-label="Beam home"><span class="orb" aria-hidden="true"></span><span><b>Beam</b><small>LAN File Transfer</small></span></a>
  %%NAV%%
</header>
<main class="wrap">%%BODY%%</main>
<footer class="foot"><span id="idx">%%INDEX%%</span><span>Bookmark: <a href="%%BOOKMARK%%">%%BOOKMARK%%</a></span></footer>
<div id="drop" class="drop" aria-hidden="true"><div><svg class="ic big"><use href="#i-upload"/></svg><p>Drop to upload into <b id="dropName"></b></p></div></div>
<section id="xfer" class="panel xfer" aria-live="polite"><h3>Uploading</h3><p id="xname"></p><div class="meter"><i id="xbar"></i></div><div class="xrow"><span id="xstat"></span><button type="button" class="btn ghost sm" id="xcancel">Cancel</button></div></section>
<div id="toast" class="toast" role="status" aria-live="polite"></div>
<script>%%JS%%</script>
</body>
</html>"""

NAV_HTML = """<form class="search" action="/search" method="get" role="search">
    <svg class="ic"><use href="#i-search"/></svg>
    <input id="q" type="search" name="q" value="%%QUERY%%" placeholder="Search every drive (typos are fine)" autocomplete="off" spellcheck="false" aria-label="Search files and folders" aria-controls="live" aria-expanded="false">
    <div id="live" class="live" role="listbox" hidden></div>
  </form>
  <nav class="tools">
    <button type="button" class="iconbtn" id="themeToggle" aria-label="Switch between dark and light" title="Switch theme"><svg class="ic sun"><use href="#i-sun"/></svg><svg class="ic moon"><use href="#i-moon"/></svg></button>
    <a class="iconbtn" href="/settings" aria-label="Settings" title="Settings"><svg class="ic"><use href="#i-settings"/></svg></a>
  </nav>"""

MESSAGES = {
    "saved": "Settings saved.",
    "added": "Folder added and being indexed.",
    "pwset": "Password set. Other devices will be asked for it.",
    "pwoff": "Password removed.",
    "port": "Port saved. It takes effect next time Beam starts.",
    "reindex": "Rebuilding the search index. Results update when it finishes.",
    "auto_on": "Beam will now start automatically with Windows.",
    "auto_off": "Beam will no longer start with Windows.",
}
ERRORS = {
    "nopath": "That folder doesn't exist on this PC. Paste a full path, e.g. F:\\Films.",
    "dup": "That folder is already shared.",
    "pwshort": "Passwords need at least 6 characters.",
    "pwmatch": "The two passwords don't match.",
    "port": "The port must be a number between 1024 and 65535.",
    "perm": "Settings can only be changed on the PC running Beam, or from any device once a password is set.",
    "auto": "Couldn't change the startup setting. Details are in beam.log.",
}


def icon(name: str, cls: str = "ic") -> str:
    return f'<svg class="{cls}"><use href="#i-{name}"/></svg>'


def mini(url: str, ico: str, label: str, newtab: bool = False, download: bool = False) -> str:
    extra = (' target="_blank" rel="noopener"' if newtab else "") + (" download" if download else "")
    return f'<a class="mini" href="{esc(url)}" title="{esc(label)}" aria-label="{esc(label)}"{extra}>{icon(ico)}</a>'


def row_html(kind, sid, rel, name, size, mtime, where=None, parent_url=None) -> str:
    qrel = quote_path(rel)
    acts = []
    if parent_url:
        acts.append(mini(parent_url, "folder", "Open the folder it's in"))
    if kind == "d":
        href = f"/b/{sid}/{qrel}"
        attrs, ico = "", "folder"
        acts.append(mini(f"/zip/{sid}/{qrel}", "archive", f"Download {name} as a ZIP"))
    else:
        href = f"/dl/{sid}/{qrel}"
        ico = icon_for(name)
        mime = INLINE_MIME.get(ext_of(name), "application/octet-stream").split(";")[0]
        attrs = f' draggable="true" download data-dl="{esc(href)}" data-name="{esc(name)}" data-mime="{esc(mime)}"'
        if ext_of(name) in INLINE_MIME:
            acts.append(mini(href + "?view=1", "eye", f"Open {name} in the browser", newtab=True))
        acts.append(mini(href, "download", f"Download {name}", download=True))
    where_html = f"<small>{esc(where)}</small>" if where else ""
    return (f'<div class="row{" dir" if kind == "d" else ""}"><a class="nm" href="{esc(href)}"{attrs}>{icon(ico)}'
            f'<span class="t"><span class="n">{esc(name)}</span>{where_html}</span></a>'
            f'<span class="num c-size">{human_size(size) if kind == "f" else ""}</span>'
            f'<span class="num c-date">{fmt_time(mtime)}</span><span class="ra">{"".join(acts)}</span></div>')


def entry_where(entry, share) -> str:
    rel = entry[2]
    parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
    return share["name"] + (" › " + parent.replace("/", " › ") if parent else "")


def entry_url(entry) -> str:
    kind, sid, rel = entry[0], entry[1], entry[2]
    return f"/{'b' if kind == 'd' else 'dl'}/{sid}/{quote_path(rel)}"


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"{APP}/{VERSION}"
    sys_version = ""
    timeout = 120
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.client_address[0], fmt % args)

    def send_response(self, code, message=None):
        self._started = True
        super().send_response(code, message)

    def do_GET(self):
        self._handle("GET")

    def do_HEAD(self):
        self._handle("HEAD")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def _handle(self, method):
        self._started = False
        try:
            self._route(method)
        except (ConnectionError, TimeoutError, socket.timeout):
            pass  # the browser went away mid-transfer; nothing to do
        except Exception:
            log.exception("Error handling %s %s", method, self.path)
            if not self._started:
                try:
                    self.error_page(500, "Something went wrong",
                                    "Beam hit an unexpected error. Details are in beam.log on the PC running Beam.")
                except Exception:
                    pass

    # ---- routing -------------------------------------------------------
    def _route(self, method):
        split = urllib.parse.urlsplit(self.path)
        self.query = urllib.parse.parse_qs(split.query, keep_blank_values=True)
        parts = urllib.parse.unquote(split.path).split("/")[1:]
        head = parts[0] if parts else ""
        sub = parts[1] if len(parts) > 1 else ""
        rest = "/".join(parts[2:])

        if not self.host_ok():
            bm = f"http://{HOSTNAME.lower()}:{self.server.server_port}/"
            return self.send_bytes(403, f"Unrecognised address. Open Beam at {bm}".encode(), "text/plain; charset=utf-8")
        if head in ("favicon.svg", "favicon.ico"):
            return self.send_bytes(200, FAVICON.encode(), "image/svg+xml", [("Cache-Control", "max-age=86400")], page=False)
        if head == "login":
            if method == "GET":
                return self.login_page()
            if method == "POST":
                return self.login_submit()
            return self.error_page(405, "Not allowed", "That action isn't supported.")
        if not self.authorised():
            if head == "api":
                return self.send_json({"error": "Please sign in again."}, 401)
            return self.redirect("/login?next=" + urllib.parse.quote(self.path, safe=""))
        if method in ("POST", "PUT") and not self.same_origin():
            if head == "api":
                return self.send_json({"error": "Blocked: request didn't come from Beam's own page."}, 403)
            return self.error_page(403, "Blocked", "That request didn't come from Beam's own page, so it was refused.")

        if method == "HEAD":
            if head == "dl":
                return self.download(sub, rest)
            return self.send_bytes(405, b"", "text/plain")
        if method == "GET":
            if head == "":
                return self.home()
            if head == "b":
                return self.browse(sub, rest)
            if head == "dl":
                return self.download(sub, rest)
            if head == "zip":
                return self.zip_folder(sub, rest)
            if head == "search":
                return self.search_page()
            if head == "settings":
                return self.settings_page()
            if head == "api" and sub == "search":
                return self.api_search()
            if head == "api" and sub == "status":
                return self.send_json(index.status())
        elif method == "POST":
            if head == "settings":
                return self.settings_submit()
            if head == "logout":
                return self.redirect("/login", [("Set-Cookie", CLEAR_SESSION)])
        elif method == "PUT":
            if head == "api" and sub == "upload" and len(parts) >= 3:
                return self.api_upload(parts[2], "/".join(parts[3:]))
        return self.error_page(404, "Not found", "There's nothing at that address.")

    # ---- request helpers ---------------------------------------------------
    def q(self, key, default=""):
        return (self.query.get(key) or [default])[0]

    def client_ip(self) -> str:
        return norm_ip(self.client_address[0])

    def is_host_machine(self) -> bool:
        return self.client_ip() in local_ips()

    def cookies(self) -> dict:
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return {}
        return {k: v.value for k, v in jar.items()}

    def theme(self) -> str:
        t = self.cookies().get("beam_theme", "")
        return t if t in ("dark", "light", "system") else "dark"

    def authorised(self) -> bool:
        if settings.get("password") is None or self.is_host_machine():
            return True
        token = self.cookies().get("beam_session")
        return bool(token) and valid_session(token)

    def can_manage(self) -> bool:
        return self.is_host_machine() or (settings.get("password") is not None and self.authorised())

    def host_ok(self) -> bool:
        """Only answer to this PC's own name/IP (blocks DNS-rebinding tricks)."""
        host = (self.headers.get("Host") or "").strip().lower().rstrip(".")
        if not host or host.startswith("["):
            return True
        name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        try:
            ipaddress.ip_address(name)
            return True
        except ValueError:
            pass
        hn = HOSTNAME.lower()
        return name in ("localhost", hn) or any(name == f"{hn}.{s}" for s in LOCAL_SUFFIXES)

    def same_origin(self) -> bool:
        src = self.headers.get("Origin") or self.headers.get("Referer")
        if not src or src == "null":
            return False
        return urllib.parse.urlsplit(src).netloc.lower() == (self.headers.get("Host") or "").lower()

    def read_form(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if n < 0 or n > MAX_FORM_BYTES:
            return None
        data = self.rfile.read(n).decode("utf-8", "replace")
        return urllib.parse.parse_qs(data, keep_blank_values=True)

    # ---- response helpers --------------------------------------------------
    def security_headers(self, page=True):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if page:
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", PAGE_CSP)
            self.send_header("Cache-Control", "no-store")

    def send_bytes(self, code, body, ctype, extra=None, page=True):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.security_headers(page)
        for k, v in extra or ():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_html(self, code, doc, extra=None):
        self.send_bytes(code, doc.encode("utf-8"), "text/html; charset=utf-8", extra)

    def send_json(self, obj, code=200):
        self.send_bytes(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def redirect(self, location, extra=None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.security_headers()
        for k, v in extra or ():
            self.send_header(k, v)
        self.end_headers()

    def page(self, title, body, query="", body_attrs="", nav=True) -> str:
        st = index.status()
        building = st["state"] == "building"
        idx_text = f"Indexing… {st['count']:,} items" if building else f"{st['count']:,} items indexed"
        if building:
            body_attrs += ' data-indexing="1"'
        bookmark = f"http://{HOSTNAME.lower()}:{self.server.server_port}/"
        values = {
            "THEME": self.theme(), "TITLE": esc(title), "CSS": CSS, "SPRITE": SPRITE,
            "NAV": NAV_HTML.replace("%%QUERY%%", esc(query)) if nav else "",
            "BODYATTRS": body_attrs, "INDEX": esc(idx_text), "BOOKMARK": esc(bookmark),
            "BODY": body, "JS": JS,
        }
        # single pass, so text inside file names can never be re-substituted
        return re.sub(r"%%([A-Z]+)%%", lambda m: values.get(m.group(1), m.group(0)), BASE_HTML)

    def error_page(self, code, title, message):
        body = (f'<div class="panel hero"><span class="orb big" aria-hidden="true"></span>'
                f'<h1 class="title">{esc(title)}</h1><p>{esc(message)}</p>'
                f'<a class="btn" href="/">Back to your drives</a></div>')
        self.send_html(code, self.page(title, body))

    # ---- pages ---------------------------------------------------------------
    def home(self):
        shares = settings.shares()
        if not shares:
            manage = self.can_manage()
            text = ("Choose which drives to share. It takes a few seconds." if manage else
                    "Open Beam's Settings on the PC running Beam to choose which drives to share.")
            btn = '<a class="btn" href="/settings">Choose drives</a>' if manage else ""
            body = (f'<div class="panel hero"><span class="orb big" aria-hidden="true"></span>'
                    f'<h1 class="title">Nothing shared yet</h1><p>{text}</p>{btn}</div>')
            return self.send_html(200, self.page("Home", body))
        tiles = []
        for s in shares:
            cap = capacity(s["path"]) if os.path.isdir(s["path"]) else None
            if cap is None:
                tiles.append(f'<div class="panel drive off"><div class="top"><span class="dicon">{icon("drive")}</span>'
                             f'<div class="t"><span class="name">{esc(s["name"])}</span><span class="sub">Not connected</span></div></div>'
                             f'<div class="meter"></div><div class="sub">Plug it in, then refresh.</div></div>')
                continue
            total, free = cap
            pct = 0 if not total else round((total - free) / total * 100, 1)
            tiles.append(f'<a class="panel drive" href="/b/{s["id"]}/"><div class="top"><span class="dicon">{icon("drive")}</span>'
                         f'<div class="t"><span class="name">{esc(s["name"])}</span><span class="sub">{esc(s["path"])}</span></div></div>'
                         f'<div class="meter" role="img" aria-label="{pct}% used"><i style="width:{pct}%"></i></div>'
                         f'<div class="sub">{human_size(free)} free of {human_size(total)}</div></a>')
        body = ('<div class="head"><div><h1 class="title">Your drives</h1>'
                '<div class="meta">Open a drive, or search everything at once. Press <kbd>/</kbd> to jump to search.</div></div></div>'
                f'<div class="drives">{"".join(tiles)}</div>')
        self.send_html(200, self.page("Your drives", body))

    def browse(self, sid, rel):
        share = find_share(sid)
        if not share:
            return self.error_page(404, "Not shared", "That drive or folder isn't shared any more.")
        target = resolve_in_share(share, rel)
        if target is None or not target.is_dir():
            if not os.path.isdir(share["path"]):
                return self.error_page(404, "Drive not connected", f"{share['name']} isn't plugged in or can't be reached.")
            return self.error_page(404, "Folder not found", "It may have been moved, renamed or deleted.")
        parts = clean_parts(rel)
        rel = "/".join(parts)
        show_hidden = settings.get("show_hidden")
        dirs, files = [], []
        try:
            with os.scandir(target) as it:
                for e in it:
                    try:
                        if skip_entry(e, show_hidden):
                            continue
                        if (e.is_symlink() or is_reparse(e.stat(follow_symlinks=False))) and \
                                resolve_in_share(share, f"{rel}/{e.name}") is None:
                            continue  # link/junction leading outside the share: hide it
                        st = e.stat()
                        is_dir = e.is_dir()
                    except OSError:
                        continue
                    (dirs if is_dir else files).append((e.name, None if is_dir else st.st_size, st.st_mtime))
        except PermissionError:
            return self.error_page(403, "Access denied", "Windows won't let Beam open this folder.")
        except OSError as exc:
            return self.error_page(500, "Couldn't open folder", str(exc.strerror or exc))

        sort = self.q("sort", "name")
        sort = sort if sort in ("name", "size", "date") else "name"
        rev = self.q("order") == "desc"
        keyf = {"name": lambda x: natural_key(x[0]),
                "size": lambda x: (x[1] or 0, natural_key(x[0])),
                "date": lambda x: (x[2], natural_key(x[0]))}[sort]
        dirs.sort(key=keyf, reverse=rev)
        files.sort(key=keyf, reverse=rev)

        def col(label, key, cls):
            on = sort == key
            nxt = "asc" if on and rev else ("desc" if on else "asc")
            arrow = (" ▾" if rev else " ▴") if on else ""
            return f'<a class="{cls}{" on" if on else ""}" href="?sort={key}&amp;order={nxt}">{label}{arrow}</a>'

        crumbs = ['<a href="/">Home</a>', f'<a href="/b/{sid}/">{esc(share["name"])}</a>']
        for i in range(len(parts)):
            crumbs.append(f'<a href="/b/{sid}/{quote_path("/".join(parts[: i + 1]))}">{esc(parts[i])}</a>')
        title = parts[-1] if parts else share["name"]
        join = lambda n: f"{rel}/{n}" if rel else n
        rows = [row_html("d", sid, join(n), n, None, m) for n, _s, m in dirs]
        rows += [row_html("f", sid, join(n), n, s, m) for n, s, m in files]
        allow = settings.get("allow_uploads")
        acts = ""
        if allow:
            acts += (f'<button type="button" class="btn" id="upFiles">{icon("upload")}Upload files</button>'
                     f'<button type="button" class="btn ghost" id="upFolder">{icon("folder")}Upload a folder</button>')
        acts += f'<a class="btn ghost" href="/zip/{sid}/{quote_path(rel)}">{icon("archive")}Download all as ZIP</a>'
        total = sum(s for _n, s, _m in files)
        summary = f'{len(dirs)} folder{"s" if len(dirs) != 1 else ""}, {len(files)} file{"s" if len(files) != 1 else ""}'
        if files:
            summary += f" ({human_size(total)})"
        if allow:
            summary += ". Drag files onto this page to upload them here"
        listing = ('<div class="lh">' + col("Name", "name", "") + col("Size", "size", "num c-size")
                   + col("Modified", "date", "num c-date") + "<span></span></div>" + "".join(rows)) if rows else \
            f'<div class="empty">This folder is empty.{" Drop files anywhere on the page to upload them here." if allow else ""}</div>'
        pickers = ('<input type="file" id="picker" multiple hidden><input type="file" id="fpicker" webkitdirectory hidden>'
                   if allow else "")
        body = (f'<div class="head"><div><nav class="crumbs" aria-label="Breadcrumb">'
                f'{"<span class=sep>›</span>".join(crumbs)}</nav><h1 class="title">{esc(title)}</h1>'
                f'<div class="meta">{esc(summary)}</div></div><div class="actions">{acts}</div></div>'
                f'<div class="panel list">{listing}</div>{pickers}')
        attrs = (f' data-upload="/api/upload/{sid}/{quote_path(rel)}" data-folder="{esc(title)}"' if allow else "")
        self.send_html(200, self.page(title, body, body_attrs=attrs))

    def search_page(self):
        q = self.q("q").strip()[:200]
        if not q:
            return self.redirect("/")
        results, total, closest = index.search(q, limit=300)
        by_id = {s["id"]: s for s in settings.shares()}
        rows = []
        for _score, e in results:
            share = by_id.get(e[1])
            if not share:
                continue
            parent = e[2].rsplit("/", 1)[0] if "/" in e[2] else ""
            rows.append(row_html(e[0], e[1], e[2], e[3], e[4], e[5], where=entry_where(e, share),
                                 parent_url=f"/b/{e[1]}/{quote_path(parent)}"))
        building = index.status()["state"] == "building"
        if rows:
            meta = f"{total:,} match{'es' if total != 1 else ''}"
            if total > len(rows):
                meta += f", showing the best {len(rows)}"
            if closest:
                meta += ". Nothing matched every word, so these are the closest"
            listing = "".join(rows)
        else:
            meta = "Still indexing your drives. Try again in a moment." if building else "Try fewer words, or check the drive is shared in Settings."
            listing = f'<div class="empty">No matches for “{esc(q)}”.</div>'
        body = (f'<div class="head"><div><nav class="crumbs"><a href="/">Home</a></nav>'
                f'<h1 class="title">Results for “{esc(q)}”</h1><div class="meta">{esc(meta)}</div></div></div>'
                f'<div class="panel list">{listing}</div>')
        self.send_html(200, self.page(f"Search: {q}", body, query=q))

    def api_search(self):
        q = self.q("q").strip()[:200]
        try:
            limit = max(1, min(200, int(self.q("limit", "12"))))
        except ValueError:
            limit = 12
        results, total, closest = index.search(q, limit=limit) if q else ([], 0, False)
        by_id = {s["id"]: s for s in settings.shares()}
        out = []
        for _score, e in results:
            share = by_id.get(e[1])
            if share:
                out.append({"kind": e[0], "name": e[3], "size": e[4], "url": entry_url(e),
                            "where": entry_where(e, share), "icon": "folder" if e[0] == "d" else icon_for(e[3])})
        st = index.status()
        self.send_json({"results": out, "total": total, "closest": closest,
                        "indexing": st["state"] == "building", "count": st["count"]})

    # ---- files ---------------------------------------------------------------
    def _file_target(self, sid, rel):
        share = find_share(sid)
        target = resolve_in_share(share, rel) if share else None
        return share, target

    def download(self, sid, rel):
        _share, target = self._file_target(sid, rel)
        if target is None or not target.is_file():
            return self.error_page(404, "File not found", "It may have been moved, renamed or deleted.")
        view = self.q("view") == "1"
        try:
            st = target.stat()
            fh = open(target, "rb")
        except PermissionError:
            return self.error_page(403, "Access denied", "Windows won't let Beam read this file (it may be in use).")
        except OSError:
            return self.error_page(404, "File not found", "It may have been moved, renamed or deleted.")
        with fh:
            size = st.st_size
            ext = ext_of(target.name)
            inline = view and ext in INLINE_MIME
            last_mod = email.utils.formatdate(st.st_mtime, usegmt=True)
            start, end, status = 0, size - 1, 200
            rng = self.headers.get("Range")
            if rng and self.headers.get("If-Range") not in (None, last_mod):
                rng = None  # file changed since the partial download began: send it whole
            if rng:
                m = re.fullmatch(r"\s*bytes=(\d*)-(\d*)\s*", rng)
                if m and (m.group(1) or m.group(2)):
                    a, b = m.groups()
                    if a:
                        start, end = int(a), (min(int(b), size - 1) if b else size - 1)
                    else:
                        start, end = max(0, size - int(b)), size - 1
                    if size == 0 or start > end or start >= size:
                        self.send_response(416)
                        self.send_header("Content-Range", f"bytes */{size}")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    status = 206
            length = max(0, end - start + 1)
            self.send_response(status)
            self.send_header("Content-Type", INLINE_MIME[ext] if inline else "application/octet-stream")
            self.send_header("Content-Length", str(length))
            self.send_header("Content-Disposition", content_disposition(target.name, inline))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Last-Modified", last_mod)
            self.send_header("Cache-Control", "private, max-age=0")
            self.security_headers(page=False)
            if not (inline and ext == "pdf"):
                self.send_header("Content-Security-Policy", "sandbox")
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.end_headers()
            if self.command == "HEAD":
                return
            if status == 200 and not view:
                log.info("Download: %s (%s) to %s", target, human_size(size), self.client_ip())
            fh.seek(start)
            remaining = length
            while remaining > 0:
                chunk = fh.read(min(CHUNK, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def zip_folder(self, sid, rel):
        share, target = self._file_target(sid, rel)
        if target is None or not target.is_dir():
            return self.error_page(404, "Folder not found", "It may have been moved, renamed or deleted.")
        name = clean_component(target.name or share["name"]) or "Beam"
        show_hidden = settings.get("show_hidden")
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", content_disposition(name + ".zip"))
        self.send_header("Cache-Control", "no-store")
        self.security_headers(page=False)
        self.end_headers()
        log.info("ZIP download: %s to %s", target, self.client_ip())
        count = 0
        with zipfile.ZipFile(self.wfile, "w", zipfile.ZIP_STORED, allowZip64=True, strict_timestamps=False) as zf:
            stack = [(str(target), "")]
            while stack:
                folder, rel_dir = stack.pop()
                try:
                    it = os.scandir(folder)
                except OSError:
                    continue
                with it:
                    for e in sorted(it, key=lambda x: natural_key(x.name)):
                        try:
                            if skip_entry(e, show_hidden):
                                continue
                            arc = f"{rel_dir}/{e.name}" if rel_dir else e.name
                            if e.is_dir(follow_symlinks=False):
                                if not is_reparse(e.stat(follow_symlinks=False)):
                                    stack.append((e.path, arc))
                            elif e.is_file(follow_symlinks=False):
                                zf.write(e.path, f"{name}/{arc}")
                                count += 1
                        except (ConnectionError, TimeoutError, socket.timeout):
                            raise
                        except OSError as exc:
                            log.warning("Skipped in ZIP: %s (%s)", e.path, exc)
        log.info("ZIP complete: %s files", count)

    def api_upload(self, sid, rel_dir):
        if not settings.get("allow_uploads"):
            return self.send_json({"error": "Uploads are switched off in Settings."}, 403)
        if self.headers.get("X-Beam") != "1":
            return self.send_json({"error": "Missing Beam upload header."}, 403)
        share, target = self._file_target(sid, rel_dir)
        if target is None or not target.is_dir():
            return self.send_json({"error": "The destination folder no longer exists."}, 404)
        comps = [clean_component(p) for p in self.q("path").replace("\\", "/").split("/") if p.strip()]
        if not comps or None in comps or len(comps) > 32:
            return self.send_json({"error": "That file name isn't allowed."}, 400)
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.send_json({"error": "Upload size missing."}, 411)
        if length < 0:
            return self.send_json({"error": "Invalid upload size."}, 400)
        cap = capacity(str(target))
        if cap and length > cap[1] - SPACE_RESERVE:
            return self.send_json({"error": f"Not enough space ({human_size(cap[1])} free)."}, 507)
        root = resolve_in_share(share, "")
        parent = target.joinpath(*comps[:-1])
        try:
            parent.mkdir(parents=True, exist_ok=True)
            parent = parent.resolve(strict=True)
        except OSError as exc:
            return self.send_json({"error": f"Couldn't create the folder: {exc.strerror or exc}"}, 500)
        if root is None or (parent != root and root not in parent.parents):
            return self.send_json({"error": "That destination isn't allowed."}, 400)
        tmp = parent / f"{TEMP_PREFIX}{secrets.token_hex(8)}.part"
        try:
            received = 0
            with open(tmp, "xb") as out:
                while received < length:
                    chunk = self.rfile.read(min(CHUNK, length - received))
                    if not chunk:
                        break
                    out.write(chunk)
                    received += len(chunk)
            if received != length:
                raise ConnectionError("upload interrupted")
            final = None
            for _ in range(50):
                cand = unique_path(parent / comps[-1])
                try:
                    os.rename(tmp, cand)  # never overwrites on Windows; retried if a name clash races us
                    final = cand
                    break
                except FileExistsError:
                    continue
            if final is None:
                raise OSError("couldn't find a free file name")
        except (ConnectionError, TimeoutError, socket.timeout):
            tmp.unlink(missing_ok=True)
            raise
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            log.error("Upload failed for %s: %s", comps[-1], exc)
            return self.send_json({"error": f"Couldn't save the file: {exc.strerror or exc}"}, 500)
        try:
            mtime = int(self.q("mtime")) / 1000
            if mtime > 0:
                os.utime(final, (time.time(), mtime))  # keep the original "date modified"
        except (ValueError, OSError, OverflowError):
            pass
        log.info("Upload: %s (%s) from %s", final, human_size(length), self.client_ip())
        index.schedule(5)
        self.send_json({"ok": True, "name": final.name})

    # ---- sign-in -------------------------------------------------------------
    def login_page(self, error="", nxt=None):
        if settings.get("password") is None or self.authorised():
            return self.redirect("/")
        nxt = safe_next(nxt if nxt is not None else self.q("next", "/"))
        flash = f'<div class="flash err">{esc(error)}</div>' if error else ""
        body = (f'<div class="panel login"><span class="orb big" aria-hidden="true"></span>'
                f'<h1 class="title">Beam is locked</h1><p class="note">Enter the password set on the PC running Beam.</p>{flash}'
                f'<form method="post" action="/login"><input type="hidden" name="next" value="{esc(nxt)}">'
                f'<div class="field"><input type="password" name="password" autocomplete="current-password" '
                f'aria-label="Password" placeholder="Password" required autofocus></div>'
                f'<div class="field"><button class="btn wide">{icon("lock")}Unlock</button></div></form></div>')
        self.send_html(401 if error else 200, self.page("Sign in", body, nav=False))

    def login_submit(self):
        if settings.get("password") is None:
            return self.redirect("/")
        if not self.same_origin():
            return self.error_page(403, "Blocked", "That sign-in didn't come from Beam's own page.")
        form = self.read_form() or {}
        nxt = safe_next((form.get("next") or ["/"])[0])
        ip = self.client_ip()
        if login_blocked(ip):
            return self.login_page("Too many wrong attempts. Wait a minute, then try again.", nxt)
        if check_password((form.get("password") or [""])[0], settings.get("password")):
            login_ok(ip)
            return self.redirect(nxt, [("Set-Cookie", session_cookie(make_session()))])
        login_failed(ip)
        log.warning("Wrong password attempt from %s", ip)
        return self.login_page("That password isn't right.", nxt)

    # ---- settings -------------------------------------------------------------
    def settings_page(self):
        manage = self.can_manage()
        dis = "" if manage else " disabled"
        flash = ""
        if MESSAGES.get(self.q("m")):
            flash += f'<div class="flash">{esc(MESSAGES[self.q("m")])}</div>'
        if ERRORS.get(self.q("e")):
            flash += f'<div class="flash err">{esc(ERRORS[self.q("e")])}</div>'
        if not manage:
            flash += ('<div class="flash">You can look around, but settings can only be changed on the PC running Beam, '
                      'or from any device once a password is set.</div>')

        shares = settings.shares()
        shared = {normkey(s["path"]) for s in shares}
        seen, rows = set(), []
        for d in detect_drives():
            k = normkey(d["path"])
            seen.add(k)
            if d["kind"] == "Network drive":
                detail = "Network drive"
            else:
                cap = capacity(d["path"])
                detail = f'{d["kind"]}, {human_size(cap[1])} free of {human_size(cap[0])}' if cap else d["kind"]
            if d["system"]:
                detail += ". Windows is installed here, so only share it if you need to"
            rows.append((d["path"], d["display"], detail, k in shared))
        for s in shares:
            if normkey(s["path"]) not in seen:
                online = os.path.isdir(s["path"])
                rows.append((s["path"], s["name"], s["path"] + ("" if online else " (not connected)"), True))
        drive_rows = "".join(
            f'<label class="check"><span class="grow"><b>{esc(title)}</b><small>{esc(detail)}</small></span>'
            f'<input class="sw" type="checkbox" name="share" value="{esc(path)}"{" checked" if on else ""}></label>'
            for path, title, detail, on in rows) or '<p class="note">No drives found. Add a folder below.</p>'

        theme = self.theme()
        radio = lambda v, label: (f'<label><input type="radio" name="theme" value="{v}" data-set-theme'
                                  f'{" checked" if theme == v else ""}><span>{label}</span></label>')
        port_now, port_saved = self.server.server_port, settings.get("port")
        bookmark = f"http://{HOSTNAME.lower()}:{port_now}/"
        backup = f"http://{primary_ip()}:{port_now}/"
        has_pw = settings.get("password") is not None
        st = index.status()
        built = time.strftime("%H:%M", time.localtime(st["built_at"])) if st["built_at"] else "not yet"

        sections = [
            f'''<section class="panel sect"><h2>Shared drives</h2>
<p class="note">Switch on the drives other devices can open. Everything else on this PC stays private.</p>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="shares">{drive_rows}
<div class="field"><button class="btn">Save drives</button></div></fieldset></form>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="add">
<div class="field"><input type="text" name="path" placeholder="Or share one folder, e.g. F:\\Films" aria-label="Folder path to share">
<button class="btn ghost">Add folder</button></div></fieldset></form></section>''',

            f'''<section class="panel sect"><h2>Appearance</h2>
<p class="note">Saved in this browser.</p>
<div class="seg" role="radiogroup" aria-label="Theme">{radio("dark", "Dark")}{radio("light", "Light")}{radio("system", "Match Windows")}</div></section>''',

            f'''<section class="panel sect"><h2>Your bookmark</h2>
<p class="note">Favourite this on your other PC. It uses this PC's name, so it keeps working when the router hands out a new IP address.</p>
<div class="kv"><code>{esc(bookmark)}</code><button type="button" class="btn ghost sm" data-copy="{esc(bookmark)}">Copy</button></div>
<p class="note" style="margin-top:12px">Backup address, which can change: <code>{esc(backup)}</code>. If the name ever stops working,
set a DHCP reservation for this PC in your router so the backup address never changes.</p>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="port">
<div class="field"><label for="port">Port</label><input id="port" type="number" name="port" min="1024" max="65535" value="{port_saved}">
<button class="btn ghost">Save port</button></div></fieldset></form></section>''',

            f'''<section class="panel sect"><h2>Uploads and hidden files</h2>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="prefs">
<label class="check"><span class="grow"><b>Allow uploads</b><small>Other devices can add files to shared drives. Nothing is ever overwritten or deleted.</small></span>
<input class="sw" type="checkbox" name="allow_uploads"{" checked" if settings.get("allow_uploads") else ""}></label>
<label class="check"><span class="grow"><b>Show hidden files</b><small>Include hidden and system files in folders and search.</small></span>
<input class="sw" type="checkbox" name="show_hidden"{" checked" if settings.get("show_hidden") else ""}></label>
<div class="field"><button class="btn">Save</button></div></fieldset></form></section>''',

            f'''<section class="panel sect"><h2>Password</h2>
<p class="note">{"A password is set. Other devices need it to open Beam; this PC never does." if has_pw else
               "No password. Anyone on your home network can open the shared drives while Beam is running."}</p>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="password">
<div class="field"><input type="password" name="password" autocomplete="new-password" placeholder="New password" aria-label="New password" minlength="6">
<input type="password" name="confirm" autocomplete="new-password" placeholder="Type it again" aria-label="Confirm new password" minlength="6"></div>
<div class="field"><button class="btn">{"Change password" if has_pw else "Set password"}</button></div></fieldset></form>
{f"""<form method="post" action="/settings" data-confirm="Remove the password? Anyone on your network will be able to open Beam."><fieldset{dis}>
<input type="hidden" name="action" value="nopassword"><div class="field"><button class="btn ghost">Remove password</button></div></fieldset></form>""" if has_pw else ""}
{"""<form method="post" action="/logout"><div class="field"><button class="btn ghost">Sign out on this device</button></div></form>""" if has_pw and not self.is_host_machine() else ""}
</section>''',
        ]
        if IS_WINDOWS:
            sections.append(f'''<section class="panel sect"><h2>Start with Windows</h2>
<p class="note">Runs Beam quietly in the background whenever this PC starts, so your bookmark always works.</p>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="autostart">
<label class="check"><span class="grow"><b>Start Beam automatically</b><small>Stop it any time with the button below.</small></span>
<input class="sw" type="checkbox" name="autostart"{" checked" if autostart_enabled() else ""}></label>
<div class="field"><button class="btn">Save</button></div></fieldset></form></section>''')
        sections.append(f'''<section class="panel sect"><h2>Search index and server</h2>
<p class="note">{st["count"]:,} items {"indexed so far" if st["state"] == "building" else f"indexed, last updated {built}"}.
It refreshes on its own every hour and after uploads.</p>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="reindex">
<div class="field"><button class="btn ghost">Rebuild search index now</button></div></fieldset></form>
<form method="post" action="/settings" data-confirm="Stop Beam? Nobody will be able to open it until it's started again on the PC running Beam.">
<fieldset{dis}><input type="hidden" name="action" value="stop"><div class="field"><button class="btn ghost">Stop Beam</button></div></fieldset></form>
<p class="note" style="margin-top:14px">Beam {VERSION}. Log file: {esc(str(LOG_PATH))}</p></section>''')

        body = (f'<div class="head"><div><nav class="crumbs"><a href="/">Home</a></nav>'
                f'<h1 class="title">Settings</h1></div></div>{flash}<div class="sgrid">{"".join(sections)}</div>')
        self.send_html(200, self.page("Settings", body))

    def settings_submit(self):
        if not self.can_manage():
            return self.redirect("/settings?e=perm")
        form = self.read_form()
        if form is None:
            return self.error_page(413, "Too much data", "That form was bigger than expected.")
        f1 = lambda k: (form.get(k) or [""])[0]
        action = f1("action")

        if action == "shares":
            known = {}
            for s in settings.shares():
                known[normkey(s["path"])] = (s["path"], s["name"])
            for d in detect_drives():
                known.setdefault(normkey(d["path"]), (d["path"], d["display"]))
            new, seen = [], set()
            for p in form.get("share", []):
                k = normkey(p)
                if k in known and k not in seen:  # only paths offered on the page
                    seen.add(k)
                    new.append({"path": known[k][0], "name": known[k][1]})
            settings.set(shares=new)
            log.info("Shared drives changed: %s", ", ".join(s["name"] for s in new) or "none")
            index.schedule(0.5)
            return self.redirect("/settings?m=saved")

        if action == "add":
            raw = f1("path").strip().strip('"').strip()
            p = os.path.normpath(os.path.abspath(os.path.expanduser(raw))) if raw else ""
            if not p or not os.path.isdir(p):
                return self.redirect("/settings?e=nopath")
            if normkey(p) in {normkey(s["path"]) for s in settings.shares()}:
                return self.redirect("/settings?e=dup")
            name = os.path.basename(p.rstrip("\\/")) or p
            for d in detect_drives():
                if normkey(d["path"]) == normkey(p):
                    name = d["display"]
            settings.set(shares=settings.get("shares") + [{"path": p, "name": name[:80]}])
            log.info("Folder shared: %s", p)
            index.schedule(0.5)
            return self.redirect("/settings?m=added")

        if action == "prefs":
            hidden = f1("show_hidden") == "on"
            changed = hidden != settings.get("show_hidden")
            settings.set(allow_uploads=f1("allow_uploads") == "on", show_hidden=hidden)
            if changed:
                index.schedule(0.5)
            return self.redirect("/settings?m=saved")

        if action == "port":
            try:
                port = int(f1("port"))
            except ValueError:
                port = -1
            if not 1024 <= port <= 65535:
                return self.redirect("/settings?e=port")
            settings.set(port=port)
            return self.redirect("/settings?m=port")

        if action == "password":
            pw, again = f1("password"), f1("confirm")
            if len(pw) < 6 or len(pw) > 256:
                return self.redirect("/settings?e=pwshort")
            if pw != again:
                return self.redirect("/settings?e=pwmatch")
            settings.set(password=hash_password(pw))
            log.info("Password set")
            return self.redirect("/settings?m=pwset", [("Set-Cookie", session_cookie(make_session()))])

        if action == "nopassword":
            settings.set(password=None)
            log.info("Password removed")
            return self.redirect("/settings?m=pwoff", [("Set-Cookie", CLEAR_SESSION)])

        if action == "autostart":
            on = f1("autostart") == "on"
            try:
                set_autostart(on)
            except OSError as exc:
                log.error("Couldn't change start-with-Windows: %s", exc)
                return self.redirect("/settings?e=auto")
            return self.redirect("/settings?m=" + ("auto_on" if on else "auto_off"))

        if action == "reindex":
            index.schedule(0)
            return self.redirect("/settings?m=reindex")

        if action == "stop":
            body = ('<div class="panel hero"><span class="orb big" aria-hidden="true"></span><h1 class="title">Beam has stopped</h1>'
                    '<p>Start it again on the PC running Beam with “Start File Transfer.bat”.</p></div>')
            self.send_html(200, self.page("Stopped", body, nav=False))
            log.info("Stopped from Settings by %s", self.client_ip())
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return

        return self.redirect("/settings")


class BeamServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = not IS_WINDOWS  # on Windows this would let two copies share a port
    request_queue_size = 64

    def __init__(self, port: int):
        try:
            dual = socket.has_dualstack_ipv6()
        except Exception:
            dual = False
        # IPv4 + IPv6, so "http://pcname:port" works however Windows resolves the name
        self.address_family = socket.AF_INET6 if dual else socket.AF_INET
        super().__init__(("::" if dual else "0.0.0.0", port), Handler)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        if IS_WINDOWS and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = HOSTNAME, self.server_address[1]

    def handle_error(self, request, client_address):
        log.debug("Connection error from %s", client_address, exc_info=True)


def periodic_reindex():
    while True:
        time.sleep(REINDEX_SECONDS)
        index.build()


def main() -> int:
    setup_logging()
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x8000)  # no "insert disk" pop-ups for empty USB slots
        except Exception:
            pass
    settings.load()
    port = settings.get("port")
    line = "=" * 66
    try:
        server = BeamServer(port)
    except OSError as exc:
        log.error("Couldn't start on port %s: %s", port, exc)
        say(line)
        say(f"  Beam couldn't start: port {port} is already in use.")
        say(f"  If Beam is already running, just open http://localhost:{port}/")
        say("  Otherwise another program is using that port: change \"port\" in")
        say(f"  {SETTINGS_PATH}")
        say(line)
        return 1

    real_port = server.server_port
    threading.Thread(target=index.build, name="indexer", daemon=True).start()
    threading.Thread(target=periodic_reindex, name="reindexer", daemon=True).start()
    shared = ", ".join(s["name"] for s in settings.shares()) or "nothing yet (open Settings)"
    say(line)
    say(f"  BEAM  |  LAN File Transfer  v{VERSION}")
    say("-" * 66)
    say(f"  Bookmark this on your other PC:  http://{HOSTNAME.lower()}:{real_port}/")
    say(f"  Backup address (can change):     http://{primary_ip()}:{real_port}/")
    say(f"  Settings (on this PC):           http://localhost:{real_port}/settings")
    say(f"  Sharing: {shared}")
    say("-" * 66)
    say("  Leave this window open while you use Beam. Close it to stop.")
    say(line)
    log.info("Beam %s started on port %s", VERSION, real_port)
    if settings.first_run and IS_WINDOWS:
        webbrowser.open(f"http://localhost:{real_port}/settings")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        say("\n  Stopping Beam...")
    finally:
        server.server_close()
        log.info("Beam stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
