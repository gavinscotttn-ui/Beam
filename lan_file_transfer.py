#!/usr/bin/env python3
"""
Beam - LAN File Transfer (v3.0)
===============================
Share the drives on this PC with any web browser on your home network.

HOW TO USE
  1. Double-click "Start File Transfer.bat" on the PC with the drives.
  2. On your other PC, open the "Bookmark" address it shows and favourite it.
  3. Choose which drives are shared in Settings (Options > Settings).

FASTEST TRANSFERS
  - Mark several files (Options > Mark several) and download them together.
    Beam runs a few downloads side by side, which fills a Wi-Fi link far
    better than one file at a time.
  - For the very fastest copies, join the two PCs with a network cable.
    Beam notices the wired route and offers to switch to it. Settings >
    Connection explains the one-off Windows setting a direct cable needs.

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

import base64
import bisect
import collections
import copy
import email.utils
import errno
import gc
import gzip
import hashlib
import hmac
import html
import http.cookies
import http.server
import ipaddress
import itertools
import json
import logging
import logging.handlers
import os
import re
import secrets
import selectors
import shutil
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.parse
import webbrowser
import zlib
from pathlib import Path

if sys.version_info < (3, 8):
    sys.exit("Beam needs Python 3.8 or newer: https://www.python.org/downloads/")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
APP = "Beam"
VERSION = "3.0"
IS_WINDOWS = os.name == "nt"
APP_DIR = Path(__file__).resolve().parent
SETTINGS_PATH = APP_DIR / "beam_settings.json"
LOG_PATH = APP_DIR / "beam.log"
HOSTNAME = socket.gethostname() or "localhost"
DEFAULT_PORT = 8000
CHUNK = 1024 * 1024                # read/write block for uploads, copies and ZIPs
SEND_STEP = 8 * 1024 * 1024        # bytes per sendfile() call (progress granularity)
WIN_SNDBUF = 4 * 1024 * 1024       # Windows send buffer for big transfers (see tune_bulk)
IO_TIMEOUT = 120                   # seconds a transfer may stall before Beam gives up
KEEPALIVE_IDLE = 20                # seconds an idle browser connection is kept open
MAX_FORM_BYTES = 64 * 1024
MAX_PICK_BYTES = 1024 * 1024       # form listing the marked items for a ZIP
MAX_DEPTH = 64
REINDEX_SECONDS = 60 * 60
SESSION_SECONDS = 30 * 24 * 3600
HANDOFF_SECONDS = 120              # lifetime of a "switch to the faster connection" link
PBKDF2_ROUNDS = 240_000
SPACE_RESERVE = 16 * 1024 * 1024
TEMP_PREFIX = ".beam-"
SPEEDTEST_MAX = 4 * 1024 ** 3
GZIP_MIN = 1024                    # compress text responses bigger than this
THEMES = ("dark", "light", "system")
ACCENTS = ("magenta", "orange", "aqua", "lime", "violet")

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

# Pages load their script from /static only (no inline script), so injected
# markup can never run. connect-src may also list this PC's other addresses so
# the page can check whether a faster (wired) route to Beam is reachable.
PAGE_CSP = ("default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "media-src 'self'; connect-src 'self'%s; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'")

# Never accepted as uploads: hidden files, and Windows files that make
# Explorer act on their contents just by showing a folder (icon/UNC tricks).
UPLOAD_BLOCKED_NAMES = {"desktop.ini", "autorun.inf", "thumbs.db", "ehthumbs.db"}
UPLOAD_BLOCKED_EXTS = {"lnk", "url", "scf", "library-ms", "searchconnector-ms"}

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


_NAT_RE = re.compile(r"(\d+)")


def natural_key(s: str):
    return [int(t) if t.isdigit() else t for t in _NAT_RE.split(s.casefold())]


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


def upload_name_blocked(name: str) -> bool:
    low = name.lower()
    return low.startswith(".") or low in UPLOAD_BLOCKED_NAMES or ext_of(low) in UPLOAD_BLOCKED_EXTS


def unique_path(p: Path) -> Path:
    if not os.path.lexists(p):
        return p
    stem, suffix = p.stem, p.suffix
    for i in range(1, 10000):
        cand = p.with_name(f"{stem} ({i}){suffix}")
        if not os.path.lexists(cand):
            return cand
    raise OSError("No free file name available")


def place_upload(tmp: Path, parent: Path, name: str) -> Path:
    """Give a finished upload its real name without ever replacing a file.

    Windows' rename refuses to overwrite. POSIX rename silently replaces, so
    there the name is first claimed with O_EXCL (atomic even on FAT/exFAT
    USB drives, where hard links aren't available)."""
    for _ in range(50):
        cand = unique_path(parent / name)
        try:
            if IS_WINDOWS:
                os.rename(tmp, cand)
            else:
                fd = os.open(cand, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                os.close(fd)
                try:
                    os.replace(tmp, cand)
                except OSError:
                    try:
                        os.unlink(cand)
                    except OSError:
                        pass
                    raise
            return cand
        except FileExistsError:
            continue  # another upload took that name a moment ago; try the next one
    raise OSError("No free file name available")


def make_dirs_within(base: Path, comps):
    """Create base/comps[0]/comps[1]/... one level at a time, refusing to pass
    through anything that isn't a plain folder (a symlink or junction there
    could otherwise lead outside the share). Returns (folder, positions in
    comps of the folders it created)."""
    cur, created = base, []
    for i, c in enumerate(comps):
        cur = cur / c
        try:
            os.mkdir(cur)
            created.append(i)
        except FileExistsError:
            pass
        st = os.lstat(cur)
        if not stat.S_ISDIR(st.st_mode) or is_reparse(st):
            raise PermissionError(errno.EACCES, f"{c} isn't a plain folder")
    return cur, created


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


_ip_cache = {"at": 0.0, "ips": frozenset({"127.0.0.1", "::1"}), "busy": False}
_ip_lock = threading.Lock()


def _refresh_local_ips() -> None:
    ips = {"127.0.0.1", "::1", primary_ip()}
    try:
        for info in socket.getaddrinfo(HOSTNAME, None):
            ips.add(norm_ip(info[4][0]))
    except OSError:
        pass
    for iface in netinfo.cached():
        ips.update(iface["ips"])
    with _ip_lock:
        _ip_cache.update(at=time.time(), ips=frozenset(ips), busy=False)


def local_ips() -> frozenset:
    """This PC's own addresses. Refreshed in the background: a slow name
    lookup must never hold up a request."""
    with _ip_lock:
        if time.time() - _ip_cache["at"] > 60 and not _ip_cache["busy"]:
            _ip_cache["busy"] = True
            threading.Thread(target=_refresh_local_ips, name="local-ips", daemon=True).start()
        return _ip_cache["ips"]


def norm_ip(ip: str) -> str:
    ip = ip.split("%", 1)[0]
    if ip.lower().startswith("::ffff:") and "." in ip:
        ip = ip[7:]
    return ip


# ---------------------------------------------------------------------------
# Network interfaces (so Beam can spot a faster wired route)
# ---------------------------------------------------------------------------
# One PowerShell call gathers everything: adapter type and speed, IPv4
# addresses, which adapters have a router (default route), and whether
# Windows treats each network as Public (firewalled) or Private.
_PS_NETINFO = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$ad = @(Get-NetAdapter | ForEach-Object { [pscustomobject]@{ i = [int]$_.ifIndex; n = [string]$_.Name;
  m = [string]$_.PhysicalMediaType; s = [string]$_.Status; sp = [double]$_.ReceiveLinkSpeed;
  v = [bool]$_.Virtual; h = [bool]$_.HardwareInterface } })
$ip = @(Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { [pscustomobject]@{ i = [int]$_.InterfaceIndex; a = [string]$_.IPAddress } })
$pr = @(Get-NetConnectionProfile | ForEach-Object { [pscustomobject]@{ i = [int]$_.InterfaceIndex; c = [string]$_.NetworkCategory } })
$gw = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | ForEach-Object { [int]$_.InterfaceIndex })
[pscustomobject]@{ ad = $ad; ip = $ip; pr = $pr; gw = $gw } | ConvertTo-Json -Depth 4 -Compress
"""


def _as_list(v):
    return v if isinstance(v, list) else ([] if v is None else [v])


def parse_win_netinfo(data) -> list:
    """Turn _PS_NETINFO's JSON into Beam's interface list (tolerates missing bits)."""
    if not isinstance(data, dict):
        return []
    ips, cats = {}, {}
    for r in _as_list(data.get("ip")):
        if isinstance(r, dict) and isinstance(r.get("a"), str):
            ips.setdefault(r.get("i"), []).append(r["a"])
    for r in _as_list(data.get("pr")):
        if isinstance(r, dict):
            cats[r.get("i")] = str(r.get("c") or "")
    gws = set(_as_list(data.get("gw")))
    out = []
    for a in _as_list(data.get("ad")):
        if not isinstance(a, dict) or str(a.get("s")) != "Up":
            continue
        idx = a.get("i")
        addrs = [x for x in ips.get(idx, []) if not x.startswith("127.")]
        if not addrs:
            continue
        media = str(a.get("m") or "")
        if "802.11" in media:
            kind = "wifi"
        elif media == "802.3" and a.get("h") and not a.get("v"):
            kind = "ethernet"
        else:
            kind = "other"
        try:
            speed = int(float(a.get("sp") or 0))
        except (TypeError, ValueError):
            speed = 0
        out.append({"name": str(a.get("n") or "")[:80], "kind": kind, "ips": addrs, "speed": speed,
                    "gateway": idx in gws, "category": cats.get(idx, ""),
                    "index": idx if isinstance(idx, int) else None})
    return out


def _win_interfaces():
    script = base64.b64encode(_PS_NETINFO.encode("utf-16-le")).decode("ascii")
    try:
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                            "-EncodedCommand", script], stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=25, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        text = r.stdout.decode("utf-8", "replace").strip().lstrip("﻿")
        return parse_win_netinfo(json.loads(text)) if text else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _linux_interfaces():
    base = Path("/sys/class/net")
    if not base.is_dir():
        return None
    import fcntl
    gws = set()
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) > 1 and f[1] == "00000000":
                gws.add(f[0])
    except OSError:
        pass

    def read(p):
        try:
            return p.read_text().strip()
        except OSError:
            return ""

    out = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for d in sorted(base.iterdir()):
            name = d.name
            if name == "lo" or read(d / "operstate") not in ("up", "unknown"):
                continue
            try:  # SIOCGIFADDR: the interface's IPv4 address
                res = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", name.encode()[:15]))
                ip = socket.inet_ntoa(res[20:24])
            except OSError:
                continue
            wifi = (d / "wireless").exists() or (d / "phy80211").exists()
            kind = "wifi" if wifi else ("ethernet" if (d / "device").exists() else "other")
            try:
                speed = max(0, int(read(d / "speed") or 0)) * 1_000_000
            except ValueError:
                speed = 0
            out.append({"name": name, "kind": kind, "ips": [ip], "speed": speed,
                        "gateway": name in gws, "category": "", "index": None})
    finally:
        s.close()
    return out


def _basic_interfaces():
    ips = {primary_ip()}
    try:
        for info in socket.getaddrinfo(HOSTNAME, None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    ips = sorted(x for x in ips if not x.startswith("127."))
    return [{"name": "", "kind": "other", "ips": ips, "speed": 0, "gateway": True,
             "category": "", "index": None}] if ips else []


def detect_interfaces() -> list:
    found = None
    try:
        if IS_WINDOWS:
            found = _win_interfaces()
        elif sys.platform.startswith("linux"):
            found = _linux_interfaces()
    except Exception:
        log.debug("Interface detection failed", exc_info=True)
    return found if found is not None else _basic_interfaces()


def is_direct_link(iface) -> bool:
    """A cable straight between two PCs: a wired adapter with no router behind
    it, or an automatic 169.254.x.x address (what Windows picks with no router)."""
    if iface["kind"] == "wifi":
        return False
    return any(ip.startswith("169.254.") for ip in iface["ips"]) or \
        (iface["kind"] == "ethernet" and not iface["gateway"])


class NetInfo:
    """This PC's network interfaces. Detection can take a second on Windows
    (it asks PowerShell), so it runs in the background and only when a page
    that shows or uses it asks, at most once every TTL seconds."""
    TTL = 60

    def __init__(self):
        self._lock = threading.Lock()
        self._ifaces = []
        self._at = 0.0
        self._busy = False

    def get(self) -> list:
        """Current list; starts a background refresh if it's getting old."""
        with self._lock:
            if time.time() - self._at > self.TTL and not self._busy:
                self._busy = True
                threading.Thread(target=self._refresh, name="netinfo", daemon=True).start()
            return self._ifaces

    def cached(self) -> list:
        with self._lock:
            return self._ifaces

    def refreshed_once(self) -> bool:
        with self._lock:
            return self._at > 0

    def refresh_now(self) -> list:
        with self._lock:
            self._busy = True
        self._refresh()
        return self.cached()

    def _refresh(self) -> None:
        try:
            found = detect_interfaces()
        finally:
            with self._lock:
                self._busy = False
        with self._lock:
            self._ifaces = found
            self._at = time.time()

    def find(self, ip: str):
        for iface in self.cached():
            if ip in iface["ips"]:
                return iface
        return None


netinfo = NetInfo()


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
                # Owner-only on Mac/Linux: the file holds the password hash and signing secret.
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as out:
                    out.write(json.dumps(self._data, indent=2))
                if not IS_WINDOWS:
                    os.chmod(tmp, 0o600)
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


def resolve_in_share(share, rel: str, show_hidden=None):
    """Real path inside the share, or None. Blocks '..', ':' (Windows
    alternate data streams), symlinks/junctions leading outside, and - unless
    "Show hidden files" is on - anything hidden. Hidden things are left out of
    listings, but they must not be reachable by typing their address either
    (think .ssh in a shared home folder, or AppData)."""
    parts = clean_parts(rel)
    if any(p == ".." or ":" in p or "\x00" in p for p in parts):
        return None
    if show_hidden is None:
        show_hidden = settings.get("show_hidden")
    for p in parts:
        if p.lower() in SKIP_NAMES or p.startswith(TEMP_PREFIX) or (not show_hidden and p.startswith(".")):
            return None
    try:
        root = Path(share["path"]).resolve(strict=True)
        target = root.joinpath(*parts).resolve(strict=True) if parts else root
    except (OSError, RuntimeError, ValueError):
        return None
    if target != root and root not in target.parents:
        return None
    if IS_WINDOWS and parts and not show_hidden:
        cur = Path(share["path"])
        for p in parts:
            cur = cur / p
            try:
                attrs = os.lstat(cur).st_file_attributes
            except OSError:
                return None
            if attrs & (stat.FILE_ATTRIBUTE_HIDDEN | stat.FILE_ATTRIBUTE_SYSTEM):
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


def _signed(seconds: int, purpose: bytes) -> str:
    msg = f"{int(time.time()) + seconds}.{secrets.token_hex(8)}"
    sig = hmac.new(_session_key() + purpose, msg.encode(), hashlib.sha256).hexdigest()
    return f"{msg}.{sig}"


def _check_signed(token: str, purpose: bytes):
    """The token's nonce if the signature is good and it hasn't expired."""
    try:
        exp, nonce, sig = token.split(".")
    except (ValueError, AttributeError):
        return None
    good = hmac.new(_session_key() + purpose, f"{exp}.{nonce}".encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(good, sig) and exp.isdigit() and int(exp) > time.time():
        return nonce
    return None


def make_session() -> str:
    return _signed(SESSION_SECONDS, b"")


def valid_session(token: str) -> bool:
    return _check_signed(token, b"") is not None


# A handoff link moves this browser to another of this PC's addresses (e.g.
# the wired one) without signing in again. Separate key, short-lived, and
# each link works once.
_handoffs = {}
_handoffs_lock = threading.Lock()


def make_handoff() -> str:
    return _signed(HANDOFF_SECONDS, b"|handoff")


def use_handoff(token: str) -> bool:
    nonce = _check_signed(token, b"|handoff")
    if nonce is None:
        return False
    now = time.time()
    with _handoffs_lock:
        for k in [k for k, exp in _handoffs.items() if exp < now]:
            del _handoffs[k]
        if nonce in _handoffs:
            return False
        _handoffs[nonce] = now + HANDOFF_SECONDS
    return True


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


_SAFE_NEXT = re.compile(r"/(?![/\\])[\x21-\x7e]*")


def safe_next(n: str) -> str:
    """Only plain same-site paths. Browsers ignore tabs and newlines inside
    URLs, so "/<tab>/evil.example" would become "//evil.example"; anything
    outside printable ASCII is refused (which also stops header injection)."""
    return n if isinstance(n, str) and _SAFE_NEXT.fullmatch(n) and "\\" not in n else "/"


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
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"  # every character a search word can contain


def fold(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s.casefold().replace("'", "").replace("’", "")


def tokens(s: str):
    return _TOKEN_RE.findall(fold(s))


def stem_key(kind: str, name: str, name_tokens=None) -> str:
    """The name's words without its extension: what an exact-name search matches."""
    if name_tokens is None:
        name_tokens = tokens(name)
    if kind != "f" or "." not in name:
        return " ".join(name_tokens)
    stem, ext = name.rsplit(".", 1)
    fext = fold(ext)
    if name_tokens and _TOKEN_RE.fullmatch(fext) and name_tokens[-1] == fext:
        return " ".join(name_tokens[:-1])  # the extension was the last word
    return " ".join(tokens(stem))


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


def _set_bits(x: int):
    """Positions of the 1 bits in x (fast for sparse numbers)."""
    if not x:
        return
    raw = x.to_bytes((x.bit_length() + 7) // 8, "little")
    for m in re.finditer(rb"[^\x00]", raw):
        base, v = m.start() * 8, raw[m.start()]
        while v:
            low = v & -v
            yield base + low.bit_length() - 1
            v ^= low


def _edits1(w: str) -> set:
    """Every string one typo away from w: a letter dropped, added, replaced,
    or two neighbours swapped."""
    out = set()
    for i in range(len(w) + 1):
        a, b = w[:i], w[i:]
        if b:
            out.add(a + b[1:])
            if len(b) > 1:
                out.add(a + b[1] + b[0] + b[2:])
            for c in _ALPHABET:
                out.add(a + c + b[1:])
        for c in _ALPHABET:
            out.add(a + c + b)
    return out


def _near_prefixes(w: str) -> set:
    """Same-length variants of w with one letter replaced or two neighbours swapped."""
    out = set()
    for i in range(len(w)):
        a, b = w[:i], w[i + 1:]
        for c in _ALPHABET:
            out.add(a + c + b)
        if i + 1 < len(w):
            out.add(a + w[i + 1] + w[i] + w[i + 2:])
    out.discard(w)
    return out


class Vocab:
    """Every word in the index, arranged for fast prefix, substring and typo lookups."""

    def __init__(self, words):
        self.words = sorted(words)
        self.set = frozenset(self.words)
        self.joined = "\n".join(self.words)
        starts, pos = [], 0
        for w in self.words:
            starts.append(pos)
            pos += len(w) + 1
        self.starts = starts
        # For two-typo matching: per word length, one bitmap per letter saying
        # which words contain it (bit i = i-th word of that length).
        groups = {}
        for w in self.words:
            if not w.isdigit():
                groups.setdefault(len(w), []).append(w)
        self.by_len = {}
        for length, ws in groups.items():
            nbytes, maps = (len(ws) + 7) // 8, {}
            for i, w in enumerate(ws):
                byte, bit = i >> 3, 1 << (i & 7)
                for c in set(w):
                    buf = maps.get(c)
                    if buf is None:
                        buf = maps[c] = bytearray(nbytes)
                    buf[byte] |= bit
            self.by_len[length] = (ws, {c: int.from_bytes(b, "little") for c, b in maps.items()},
                                   (1 << len(ws)) - 1)

    def missing_at_most_two(self, qt: str, length: int):
        """Words of this length lacking at most two of qt's letters. Counts
        the missing letters for every word at once with big-integer bit
        operations (bit-sliced counters), rather than word by word."""
        group = self.by_len.get(length)
        if not group:
            return []
        ws, maps, full = group
        ones = twos = threes = 0
        for c in set(qt):
            miss = full & ~maps.get(c, 0)
            threes |= twos & miss
            twos |= ones & miss
            ones |= miss
        return [ws[i] for i in _set_bits(full & ~threes)]

    def prefixed(self, p: str):
        words = self.words
        lo = bisect.bisect_left(words, p)
        return words[lo:bisect.bisect_left(words, p + "\x7f", lo)]

    def containing(self, s: str):
        words, starts, joined = self.words, self.starts, self.joined
        out, last = [], len(starts) - 1
        pos = joined.find(s)
        while pos != -1:
            k = bisect.bisect_right(starts, pos) - 1
            out.append(words[k])
            if k == last:
                break
            pos = joined.find(s, starts[k + 1])
        return out


def _score_token(qt: str, n: int, maxd: int, qset: set, vt: str) -> float:
    """How well vocabulary word vt matches query word qt."""
    if vt == qt:
        return 1.0
    if vt.startswith(qt):
        return 0.9 if n > 1 else 0.6
    if n >= 3 and qt in vt:
        return 0.75
    if maxd and not vt.isdigit() and len(qset - set(vt)) <= maxd:
        lv = len(vt)
        if abs(lv - n) <= maxd and osa_distance(qt, vt, maxd) <= maxd:
            return 0.7 if osa_distance(qt, vt, 1) <= 1 else 0.55
        if lv > n and osa_distance(qt, vt[:n], 1) <= 1:
            return 0.6  # typo in a half-typed word
    return 0.0


def match_token(qt: str, vocab: Vocab, extra=()):
    """[(vocabulary word, score)] for one query word. Candidates are gathered
    cheaply (sorted-list ranges, a substring scan done in C, generated
    one-typo variants) and then scored by _score_token, so the result is the
    same as scoring every word in the vocabulary, only much faster."""
    n = len(qt)
    maxd = 0 if qt.isdigit() or n < 4 else (1 if n <= 6 else 2)
    cands = set(vocab.prefixed(qt))
    if n >= 3:
        cands.update(vocab.containing(qt))
    if maxd:
        cands.update(_edits1(qt) & vocab.set)
        for p in _near_prefixes(qt):
            cands.update(vocab.prefixed(p))
        if maxd > 1:  # two typos: words of similar length lacking at most two of its letters
            for length in range(n - maxd, n + maxd + 1):
                cands.update(vocab.missing_at_most_two(qt, length))
    cands.update(extra)
    qset = set(qt)
    out = []
    for vt in cands:
        s = _score_token(qt, n, maxd, qset, vt)
        if s:
            out.append((vt, s))
    return out


class SearchIndex:
    def __init__(self):
        self._lock = threading.Lock()
        self._build_lock = threading.Lock()
        self._rerun = False
        self._timer = None
        self.state = "idle"
        self.progress = 0
        self.built_at = None
        self._install([], {}, {})

    def _install(self, entries, name_post, path_post, vocab=None) -> None:
        # entries: (kind 'd'/'f', share_id, rel_posix, name, size, mtime, stem_key)
        # name_post: token -> [entry index]  (token is in the name)
        # path_post: token -> [entry index]  (token is in a parent folder name)
        self.entries, self.name_post, self.path_post = entries, name_post, path_post
        self.vocab = vocab if vocab is not None else Vocab(set(name_post) | set(path_post))
        self.extra = []  # words added since the last build (uploads)
        self._match_cache = {}
        self._natkeys = {}  # entry index -> natural sort key, filled as searches need them

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
                            kind = "d" if is_dir else "f"
                            ntl = tokens(e.name)
                            entries.append((kind, share["id"], erel, e.name, None if is_dir else st.st_size,
                                            st.st_mtime, stem_key(kind, e.name, ntl)))
                            ntoks = frozenset(ntl)
                            for t in ntoks:
                                name_post.setdefault(t, []).append(idx)
                            for t in ancestors - ntoks:
                                path_post.setdefault(t, []).append(idx)
                            if idx % 2000 == 0:
                                self.progress = idx
                            if is_dir and not is_reparse(st) and erel.count("/") < MAX_DEPTH:
                                stack.append((e.path, erel, ntoks, dir_toks))
            vocab = Vocab(set(name_post) | set(path_post))
            with self._lock:
                self._install(entries, name_post, path_post, vocab)
                self.built_at = time.time()
            log.info("Search index ready: %s items in %.1fs", f"{len(entries):,}", time.time() - started)
            # The index is millions of long-lived objects. Tell the garbage
            # collector to stop re-checking them, or its periodic sweeps stall
            # every request (and search) for a noticeable moment.
            gc.collect()
            gc.freeze()
        except Exception:
            log.exception("Indexing failed")
        finally:
            with self._lock:
                self.state = "idle"

    def add(self, sid: str, items) -> None:
        """Make just-uploaded files (and folders created for them) searchable
        at once, without rescanning every drive. items: (kind, rel, name,
        size, mtime), parents before children."""
        with self._lock:
            if self.state == "building":
                self._rerun = True  # the scan in progress may already have passed them
            entries, npost, ppost = self.entries, self.name_post, self.path_post
            known, extra_set = self.vocab.set, set(self.extra)
            for kind, rel, name, size, mtime in items:
                parts = rel.split("/")
                dir_toks = frozenset(tokens(parts[-2])) if len(parts) > 1 else frozenset()
                parent_toks = frozenset(tokens(parts[-3])) if len(parts) > 2 else frozenset()
                ntl = tokens(name)
                ntoks = frozenset(ntl)
                idx = len(entries)
                entries.append((kind, sid, rel, name, size, mtime, stem_key(kind, name, ntl)))
                for t in ntoks:
                    npost.setdefault(t, []).append(idx)
                for t in (dir_toks | parent_toks) - ntoks:
                    ppost.setdefault(t, []).append(idx)
                for t in ntoks | dir_toks | parent_toks:
                    if t not in known and t not in extra_set:
                        extra_set.add(t)
                        self.extra.append(t)
            self._match_cache = {}

    @staticmethod
    def _best(qt, npost, ppost, vocab, extra, cache) -> dict:
        """entry index -> best score for one query word."""
        matches = cache.get(qt)
        if matches is None:
            matches = match_token(qt, vocab, extra)
            if len(cache) > 256:
                cache.clear()
            cache[qt] = matches  # typing "breaking bad s0" re-uses "breaking" and "bad"
        pairs = []
        for vt, s in matches:
            pl = npost.get(vt)
            if pl:
                pairs.append((s, pl))
            pl = ppost.get(vt)
            if pl:
                pairs.append((s * 0.55, pl))  # matched a parent folder, not the name itself
        pairs.sort(key=lambda x: x[0])
        best = {}
        for s, pl in pairs:  # ascending, so every entry ends up with its best score
            best.update(zip(pl, itertools.repeat(s)))
        return best

    def search(self, query: str, limit: int = 100):
        """Returns ([(score, entry)], total_matches, closest_only)."""
        qts = list(dict.fromkeys(tokens(query)))[:8]
        with self._lock:
            entries, npost, ppost, vocab = self.entries, self.name_post, self.path_post, self.vocab
            extra, cache, natkeys = list(self.extra), self._match_cache, self._natkeys
        if not qts or not entries:
            return [], 0, False
        n = len(qts)
        bests = [self._best(qt, npost, ppost, vocab, extra, cache) for qt in qts]
        if n == 1:
            totals, top = bests[0], 1
        else:
            order = sorted(bests, key=len)
            common = order[0].keys() & order[1].keys()  # set operations run in C
            for d in order[2:]:
                common = common & d.keys()
            if common:
                if n == 2:
                    b0, b1 = bests
                    totals = {i: b0[i] + b1[i] for i in common}
                else:
                    totals = {i: sum(d[i] for d in bests) for i in common}
                top = n
            else:  # nothing matched every word: offer what matched the most
                counts = collections.Counter()
                for d in bests:
                    counts.update(d.keys())
                if not counts:
                    return [], 0, False
                top = max(counts.values())
                totals = {i: sum(d.get(i, 0.0) for d in bests) for i, c in counts.items() if c == top}
        if not totals:
            return [], 0, False
        phrase = " ".join(qts)
        if len(totals) > 3000:
            # Rank the best by word score, plus anything whose name starts with
            # the query: an exact name can hide among thousands of equal scores.
            pool = set(sorted(totals, key=totals.__getitem__, reverse=True)[:2000])
            pool.update(i for i in totals if entries[i][6].startswith(phrase))
        else:
            pool = totals
        scored = []
        for i in pool:
            e = entries[i]
            score = totals[i] / n
            if e[6] == phrase:
                score += 0.35
            elif e[6].startswith(phrase):
                score += 0.15
            if e[0] == "d":
                score += 0.03
            scored.append((round(score, 4), i))
        scored.sort(key=lambda x: -x[0])
        if len(scored) > limit:
            cut, keep = scored[limit - 1][0], limit
            while keep < len(scored) and scored[keep][0] == cut:
                keep += 1  # keep ties at the cut so they can be ordered properly
            del scored[keep:]
        if len(natkeys) > 200_000:
            natkeys.clear()
        # Among equal scores, results from one folder stay together in that folder's
        # own natural order (a season reads E01, E02 ... E10 whatever the titles), and
        # the folder whose match has the shortest name comes first.
        shortest = {}
        for sc, i in scored:
            e = entries[i]
            g = (sc, e[1], e[2].rpartition("/")[0])
            shortest[g] = min(shortest.get(g, 1 << 30), len(e[3]))

        def order(x):
            sc, i = x
            e = entries[i]
            g = (sc, e[1], e[2].rpartition("/")[0])
            k = natkeys.get(i)
            if k is None:
                k = natkeys[i] = natural_key(e[3])
            return -sc, shortest[g], g[1], g[2], k
        scored.sort(key=order)
        return [(s, entries[i]) for s, i in scored[:limit]], len(totals), top < n


index = SearchIndex()


# ---------------------------------------------------------------------------
# Sending files fast
# ---------------------------------------------------------------------------
def tune_bulk(sock) -> None:
    """Call before a big transfer. Python sockets with a timeout are
    non-blocking underneath, and on Windows the amount of unacknowledged data
    a non-blocking socket can have in flight is capped by its send buffer.
    Over Wi-Fi, where every round trip takes a few milliseconds, a small
    buffer alone can hold a download to a fraction of the link's speed, so
    Beam asks for 4 MB (enough for even a slow, jittery Wi-Fi hop). Linux and
    macOS grow their buffers automatically; setting one there would stop that."""
    if IS_WINDOWS:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, WIN_SNDBUF)
        except OSError:
            pass


def open_for_reading(path):
    """Unbuffered handle with a "reading straight through" hint, so the OS
    reads ahead in bigger pieces (a big help for USB hard drives)."""
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_SEQUENTIAL", 0)
             | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags)
    try:
        if hasattr(os, "posix_fadvise"):
            try:
                os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_SEQUENTIAL)
            except OSError:
                pass
        return open(fd, "rb", buffering=0)
    except BaseException:
        os.close(fd)
        raise


class _NoSendfile(Exception):
    pass


_SENDFILE = hasattr(os, "sendfile") and not IS_WINDOWS
_NO_SENDFILE_ERRNOS = {errno.EINVAL, errno.ENOSYS, errno.ENOTSOCK, errno.EOPNOTSUPP,
                       getattr(errno, "ENOTSUP", errno.EOPNOTSUPP)}


def send_file(sock, fh, offset: int, count: int, progress=None) -> int:
    """Send count bytes of fh starting at offset. Returns the number sent,
    which is only less than count if the file shrank meanwhile."""
    if _SENDFILE and count:
        try:
            return _sendfile_loop(sock, fh, offset, count, progress)
        except _NoSendfile:
            pass
    return _copy_loop(sock, fh, offset, count, progress)


def _sendfile_loop(sock, fh, offset, count, progress):
    """Linux/macOS: the kernel moves file data straight to the network (no copies)."""
    sfd, ffd, timeout = sock.fileno(), fh.fileno(), sock.gettimeout()
    sel = (selectors.PollSelector if hasattr(selectors, "PollSelector") else selectors.SelectSelector)()
    sent = 0
    try:
        sel.register(sfd, selectors.EVENT_WRITE)
        while sent < count:
            try:
                n = os.sendfile(sfd, ffd, offset + sent, min(SEND_STEP, count - sent))
            except (BlockingIOError, InterruptedError):
                if not sel.select(timeout):
                    raise socket.timeout("timed out")
                continue
            except OSError as exc:
                if sent == 0 and exc.errno in _NO_SENDFILE_ERRNOS:
                    raise _NoSendfile() from exc
                raise
            if n == 0:
                break
            sent += n
            if progress:
                progress(n)
    finally:
        sel.close()
    return sent


def _copy_loop(sock, fh, offset, count, progress):
    """Windows (and fallback): 1 MB reads into one reused buffer, no per-block allocations."""
    buf = memoryview(bytearray(min(CHUNK, max(count, 1))))
    fh.seek(offset)
    left = count
    while left > 0:
        n = fh.readinto(buf[:min(len(buf), left)])
        if not n:
            break
        sock.sendall(buf[:n])
        left -= n
        if progress:
            progress(n)
    return count - left


# ---------------------------------------------------------------------------
# Download progress for Beam's own download queue
# ---------------------------------------------------------------------------
class Transfers:
    """When the page downloads several files it adds ?tx=<batch>.<n> to each
    link. Browsers don't tell a page how its downloads are going, so Beam
    keeps count here: connections open per file (the page keeps the total low
    enough that browsing stays responsive), bytes sent, and whether each one
    finished. Only small numbers, capped and expired after an hour idle."""
    _TX = re.compile(r"([A-Za-z0-9]{8,32})\.(\d{1,5})")
    RUNNING, DONE, FAILED = 0, 1, 2

    def __init__(self):
        self._lock = threading.Lock()
        self._batches = {}

    def begin(self, tx: str, size: int):
        m = self._TX.fullmatch(tx or "")
        if not m:
            return None
        bid, n = m.group(1), int(m.group(2))
        now = time.time()
        with self._lock:
            self._prune(now)
            batch = self._batches.setdefault(bid, {"at": now, "items": {}})
            batch["at"] = now
            item = batch["items"].get(n)
            if item is None:
                if len(batch["items"]) >= 20000:
                    return None
                item = batch["items"][n] = [0, 0, size, self.RUNNING]  # open connections, bytes, size, state
            item[0] += 1
            item[2] = size
            item[3] = self.RUNNING
        return _TxItem(self._lock, item)

    def snapshot(self, bid: str) -> dict:
        with self._lock:
            batch = self._batches.get(bid)
            if not batch:
                return {}
            batch["at"] = time.time()
            return {str(n): list(v) for n, v in batch["items"].items()}

    def _prune(self, now: float) -> None:
        if len(self._batches) < 50:
            return
        for bid in [b for b, v in self._batches.items() if now - v["at"] > 3600]:
            del self._batches[bid]
        while len(self._batches) >= 200:
            del self._batches[min(self._batches, key=lambda b: self._batches[b]["at"])]


class _TxItem:
    __slots__ = ("_lock", "_item")

    def __init__(self, lock, item):
        self._lock, self._item = lock, item

    def add(self, n: int) -> None:
        with self._lock:
            self._item[1] += n

    def end(self, ok: bool) -> None:
        with self._lock:
            self._item[0] = max(0, self._item[0] - 1)
            if self._item[0] == 0:
                self._item[3] = Transfers.DONE if ok else Transfers.FAILED


transfers = Transfers()


def rate_text(nbytes: int, secs: float) -> str:
    return f"{human_size(nbytes)} in {secs:.1f}s, {human_size(nbytes / max(secs, 1e-6))}/s"


# ---------------------------------------------------------------------------
# Streaming ZIP (stored, ZIP64 when needed) with its exact size known up front
# ---------------------------------------------------------------------------
ZIP64_LIMIT = (1 << 31) - 1          # the same thresholds as Python's zipfile, which Beam
ZIP_FILECOUNT_LIMIT = (1 << 16) - 1  # used before, so archives open exactly as they did
_ZIP_FILE_ATTR = 0o100644 << 16      # a plain, readable file


def _dos_datetime(ts: float):
    try:
        t = time.localtime(ts)
    except (OverflowError, OSError, ValueError):
        return 33, 0
    if t.tm_year < 1980:
        return 33, 0  # 1 Jan 1980, the earliest date a ZIP can hold
    if t.tm_year > 2107:
        return (127 << 9) | (12 << 5) | 31, (23 << 11) | (59 << 5) | 29
    return (((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday,
            (t.tm_hour << 11) | (t.tm_min << 5) | (min(t.tm_sec, 59) // 2))


def zip_plan(folder: str, top: str, show_hidden: bool, pick=None):
    """Files under folder as (path, name in the ZIP, size, mtime), in natural
    order: each folder's files, then its subfolders. pick limits the top
    level to those names (the marked items)."""
    out, stack = [], [(folder, "", 0)]
    while stack:
        path, rel, depth = stack.pop()
        try:
            with os.scandir(path) as it:
                ents = sorted(it, key=lambda e: natural_key(e.name))
        except OSError:
            continue
        subdirs = []
        for e in ents:
            if not rel and pick is not None and e.name not in pick:
                continue
            try:
                if skip_entry(e, show_hidden):
                    continue
                arc = f"{rel}/{e.name}" if rel else e.name
                if e.is_dir(follow_symlinks=False):
                    if not is_reparse(e.stat(follow_symlinks=False)) and depth < MAX_DEPTH:
                        subdirs.append((e.path, arc, depth + 1))
                elif e.is_file(follow_symlinks=False):
                    st = e.stat(follow_symlinks=False)
                    out.append((e.path, f"{top}/{arc}", st.st_size, st.st_mtime))
            except OSError as exc:
                log.warning("Skipped in ZIP: %s (%s)", e.path, exc)
        stack.extend(reversed(subdirs))
    return out


class ZipStream:
    """Stored (uncompressed) ZIP written straight to the network: no temp
    files, 1 MB reads, and an exact size before the first byte so the
    browser shows progress and time left. Video and photos don't compress,
    so storing is the fastest choice. If a file changes size or vanishes
    while the ZIP is being sent, its data is padded or cut to the size
    already announced and its checksum is deliberately spoiled: unzipping
    then reports that one file as damaged instead of quietly keeping bad data."""

    def __init__(self, files):
        self.items, offset = [], 0
        for path, arc, size, mtime in files:
            name = arc.encode("utf-8")
            if len(name) > 0xFFFF:
                log.warning("Skipped in ZIP (path too long): %s", path)
                continue
            z64 = size * 1.05 > ZIP64_LIMIT
            date, tim = _dos_datetime(mtime)
            flags = 0x08 | (0 if arc.isascii() else 0x800)  # sizes follow the data; UTF-8 names
            # path, name, size, date, time, flags, zip64, offset, crc
            self.items.append([path, name, size, date, tim, flags, z64, offset, 0])
            offset += 30 + len(name) + (20 if z64 else 0) + size + (24 if z64 else 16)
        self.cd_offset = offset
        self.cd_size = sum(46 + len(it[1]) + len(self._cd_extra(it)) for it in self.items)
        self.zip64_end = (len(self.items) > ZIP_FILECOUNT_LIMIT or self.cd_offset > ZIP64_LIMIT
                          or self.cd_size > ZIP64_LIMIT)
        self.size = self.cd_offset + self.cd_size + (76 if self.zip64_end else 0) + 22
        self.damaged = 0

    @staticmethod
    def _cd_extra(it) -> bytes:
        vals = ([it[2], it[2]] if it[2] > ZIP64_LIMIT else []) + ([it[7]] if it[7] > ZIP64_LIMIT else [])
        return struct.pack("<HH" + "Q" * len(vals), 1, 8 * len(vals), *vals) if vals else b""

    def stream(self, send, progress=None) -> int:
        cap = CHUNK
        view = memoryview(bytearray(cap))
        zeros = memoryview(bytes(cap))
        pos = sent = 0

        def flush():
            nonlocal pos, sent
            if pos:
                send(view[:pos])
                sent += pos
                if progress:
                    progress(pos)
                pos = 0

        def put(data: bytes):
            nonlocal pos
            if pos + len(data) > cap:
                flush()
            view[pos:pos + len(data)] = data
            pos += len(data)

        for it in self.items:
            path, name, size, date, tim, flags, z64, _offset, _crc = it
            put(struct.pack("<4s5H3L2H", b"PK\x03\x04", 45 if z64 else 20, flags, 0, tim, date, 0, 0, 0,
                            len(name), 20 if z64 else 0) + name
                + (struct.pack("<HHQQ", 1, 16, 0, 0) if z64 else b""))
            crc, left, damaged = 0, size, False
            try:
                fh = open_for_reading(path)
            except OSError as exc:
                fh, damaged = None, True
                log.warning("ZIP: couldn't read %s (%s)", path, exc)
            if fh is not None:
                with fh:
                    try:
                        if os.fstat(fh.fileno()).st_size != size:
                            damaged = True
                        while left:
                            if pos == cap:
                                flush()
                            n = fh.readinto(view[pos:pos + min(cap - pos, left)])
                            if not n:
                                break
                            crc = zlib.crc32(view[pos:pos + n], crc)
                            pos += n
                            left -= n
                    except OSError as exc:
                        damaged = True
                        log.warning("ZIP: error reading %s (%s)", path, exc)
            while left:  # keep the size announced up front
                damaged = True
                if pos == cap:
                    flush()
                k = min(cap - pos, left)
                view[pos:pos + k] = zeros[:k]
                crc = zlib.crc32(zeros[:k], crc)
                pos += k
                left -= k
            if damaged:
                crc ^= 0xFFFFFFFF
                self.damaged += 1
                log.warning("ZIP: %s changed while it was being sent, so it's marked as damaged in the ZIP", path)
            it[8] = crc
            put(struct.pack("<4sLQQ", b"PK\x07\x08", crc, size, size) if z64
                else struct.pack("<4s3L", b"PK\x07\x08", crc, size, size))

        for it in self.items:  # central directory
            _path, name, size, date, tim, flags, z64, offset, crc = it
            extra = self._cd_extra(it)
            ver = 45 if (extra or z64) else 20
            big_size, big_off = size > ZIP64_LIMIT, offset > ZIP64_LIMIT
            put(struct.pack("<4s6H3L5H2L", b"PK\x01\x02", (3 << 8) | ver, ver, flags, 0, tim, date, crc,
                            0xFFFFFFFF if big_size else size, 0xFFFFFFFF if big_size else size,
                            len(name), len(extra), 0, 0, 0, _ZIP_FILE_ATTR,
                            0xFFFFFFFF if big_off else offset) + name + extra)
        count = len(self.items)
        if self.zip64_end:
            put(struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count,
                            self.cd_size, self.cd_offset))
            put(struct.pack("<4sLQL", b"PK\x06\x07", 0, self.cd_offset + self.cd_size, 1))
        put(struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, min(count, 0xFFFF), min(count, 0xFFFF),
                        min(self.cd_size, 0xFFFFFFFF), min(self.cd_offset, 0xFFFFFFFF), 0))
        flush()
        return sent


# A block of random bytes for the speed test (random, so nothing on the way can compress it).
_SPEED_BLOCK = memoryview(os.urandom(CHUNK))


# ---------------------------------------------------------------------------
# Look & feel: a mid-2000s phone menu. Status bar, glossy title bar, soft
# keys, glossy highlight bar and bright glossy icons, on modern, accessible CSS.
# ---------------------------------------------------------------------------
LIGHT_VARS = ("--bg:#dfe3ea;--wall:radial-gradient(900px 420px at 88% -8%,rgba(var(--m-rgb),.16),transparent 64%),"
              "radial-gradient(700px 380px at -8% 108%,rgba(var(--m-rgb),.10),transparent 60%),"
              "linear-gradient(180deg,#eef0f4,#d9dde5);"
              "--panel:linear-gradient(180deg,#ffffff,#f1f3f7);--solid:#ffffff;--line:#d3d7df;--line-hi:#b7bcc8;"
              "--text:#15161b;--muted:#545866;--hot:var(--hot-l);--input:#ffffff;--row-hi:rgba(0,0,0,.045);"
              "--bar:linear-gradient(180deg,#ffffff 0%,#eef0f4 48%,#dcdfe6 52%,#e8ebf0 100%);--bar-edge:#b9bec9;"
              "--sbar:linear-gradient(180deg,#f9fafb,#e3e6ec);--sbar-text:#2a2c33;"
              "--skeys:linear-gradient(180deg,#ffffff 0%,#eceef2 48%,#d9dce3 52%,#e6e9ee 100%);--skeys-text:#16171c;"
              "--shadow:0 12px 30px -16px rgba(30,30,60,.4);--gloss:rgba(255,255,255,.95);"
              "--tile:linear-gradient(180deg,#ffffff,#e4e7ed);--scrim:rgba(20,22,30,.45);color-scheme:light;")

CSS = r"""
:root{--m:#e20074;--m-rgb:226,0,116;--hl2:#c2005f;--on-hl:#fff;--hot-d:#ff5aad;--hot-l:#b3005c;
--font:"Segoe UI","Segoe UI Variable Text",Tahoma,system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
--chrome:Tahoma,"Segoe UI",Verdana,system-ui,-apple-system,sans-serif;--sk-h:48px}
[data-accent=orange]{--m:#ff7a00;--m-rgb:255,122,0;--hl2:#f28c28;--on-hl:#1a0b00;--hot-d:#ff9a3c;--hot-l:#a04600}
[data-accent=aqua]{--m:#0a9ff5;--m-rgb:10,159,245;--hl2:#0064ad;--on-hl:#fff;--hot-d:#4cc3ff;--hot-l:#005c99}
[data-accent=lime]{--m:#6ec72d;--m-rgb:110,199,45;--hl2:#7ccf35;--on-hl:#0f1a00;--hot-d:#8fe04f;--hot-l:#2e6e0a}
[data-accent=violet]{--m:#8a3ffc;--m-rgb:138,63,252;--hl2:#6526cc;--on-hl:#fff;--hot-d:#b48cff;--hot-l:#5b21b6}
:root,[data-theme=dark]{--bg:#050507;--wall:radial-gradient(1000px 480px at 86% -10%,rgba(var(--m-rgb),.20),transparent 62%),
radial-gradient(760px 420px at -10% 112%,rgba(var(--m-rgb),.10),transparent 60%),linear-gradient(180deg,#0b0b0f,#030304);
--panel:linear-gradient(180deg,rgba(32,32,40,.94),rgba(13,13,17,.94));--solid:#121217;--line:#26262e;--line-hi:#3b3b45;
--text:#f4f4f7;--muted:#a4a4b1;--hot:var(--hot-d);--input:#09090c;--row-hi:rgba(255,255,255,.05);
--bar:linear-gradient(180deg,#35353e 0%,#1b1b21 48%,#060608 52%,#101014 100%);--bar-edge:#000;
--sbar:linear-gradient(180deg,#000,#0e0e12);--sbar-text:#e9e9ef;
--skeys:linear-gradient(180deg,#2c2c34 0%,#151519 48%,#040405 52%,#0c0c0f 100%);--skeys-text:#fff;
--shadow:0 14px 34px -16px rgba(0,0,0,.95);--gloss:rgba(255,255,255,.08);--tile:linear-gradient(180deg,#2c2c35,#0d0d11);
--scrim:rgba(0,0,0,.72);color-scheme:dark}
[data-theme=light]{/*LIGHT*/}
@media (prefers-color-scheme:light){[data-theme=system]{/*LIGHT*/}}
:root{--hl:linear-gradient(180deg,rgba(255,255,255,.26) 0%,rgba(255,255,255,.08) 49%,rgba(0,0,0,0) 51%,rgba(0,0,0,.14) 100%),var(--hl2)}
*{box-sizing:border-box}
html,body{margin:0}
body{font:15px/1.5 var(--font);background-color:var(--bg);background-image:var(--wall);background-attachment:fixed;color:var(--text);min-height:100vh;display:flex;flex-direction:column;
 padding-bottom:calc(var(--sk-h) + env(safe-area-inset-bottom,0px));-webkit-font-smoothing:antialiased}
a{color:var(--hot);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--hot);outline-offset:2px}
button{font-family:inherit}
code{font-family:Consolas,"Cascadia Mono",monospace;font-size:13.5px;color:var(--hot);word-break:break-all}
kbd{font:600 12px var(--chrome);padding:1px 7px;border-radius:5px;border:1px solid var(--line-hi);background:var(--solid);box-shadow:inset 0 -1px 0 var(--line-hi)}
.vh{position:absolute!important;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.ic{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
.fi{width:24px;height:24px;flex:none;filter:drop-shadow(0 1px 1px rgba(0,0,0,.35))}
.fi.lg{width:52px;height:52px;filter:drop-shadow(0 3px 5px rgba(0,0,0,.45))}
/* ---- status bar ---- */
.top{position:sticky;top:0;z-index:30}
.sbar{display:flex;align-items:center;gap:12px;height:24px;padding:0 14px;background:var(--sbar);color:var(--sbar-text);font:700 12px/1 var(--chrome);letter-spacing:.3px;border-bottom:1px solid rgba(255,255,255,.04)}
.sbar .op{text-transform:uppercase;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.sbar .gap{flex:1}
.sig{display:inline-flex;align-items:flex-end;gap:1.5px;height:12px;flex:none}
.sig i{width:3px;background:currentColor;border-radius:1px;opacity:.22}
.sig i:nth-child(1){height:25%}.sig i:nth-child(2){height:43%}.sig i:nth-child(3){height:62%}.sig i:nth-child(4){height:81%}.sig i:nth-child(5){height:100%}
.sig[data-bars="1"] i:nth-child(-n+1),.sig[data-bars="2"] i:nth-child(-n+2),.sig[data-bars="3"] i:nth-child(-n+3),
.sig[data-bars="4"] i:nth-child(-n+4),.sig[data-bars="5"] i:nth-child(-n+5){opacity:1}
.sig[data-bars="0"]{color:#ff5a5a}
.sb-ic{width:14px;height:14px;stroke-width:2.2}
.sb-ic.spin{animation:spin 2.4s steps(8) infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.cable{display:inline-flex;align-items:center;gap:4px;padding:1px 7px;border-radius:9px;background:rgba(var(--m-rgb),.22);color:inherit;font:inherit;border:0;cursor:pointer}
.cable[hidden]{display:none}
.bat{position:relative;display:inline-block;width:22px;height:11px;border:1.5px solid currentColor;border-radius:2px;flex:none}
.bat::after{content:"";position:absolute;right:-4px;top:2px;width:2px;height:4px;background:currentColor;border-radius:0 1px 1px 0}
.bat i{position:absolute;left:1px;top:1px;bottom:1px;width:calc((100% - 2px) * var(--lvl,1));background:currentColor;border-radius:1px}
.bat.low i{background:#ff5a5a}
.bat[hidden]{display:none}
/* ---- title bar ---- */
.tbar{display:flex;align-items:center;gap:18px;padding:9px 20px;background:var(--bar);border-bottom:1px solid var(--bar-edge);box-shadow:0 1px 0 var(--m),0 10px 26px -12px rgba(var(--m-rgb),.55)}
.brand{display:flex;align-items:center;gap:11px;color:var(--text);text-decoration:none!important;flex:none}
.orb{position:relative;display:inline-block;width:34px;height:34px;border-radius:50%;flex:none;
 background:radial-gradient(circle at 50% 120%,rgba(255,255,255,.55) 0%,var(--m) 46%,rgba(0,0,0,.65) 100%),var(--m);
 box-shadow:0 0 0 1px rgba(0,0,0,.55),0 0 18px rgba(var(--m-rgb),.6),inset 0 -3px 7px rgba(0,0,0,.35)}
.orb::after{content:"";position:absolute;left:18%;right:18%;top:7%;height:44%;border-radius:50%;background:linear-gradient(180deg,rgba(255,255,255,.92),rgba(255,255,255,.06))}
.orb.big{width:72px;height:72px;margin-bottom:12px}
.brand b{display:block;font:300 21px/1.1 var(--font);letter-spacing:.6px}
.brand small{display:block;font:11.5px var(--chrome);color:var(--muted)}
.search{position:relative;flex:1;max-width:640px;margin:0 auto;display:flex;align-items:center}
.search>.ic{position:absolute;left:14px;color:var(--muted);pointer-events:none}
.search input{width:100%;height:40px;padding:0 16px 0 42px;border-radius:20px;border:1px solid var(--line-hi);background:var(--input);color:var(--text);font:inherit;box-shadow:inset 0 2px 5px rgba(0,0,0,.35)}
.search input:focus{outline:none;border-color:var(--m);box-shadow:inset 0 2px 5px rgba(0,0,0,.35),0 0 0 3px rgba(var(--m-rgb),.3)}
.tools{display:flex;gap:8px;flex:none}
.iconbtn{display:inline-grid;place-items:center;width:40px;height:40px;border-radius:50%;border:1px solid var(--line-hi);background:linear-gradient(180deg,var(--gloss),transparent 55%),var(--solid);color:var(--text);cursor:pointer}
.iconbtn:hover{border-color:var(--m);color:var(--hot);text-decoration:none}
.moon{display:none}
[data-theme=light] .sun{display:none}[data-theme=light] .moon{display:block}
@media (prefers-color-scheme:light){[data-theme=system] .sun{display:none}[data-theme=system] .moon{display:block}}
/* ---- live search ---- */
.live{position:absolute;top:46px;left:0;right:0;max-height:min(440px,calc(100vh - 160px));overflow:auto;padding:6px;background:var(--solid);border:1px solid var(--line-hi);border-radius:14px;box-shadow:var(--shadow),0 0 0 1px rgba(var(--m-rgb),.18)}
.live a{display:flex;align-items:center;gap:11px;padding:8px 10px;border-radius:9px;color:var(--text)}
.live a:hover,.live a[aria-selected=true]{background:var(--hl);color:var(--on-hl);text-decoration:none}
.live a:hover small,.live a[aria-selected=true] small{color:inherit;opacity:.85}
.live .more{justify-content:center;color:var(--hot);font-weight:600}
.hint{padding:10px 12px;color:var(--muted);font-size:13.5px}
.t{display:flex;flex-direction:column;min-width:0}
.t .n{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.t small{color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* ---- page ---- */
.wrap{width:100%;max-width:1120px;margin:0 auto;padding:22px 20px 40px;flex:1}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow),inset 0 1px 0 var(--gloss)}
.head{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:12px;margin-bottom:16px}
.title{display:flex;align-items:center;gap:10px;font-size:28px;font-weight:300;letter-spacing:.2px;margin:0;line-height:1.2;overflow-wrap:anywhere}
.meta{color:var(--muted);font-size:13.5px;margin-top:4px}
.crumbs{display:flex;flex-wrap:wrap;align-items:center;gap:6px;font-size:13.5px;margin-bottom:4px}
.crumbs a{color:var(--muted)}.crumbs a:hover{color:var(--hot)}
.crumbs .sep{color:var(--m)}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.strip{display:flex;align-items:center;gap:10px;min-height:34px;padding:0 14px;border-radius:13px 13px 0 0;border-bottom:1px solid var(--line);
 background:linear-gradient(180deg,var(--gloss),transparent),rgba(var(--m-rgb),.10);font:700 13px var(--chrome);letter-spacing:.3px}
.strip .grow{flex:1}
#cap{font-weight:400;color:var(--hot);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
/* ---- buttons ---- */
.btn{display:inline-flex;align-items:center;gap:8px;height:36px;padding:0 16px;border-radius:18px;border:1px solid rgba(0,0,0,.35);background:var(--hl);color:var(--on-hl);
 font:700 13.5px var(--chrome);letter-spacing:.2px;cursor:pointer;white-space:nowrap;text-shadow:0 1px 1px rgba(0,0,0,.18);box-shadow:inset 0 1px 0 rgba(255,255,255,.45),0 5px 14px -7px rgba(var(--m-rgb),.9)}
.btn:hover{filter:brightness(1.07);text-decoration:none}
.btn:active{filter:brightness(.94);transform:translateY(1px)}
.btn .ic{width:18px;height:18px}
.btn.ghost{border-color:var(--line-hi);background:linear-gradient(180deg,var(--gloss),transparent 55%),var(--solid);color:var(--text);text-shadow:none;box-shadow:inset 0 1px 0 var(--gloss)}
.btn.ghost:hover{border-color:var(--m);color:var(--hot)}
.btn.sm{height:30px;padding:0 12px;font-size:12.5px}
.btn.wide{width:100%;justify-content:center}
fieldset[disabled] .btn,.btn:disabled{opacity:.45;cursor:not-allowed;filter:none}
/* ---- tabs (drives, settings) ---- */
.tabs{display:flex;align-items:center;gap:4px;margin:0 0 12px;padding:4px;border-radius:12px;background:var(--input);border:1px solid var(--line);overflow-x:auto;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tab{display:inline-flex;align-items:center;gap:7px;padding:6px 13px;border-radius:9px;color:var(--muted);font:700 13px var(--chrome);white-space:nowrap;border:0;background:none;cursor:pointer}
.tab:hover{color:var(--text);text-decoration:none;background:var(--row-hi)}
.tab[aria-selected=true],.tab[aria-current]{background:var(--hl);color:var(--on-hl);box-shadow:inset 0 1px 0 rgba(255,255,255,.35)}
.tab .ic{width:17px;height:17px}
.tabs .arr{flex:none;display:inline-grid;place-items:center;width:28px;height:28px;border-radius:8px;color:var(--hot);font-size:12px}
.tabs .arr:hover{background:var(--row-hi);text-decoration:none}
/* ---- main menu (home) ---- */
.menu-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px;padding:16px}
.tile{position:relative;display:flex;flex-direction:column;align-items:center;text-align:center;gap:6px;padding:18px 16px 16px;border-radius:14px;border:1px solid var(--line);
 background:linear-gradient(180deg,var(--gloss),transparent 60%),var(--solid);color:var(--text);text-decoration:none!important;transition:box-shadow .12s,border-color .12s}
.tile .ico{display:grid;place-items:center;width:78px;height:78px;border-radius:20px;margin-bottom:4px;transition:background .12s}
.tile:hover,.tile:focus-visible{border-color:var(--m);outline:none;box-shadow:0 0 0 2px var(--m),0 0 26px -6px rgba(var(--m-rgb),.75)}
.tile:hover .ico,.tile:focus-visible .ico{background:var(--hl);box-shadow:inset 0 1px 0 rgba(255,255,255,.4),0 6px 16px -8px rgba(var(--m-rgb),.9)}
.tile .name{font-weight:700;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tile .sub{max-width:100%;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow-wrap:anywhere}
.tile .meter{width:100%;margin-top:6px}
.tile.off{opacity:.55}
.sub{font-size:12.5px;color:var(--muted)}
.meter{height:10px;border-radius:5px;background:var(--input);border:1px solid var(--line);overflow:hidden}
.meter i{display:block;height:100%;width:0;background:repeating-linear-gradient(90deg,var(--m) 0 9px,rgba(var(--m-rgb),.55) 9px 11px);box-shadow:0 0 10px rgba(var(--m-rgb),.6);transition:width .2s}
/* ---- file list ---- */
.list{overflow:hidden}
.lh,.row{display:grid;grid-template-columns:minmax(0,1fr) 100px 164px 112px;align-items:center;gap:12px;padding:0 14px}
.lh{height:36px;font:700 12.5px var(--chrome);color:var(--muted);border-bottom:1px solid var(--line);background:linear-gradient(180deg,var(--gloss),transparent)}
.lh a{color:var(--muted)}.lh a.on{color:var(--hot)}
.row{min-height:46px;border-bottom:1px solid var(--line);position:relative;transition:background-color .08s}
.row:last-child{border-bottom:0}
.row:hover,.row:focus-within{background:var(--hl);color:var(--on-hl)}
.row:hover .nm,.row:focus-within .nm,.row:hover .num,.row:focus-within .num,.row:hover .mini,.row:focus-within .mini,
.row:hover .t small,.row:focus-within .t small{color:var(--on-hl)}
.row:hover .num,.row:focus-within .num,.row:hover .t small,.row:focus-within .t small{opacity:.88}
.c1{display:flex;align-items:center;gap:8px;min-width:0}
.nm{flex:1;display:flex;align-items:center;gap:11px;min-width:0;color:var(--text);padding:7px 0;border-radius:6px}
.nm:hover{text-decoration:none}
.nm:focus-visible{outline:none}
.row.dir .n{font-weight:700}
.num{font-size:13px;color:var(--muted);text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.ra{display:flex;justify-content:flex-end;gap:2px}
.mini{width:32px;height:32px;display:inline-grid;place-items:center;border-radius:50%;color:var(--muted);border:1px solid transparent}
.mini:hover,.mini:focus-visible{border-color:currentColor;background:rgba(0,0,0,.12);outline:none}
.mini .ic{width:18px;height:18px}
.mk{display:none;appearance:none;-webkit-appearance:none;width:20px;height:20px;margin:0 2px 0 0;border-radius:5px;border:1.5px solid var(--line-hi);background:var(--input);flex:none;cursor:pointer;position:relative}
.mk:checked{background:var(--m);border-color:var(--m)}
.mk:checked::after{content:"";position:absolute;left:5.5px;top:2px;width:5px;height:10px;border:solid #fff;border-width:0 2.5px 2.5px 0;transform:rotate(45deg)}
.marking .mk{display:inline-block}
.marking .row.marked{box-shadow:inset 4px 0 0 var(--m)}
.empty{padding:48px 20px;text-align:center;color:var(--muted)}
.hero{padding:52px 24px;text-align:center}
.hero p{color:var(--muted);max-width:48ch;margin:10px auto 22px}
.markbar{position:sticky;bottom:calc(var(--sk-h) + env(safe-area-inset-bottom,0px) + 10px);z-index:20;display:none;align-items:center;gap:10px;flex-wrap:wrap;margin-top:12px;padding:10px 14px;border-radius:14px;
 background:var(--solid);border:1px solid var(--m);box-shadow:var(--shadow),0 0 22px -6px rgba(var(--m-rgb),.6)}
.marking .markbar{display:flex}
.markbar b{font:700 14px var(--chrome)}
.markbar .grow{flex:1}
/* ---- soft keys ---- */
.skeys{position:fixed;left:0;right:0;bottom:0;z-index:35;display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:8px;height:calc(var(--sk-h) + env(safe-area-inset-bottom,0px));
 padding:0 12px env(safe-area-inset-bottom,0px);background:var(--skeys);border-top:1px solid var(--bar-edge);box-shadow:0 -1px 0 rgba(var(--m-rgb),.55),0 -10px 24px -14px rgba(var(--m-rgb),.5)}
.sk{justify-self:start;min-width:0;max-width:100%;height:36px;padding:0 14px;border:0;border-radius:10px;background:none;color:var(--skeys-text);font:700 14px var(--chrome);letter-spacing:.3px;cursor:pointer;
 white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:inline-flex;align-items:center;gap:6px}
.sk:hover{background:rgba(var(--m-rgb),.16);text-decoration:none}
.sk-r{justify-self:end}
.sk-c{justify-self:center;min-width:110px;justify-content:center;border-radius:18px;background:var(--hl);color:var(--on-hl);box-shadow:inset 0 1px 0 rgba(255,255,255,.45),0 4px 12px -6px rgba(var(--m-rgb),.9)}
.sk-c:hover{background:var(--hl);filter:brightness(1.08)}
.sk[hidden]{display:inline-flex;visibility:hidden}
.sk kbd{font-size:10.5px;padding:0 5px;opacity:.75}
/* ---- options menu ---- */
.menu{position:fixed;left:10px;bottom:calc(var(--sk-h) + env(safe-area-inset-bottom,0px) + 8px);z-index:45;width:min(300px,calc(100vw - 20px));max-height:calc(100vh - var(--sk-h) - 60px);overflow:auto;
 padding:0 0 6px;border-radius:14px;background:var(--solid);border:1px solid var(--line-hi);box-shadow:var(--shadow),0 0 0 1px rgba(var(--m-rgb),.2)}
.menu[hidden]{display:none}
.menu .strip{position:sticky;top:0;background:linear-gradient(180deg,var(--gloss),transparent),var(--solid);z-index:1}
.menu [role=menuitem],.menu [role=menuitemradio]{display:flex;align-items:center;gap:11px;width:calc(100% - 12px);margin:4px 6px 0;padding:9px 12px;border:0;border-radius:9px;background:none;color:var(--text);font:600 14px var(--font);text-align:left;cursor:pointer}
.menu [role=menuitem]:hover,.menu [role=menuitem]:focus,.menu [role=menuitemradio]:hover,.menu [role=menuitemradio]:focus{background:var(--hl);color:var(--on-hl);outline:none;text-decoration:none}
.menu hr{border:0;border-top:1px solid var(--line);margin:6px 10px 0}
/* ---- dialog ---- */
.dlg{padding:0;border:1px solid var(--line-hi);border-radius:16px;background:var(--solid);color:var(--text);width:min(420px,calc(100vw - 32px));box-shadow:var(--shadow),0 0 40px -10px rgba(var(--m-rgb),.55)}
.dlg::backdrop{background:var(--scrim)}
.dlg .strip{border-radius:15px 15px 0 0}
.dlg .body{display:flex;gap:14px;align-items:flex-start;padding:18px 18px 8px}
.dlg .body .ic{width:34px;height:34px;color:var(--hot)}
.dlg p{margin:4px 0 0;white-space:pre-line}
.dlg .keys{display:flex;justify-content:flex-end;gap:10px;padding:14px 18px 18px}
/* ---- transfers ---- */
.xfer{position:fixed;right:16px;bottom:calc(var(--sk-h) + env(safe-area-inset-bottom,0px) + 14px);z-index:40;width:min(400px,calc(100vw - 32px))}
.xfer[hidden]{display:none}
.xsec{padding:12px 16px 14px}
.xsec+.xsec{border-top:1px solid var(--line)}
.xsec[hidden]{display:none}
.xsec h3{display:flex;align-items:center;gap:8px;margin:0 0 2px;font:700 14px var(--chrome)}
.xsec h3 .ic{width:17px;height:17px;color:var(--hot)}
.xsec p{margin:0 0 9px;font-size:12.5px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.xrow{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-top:9px;font-size:12.5px;color:var(--muted);font-variant-numeric:tabular-nums}
.xnote{margin-top:8px!important;white-space:normal!important;color:var(--hot)!important}
.xnote[hidden]{display:none}
/* ---- toast ---- */
.toast{position:fixed;left:50%;bottom:calc(var(--sk-h) + env(safe-area-inset-bottom,0px) + 18px);z-index:60;transform:translate(-50%,14px);opacity:0;pointer-events:none;max-width:calc(100vw - 40px);
 display:flex;align-items:center;gap:9px;padding:10px 16px;border-radius:12px;background:#0d0d11;color:#fff;border:1px solid var(--m);box-shadow:0 0 22px rgba(var(--m-rgb),.45);transition:opacity .18s,transform .18s;font-size:14px}
.toast.on{opacity:1;transform:translate(-50%,0)}
.toast.err{border-color:#ff5a5a;box-shadow:0 0 22px rgba(255,80,80,.4)}
.toast .ic{width:18px;height:18px;color:var(--hot-d)}
.toast.err .ic{color:#ff7a7a}
/* ---- drop target ---- */
.drop{position:fixed;inset:0;z-index:50;display:none;place-items:center;background:var(--scrim)}
.drop.on{display:grid}
.drop>div{padding:34px 52px;border:2px dashed var(--m);border-radius:20px;background:var(--solid);text-align:center;font-size:18px;box-shadow:0 0 50px rgba(var(--m-rgb),.45)}
.drop p{margin:12px 0 0}
.drop .ic{width:44px;height:44px;color:var(--hot)}
/* ---- settings ---- */
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,440px),1fr));gap:16px;align-items:start}
.pane[hidden]{display:none}
.sect{padding:20px 22px}
.sect h2{font-size:17px;font-weight:600;margin:0 0 4px;display:flex;align-items:center;gap:10px}
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
.sw:checked{background:var(--hl);border-color:rgba(0,0,0,.3)}
.sw:checked::after{left:22px}
.sw:disabled{opacity:.5;cursor:not-allowed}
.field{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:14px}
.field input[type=text],.field input[type=password],.field input[type=number]{flex:1;min-width:170px;height:40px;padding:0 14px;border-radius:10px;border:1px solid var(--line-hi);background:var(--input);color:var(--text);font:inherit;box-shadow:inset 0 2px 4px rgba(0,0,0,.3)}
.field input:focus{outline:none;border-color:var(--m);box-shadow:0 0 0 3px rgba(var(--m-rgb),.28)}
.field input[type=number]{flex:0 0 130px;min-width:0}
.seg{display:inline-flex;border:1px solid var(--line-hi);border-radius:20px;overflow:hidden;background:var(--solid)}
.seg label{position:relative;cursor:pointer}
.seg input{position:absolute;opacity:0;pointer-events:none}
.seg span{display:block;padding:8px 16px;font:700 13.5px var(--chrome);border-right:1px solid var(--line)}
.seg label:last-child span{border-right:0}
.seg input:checked+span{color:var(--on-hl);background:var(--hl)}
.seg input:focus-visible+span{outline:2px solid var(--hot);outline-offset:-3px}
.swatches{display:flex;gap:12px;flex-wrap:wrap}
.swatch{position:relative;cursor:pointer}
.swatch input{position:absolute;opacity:0;pointer-events:none}
.swatch span{display:grid;place-items:center;gap:4px;font:700 12px var(--chrome);color:var(--muted)}
.swatch i{display:block;width:40px;height:40px;border-radius:50%;border:2px solid var(--line-hi);box-shadow:inset 0 -6px 10px rgba(0,0,0,.35),inset 0 6px 8px rgba(255,255,255,.35)}
.swatch input:checked+span{color:var(--text)}
.swatch input:checked+span i{border-color:var(--text);box-shadow:0 0 0 3px var(--solid),0 0 0 5px var(--text),inset 0 -6px 10px rgba(0,0,0,.35)}
.swatch input:focus-visible+span i{outline:2px solid var(--hot);outline-offset:4px}
.kv{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:11px 14px;border-radius:11px;background:var(--input);border:1px solid var(--line)}
.flash{padding:11px 16px;border-radius:12px;margin-bottom:16px;border:1px solid var(--m);background:rgba(var(--m-rgb),.12)}
.flash.err{border-color:#ff5a5a;background:rgba(255,90,90,.12)}
.badge{font:700 11px var(--chrome);padding:2px 8px;border-radius:9px;border:1px solid var(--line-hi);color:var(--muted);white-space:nowrap}
.badge.on{border-color:var(--m);color:var(--hot)}
.ifaces{width:100%;border-collapse:collapse;font-size:13px;margin:4px 0 12px}
.ifaces th{text-align:left;font:700 12px var(--chrome);color:var(--muted);padding:6px 8px;border-bottom:1px solid var(--line)}
.ifaces td{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
.steps{margin:0 0 12px;padding-left:20px;color:var(--muted);font-size:13.5px}
.steps li{margin:4px 0}
.speed{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:10px;margin:4px 0 14px}
.gauge{padding:12px;border-radius:12px;background:var(--input);border:1px solid var(--line);text-align:center}
.gauge b{display:block;font:300 26px/1.2 var(--font);font-variant-numeric:tabular-nums}
.gauge small{display:block;font:700 11.5px var(--chrome);color:var(--muted);margin-top:2px}
.gauge .meter{margin-top:8px;height:8px}
.login{max-width:400px;margin:48px auto;padding:30px 28px;text-align:center}
.lockic{width:64px;height:64px;color:var(--hot);margin-bottom:6px}
@media (max-width:760px){
 .sbar{padding:0 10px;gap:9px}
 .tbar{flex-wrap:wrap;gap:8px 10px;padding:8px 12px}
 .brand small{display:none}
 .search{order:3;flex-basis:100%;max-width:none}
 .tools{margin-left:auto}
 .wrap{padding:16px 12px 30px}
 .lh,.row{grid-template-columns:minmax(0,1fr) 78px;padding:0 10px;gap:8px}
 .c-size,.c-date{display:none}
 .title{font-size:24px}
 .menu-grid{grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;padding:10px}
 .tile{padding:14px 10px 12px}
 .tile .ico{width:64px;height:64px}
 .sk{padding:0 8px;font-size:13px}
 .sk-c{min-width:92px}
 .sk kbd{display:none}
 .actions .btn.ghost{display:none}
}
@media (pointer:coarse){.kb{display:none}}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
@media (forced-colors:active){
 .row:hover,.row:focus-within,.live a:hover,.live a[aria-selected=true],.tab[aria-selected=true],.tab[aria-current],
 .menu [role=menuitem]:focus,.menu [role=menuitem]:hover{background:Highlight;color:HighlightText;forced-color-adjust:none}
 .btn,.sk-c{border:1px solid ButtonText}
 .meter i{background:Highlight}
}
""".replace("/*LIGHT*/", LIGHT_VARS)

_GRADIENTS = (
    '<linearGradient id="gFold" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffe27a"/>'
    '<stop offset=".5" stop-color="#ffc21c"/><stop offset=".51" stop-color="#f2a600"/><stop offset="1" stop-color="#ffb81a"/></linearGradient>'
    '<linearGradient id="gFoldB" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#e8a200"/><stop offset="1" stop-color="#b87400"/></linearGradient>'
    '<linearGradient id="gVid" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#8f9dff"/>'
    '<stop offset=".5" stop-color="#5a4ff0"/><stop offset="1" stop-color="#3423b8"/></linearGradient>'
    '<radialGradient id="gAud" cx=".5" cy=".3" r=".75"><stop offset="0" stop-color="#ffc26b"/>'
    '<stop offset=".55" stop-color="#ff7a00"/><stop offset="1" stop-color="#c24a00"/></radialGradient>'
    '<linearGradient id="gSky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#8fdcff"/><stop offset="1" stop-color="#2b86d6"/></linearGradient>'
    '<linearGradient id="gHill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#8ee05a"/><stop offset="1" stop-color="#2f8a26"/></linearGradient>'
    '<linearGradient id="gArc" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#e2ad72"/><stop offset="1" stop-color="#a0612b"/></linearGradient>'
    '<linearGradient id="gArcT" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f0c894"/><stop offset="1" stop-color="#c98a4b"/></linearGradient>'
    '<linearGradient id="gDoc" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#dfe5ee"/></linearGradient>'
    '<linearGradient id="gPdf" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ff6a5f"/><stop offset="1" stop-color="#c9150b"/></linearGradient>'
    '<linearGradient id="gDrv" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f6f7f9"/>'
    '<stop offset=".5" stop-color="#c3c8d1"/><stop offset=".51" stop-color="#a9b0bc"/><stop offset="1" stop-color="#d0d4db"/></linearGradient>'
    '<linearGradient id="gGear" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f1f3f6"/><stop offset="1" stop-color="#8b94a3"/></linearGradient>'
    '<radialGradient id="gLed" cx=".5" cy=".5" r=".5"><stop offset="0" stop-color="#d8ffd9"/><stop offset="1" stop-color="#22c932"/></radialGradient>'
)

# Bright glossy icons for files, folders and drives (fixed colours, like a phone's menu).
_FILE_ICONS = {
    "folder": '<path d="M2.5 6.2c0-.9.7-1.6 1.6-1.6h4.7c.5 0 .9.2 1.2.5l1.3 1.4h8.6c.9 0 1.6.7 1.6 1.6V9H2.5z" fill="url(#gFoldB)"/>'
              '<rect x="2" y="8.2" width="20" height="11.6" rx="1.8" fill="url(#gFold)"/>'
              '<path d="M3.8 8.9h16.4c.6 0 1.1.5 1.1 1.1v2.2c-5.8 1.6-12.9 1.6-18.6 0V10c0-.6.5-1.1 1.1-1.1z" fill="#fff" opacity=".45"/>'
              '<rect x="2.4" y="8.6" width="19.2" height="10.8" rx="1.5" fill="none" stroke="#8a5a00" stroke-opacity=".35" stroke-width=".6"/>',
    "video": '<rect x="2.5" y="4.5" width="19" height="15" rx="3" fill="url(#gVid)"/>'
             '<path d="M4.6 7h1.4M7.6 7h1.4M10.6 7h1.4M13.6 7h1.4M16.6 7h1.4M4.6 17h1.4M7.6 17h1.4M10.6 17h1.4M13.6 17h1.4M16.6 17h1.4" '
             'stroke="#fff" stroke-opacity=".6" stroke-width="1.3" stroke-linecap="round"/>'
             '<path d="M10.2 9.4v5.2l4.4-2.6z" fill="#fff"/>'
             '<path d="M5.5 5h13a2.6 2.6 0 0 1 2.6 2.6v2.2c-6 1.5-12.2 1.5-18.2 0V7.6A2.6 2.6 0 0 1 5.5 5z" fill="#fff" opacity=".25"/>',
    "audio": '<circle cx="12" cy="12" r="9.5" fill="url(#gAud)"/>'
             '<path d="M10 16.2V8.4l6-1.4v7.6" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>'
             '<circle cx="8.7" cy="16.3" r="1.8" fill="#fff"/><circle cx="14.7" cy="14.7" r="1.8" fill="#fff"/>'
             '<path d="M5.1 9.3a7.6 7.6 0 0 1 13.8 0c-4.4 1.4-9.4 1.4-13.8 0z" fill="#fff" opacity=".32"/>',
    "image": '<rect x="2.5" y="4" width="19" height="16" rx="2.2" fill="url(#gSky)"/>'
             '<circle cx="16.4" cy="8.7" r="1.9" fill="#fff6a8"/>'
             '<path d="M2.5 16.4l5.2-5.2 4.2 4 2.8-2.7 6.8 5.8v.5a2.2 2.2 0 0 1-2.2 2.2H4.7a2.2 2.2 0 0 1-2.2-2.2z" fill="url(#gHill)"/>'
             '<rect x="2.5" y="4" width="19" height="16" rx="2.2" fill="none" stroke="#fff" stroke-opacity=".75" stroke-width="1"/>'
             '<path d="M4.7 4.6h14.6a1.7 1.7 0 0 1 1.7 1.7v2.4c-5.6 1.2-12.4 1.2-18 0V6.3a1.7 1.7 0 0 1 1.7-1.7z" fill="#fff" opacity=".25"/>',
    "archive": '<path d="M3 8h18v10.5A1.5 1.5 0 0 1 19.5 20h-15A1.5 1.5 0 0 1 3 18.5z" fill="url(#gArc)"/>'
               '<path d="M2.2 5.5A1.5 1.5 0 0 1 3.7 4h16.6a1.5 1.5 0 0 1 1.5 1.5v3H2.2z" fill="url(#gArcT)"/>'
               '<path d="M10.9 4h2.2v16h-2.2z" fill="#6b3d14" opacity=".4"/>'
               '<path d="M11.1 5.3h1.8M11.1 7.1h1.8M11.1 8.9h1.8M11.1 10.7h1.8" stroke="#fff3dc" stroke-width=".9"/>'
               '<path d="M3.7 4.6h16.6c.5 0 .9.4.9.9v1.5c-6.1.9-12.3.9-18.4 0V5.5c0-.5.4-.9.9-.9z" fill="#fff" opacity=".38"/>',
    "doc": '<path d="M6.5 2.5h7.7L19 7.3V20a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 20V4a1.5 1.5 0 0 1 1.5-1.5z" fill="url(#gDoc)" stroke="#8a95a8" stroke-width=".8"/>'
           '<path d="M14 2.7v4.8h4.8" fill="#d5dce7" stroke="#8a95a8" stroke-width=".8" stroke-linejoin="round"/>'
           '<path d="M7.8 11h8.4M7.8 13.6h8.4M7.8 16.2h5.8" stroke="#3d7bd9" stroke-width="1.3" stroke-linecap="round"/>',
    "pdf": '<path d="M6.5 2.5h7.7L19 7.3V20a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 20V4a1.5 1.5 0 0 1 1.5-1.5z" fill="url(#gDoc)" stroke="#8a95a8" stroke-width=".8"/>'
           '<path d="M14 2.7v4.8h4.8" fill="#d5dce7" stroke="#8a95a8" stroke-width=".8" stroke-linejoin="round"/>'
           '<rect x="3.2" y="11.6" width="13" height="6.4" rx="1.4" fill="url(#gPdf)"/>'
           '<path d="M5.4 14.8h2.4M9 14.8h1.6M11.8 14.8h2.2" stroke="#fff" stroke-width="1.6" stroke-linecap="round"/>',
    "file": '<path d="M6.5 2.5h7.7L19 7.3V20a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 20V4a1.5 1.5 0 0 1 1.5-1.5z" fill="url(#gDoc)" stroke="#8a95a8" stroke-width=".8"/>'
            '<path d="M14 2.7v4.8h4.8" fill="#d5dce7" stroke="#8a95a8" stroke-width=".8" stroke-linejoin="round"/>',
    "drive": '<rect x="1.5" y="4.5" width="21" height="15" rx="3" fill="url(#gDrv)" stroke="#5f6773" stroke-width=".7"/>'
             '<rect x="3.4" y="13" width="17.2" height="4.2" rx="1.5" fill="#2a2e35"/>'
             '<path d="M5.2 15.1h8" stroke="#6f7784" stroke-width="1" stroke-linecap="round"/>'
             '<circle cx="18.2" cy="15.1" r="1.15" fill="url(#gLed)"/>'
             '<path d="M4.5 5.1h15a2.4 2.4 0 0 1 2.4 2.4v2.4c-6.6 1.4-13.3 1.4-19.8 0V7.5a2.4 2.4 0 0 1 2.4-2.4z" fill="#fff" opacity=".6"/>',
    "gear": '<circle cx="12" cy="12" r="8.2" fill="none" stroke="url(#gGear)" stroke-width="3.4" stroke-dasharray="3.2 3.24"/>'
            '<circle cx="12" cy="12" r="6.6" fill="url(#gGear)" stroke="#6b7482" stroke-width=".6"/>'
            '<circle cx="12" cy="12" r="2.7" fill="#39404b"/>'
            '<path d="M7 9.6a5.6 5.6 0 0 1 10 0c-3.2.9-6.8.9-10 0z" fill="#fff" opacity=".55"/>',
}

# Line icons for controls (they take the text colour).
_ICONS = {
    "download": '<path d="M12 4v11"/><path d="M7 10l5 5 5-5"/><path d="M5 20h14"/>',
    "upload": '<path d="M12 20V9"/><path d="M7 14l5-5 5 5"/><path d="M5 4h14"/>',
    "search": '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>',
    "settings": '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    "moon": '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
    "eye": '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "lock": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3"/>',
    "folder": '<path d="M3 7.5A1.5 1.5 0 0 1 4.5 6h4.3l2 2h8.7A1.5 1.5 0 0 1 21 9.5v8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z"/>',
    "archive": '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9"/><path d="M10 13h4"/>',
    "mark": '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8.5 12.5l2.5 2.5 5-6"/>',
    "check": '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    "x": '<path d="M6 6l12 12M18 6L6 18"/>',
    "back": '<path d="M15 5l-7 7 7 7"/>',
    "home": '<path d="M4 11l8-7 8 7"/><path d="M6 9.5V20h12V9.5"/><path d="M10 20v-5h4v5"/>',
    "hourglass": '<path d="M7 3h10M7 21h10"/><path d="M8 3c0 5 8 5 8 9s-8 4-8 9M16 3c0 5-8 5-8 9s8 4 8 9"/>',
    "cable": '<path d="M9 3h6v5H9z"/><path d="M10.5 3v2M13.5 3v2"/><path d="M7.5 8h9v3.5a3 3 0 0 1-3 3h-3a3 3 0 0 1-3-3z"/><path d="M12 14.5V21"/>',
    "gauge": '<path d="M4.5 17a8 8 0 1 1 15 0"/><path d="M12 14l4.5-5"/><circle cx="12" cy="14.5" r="1.3"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.01"/>',
    "warn": '<path d="M12 3.5l9.5 16.5h-19z"/><path d="M12 10v4.5M12 17.5v.01"/>',
    "question": '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1 .9-1 1.7M12 16.8v.01"/>',
    "menu": '<path d="M4 7h16M4 12h16M4 17h16"/>',
    "power": '<path d="M12 3v8"/><path d="M6.3 6.8a8 8 0 1 0 11.4 0"/>',
    "palette": '<path d="M12 3a9 9 0 1 0 0 18c1.1 0 1.6-.7 1.6-1.5 0-1.2-1-1.4-1-2.6 0-.9.7-1.4 1.7-1.4H17a4 4 0 0 0 4-4c0-4.7-4-8.5-9-8.5z"/>'
               '<circle cx="7.5" cy="11.5" r="1"/><circle cx="10" cy="7.5" r="1"/><circle cx="14.5" cy="7.5" r="1"/>',
    "shield": '<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6z"/>',
    "drive": '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M5 13l2.5-8h9L19 13"/><path d="M7 16.5h.01M10 16.5h.01"/>',
}
SPRITE = ('<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false"><defs>' + _GRADIENTS
          + "".join(f'<symbol id="f-{k}" viewBox="0 0 24 24">{v}</symbol>' for k, v in _FILE_ICONS.items())
          + "".join(f'<symbol id="i-{k}" viewBox="0 0 24 24">{v}</symbol>' for k, v in _ICONS.items())
          + "</defs></svg>")

FAVICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs>'
           '<radialGradient id="g" cx="50%" cy="100%" r="95%"><stop offset="0" stop-color="#ff79c0"/>'
           '<stop offset=".5" stop-color="#e20074"/><stop offset="1" stop-color="#52002b"/></radialGradient>'
           '<linearGradient id="h" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".9"/>'
           '<stop offset="1" stop-color="#fff" stop-opacity=".05"/></linearGradient></defs>'
           '<circle cx="32" cy="32" r="30" fill="url(#g)"/><ellipse cx="32" cy="19" rx="19" ry="12" fill="url(#h)"/></svg>')

JS = r"""(() => {
"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = s => String(s).replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const fmt = n => { if (n == null) return ""; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return (i ? n.toFixed(1) : Math.round(n)) + " " + u[i]; };
const left = s => !isFinite(s) || s <= 0 ? "" : s < 60 ? Math.ceil(s) + " s left" : s < 5400 ? Math.round(s / 60) + " min left" : (s / 3600).toFixed(1) + " h left";
const mbs = r => (r / 1048576 >= 100 ? Math.round(r / 1048576) : (r / 1048576).toFixed(1));
const svg = (id, cls) => '<svg class="' + (cls || "ic") + '" aria-hidden="true"><use href="#' + id + '"/></svg>';
const body = document.body, root = document.documentElement, D = body.dataset, PAGE = D.page || "";
const store = {
  get(k) { try { return sessionStorage.getItem(k); } catch (_) { return null; } },
  set(k, v) { try { sessionStorage.setItem(k, v); } catch (_) {} },
  del(k) { try { sessionStorage.removeItem(k); } catch (_) {} }
};
const rid = () => Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, "0")).join("");

/* ---- pop-up messages ---- */
const toastEl = $("#toast"); let toastTimer = 0;
function toast(msg, err) {
  if (!toastEl) return;
  toastEl.innerHTML = svg(err ? "i-warn" : "i-check") + "<span></span>";
  toastEl.lastChild.textContent = msg;
  toastEl.className = "toast on" + (err ? " err" : "");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { toastEl.className = "toast"; }, err ? 7000 : 3200);
}
const dlg = $("#dlg");
function ask(msg, o) {
  o = o || {};
  if (!dlg || typeof dlg.showModal !== "function") return Promise.resolve(o.no === null ? (alert(msg), true) : confirm(msg));
  $("#dlgTitle").textContent = o.title || "Please confirm";
  $("#dlgMsg").textContent = msg;
  $("#dlgIcon").innerHTML = '<use href="#i-' + (o.icon || "question") + '"/>';
  const y = $("#dlgYes"), n = $("#dlgNo");
  y.textContent = o.yes || "Yes";
  n.textContent = o.no || "No"; n.hidden = o.no === null;
  return new Promise(res => {
    const done = v => { if (dlg.open) dlg.close(); res(v); };
    y.onclick = () => done(true); n.onclick = () => done(false);
    dlg.oncancel = e => { e.preventDefault(); done(false); };
    dlg.showModal(); (o.focusNo ? n : y).focus();
  });
}

/* ---- theme and colour (remembered per browser) ---- */
const cookie = (k, v) => { document.cookie = k + "=" + v + "; path=/; max-age=31536000; samesite=lax"; };
function setTheme(t) { root.dataset.theme = t; cookie("beam_theme", t); $$("input[data-set-theme]").forEach(r => { r.checked = r.value === t; }); }
function setAccent(a) { root.dataset.accent = a; cookie("beam_accent", a); $$("input[data-set-accent]").forEach(r => { r.checked = r.value === a; }); }
const effTheme = () => root.dataset.theme === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : root.dataset.theme;
const flipTheme = () => setTheme(effTheme() === "dark" ? "light" : "dark");
const tt = $("#themeToggle"); if (tt) tt.addEventListener("click", flipTheme);
$$("input[data-set-theme]").forEach(r => r.addEventListener("change", () => { if (r.checked) setTheme(r.value); }));
$$("input[data-set-accent]").forEach(r => r.addEventListener("change", () => { if (r.checked) setAccent(r.value); }));

$$("form[data-confirm]").forEach(f => f.addEventListener("submit", e => {
  e.preventDefault();
  ask(f.dataset.confirm, { title: f.dataset.title || "Please confirm", icon: "warn", focusNo: true }).then(ok => { if (ok) f.submit(); });
}));
$$("[data-copy]").forEach(b => b.addEventListener("click", async () => {
  const t = b.dataset.copy;
  try { await navigator.clipboard.writeText(t); }
  catch (_) {
    const a = document.createElement("textarea"); a.value = t; a.style.position = "fixed"; a.style.opacity = "0";
    body.appendChild(a); a.select(); try { document.execCommand("copy"); } catch (__) {} a.remove();
  }
  toast("Copied " + t);
}));
const q = $("#q");
const focusSearch = () => { if (q) { q.focus(); q.select(); } else location.href = "/"; };

/* ---- status bar: signal (really the round trip to Beam), clock, battery, indexing ---- */
const sig = $("#sig"), clock = $("#clock"), bat = $("#bat"), sbIdx = $("#sbIdx"), idxText = $("#idx");
function tick() {
  if (!clock) return;
  const d = new Date();
  clock.textContent = String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
  setTimeout(tick, 60050 - Date.now() % 60000);
}
tick();
if (bat && navigator.getBattery) navigator.getBattery().then(b => {
  const upd = () => { bat.style.setProperty("--lvl", b.level); bat.classList.toggle("low", b.level < 0.15 && !b.charging); bat.title = Math.round(b.level * 100) + "%" + (b.charging ? ", charging" : ""); bat.hidden = false; };
  upd(); b.addEventListener("levelchange", upd); b.addEventListener("chargingchange", upd);
}).catch(() => {});
let building = D.indexing === "1", offline = false, pingTimer = 0;
const rtts = [];
function setBars(n, label) { if (!sig) return; sig.dataset.bars = n; sig.setAttribute("aria-label", label); sig.title = label; }
function showIndex(d) {
  building = d.state === "building";
  if (sbIdx) sbIdx.hidden = !building;
  if (idxText) idxText.textContent = building ? "Indexing… " + d.count.toLocaleString() + " items so far" : d.count.toLocaleString() + " items indexed";
}
async function ping() {
  const t0 = performance.now();
  try {
    const r = await fetch("/api/status", { cache: "no-store" });
    if (r.status === 401) { location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search); return; }
    const d = await r.json();
    rtts.push(performance.now() - t0); if (rtts.length > 3) rtts.shift();
    const ms = rtts.slice().sort((a, b) => a - b)[rtts.length >> 1];
    setBars(ms <= 8 ? 5 : ms <= 20 ? 4 : ms <= 45 ? 3 : ms <= 100 ? 2 : 1, "Connected to " + (D.host || "Beam") + ", " + (ms < 10 ? ms.toFixed(1) : Math.round(ms)) + " ms");
    if (offline) { offline = false; toast("Back in touch with Beam"); }
    showIndex(d);
  } catch (_) {
    setBars(0, "Can't reach Beam");
    if (!offline) { offline = true; toast("Can't reach Beam on " + (D.host || "the other PC") + ". Is it still running?", true); }
  }
}
function schedulePing(ms) {
  clearTimeout(pingTimer);
  pingTimer = setTimeout(async () => { if (!document.hidden) await ping(); schedulePing(building ? 2500 : offline ? 5000 : 20000); }, ms);
}
if (PAGE !== "login" && PAGE !== "stopped") {
  schedulePing(400);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) schedulePing(50); });
}

/* ---- soft keys and the Options menu ---- */
const menu = $("#menu"), skL = $("#skLeft"), skC = $("#skCenter"), skR = $("#skRight");
const NAV = ".row .nm, a.tile";
let current = null;
const menuItems = () => $$("[role=menuitem]", menu).filter(x => !x.hidden);
function openMenu() {
  if (!menu) return;
  menu.hidden = false; skL.setAttribute("aria-expanded", "true");
  const it = menuItems(); if (it[0]) it[0].focus();
}
function closeMenu(back) {
  if (!menu || menu.hidden) return;
  menu.hidden = true; skL.setAttribute("aria-expanded", "false");
  if (back) skL.focus();
}
if (skL && menu) {
  skL.addEventListener("click", e => { e.stopPropagation(); if (menu.hidden) openMenu(); else closeMenu(true); });
  menu.addEventListener("keydown", e => {
    const it = menuItems(), i = it.indexOf(document.activeElement);
    const go = j => { e.preventDefault(); if (it.length) it[(j + it.length) % it.length].focus(); };
    if (e.key === "ArrowDown") go(i + 1);
    else if (e.key === "ArrowUp") go(i - 1);
    else if (e.key === "Home") go(0);
    else if (e.key === "End") go(it.length - 1);
    else if (e.key === "Escape") { e.preventDefault(); closeMenu(true); }
    else if (e.key === "Tab") closeMenu(false);
  });
  menu.addEventListener("click", e => {
    const b = e.target.closest("[data-act]");
    closeMenu(false);
    if (b) { e.preventDefault(); act(b.dataset.act); }
  });
  document.addEventListener("click", e => { if (!e.target.closest("#menu, #skLeft")) closeMenu(false); });
}
if (skC) skC.addEventListener("click", () => act(skC.dataset.act || "select"));
if (skR) skR.addEventListener("click", e => { if (marking) { e.preventDefault(); exitMark(); } });
const cap = $("#cap");
function setCurrent(it) { current = it; if (cap && it.dataset.cap) cap.textContent = it.dataset.cap; }
document.addEventListener("focusin", e => { const it = e.target.closest && e.target.closest(NAV); if (it) setCurrent(it); });
document.addEventListener("mouseover", e => { const it = e.target.closest && e.target.closest(NAV); if (it) setCurrent(it); });

function act(a) {
  switch (a) {
    case "select": return select();
    case "search": return focusSearch();
    case "theme": return flipTheme();
    case "home": location.href = "/"; return;
    case "upfiles": { const p = $("#picker"); if (p) p.click(); return; }
    case "upfolder": { const p = $("#fpicker"); if (p) p.click(); return; }
    case "mark": return enterMark();
    case "mark-off": return exitMark();
    case "mark-all": $$(".row[data-kind]").forEach(r => toggleRow(r, true)); return;
    case "mark-none": $$(".row[data-kind]").forEach(r => toggleRow(r, false)); return;
    case "dl-marked": return downloadMarked(false);
    case "zip-marked": return downloadMarked(true);
    case "dl-all": return downloadAll();
    case "speedtest": if (spBtn) { spBtn.scrollIntoView({ block: "center" }); runSpeed(); } else location.href = "/settings?t=net#speed"; return;
    case "cable": return cableOffer ? switchTo(cableOffer) : (location.href = "/settings?t=net");
    case "submit": { const f = $("form[data-softkey]"); if (f) f.requestSubmit ? f.requestSubmit() : f.submit(); return; }
  }
}
function select() {
  if (marking) { const r = current && current.closest(".row"); if (r) toggleRow(r); return; }
  const items = $$(NAV);
  const it = current && document.contains(current) ? current : items[0];
  if (!it) return;
  if (document.activeElement !== it) { it.focus(); it.scrollIntoView({ block: "nearest" }); } else it.click();
}

/* ---- joystick: arrow keys move the highlight, Enter opens, Backspace goes back ---- */
function columns(items) {
  const top = items[0].getBoundingClientRect().top; let c = 0;
  for (const it of items) { if (Math.abs(it.getBoundingClientRect().top - top) > 4) break; c++; }
  return Math.max(1, c);
}
document.addEventListener("keydown", e => {
  if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey || (dlg && dlg.open)) return;
  const t = e.target;
  const typing = t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) && !/^(checkbox|radio)$/.test(t.type || "");
  if (e.key === "/" && !typing) { e.preventDefault(); focusSearch(); return; }
  if (typing || (menu && !menu.hidden)) return;
  if (e.key === "Escape" && marking) { exitMark(); return; }
  if (e.key === "Backspace") {
    if (marking) { e.preventDefault(); exitMark(); }
    else if (skR && skR.getAttribute("href")) { e.preventDefault(); skR.click(); }
    return;
  }
  const items = $$(NAV);
  if (!items.length) return;
  const i = t && t.closest ? items.indexOf(t.closest(NAV)) : -1;
  const grid = items[0].classList.contains("tile"), cols = grid ? columns(items) : 1;
  let j = -1;
  switch (e.key) {
    case "ArrowDown": j = i < 0 ? 0 : Math.min(items.length - 1, i + cols); break;
    case "ArrowUp": j = i < 0 ? 0 : Math.max(0, i - cols); break;
    case "ArrowRight":
      if (grid) j = i < 0 ? 0 : Math.min(items.length - 1, i + 1);
      else if (i >= 0 && !marking && items[i].closest(".row.dir")) { e.preventDefault(); items[i].click(); return; }
      break;
    case "ArrowLeft":
      if (grid) j = i < 0 ? 0 : Math.max(0, i - 1);
      else if (i >= 0 && skR && skR.getAttribute("href")) { e.preventDefault(); skR.click(); return; }
      break;
    case "Home": j = 0; break;
    case "End": j = items.length - 1; break;
    case "PageDown": j = i < 0 ? 0 : Math.min(items.length - 1, i + 10); break;
    case "PageUp": j = i < 0 ? 0 : Math.max(0, i - 10); break;
    case " ": if (marking && i >= 0) { e.preventDefault(); toggleRow(items[i].closest(".row")); } return;
    default: return;
  }
  if (j >= 0) { e.preventDefault(); items[j].focus(); items[j].scrollIntoView({ block: "nearest" }); }
});

/* ---- live search ---- */
const live = $("#live");
if (q && live) {
  let timer = 0, ctl = null, sel = -1;
  const hide = () => { live.hidden = true; sel = -1; q.setAttribute("aria-expanded", "false"); };
  const render = (d, v) => {
    let h = "";
    if (!d.results.length) {
      h = d.indexing ? '<div class="hint">Still indexing your drives (' + d.count.toLocaleString() + " items so far)…</div>"
                     : '<div class="hint">No matches for “' + esc(v) + "”. Try fewer words.</div>";
    } else {
      if (d.closest) h += '<div class="hint">No exact match. Closest results:</div>';
      for (const r of d.results) {
        h += '<a role="option" href="' + esc(r.url) + '"' + (r.kind === "f" ? " download" : "") + ">" + svg("f-" + r.icon, "fi") +
             '<span class="t"><span class="n">' + esc(r.name) + "</span><small>" + esc(r.where) + "</small></span></a>";
      }
      h += '<a class="more" href="/search?q=' + encodeURIComponent(v) + '">See all ' + d.total.toLocaleString() + " result" + (d.total === 1 ? "" : "s") + "</a>";
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
  q.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(run, 120); });
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
}

/* ---- drag a file out of the page onto the desktop (Chrome and Edge) ---- */
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

/* ---- the transfers box ---- */
const xfer = $("#xfer");
const X = {
  show(k) { if (!xfer) return; xfer.hidden = false; $("#x" + k).hidden = false; },
  hide(k) { if (!xfer) return; $("#x" + k).hidden = true; if ($("#xup").hidden && $("#xdown").hidden) xfer.hidden = true; },
  paint(k, o) {
    $("#x" + k + "T").textContent = o.title;
    $("#x" + k + "N").textContent = o.name || "";
    const pct = o.total ? Math.min(100, o.done / o.total * 100) : (o.finished ? 100 : 0);
    $("#x" + k + "B").style.width = pct.toFixed(1) + "%";
    $("#x" + k + "S").textContent = o.stats;
  }
};

/* ---- uploads: drop files or folders anywhere, or use the buttons; three at a time ---- */
// Hidden and system files are skipped (Beam refuses them anyway).
const BLOCKED = /^(\.|desktop\.ini$|thumbs\.db$|ehthumbs\.db$|autorun\.inf$)|\.(lnk|url|scf|library-ms|searchconnector-ms)$/i;
const blocked = path => path.split("/").some(p => BLOCKED.test(p));
const up = { queue: [], active: new Set(), done: 0, failed: 0, skipped: 0, cancelled: false, bytesDone: 0, bytesTotal: 0, rate: 0, lastT: 0, lastB: 0 };
const upBase = D.upload;
if (upBase) {
  const drop = $("#drop");
  $("#dropName").textContent = D.folder || "this folder";
  let depth = 0;
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
  const MAXUP = 3;
  function paint() {
    const now = performance.now();
    if (now - up.lastT >= 700) {
      if (up.lastT) { const r = (up.bytesDone - up.lastB) / ((now - up.lastT) / 1000); up.rate = up.rate ? up.rate * 0.6 + r * 0.4 : r; }
      up.lastT = now; up.lastB = up.bytesDone;
    }
    const names = Array.from(up.active, x => x.item.path);
    const pending = up.queue.length + up.active.size;
    let s = Math.floor(up.bytesTotal ? up.bytesDone / up.bytesTotal * 100 : 100) + "% · " + fmt(up.bytesDone) + " of " + fmt(up.bytesTotal);
    if (up.rate > 0) s += " · " + fmt(up.rate) + "/s · " + left((up.bytesTotal - up.bytesDone) / up.rate);
    X.paint("up", { title: "Sending " + pending + " file" + (pending === 1 ? "" : "s") + " to " + (D.folder || "Beam"), name: names.join(", "), done: up.bytesDone, total: up.bytesTotal, stats: s });
  }
  function finish() {
    const bits = [];
    if (up.done) bits.push(up.done + " uploaded");
    if (up.failed) bits.push(up.failed + " failed");
    if (up.skipped) bits.push(up.skipped + " hidden/system skipped");
    if (up.cancelled) bits.push("cancelled");
    X.paint("up", { title: "Sending finished", name: "", done: 1, total: 1, stats: bits.join(" · ") || "Nothing uploaded" });
    if (up.done) {
      toast(up.done + " file" + (up.done === 1 ? "" : "s") + " uploaded");
      if (dq.busy()) toast(up.done + " file" + (up.done === 1 ? "" : "s") + " uploaded. Refresh to see them.");
      else setTimeout(() => location.reload(), 900);
    }
    setTimeout(() => X.hide("up"), 4000);
  }
  function pump() {
    while (up.active.size < MAXUP && up.queue.length) start(up.queue.shift());
    if (!up.active.size) finish(); else paint();
  }
  function start(item) {
    const xhr = new XMLHttpRequest(); let sent = 0;
    xhr.item = item; up.active.add(xhr);
    const settle = () => { up.bytesDone += item.file.size - sent; sent = item.file.size; up.active.delete(xhr); };
    xhr.open("PUT", upBase + "?path=" + encodeURIComponent(item.path) + "&mtime=" + (item.file.lastModified || ""));
    xhr.setRequestHeader("X-Beam", "1");
    xhr.upload.onprogress = ev => { up.bytesDone += ev.loaded - sent; sent = ev.loaded; paint(); };
    xhr.onload = () => {
      settle();
      if (xhr.status >= 200 && xhr.status < 300) up.done++;
      else {
        up.failed++;
        let m = ""; try { m = JSON.parse(xhr.responseText).error || ""; } catch (_) {}
        toast("Couldn't upload " + item.path + ": " + (m || "error " + xhr.status), true);
      }
      pump();
    };
    xhr.onerror = () => { settle(); up.failed++; toast("Upload of " + item.path + " failed. The connection dropped, the drive may be full, or uploads are switched off.", true); pump(); };
    xhr.onabort = () => { settle(); pump(); };
    xhr.send(item.file);
  }
  function enqueue(list) {
    const ok = list.filter(it => !blocked(it.path));
    const skipped = list.length - ok.length;
    if (!ok.length) { toast(list.length ? "Those are hidden or system files, which Beam doesn't accept." : "Nothing to upload. Empty folders are skipped.", true); return; }
    if (!up.active.size && !up.queue.length) Object.assign(up, { done: 0, failed: 0, skipped: 0, cancelled: false, bytesDone: 0, bytesTotal: 0, rate: 0, lastT: 0, lastB: 0 });
    up.skipped += skipped;
    for (const it of ok) { up.queue.push(it); up.bytesTotal += it.file.size; }
    X.show("up"); pump();
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
    if (!input) return;
    if (btn) btn.addEventListener("click", () => input.click());
    input.addEventListener("change", () => {
      enqueue(Array.from(input.files).map(f => ({ file: f, path: f.webkitRelativePath || f.name })));
      input.value = "";
    });
  };
  wire("#picker", "#upFiles");
  wire("#fpicker", "#upFolder");
  $("#xupStop").addEventListener("click", () => { up.cancelled = true; up.queue.length = 0; Array.from(up.active).forEach(x => x.abort()); if (!up.active.size) finish(); });
}

/* ---- Mark several, and the download queue ----
   Several downloads side by side fill a Wi-Fi link far better than one at a
   time. The page asks Beam how each one is going (browsers don't say) and
   keeps at most four connections busy, so browsing stays quick meanwhile.
   The queue survives moving to another folder in this tab. */
let marking = false, lastMarked = null;
const markbar = $("#markbar"), menuHTML = menu ? menu.innerHTML : "";
const skSaved = {};
function rowOf(el) { return el && el.closest ? el.closest(".row[data-kind]") : null; }
function toggleRow(row, on) {
  const c = row && $(".mk", row);
  if (!c) return;
  c.checked = on === undefined ? !c.checked : on;
  row.classList.toggle("marked", c.checked);
  lastMarked = row;
  updateMarkbar();
}
function marked() { return $$(".row.marked[data-kind]"); }
function updateMarkbar() {
  if (!markbar) return;
  const rows = marked();
  let bytes = 0, files = 0, dirs = 0;
  for (const r of rows) { if (r.dataset.kind === "d") dirs++; else { files++; bytes += +r.dataset.size || 0; } }
  const parts = [];
  if (files) parts.push(files + " file" + (files === 1 ? "" : "s") + " (" + fmt(bytes) + ")");
  if (dirs) parts.push(dirs + " folder" + (dirs === 1 ? "" : "s"));
  $("#markCount").textContent = rows.length ? parts.join(" + ") + " marked" : "Nothing marked yet";
  $$("[data-need-marks]").forEach(b => { b.disabled = !rows.length; });
}
function enterMark() {
  if (!$$(".row[data-kind]").length || marking) return;
  marking = true; body.classList.add("marking");
  if (skC) { skSaved.c = [skC.textContent, skC.dataset.act]; skC.textContent = "Mark"; skC.dataset.act = "select"; }
  if (skR) { skSaved.r = skR.textContent; skR.textContent = "Done"; skR.hidden = false; }
  if (menu) menu.innerHTML = $("#markMenu").innerHTML;
  updateMarkbar();
  const first = $(NAV); if (first) first.focus();
}
function exitMark() {
  if (!marking) return;
  marking = false; body.classList.remove("marking");
  $$(".row.marked").forEach(r => { r.classList.remove("marked"); const c = $(".mk", r); if (c) c.checked = false; });
  if (skC && skSaved.c) { skC.textContent = skSaved.c[0]; skC.dataset.act = skSaved.c[1] || "select"; }
  if (skR && skSaved.r !== undefined) { skR.textContent = skSaved.r; skR.hidden = !skR.getAttribute("href"); }
  if (menu) menu.innerHTML = menuHTML;
}
document.addEventListener("click", e => {
  if (!marking) return;
  const nm = e.target.closest(".row .nm");
  const row = rowOf(e.target);
  if (!row || e.target.closest(".mini")) return;
  if (e.target.classList.contains("mk")) {
    row.classList.toggle("marked", e.target.checked); lastMarked = row; updateMarkbar(); return;
  }
  if (nm || e.target.closest(".row")) {
    e.preventDefault();
    if (e.shiftKey && lastMarked && lastMarked !== row) {
      const all = $$(".row[data-kind]"), a = all.indexOf(lastMarked), b = all.indexOf(row);
      const on = $(".mk", lastMarked).checked;
      all.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(r => toggleRow(r, on));
    } else toggleRow(row);
  }
});
$$("[data-act]").forEach(b => { if (!b.closest("#menu") && b !== skC) b.addEventListener("click", e => { e.preventDefault(); act(b.dataset.act); }); });

const dq = {
  max: 4, batch: "", n: 0, items: [], timer: 0, lastT: 0, lastB: 0, rate: 0, started: 0,
  busy() { return this.items.some(it => it.st === "q" || it.st === "t" || it.st === "r"); },
  save() { if (this.items.length) store.set("beam_dq", JSON.stringify({ batch: this.batch, n: this.n, items: this.items, started: this.started })); else store.del("beam_dq"); },
  load() {
    try { const s = JSON.parse(store.get("beam_dq") || "null"); if (s && s.batch && Array.isArray(s.items)) Object.assign(this, s); } catch (_) {}
    if (this.items.length) { X.show("down"); this.poll(); }
  },
  add(list) {
    if (!this.busy()) { this.batch = rid(); this.n = 0; this.items = []; this.started = Date.now(); this.rate = 0; this.lastT = 0; }
    for (const x of list) this.items.push({ id: this.n++, url: x.url, name: x.name, size: x.size, post: x.post || null, st: "q", sent: 0, conns: 0 });
    this.save(); X.show("down"); this.pump(); this.paint(); this.poll();
  },
  active() { const now = Date.now(); return this.items.reduce((n, it) => n + (it.st === "r" ? Math.max(1, it.conns) : it.st === "t" && now - it.t < 20000 ? 1 : 0), 0); },
  trigger(it) {
    const url = it.url + (it.url.indexOf("?") < 0 ? "?" : "&") + "tx=" + this.batch + "." + it.id;
    if (it.post) {
      const f = document.createElement("form");
      f.method = "post"; f.action = url; f.hidden = true;
      for (const [k, v] of it.post) { const i = document.createElement("input"); i.type = "hidden"; i.name = k; i.value = v; f.appendChild(i); }
      body.appendChild(f); f.submit(); setTimeout(() => f.remove(), 1000);
    } else {
      const a = document.createElement("a");
      a.href = url; a.download = it.name || ""; a.hidden = true;
      body.appendChild(a); a.click(); a.remove();
    }
    it.st = "t"; it.t = Date.now();
  },
  pump() {
    let busy = this.active();
    for (const it of this.items) {
      if (busy >= this.max) break;
      if (it.st === "q") { this.trigger(it); busy++; }
    }
    this.save();
  },
  async poll() {
    clearTimeout(this.timer);
    if (!this.items.length) return;
    try {
      const r = await fetch("/api/transfers?b=" + this.batch, { cache: "no-store" });
      if (r.ok) {
        const snap = (await r.json()).items || {};
        for (const it of this.items) {
          const s = snap[it.id];
          if (!s) continue;
          it.conns = s[0]; it.sent = s[1]; it.size = s[2];
          if (it.st === "t" || it.st === "r") it.st = s[3] === 0 ? "r" : s[3] === 1 ? "d" : "f";
        }
        for (const it of this.items) if (it.st === "t" && Date.now() - it.t > 60000) it.st = "f"; // the browser never started it
      }
    } catch (_) {}
    this.pump(); this.paint();
    if (this.busy()) this.timer = setTimeout(() => this.poll(), 700);
    else this.finish();
  },
  paint() {
    const n = this.items.length, done = this.items.filter(it => it.st === "d").length;
    const running = this.items.filter(it => it.st === "r" || it.st === "t");
    let bytes = 0, total = 0, known = true;
    for (const it of this.items) { if (it.size == null) known = false; else { total += it.size; bytes += Math.min(it.sent || 0, it.size); } }
    const now = performance.now();
    if (now - this.lastT >= 700) {
      if (this.lastT) { const r = Math.max(0, bytes - this.lastB) / ((now - this.lastT) / 1000); this.rate = this.rate ? this.rate * 0.6 + r * 0.4 : r; }
      this.lastT = now; this.lastB = bytes;
    }
    let s = done + " of " + n + " done · " + fmt(bytes) + (known ? " of " + fmt(total) : "");
    if (this.rate > 0 && running.length) s += " · " + fmt(this.rate) + "/s" + (known ? " · " + left((total - bytes) / this.rate) : "");
    X.paint("down", { title: running.length ? "Receiving " + running.length + " at once" : this.busy() ? "Waiting…" : "Receiving finished", name: running.map(it => it.name).join(", "), done: bytes, total: known ? total : 0, stats: s, finished: !this.busy() });
    const stuck = this.items.some(it => it.st === "t" && Date.now() - it.t > 8000);
    const note = $("#xdownNote");
    if (note) note.hidden = !stuck;
  },
  finish() {
    const ok = this.items.filter(it => it.st === "d").length, bad = this.items.filter(it => it.st === "f").length;
    if (this.items.length) toast(ok + " download" + (ok === 1 ? "" : "s") + " finished" + (bad ? ", " + bad + " interrupted (see your browser's downloads)" : ""), bad > 0);
    this.items = []; this.save();
    setTimeout(() => { if (!this.busy()) X.hide("down"); }, 5000);
  },
  stop() {
    let n = 0;
    for (const it of this.items) if (it.st === "q") { it.st = "x"; n++; }
    this.save(); this.paint();
    toast(n ? n + " queued download" + (n === 1 ? "" : "s") + " cancelled. Ones already started carry on in your browser." : "Downloads already started carry on in your browser.");
    if (!this.busy()) this.finish();
  }
};
if (xfer) { const s = $("#xdownStop"); if (s) s.addEventListener("click", () => dq.stop()); }
dq.load();
window.addEventListener("beforeunload", e => {
  if (up.active.size || up.queue.length) { e.preventDefault(); e.returnValue = ""; }
});
function itemsFromRows(rows) {
  return rows.map(r => ({ url: r.dataset.url, name: r.dataset.kind === "d" ? r.dataset.name + ".zip" : r.dataset.name, size: r.dataset.kind === "d" ? null : +r.dataset.size || 0 }));
}
function downloadMarked(asZip) {
  const rows = marked();
  if (!rows.length) { toast("Mark some items first", true); return; }
  if (asZip && D.zip) {
    const post = rows.map(r => ["pick", r.dataset.name]);
    dq.add([{ url: D.zip, name: (D.folder || "Beam") + ".zip", size: null, post }]);
  } else {
    dq.add(itemsFromRows(rows));
    if (rows.length > 1) toast("Downloading " + rows.length + " items, up to " + dq.max + " at a time. If your browser asks about multiple downloads, choose Allow.");
  }
  exitMark();
}
function downloadAll() {
  const rows = $$(".row[data-kind=f]");
  if (!rows.length) { toast("There are no files directly in this folder", true); return; }
  dq.add(itemsFromRows(rows));
  toast("Downloading " + rows.length + " files, up to " + dq.max + " at a time. If your browser asks about multiple downloads, choose Allow.");
}

/* ---- Settings tabs ---- */
const tabs = $$(".tabs [role=tab]");
if (tabs.length) {
  const show = (tab, remember) => {
    tabs.forEach(t => {
      const on = t === tab;
      t.setAttribute("aria-selected", on ? "true" : "false"); t.tabIndex = on ? 0 : -1;
      const p = document.getElementById(t.getAttribute("aria-controls")); if (p) p.hidden = !on;
    });
    if (remember) history.replaceState(null, "", "?t=" + tab.dataset.tab);
  };
  tabs.forEach((t, i) => {
    t.addEventListener("click", e => { e.preventDefault(); show(t, true); });
    t.addEventListener("keydown", e => {
      const j = e.key === "ArrowRight" ? i + 1 : e.key === "ArrowLeft" ? i - 1 : e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : null;
      if (j === null) return;
      e.preventDefault(); e.stopPropagation();
      const n = tabs[(j + tabs.length) % tabs.length]; show(n, true); n.focus();
    });
  });
}

/* ---- speed test (Settings > Connection) ---- */
const spBtn = $("#spRun");
async function rttOf(url, cross) {
  const samples = [];
  for (let i = 0; i < 5; i++) {
    const ctl = new AbortController(), tm = setTimeout(() => ctl.abort(), 1500), t0 = performance.now();
    try {
      await fetch(url + (url.indexOf("?") < 0 ? "?" : "&") + "r=" + Math.random(), cross ? { mode: "no-cors", credentials: "omit", cache: "no-store", signal: ctl.signal } : { cache: "no-store", signal: ctl.signal });
    } catch (_) { clearTimeout(tm); return null; }
    clearTimeout(tm);
    if (i) samples.push(performance.now() - t0); // the first includes connecting
  }
  samples.sort((a, b) => a - b);
  return samples[samples.length >> 1];
}
async function dlTest(streams, ms) {
  const ctl = new AbortController(), t0 = performance.now();
  let bytes = 0, mark = 0, tMark = 0;
  const one = async () => {
    const r = await fetch("/api/speedtest?bytes=4294967296", { cache: "no-store", signal: ctl.signal });
    if (!r.ok || !r.body) throw new Error("the test download was refused (" + r.status + ")");
    const rd = r.body.getReader();
    for (;;) {
      const { done, value } = await rd.read();
      if (done) break;
      bytes += value.byteLength;
      if (!tMark && performance.now() - t0 > 700) { tMark = performance.now(); mark = bytes; } // skip TCP's warm-up
    }
  };
  const timer = setTimeout(() => ctl.abort(), ms);
  try { await Promise.all(Array.from({ length: streams }, () => one().catch(e => { if (e.name !== "AbortError") throw e; }))); }
  finally { clearTimeout(timer); }
  const end = performance.now();
  return tMark && end > tMark ? (bytes - mark) / ((end - tMark) / 1000) : bytes / ((end - t0) / 1000);
}
async function ulTest() {
  let size = 8 * 1048576, rate = 0;
  for (let round = 0; round < 3; round++) {
    const t0 = performance.now();
    const r = await fetch("/api/speedtest", { method: "PUT", body: new Blob([new Uint8Array(size)]), headers: { "X-Beam": "1" }, cache: "no-store" });
    if (!r.ok) throw new Error("the test upload was refused (" + r.status + ")");
    await r.json();
    const secs = (performance.now() - t0) / 1000;
    rate = size / secs;
    if (secs > 1.5 || size >= 128 * 1048576) break;
    size = Math.min(128 * 1048576, Math.max(size * 2, Math.round(rate * 2.5)));
  }
  return rate;
}
async function runSpeed() {
  if (!spBtn || spBtn.disabled) return;
  spBtn.disabled = true;
  const note = $("#spNote");
  const gauge = (k, v, frac) => { const g = $("#sp" + k); if (!g) return; $("b", g).textContent = v; const m = $(".meter i", g); if (m) m.style.width = Math.max(0, Math.min(100, frac * 100)).toFixed(0) + "%"; };
  ["Ping", "One", "Many", "Up"].forEach(k => gauge(k, "…", 0));
  note.textContent = "Testing… keep this page open for about 15 seconds.";
  try {
    const p = await rttOf("/api/ping");
    if (p == null) throw new Error("Beam isn't answering");
    gauge("Ping", (p < 10 ? p.toFixed(1) : Math.round(p)) + " ms", Math.max(0.05, 1 - p / 60));
    const one = await dlTest(1, 4000); gauge("One", mbs(one) + " MB/s", one / 125e6);
    const many = await dlTest(4, 4000); gauge("Many", mbs(many) + " MB/s", many / 125e6);
    const upl = await ulTest(); gauge("Up", mbs(upl) + " MB/s", upl / 125e6);
    let t = "Downloads from " + (D.host || "the Beam PC") + " can reach about " + mbs(Math.max(one, many)) + " MB/s over this connection.";
    if (many > one * 1.2) t += " Several at once are clearly faster here, so use Mark several for batches.";
    t += " For comparison: wired gigabit manages about 110 MB/s, Wi-Fi 6 roughly 40–90, older Wi-Fi 5–30. If a real download is slower than this, the drive is the limit (USB 2.0 drives top out near 35 MB/s).";
    note.textContent = t;
  } catch (e) {
    note.textContent = "The test couldn't finish: " + (e.message || e) + ".";
  } finally { spBtn.disabled = false; }
}
if (spBtn) { spBtn.addEventListener("click", runSpeed); if (location.hash === "#speed" && PAGE === "settings") setTimeout(runSpeed, 400); }

/* ---- a faster route: is this PC reachable by cable as well? ---- */
let cableOffer = null;
const cableBtn = $("#sbCable");
async function switchTo(o) {
  try {
    const r = await fetch("/api/handoff", { cache: "no-store" });
    const d = await r.json();
    location.href = "http://" + o.ip + ":" + o.port + "/handoff?t=" + encodeURIComponent(d.token) + "&next=" + encodeURIComponent(location.pathname + location.search) +
      "&theme=" + encodeURIComponent(root.dataset.theme) + "&accent=" + encodeURIComponent(root.dataset.accent || "");
  } catch (_) { toast("Couldn't switch. Try opening http://" + o.ip + ":" + o.port + "/ yourself.", true); }
}
function offerCable(o, cur) {
  cableOffer = o;
  if (cableBtn) { cableBtn.hidden = false; cableBtn.title = "A wired connection to " + (D.host || "Beam") + " is available: switch to it"; }
  if (store.get("beam_cable_asked")) return;
  store.set("beam_cable_asked", "1");
  ask("This device can also reach " + (D.host || "the Beam PC") + " over a wired connection (" + o.ms.toFixed(1) + " ms against " + cur.toFixed(1) + " ms now), which is usually much faster. Switch to it?",
      { title: "Faster connection found", yes: "Switch", no: "Not now", icon: "cable" }).then(ok => { if (ok) switchTo(o); });
}
async function checkPaths() {
  let c = null;
  try { c = JSON.parse(store.get("beam_paths") || "null"); } catch (_) {}
  if (c && Date.now() - c.at < 300000 && c.origin === location.host) { if (c.offer) offerCable(c.offer, c.cur); return; }
  let info;
  try { const r = await fetch("/api/paths", { cache: "no-store" }); if (!r.ok) return; info = await r.json(); } catch (_) { return; }
  const save = (offer, cur) => store.set("beam_paths", JSON.stringify({ at: Date.now(), origin: location.host, offer, cur }));
  if (info.current && info.current.direct) { save(null, 0); return; }
  const cands = (info.others || []).slice(0, 4);
  if (!cands.length) { save(null, 0); return; }
  const cur = await rttOf("/api/ping");
  if (cur == null) return;
  let best = null;
  for (const o of cands) {
    const ms = await rttOf("http://" + o.ip + ":" + info.port + "/api/ping", true);
    if (ms != null && (!best || ms < best.ms)) best = Object.assign({}, o, { ms, port: info.port });
  }
  const offer = best && best.ms < cur * 0.6 && cur - best.ms > 0.4 ? best : null;
  save(offer, cur);
  if (offer) offerCable(offer, cur);
}
if (cableBtn) cableBtn.addEventListener("click", () => act("cable"));
if (D.paths === "1") setTimeout(checkPaths, 1500);
})();
"""


def _static_asset(name: str, text: str, ctype: str) -> str:
    """Serve a page asset from memory under a content-hashed name, so browsers
    can cache it for a year and still pick up a new version at once."""
    data = text.encode("utf-8")
    fname = f"{name}.{hashlib.sha256(data).hexdigest()[:12]}"
    STATIC[fname] = (data, gzip.compress(data, 9), ctype)
    return "/static/" + fname


STATIC = {}
CSS_URL = _static_asset("beam.css", CSS, "text/css; charset=utf-8")
JS_URL = _static_asset("beam.js", JS, "text/javascript; charset=utf-8")

BASE_HTML = """<!DOCTYPE html>
<html lang="en-GB" data-theme="%%THEME%%" data-accent="%%ACCENT%%">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<title>%%TITLE%% | Beam</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="%%CSSURL%%">
<script src="%%JSURL%%" defer></script>
</head>
<body%%BODYATTRS%%>
%%SPRITE%%
<div class="top">
<div class="sbar">
  <span class="sig" id="sig" data-bars="4" role="img" aria-label="Connection to %%HOST%%"><i></i><i></i><i></i><i></i><i></i></span>
  <span class="op" title="The PC running Beam">%%HOST%%</span>
  <span id="sbIdx" title="Indexing your drives"%%IDXHIDDEN%%><svg class="ic sb-ic spin" role="img" aria-label="Indexing"><use href="#i-hourglass"/></svg></span>
  %%LINKICON%%
  <button type="button" class="cable" id="sbCable" hidden><svg class="ic sb-ic" aria-hidden="true"><use href="#i-cable"/></svg>Cable</button>
  <span class="gap"></span>
  %%LOCKICON%%
  <time id="clock">%%TIME%%</time>
  <span class="bat" id="bat" role="img" aria-label="Battery" hidden><i></i></span>
</div>
<header class="tbar">
  <a class="brand" href="/" aria-label="Beam home"><span class="orb" aria-hidden="true"></span><span><b>Beam</b><small>LAN File Transfer</small></span></a>
  %%NAV%%
</header>
</div>
<main class="wrap" id="main">%%BODY%%</main>
%%SOFTKEYS%%
<div id="drop" class="drop" aria-hidden="true"><div><svg class="ic"><use href="#i-upload"/></svg><p>Drop to send to <b id="dropName"></b></p></div></div>
<section id="xfer" class="panel xfer" aria-live="polite" aria-label="Transfers" hidden>
<div class="xsec" id="xdown" hidden><h3><svg class="ic" aria-hidden="true"><use href="#i-download"/></svg><span id="xdownT">Receiving</span></h3>
<p id="xdownN"></p><div class="meter"><i id="xdownB"></i></div>
<div class="xrow"><span id="xdownS"></span><button type="button" class="btn ghost sm" id="xdownStop">Stop queue</button></div>
<p class="xnote" id="xdownNote" hidden>Waiting for your browser. If it asks whether Beam may download multiple files, choose Allow.</p></div>
<div class="xsec" id="xup" hidden><h3><svg class="ic" aria-hidden="true"><use href="#i-upload"/></svg><span id="xupT">Sending</span></h3>
<p id="xupN"></p><div class="meter"><i id="xupB"></i></div>
<div class="xrow"><span id="xupS"></span><button type="button" class="btn ghost sm" id="xupStop">Cancel</button></div></div>
</section>
<div id="toast" class="toast" role="status" aria-live="polite"></div>
<dialog id="dlg" class="dlg" aria-labelledby="dlgTitle">
<div class="strip"><span id="dlgTitle">Please confirm</span></div>
<div class="body"><svg class="ic" id="dlgIcon" aria-hidden="true"><use href="#i-question"/></svg><p id="dlgMsg"></p></div>
<div class="keys"><button type="button" class="btn ghost" id="dlgNo">No</button><button type="button" class="btn" id="dlgYes">Yes</button></div>
</dialog>
</body>
</html>"""

NAV_HTML = """<form class="search" action="/search" method="get" role="search">
    <svg class="ic" aria-hidden="true"><use href="#i-search"/></svg>
    <input id="q" type="search" name="q" value="%%QUERY%%" placeholder="Search every drive (typos are fine)" autocomplete="off" spellcheck="false" aria-label="Search files and folders" aria-controls="live" aria-expanded="false">
    <div id="live" class="live" role="listbox" aria-label="Search results" hidden></div>
  </form>
  <nav class="tools" aria-label="Quick settings">
    <button type="button" class="iconbtn" id="themeToggle" aria-label="Switch between dark and light" title="Switch theme"><svg class="ic sun" aria-hidden="true"><use href="#i-sun"/></svg><svg class="ic moon" aria-hidden="true"><use href="#i-moon"/></svg></button>
    <a class="iconbtn" href="/settings" aria-label="Settings" title="Settings"><svg class="ic" aria-hidden="true"><use href="#i-settings"/></svg></a>
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
    "private": "Windows is asking for permission on this PC. Once you approve it, the cable network becomes Private and Beam works over it.",
}
ERRORS = {
    "nopath": "That folder doesn't exist on this PC. Paste a full path, e.g. F:\\Films.",
    "dup": "That folder is already shared.",
    "pwshort": "Passwords need at least 6 characters.",
    "pwmatch": "The two passwords don't match.",
    "port": "The port must be a number between 1024 and 65535.",
    "perm": "Settings can only be changed on the PC running Beam, or from any device once a password is set.",
    "auto": "Couldn't change the startup setting. Details are in beam.log.",
    "private": "Couldn't ask Windows to change the network. Use the PowerShell command shown below instead.",
    "hostonly": "That can only be done on the PC running Beam itself.",
}
SETTINGS_TABS = (("drives", "Drives", "drive"), ("display", "Display", "palette"), ("net", "Connection", "cable"),
                 ("security", "Security", "shield"), ("system", "System", "power"))
ACTION_TAB = {"shares": "drives", "add": "drives", "prefs": "drives", "port": "net", "netprivate": "net",
              "password": "security", "nopassword": "security", "autostart": "system", "reindex": "system"}
ACCENT_COLOURS = {"magenta": "#e20074", "orange": "#ff7a00", "aqua": "#0a9ff5", "lime": "#6ec72d", "violet": "#8a3ffc"}


def icon(name: str, cls: str = "ic") -> str:
    return f'<svg class="{cls}" aria-hidden="true"><use href="#i-{name}"/></svg>'


def ficon(name: str, cls: str = "fi") -> str:
    return f'<svg class="{cls}" aria-hidden="true"><use href="#f-{name}"/></svg>'


def mini(url: str, ico: str, label: str, newtab: bool = False, download: bool = False) -> str:
    extra = (' target="_blank" rel="noopener"' if newtab else "") + (" download" if download else "")
    return f'<a class="mini" href="{esc(url)}" title="{esc(label)}" aria-label="{esc(label)}"{extra}>{icon(ico)}</a>'


def file_icon(name: str) -> str:
    e = ext_of(name)
    if e == "pdf":
        return "pdf"
    if e in ("txt", "log", "md", "srt", "vtt", "nfo", "csv", "json", "ini", "cfg", "doc", "docx", "odt", "rtf",
             "xls", "xlsx", "ppt", "pptx"):
        return "doc"
    return icon_for(name)


_MINI_ICONS = {k: icon(k) for k in ("folder", "archive", "eye", "download")}
_FILE_SVGS = {k: ficon(k) for k in _FILE_ICONS}


def row_html(kind, sid, rel, name, size, mtime, where=None, parent_url=None) -> str:
    """One line of a folder listing or search results. Folders can hold
    thousands of these, so each name is escaped once and icons are reused."""
    qrel = quote_path(rel)
    en = esc(name)
    acts = (f'<a class="mini" href="{esc(parent_url)}" title="Open the folder it\'s in">{_MINI_ICONS["folder"]}</a>'
            if parent_url else "")
    if kind == "d":
        href = eh = f"/b/{sid}/{esc(qrel)}"
        ez = f"/zip/{sid}/{esc(qrel)}"
        acts += f'<a class="mini" href="{ez}" title="Download {en} as a ZIP" download>{_MINI_ICONS["archive"]}</a>'
        head = f'<div class="row dir" data-kind="d" data-name="{en}" data-url="{ez}">'
        attrs, ico = "", _FILE_SVGS["folder"]
    else:
        href = eh = f"/dl/{sid}/{esc(qrel)}"
        ext = ext_of(name)
        ico = _FILE_SVGS[file_icon(name)]
        mime = INLINE_MIME.get(ext, "application/octet-stream").split(";")[0]
        attrs = f' draggable="true" download data-dl="{eh}" data-name="{en}" data-mime="{mime}"'
        if ext in INLINE_MIME:
            acts += (f'<a class="mini" href="{eh}?view=1" title="Open {en} in the browser" target="_blank" '
                     f'rel="noopener">{_MINI_ICONS["eye"]}</a>')
        acts += f'<a class="mini" href="{eh}" title="Download {en}" download>{_MINI_ICONS["download"]}</a>'
        head = f'<div class="row" data-kind="f" data-name="{en}" data-url="{eh}" data-size="{int(size or 0)}">'
    where_html = f"<small>{esc(where)}</small>" if where else ""
    return (f'{head}<span class="c1"><input type="checkbox" class="mk" tabindex="-1" aria-label="Mark {en}">'
            f'<a class="nm" href="{href}"{attrs}>{ico}<span class="t"><span class="n">{en}</span>{where_html}</span></a></span>'
            f'<span class="num c-size">{human_size(size) if kind == "f" else ""}</span>'
            f'<span class="num c-date">{fmt_time(mtime)}</span><span class="ra">{acts}</span></div>')


def entry_where(entry, share) -> str:
    rel = entry[2]
    parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
    return share["name"] + (" › " + parent.replace("/", " › ") if parent else "")


def entry_url(entry) -> str:
    kind, sid, rel = entry[0], entry[1], entry[2]
    return f"/{'b' if kind == 'd' else 'dl'}/{sid}/{quote_path(rel)}"


def menu_item(label: str, ico: str, href: str = None, act: str = None) -> str:
    if href:
        return f'<a role="menuitem" tabindex="-1" href="{esc(href)}">{icon(ico)}{esc(label)}</a>'
    return f'<button type="button" role="menuitem" tabindex="-1" data-act="{esc(act)}">{icon(ico)}{esc(label)}</button>'


def softkeys(items=(), center=("Select", "select"), back=None, mark_menu="") -> str:
    """The phone-style key bar: Options (left), the centre key, Back (right)."""
    left = ('<button type="button" class="sk sk-l" id="skLeft" aria-haspopup="menu" aria-expanded="false" '
            'aria-controls="menu">Options</button>') if items else '<span></span>'
    mid = (f'<button type="button" class="sk sk-c" id="skCenter" data-act="{esc(center[1])}">{esc(center[0])}</button>'
           if center else '<span></span>')
    right = (f'<a class="sk sk-r" id="skRight" href="{esc(back)}">Back</a>' if back
             else '<a class="sk sk-r" id="skRight" hidden>Back</a>')
    menu = ""
    if items:
        body = "".join('<hr role="separator">' if it == "-" else menu_item(*it) for it in items)
        menu = f'<div id="menu" class="menu" role="menu" aria-label="Options" hidden><div class="strip">Options</div>{body}</div>'
    tpl = f'<template id="markMenu">{mark_menu}</template>' if mark_menu else ""
    return f'<nav class="skeys" aria-label="Soft keys">{left}{mid}{right}</nav>{menu}{tpl}'


def mark_menu(zip_ok: bool) -> str:
    items = [("Download marked", "download", None, "dl-marked")]
    if zip_ok:
        items.append(("Download marked as one ZIP", "archive", None, "zip-marked"))
    items += [("Mark all", "mark", None, "mark-all"), ("Unmark all", "x", None, "mark-none"), "-",
              ("Stop marking", "back", None, "mark-off")]
    return '<div class="strip">Marking</div>' + "".join(
        '<hr role="separator">' if it == "-" else menu_item(*it) for it in items)


def markbar(zip_ok: bool) -> str:
    return ('<div class="markbar" id="markbar"><b id="markCount">Nothing marked yet</b><span class="grow"></span>'
            f'<button type="button" class="btn" data-act="dl-marked" data-need-marks disabled>{icon("download")}Download</button>'
            + (f'<button type="button" class="btn ghost" data-act="zip-marked" data-need-marks disabled>{icon("archive")}As one ZIP</button>'
               if zip_ok else "")
            + '<button type="button" class="btn ghost sm" data-act="mark-all">Mark all</button>'
              '<button type="button" class="btn ghost sm" data-act="mark-off">Done</button></div>')


def link_speed(bps: int) -> str:
    if not bps:
        return ""
    return f"{bps / 1e9:g} Gb/s" if bps >= 1e9 else f"{bps / 1e6:g} Mb/s"


def make_network_private(if_index: int) -> bool:
    """Ask Windows, via its administrator prompt on this PC, to treat one
    network as Private so the firewall lets Beam answer on it."""
    import ctypes
    shell = ctypes.windll.shell32
    shell.ShellExecuteW.restype = ctypes.c_ssize_t
    params = ("-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "
              f'"Set-NetConnectionProfile -InterfaceIndex {int(if_index)} -NetworkCategory Private"')
    return shell.ShellExecuteW(None, "runas", "powershell.exe", params, None, 0) > 32


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"{APP}/{VERSION}"
    sys_version = ""
    protocol_version = "HTTP/1.1"    # keep-alive: no new connection (and handshake) for every request
    disable_nagle_algorithm = True   # small replies go out at once instead of waiting up to 200 ms
    timeout = IO_TIMEOUT

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.client_address[0], fmt % args)

    def send_response(self, code, message=None):
        self._started = True
        super().send_response(code, message)

    def send_header(self, keyword, value):
        # Header values can't carry line breaks (response splitting) or non-Latin-1 text.
        value = str(value).replace("\r", " ").replace("\n", " ")
        super().send_header(keyword, value.encode("latin-1", "replace").decode("latin-1"))

    def handle_one_request(self):
        try:  # an idle keep-alive connection is only kept for KEEPALIVE_IDLE seconds
            self.connection.settimeout(KEEPALIVE_IDLE)
        except OSError:
            self.close_connection = True
            return
        super().handle_one_request()

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
        self._body_left = 0
        try:
            self.connection.settimeout(self.timeout)
        except OSError:
            self.close_connection = True
            return
        if self.request_version != "HTTP/1.1":
            self.close_connection = True
        try:
            self._body_left = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._body_left = -1
        if self.headers.get("Transfer-Encoding") or self._body_left < 0:
            self._body_left = 0
            self.close_connection = True
            return self.send_bytes(411, b"Beam needs a Content-Length.", "text/plain; charset=utf-8", page=False)
        try:
            self._route(method)
        except (ConnectionError, TimeoutError, socket.timeout):
            self.close_connection = True  # the browser went away mid-transfer; nothing to do
        except Exception:
            self.close_connection = True
            log.exception("Error handling %s %s", method, self.path)
            if not self._started:
                try:
                    self.error_page(500, "Something went wrong",
                                    "Beam hit an unexpected error. Details are in beam.log on the PC running Beam.")
                except Exception:
                    pass
        if self._body_left:
            self.close_connection = True  # an unread request body can't be skipped safely

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
            return self.send_bytes(200, FAVICON.encode(), "image/svg+xml", page=False, cache="public, max-age=86400")
        if head == "static" and method in ("GET", "HEAD"):
            return self.static(sub)
        if head == "api" and sub == "ping" and method in ("GET", "HEAD"):
            # Lets a page check whether this PC also answers on another (wired) address.
            return self.begin(204, cache="no-store")
        if head == "handoff" and method == "GET":
            return self.handoff()
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
            return self.send_bytes(405, b"", "text/plain", page=False)
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
            if head == "api":
                if sub == "search":
                    return self.api_search()
                if sub == "status":
                    return self.send_json(index.status())
                if sub == "transfers":
                    b = self.q("b")
                    return self.send_json({"items": transfers.snapshot(b) if re.fullmatch(r"[A-Za-z0-9]{8,32}", b) else {}})
                if sub == "paths":
                    return self.api_paths()
                if sub == "handoff":
                    return self.send_json({"token": make_handoff()})
                if sub == "speedtest":
                    return self.speedtest_down()
        elif method == "POST":
            if head == "settings":
                return self.settings_submit()
            if head == "zip":
                return self.zip_marked(sub, rest)
            if head == "logout":
                return self.redirect("/login", [("Set-Cookie", CLEAR_SESSION)])
        elif method == "PUT":
            if head == "api" and sub == "upload" and len(parts) >= 3:
                return self.api_upload(parts[2], "/".join(parts[3:]))
            if head == "api" and sub == "speedtest":
                return self.speedtest_up()
        return self.error_page(404, "Not found", "There's nothing at that address.")

    # ---- request helpers ---------------------------------------------------
    def q(self, key, default=""):
        return (self.query.get(key) or [default])[0]

    def client_ip(self) -> str:
        return norm_ip(self.client_address[0])

    def local_ip(self) -> str:
        try:
            return norm_ip(self.connection.getsockname()[0])
        except OSError:
            return ""

    def is_host_machine(self) -> bool:
        ip = self.client_ip()
        try:
            if ipaddress.ip_address(ip).is_loopback:
                return True
        except ValueError:
            return False
        # A connection whose two ends share an address can only come from this PC.
        return ip == self.local_ip() or ip in local_ips()

    def cookies(self) -> dict:
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return {}
        return {k: v.value for k, v in jar.items()}

    def theme(self) -> str:
        t = self.cookies().get("beam_theme", "")
        return t if t in THEMES else "dark"

    def accent(self) -> str:
        a = self.cookies().get("beam_accent", "")
        return a if a in ACCENTS else ACCENTS[0]

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

    def accepts_gzip(self) -> bool:
        for part in self.headers.get("Accept-Encoding", "").lower().split(","):
            name, _, params = part.strip().partition(";")
            if name.strip() == "gzip":
                m = re.search(r"q\s*=\s*([0-9.]+)", params)
                try:
                    return not m or float(m.group(1)) > 0
                except ValueError:
                    return False
        return False

    def read_form(self, limit=MAX_FORM_BYTES):
        n = self._body_left
        if n > limit:
            return None  # left unread: the connection is closed afterwards
        data = self.rfile.read(n) if n else b""
        self._body_left -= len(data)
        return urllib.parse.parse_qs(data.decode("utf-8", "replace"), keep_blank_values=True)

    # ---- response helpers --------------------------------------------------
    def page_csp(self) -> str:
        # Allow the page to check this PC's other addresses for a faster route.
        port, here = self.server.server_port, self.local_ip()
        alt = sorted({ip for iface in netinfo.cached() for ip in iface["ips"]
                      if ip != here and ":" not in ip and not ip.startswith("127.")})[:8]
        return PAGE_CSP % "".join(f" http://{ip}:{port}" for ip in alt)

    def begin(self, code, ctype=None, length=None, headers=(), page=False, cache=None):
        """Status line and headers; decides whether the connection stays open."""
        if self._body_left:
            self.close_connection = True
        self.send_response(code)
        if ctype:
            self.send_header("Content-Type", ctype)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if page:
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", self.page_csp())
        if cache:
            self.send_header("Cache-Control", cache)
        for k, v in headers:
            self.send_header(k, v)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()

    def send_bytes(self, code, body, ctype, extra=(), page=True, cache="no-store"):
        headers = list(extra)
        if ctype.startswith(("text/", "application/json", "image/svg")):
            headers.append(("Vary", "Accept-Encoding"))
            if len(body) >= GZIP_MIN and self.accepts_gzip():
                body = gzip.compress(body, 5 if len(body) < 262144 else 1)
                headers.append(("Content-Encoding", "gzip"))
        self.begin(code, ctype, len(body), headers, page=page, cache=cache)
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def send_html(self, code, doc, extra=()):
        self.send_bytes(code, doc.encode("utf-8"), "text/html; charset=utf-8", extra)

    def send_json(self, obj, code=200):
        self.send_bytes(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8", page=False)

    def redirect(self, location, extra=()):
        self.begin(303, None, 0, [("Location", location)] + list(extra), page=True, cache="no-store")

    def static(self, name):
        item = STATIC.get(name)
        if item is None:
            return self.send_bytes(404, b"Not found", "text/plain; charset=utf-8", page=False)
        data, gz, ctype = item
        headers = [("Vary", "Accept-Encoding")]
        if self.accepts_gzip():
            data = gz
            headers.append(("Content-Encoding", "gzip"))
        self.begin(200, ctype, len(data), headers, cache="public, max-age=31536000, immutable")
        if self.command != "HEAD":
            self.wfile.write(data)

    def page(self, title, body, query="", body_attrs="", nav=True, keys="", kind="") -> str:
        st = index.status()
        building = st["state"] == "building"
        attrs = f' data-page="{kind}" data-host="{esc(HOSTNAME.upper())}"'
        if building:
            attrs += ' data-indexing="1"'
        here = netinfo.find(self.local_ip())
        direct = bool(here and is_direct_link(here))
        if kind not in ("login", "stopped", "error"):
            attrs += ' data-paths="1"'
        values = {
            "THEME": self.theme(), "ACCENT": self.accent(), "TITLE": esc(title), "CSSURL": CSS_URL, "JSURL": JS_URL,
            "SPRITE": SPRITE, "HOST": esc(HOSTNAME.upper()), "IDXHIDDEN": "" if building else " hidden",
            "LINKICON": (f'<span title="Connected by cable">{icon("cable", "ic sb-ic")}</span>' if direct else ""),
            "LOCKICON": (f'<span title="Password protected">{icon("lock", "ic sb-ic")}</span>'
                         if settings.get("password") is not None else ""),
            "TIME": time.strftime("%H:%M"),
            "NAV": NAV_HTML.replace("%%QUERY%%", esc(query)) if nav else "",
            "BODYATTRS": attrs + body_attrs, "BODY": body, "SOFTKEYS": keys,
        }
        # single pass, so text inside file names can never be re-substituted
        return re.sub(r"%%([A-Z]+)%%", lambda m: values.get(m.group(1), m.group(0)), BASE_HTML)

    def error_page(self, code, title, message):
        body = (f'<div class="panel hero">{icon("warn", "ic lockic")}'
                f'<h1 class="title" style="justify-content:center">{esc(title)}</h1><p>{esc(message)}</p>'
                f'<a class="btn" href="/">{icon("home")}Back to your drives</a></div>')
        keys = softkeys([("Your drives", "home", "/", None), ("Settings", "settings", "/settings", None)],
                        center=("Home", "home"), back="/")
        self.send_html(code, self.page(title, body, keys=keys, kind="error"))

    # ---- pages ---------------------------------------------------------------
    def home(self):
        shares = settings.shares()
        manage = self.can_manage()
        keys = softkeys([("Search", "search", None, "search"), ("Settings", "settings", "/settings", None),
                         ("Speed test", "gauge", "/settings?t=net#speed", None), "-",
                         ("Switch dark/light", "sun", None, "theme")])
        if not shares:
            text = ("Choose which drives to share. It takes a few seconds." if manage else
                    "Open Beam's Settings on the PC running Beam to choose which drives to share.")
            btn = f'<a class="btn" href="/settings">{icon("drive")}Choose drives</a>' if manage else ""
            body = (f'<div class="panel hero"><span class="orb big" aria-hidden="true"></span>'
                    f'<h1 class="title" style="justify-content:center">Nothing shared yet</h1><p>{text}</p>{btn}</div>')
            return self.send_html(200, self.page("Home", body, keys=keys, kind="home"))
        tiles = []
        for s in shares:
            cap = capacity(s["path"]) if os.path.isdir(s["path"]) else None
            if cap is None:
                tiles.append(f'<div class="tile off" aria-disabled="true"><span class="ico">{ficon("drive", "fi lg")}</span>'
                             f'<span class="name">{esc(s["name"])}</span><span class="sub">Not connected. Plug it in, then refresh.</span>'
                             f'<div class="meter"></div></div>')
                continue
            total, free = cap
            pct = 0 if not total else round((total - free) / total * 100, 1)
            tiles.append(f'<a class="tile" href="/b/{s["id"]}/" data-cap="{esc(s["name"])}"><span class="ico">{ficon("drive", "fi lg")}</span>'
                         f'<span class="name">{esc(s["name"])}</span><span class="sub">{human_size(free)} free of {human_size(total)}</span>'
                         f'<div class="meter" role="img" aria-label="{pct}% used"><i style="width:{pct}%"></i></div></a>')
        tiles.append(f'<a class="tile" href="/settings" data-cap="Settings"><span class="ico">{ficon("gear", "fi lg")}</span>'
                     f'<span class="name">Settings</span><span class="sub">Drives, password, speed test</span></a>')
        st = index.status()
        idx = (f"Indexing… {st['count']:,} items so far" if st["state"] == "building" else f"{st['count']:,} items indexed")
        body = ('<div class="head"><div><h1 class="title">Your drives</h1>'
                f'<div class="meta"><span id="idx">{esc(idx)}</span><span class="kb"> · <kbd>/</kbd> search · arrow keys move · '
                '<kbd>Enter</kbd> opens</span></div></div></div>'
                f'<section class="panel" aria-label="Main menu"><div class="strip"><span>Main menu</span><span class="grow"></span>'
                f'<span id="cap" aria-hidden="true"></span></div><div class="menu-grid">{"".join(tiles)}</div></section>')
        self.send_html(200, self.page("Your drives", body, keys=keys, kind="home"))

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
                                resolve_in_share(share, f"{rel}/{e.name}", show_hidden) is None:
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
        zurl = f"/zip/{sid}/{quote_path(rel)}"
        acts = ""
        if allow:
            acts += (f'<button type="button" class="btn" id="upFiles">{icon("upload")}Upload files</button>'
                     f'<button type="button" class="btn ghost" id="upFolder">{icon("folder")}Upload a folder</button>')
        if rows:
            acts += f'<button type="button" class="btn ghost" data-act="mark">{icon("mark")}Mark several</button>'
        acts += f'<a class="btn ghost" href="{zurl}" download>{icon("archive")}Download as ZIP</a>'
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
        shares = settings.shares()
        tabs = ""
        if len(shares) > 1:
            i = next((k for k, s in enumerate(shares) if s["id"] == sid), 0)
            prv, nxt_s = shares[i - 1], shares[(i + 1) % len(shares)]
            tabs = (f'<nav class="tabs" aria-label="Drives"><a class="arr" href="/b/{prv["id"]}/" title="Previous drive: {esc(prv["name"])}" '
                    f'aria-label="Previous drive: {esc(prv["name"])}">&#9664;</a>'
                    + "".join(f'<a class="tab" href="/b/{s["id"]}/"{" aria-current=true" if s["id"] == sid else ""}>'
                              f'{icon("drive")}{esc(s["name"])}</a>' for s in shares)
                    + f'<a class="arr" href="/b/{nxt_s["id"]}/" title="Next drive: {esc(nxt_s["name"])}" '
                      f'aria-label="Next drive: {esc(nxt_s["name"])}">&#9654;</a></nav>')
        body = (f'<div class="head"><div><nav class="crumbs" aria-label="Breadcrumb">'
                f'{"<span class=sep>›</span>".join(crumbs)}</nav><h1 class="title">{ficon("folder")}{esc(title)}</h1>'
                f'<div class="meta">{esc(summary)}</div></div><div class="actions">{acts}</div></div>{tabs}'
                f'<div class="panel list">{listing}</div>{markbar(True) if rows else ""}{pickers}')
        up = "/b/" + sid + "/" + quote_path("/".join(parts[:-1])) if parts else "/"
        items = []
        if rows:
            items += [("Mark several", "mark", None, "mark")]
            if files:
                items += [(f"Download all {len(files)} files", "download", None, "dl-all")]
        items += [("Download folder as ZIP", "archive", zurl, None)]
        if allow:
            items += [("Upload files", "upload", None, "upfiles"), ("Upload a folder", "folder", None, "upfolder")]
        items += ["-", ("Sort by name", "menu", "?sort=name", None), ("Sort by size", "menu", "?sort=size&order=desc", None),
                  ("Sort by date", "menu", "?sort=date&order=desc", None), "-",
                  ("Search", "search", None, "search"), ("Settings", "settings", "/settings", None)]
        keys = softkeys(items, back=up, mark_menu=mark_menu(True) if rows else "")
        attrs = (f' data-folder="{esc(title)}" data-zip="{esc(zurl)}"'
                 + (f' data-upload="/api/upload/{sid}/{quote_path(rel)}"' if allow else ""))
        self.send_html(200, self.page(title, body, body_attrs=attrs, keys=keys, kind="browse"))

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
        body = (f'<div class="head"><div><nav class="crumbs" aria-label="Breadcrumb"><a href="/">Home</a></nav>'
                f'<h1 class="title">{icon("search")}Results for “{esc(q)}”</h1><div class="meta">{esc(meta)}</div></div>'
                + (f'<div class="actions"><button type="button" class="btn ghost" data-act="mark">{icon("mark")}Mark several</button></div>' if rows else "")
                + f'</div><div class="panel list">{listing}</div>{markbar(False) if rows else ""}')
        items = ([("Mark several", "mark", None, "mark")] if rows else []) + [
            ("Search again", "search", None, "search"), ("Your drives", "home", "/", None), ("Settings", "settings", "/settings", None)]
        keys = softkeys(items, back="/", mark_menu=mark_menu(False) if rows else "")
        self.send_html(200, self.page(f"Search: {q}", body, query=q, keys=keys, kind="search"))

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
                            "where": entry_where(e, share), "icon": "folder" if e[0] == "d" else file_icon(e[3])})
        st = index.status()
        self.send_json({"results": out, "total": total, "closest": closest,
                        "indexing": st["state"] == "building", "count": st["count"]})

    def api_paths(self):
        """This PC's other addresses, so the page can test for a faster (wired) route."""
        ifaces = netinfo.get() if netinfo.cached() or netinfo.refreshed_once() else netinfo.refresh_now()
        here = self.local_ip()
        cur = netinfo.find(here)
        others, seen = [], {here}
        for iface in sorted(ifaces, key=lambda i: (i["kind"] == "wifi", not is_direct_link(i))):
            for ip in iface["ips"]:
                if ip in seen or ":" in ip or ip.startswith("127."):
                    continue
                seen.add(ip)
                others.append({"ip": ip, "kind": iface["kind"], "name": iface["name"], "direct": is_direct_link(iface)})
        self.send_json({"current": {"ip": here, "kind": cur["kind"] if cur else "",
                                    "direct": bool(cur and is_direct_link(cur))},
                        "others": others[:6], "port": self.server.server_port})

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
            fh = open_for_reading(target)
            st = os.fstat(fh.fileno())
        except PermissionError:
            return self.error_page(403, "Access denied", "Windows won't let Beam read this file (it may be in use).")
        except OSError:
            return self.error_page(404, "File not found", "It may have been moved, renamed or deleted.")
        with fh:
            size = st.st_size
            ext = ext_of(target.name)
            inline = view and ext in INLINE_MIME
            last_mod = email.utils.formatdate(st.st_mtime, usegmt=True)
            etag = f'"{size:x}-{st.st_mtime_ns:x}"'
            headers = [("Last-Modified", last_mod), ("ETag", etag), ("Accept-Ranges", "bytes")]
            inm = self.headers.get("If-None-Match")
            if (inm is not None and (inm.strip() == "*" or etag in [t.strip() for t in inm.split(",")])) or \
                    (inm is None and self.headers.get("If-Modified-Since") == last_mod):
                return self.begin(304, None, None, headers, cache="private, max-age=0")
            start, end, status = 0, size - 1, 200
            rng = self.headers.get("Range")
            if rng and self.headers.get("If-Range") not in (None, last_mod, etag):
                rng = None  # the file changed since the partial download began: send it whole
            if rng:
                m = re.fullmatch(r"\s*bytes=(\d*)-(\d*)\s*", rng)
                if m and (m.group(1) or m.group(2)):
                    a, b = m.groups()
                    if a:
                        start, end = int(a), (min(int(b), size - 1) if b else size - 1)
                    else:
                        start, end = max(0, size - int(b)), size - 1
                    if size == 0 or start > end or start >= size:
                        return self.begin(416, None, 0, [("Content-Range", f"bytes */{size}")])
                    status = 206
            length = max(0, end - start + 1)
            headers += [("Content-Disposition", content_disposition(target.name, inline))]
            if not (inline and ext == "pdf"):
                headers.append(("Content-Security-Policy", "sandbox"))
            if status == 206:
                headers.append(("Content-Range", f"bytes {start}-{end}/{size}"))
            self.begin(status, INLINE_MIME[ext] if inline else "application/octet-stream", length, headers,
                       cache="private, max-age=0")
            if self.command == "HEAD" or not length:
                return
            tune_bulk(self.connection)
            tx = transfers.begin(self.q("tx"), size)
            t0, sent = time.perf_counter(), 0
            try:
                sent = send_file(self.connection, fh, start, length, tx.add if tx else None)
            finally:
                if tx:
                    tx.end(sent == length)
            if sent < length:
                self.close_connection = True  # the file shrank: the browser sees an incomplete download
                log.warning("Download cut short (file changed): %s", target)
            elif not view and length >= 8 * 1024 * 1024:
                log.info("Download: %s to %s: %s", target, self.client_ip(), rate_text(sent, time.perf_counter() - t0))

    def zip_folder(self, sid, rel, pick=None):
        share, target = self._file_target(sid, rel)
        if target is None or not target.is_dir():
            return self.error_page(404, "Folder not found", "It may have been moved, renamed or deleted.")
        name = clean_component(target.name or share["name"]) or "Beam"
        zs = ZipStream(zip_plan(str(target), name, settings.get("show_hidden"), pick))
        fname = name + (" (selection)" if pick is not None else "") + ".zip"
        self.begin(200, "application/zip", zs.size, [("Content-Disposition", content_disposition(fname))],
                   cache="no-store")
        tune_bulk(self.connection)
        tx = transfers.begin(self.q("tx"), zs.size)
        log.info("ZIP download: %s (%s files, %s) to %s", target, f"{len(zs.items):,}", human_size(zs.size), self.client_ip())
        t0, sent = time.perf_counter(), 0
        try:
            sent = zs.stream(self.connection.sendall, tx.add if tx else None)
        finally:
            if tx:
                tx.end(sent == zs.size)
        log.info("ZIP complete: %s", rate_text(sent, time.perf_counter() - t0))

    def zip_marked(self, sid, rel):
        form = self.read_form(MAX_PICK_BYTES)
        if form is None:
            return self.error_page(413, "Too many items", "That's more marked items than Beam can put in one ZIP request.")
        pick = {p for p in form.get("pick", []) if p and "/" not in p and "\\" not in p and p not in (".", "..")}
        if not pick:
            return self.error_page(400, "Nothing marked", "Mark some files or folders first.")
        return self.zip_folder(sid, rel, pick)

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
        if any(upload_name_blocked(c) for c in comps):
            return self.send_json({"error": "Hidden and system files (like .DS_Store or desktop.ini) aren't accepted."}, 400)
        if self.headers.get("Content-Length") is None:
            return self.send_json({"error": "Upload size missing."}, 411)
        length = self._body_left
        cap = capacity(str(target))
        if cap and length > cap[1] - SPACE_RESERVE:
            return self.send_json({"error": f"Not enough space ({human_size(cap[1])} free)."}, 507)
        root = resolve_in_share(share, "")
        try:
            parent, created = make_dirs_within(target, comps[:-1])
            real_parent = parent.resolve(strict=True)
        except OSError as exc:
            return self.send_json({"error": f"Couldn't create the folder: {exc.strerror or exc}"}, 500)
        if root is None or (real_parent != root and root not in real_parent.parents):
            return self.send_json({"error": "That destination isn't allowed."}, 400)
        tmp = parent / f"{TEMP_PREFIX}{secrets.token_hex(8)}.part"
        t0, received = time.perf_counter(), 0
        try:
            buf = memoryview(bytearray(min(CHUNK, max(length, 1))))
            with open(tmp, "xb", buffering=0) as out:
                while received < length:
                    n = self.rfile.readinto(buf[:min(len(buf), length - received)])
                    if not n:
                        break
                    self._body_left -= n
                    received += n
                    chunk = buf[:n]
                    while chunk:
                        chunk = chunk[out.write(chunk):]
            if received != length:
                raise ConnectionError("upload interrupted")
            final = place_upload(tmp, parent, comps[-1])
        except (ConnectionError, TimeoutError, socket.timeout):
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
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
        log.info("Upload: %s from %s: %s", final, self.client_ip(), rate_text(length, time.perf_counter() - t0))
        base = clean_parts(rel_dir)
        now = time.time()
        items = [("d", "/".join(base + comps[:i + 1]), comps[i], None, now) for i in created]
        items.append(("f", "/".join(base + comps[:-1] + [final.name]), final.name, length, now))
        index.add(sid, items)  # searchable straight away, no rescan of every drive
        self.send_json({"ok": True, "name": final.name})

    def speedtest_down(self):
        try:
            n = max(0, min(int(self.q("bytes", "0")), SPEEDTEST_MAX))
        except ValueError:
            n = 0
        self.begin(200, "application/octet-stream", n, cache="no-store")
        if self.command == "HEAD":
            return
        tune_bulk(self.connection)
        block, left = _SPEED_BLOCK, n
        send = self.connection.sendall
        while left > 0:
            k = min(left, len(block))
            send(block[:k])
            left -= k

    def speedtest_up(self):
        if self.headers.get("X-Beam") != "1":
            return self.send_json({"error": "Missing Beam header."}, 403)
        if self._body_left > 1 << 30:
            return self.send_json({"error": "That's more than the speed test needs."}, 413)
        buf, got, t0 = memoryview(bytearray(CHUNK)), 0, time.perf_counter()
        while self._body_left > 0:
            n = self.rfile.readinto(buf[:min(CHUNK, self._body_left)])
            if not n:
                break
            self._body_left -= n
            got += n
        self.send_json({"bytes": got, "ms": round((time.perf_counter() - t0) * 1000)})

    # ---- sign-in -------------------------------------------------------------
    def login_page(self, error="", nxt=None):
        if settings.get("password") is None or self.authorised():
            return self.redirect("/")
        nxt = safe_next(nxt if nxt is not None else self.q("next", "/"))
        flash = f'<div class="flash err">{esc(error)}</div>' if error else ""
        body = (f'<div class="panel login">{icon("lock", "ic lockic")}'
                f'<h1 class="title" style="justify-content:center">Beam is locked</h1><p class="note">Enter the password set on the PC running Beam.</p>{flash}'
                f'<form method="post" action="/login" data-softkey><input type="hidden" name="next" value="{esc(nxt)}">'
                f'<div class="field"><input type="password" name="password" autocomplete="current-password" '
                f'aria-label="Password" placeholder="Password" required autofocus></div>'
                f'<div class="field"><button class="btn wide">{icon("lock")}Unlock</button></div></form></div>')
        self.send_html(401 if error else 200,
                       self.page("Sign in", body, nav=False, keys=softkeys(center=("Unlock", "submit")), kind="login"))

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

    def handoff(self):
        """Arriving from this PC's other address (e.g. switching to the cable)."""
        nxt = safe_next(self.q("next", "/"))
        extra = []
        if self.q("theme") in THEMES:
            extra.append(("Set-Cookie", f"beam_theme={self.q('theme')}; Path=/; Max-Age=31536000; SameSite=Lax"))
        if self.q("accent") in ACCENTS:
            extra.append(("Set-Cookie", f"beam_accent={self.q('accent')}; Path=/; Max-Age=31536000; SameSite=Lax"))
        has_pw = settings.get("password") is not None
        if use_handoff(self.q("t")):
            if has_pw:
                extra.append(("Set-Cookie", session_cookie(make_session())))
            log.info("Switched connection: %s now using %s", self.client_ip(), self.local_ip())
            return self.redirect(nxt, extra)
        return self.redirect(("/login?next=" + urllib.parse.quote(nxt, safe="")) if has_pw else nxt, extra)

    # ---- settings -------------------------------------------------------------
    def settings_page(self):
        manage = self.can_manage()
        host_pc = self.is_host_machine()
        dis = "" if manage else " disabled"
        tab = self.q("t", "drives")
        tab = tab if tab in [t[0] for t in SETTINGS_TABS] else "drives"
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

        theme, accent = self.theme(), self.accent()
        radio = lambda v, label: (f'<label><input type="radio" name="theme" value="{v}" data-set-theme'
                                  f'{" checked" if theme == v else ""}><span>{label}</span></label>')
        swatch = lambda v: (f'<label class="swatch"><input type="radio" name="accent" value="{v}" data-set-accent'
                            f'{" checked" if accent == v else ""}><span><i style="background:{ACCENT_COLOURS[v]}"></i>'
                            f'{v.title()}</span></label>')
        port_now, port_saved = self.server.server_port, settings.get("port")
        bookmark = f"http://{HOSTNAME.lower()}:{port_now}/"
        backup = f"http://{primary_ip()}:{port_now}/"
        has_pw = settings.get("password") is not None
        st = index.status()
        built = time.strftime("%H:%M", time.localtime(st["built_at"])) if st["built_at"] else "not yet"

        # ---- connection details
        ifaces = netinfo.get()
        here = self.local_ip()
        cur = netinfo.find(here)
        kinds = {"ethernet": "Cable", "wifi": "Wi-Fi", "other": "Other"}
        if cur and is_direct_link(cur):
            how = f"This device is connected <b>by cable</b>, straight to this PC ({esc(cur['name'] or here)}). That's the fastest route."
        elif cur:
            how = (f"This device reaches Beam through this PC's <b>{esc(kinds.get(cur['kind'], 'network'))}</b> connection "
                   f"({esc(cur['name'] or here)}, {esc(here)}).")
        else:
            how = f"This device reaches Beam at {esc(here or 'this PC')}."
        iface_rows = ""
        warn = ""
        for iface in ifaces:
            direct = is_direct_link(iface)
            kind = "Cable (direct)" if direct else kinds.get(iface["kind"], "Other")
            cat = iface.get("category") or ""
            cat_html = ""
            if cat:
                cat_html = f'<span class="badge{" on" if cat == "Public" else ""}">{esc(cat)}</span>'
            addr = "<br>".join(f"<code>http://{esc(ip)}:{port_now}/</code>" for ip in iface["ips"])
            iface_rows += (f'<tr><td>{esc(iface["name"] or "This PC")}</td><td>{esc(kind)}</td><td>{addr}</td>'
                           f'<td>{esc(link_speed(iface["speed"]))}</td>' + (f"<td>{cat_html}</td>" if IS_WINDOWS else "") + "</tr>")
            if IS_WINDOWS and cat == "Public" and iface["kind"] == "ethernet" and iface.get("index") is not None:
                cmd = f"Set-NetConnectionProfile -InterfaceIndex {iface['index']} -NetworkCategory Private"
                fix = ""
                if host_pc:
                    fix = (f'<form method="post" action="/settings"><input type="hidden" name="action" value="netprivate">'
                           f'<input type="hidden" name="index" value="{iface["index"]}"><div class="field">'
                           f'<button class="btn">{icon("shield")}Make “{esc(iface["name"])}” Private</button></div></form>')
                warn += (f'<div class="flash err">Windows treats the network on <b>{esc(iface["name"])}</b> as <b>Public</b>, so its '
                         f'firewall stops other PCs reaching Beam over it. Make it Private (Windows asks for permission), '
                         f'or run this in PowerShell as administrator:<div class="kv" style="margin-top:8px"><code>{esc(cmd)}</code>'
                         f'<button type="button" class="btn ghost sm" data-copy="{esc(cmd)}">Copy</button></div>{fix}</div>')
        iface_table = ('<table class="ifaces"><thead><tr><th>Connection</th><th>Type</th><th>Address</th><th>Speed</th>'
                       + ("<th>Windows network</th>" if IS_WINDOWS else "") + f"</tr></thead><tbody>{iface_rows}</tbody></table>"
                       if iface_rows else '<p class="note">Looking up this PC\'s connections… refresh in a moment.</p>')

        sw_row = lambda name, label, small, on: (
            f'<label class="check"><span class="grow"><b>{label}</b><small>{small}</small></span>'
            f'<input class="sw" type="checkbox" name="{name}"{" checked" if on else ""}></label>')
        panes = {
            "drives": [
                f'''<section class="panel sect"><h2>Shared drives</h2>
<p class="note">Switch on the drives other devices can open. Everything else on this PC stays private.</p>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="shares">{drive_rows}
<div class="field"><button class="btn">{icon("check")}Save drives</button></div></fieldset></form>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="add">
<div class="field"><input type="text" name="path" placeholder="Or share one folder, e.g. F:\\Films" aria-label="Folder path to share">
<button class="btn ghost">Add folder</button></div></fieldset></form></section>''',
                f'''<section class="panel sect"><h2>Uploads and hidden files</h2>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="prefs">
{sw_row("allow_uploads", "Allow uploads", "Other devices can add files to shared drives. Nothing is ever overwritten or deleted. Hidden and system files are never accepted.", settings.get("allow_uploads"))}
{sw_row("show_hidden", "Show hidden files", "Include hidden and system files in folders, search and ZIPs. While this is off they can't be opened at all.", settings.get("show_hidden"))}
<div class="field"><button class="btn">{icon("check")}Save</button></div></fieldset></form></section>''',
            ],
            "display": [
                f'''<section class="panel sect"><h2>Theme</h2>
<p class="note">Saved in this browser.</p>
<div class="seg" role="radiogroup" aria-label="Theme">{radio("dark", "Dark")}{radio("light", "Light")}{radio("system", "Match Windows")}</div></section>''',
                f'''<section class="panel sect"><h2>Colour</h2>
<p class="note">The highlight colour, like a phone theme. Saved in this browser.</p>
<div class="swatches" role="radiogroup" aria-label="Colour">{"".join(swatch(a) for a in ACCENTS)}</div></section>''',
                '''<section class="panel sect"><h2>Keys</h2>
<p class="note">Beam works like a phone menu as well as a web page:</p>
<ul class="steps"><li><kbd>↑</kbd> <kbd>↓</kbd> move the highlight, <kbd>Enter</kbd> opens, <kbd>→</kbd> opens a folder</li>
<li><kbd>←</kbd> or <kbd>Backspace</kbd> goes back up</li><li><kbd>/</kbd> jumps to search</li>
<li>In Mark several, <kbd>Space</kbd> or <kbd>Enter</kbd> marks, and Shift-click marks a run</li>
<li>The keys along the bottom are Options, Select and Back</li></ul></section>''',
            ],
            "net": [
                f'''<section class="panel sect"><h2>Your bookmark</h2>
<p class="note">Favourite this on your other PC. It uses this PC's name, so it keeps working when the router hands out a new IP address.</p>
<div class="kv"><code>{esc(bookmark)}</code><button type="button" class="btn ghost sm" data-copy="{esc(bookmark)}">Copy</button></div>
<p class="note" style="margin-top:12px">Backup address, which can change: <code>{esc(backup)}</code>. If the name ever stops working,
set a DHCP reservation for this PC in your router so the backup address never changes.</p>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="port">
<div class="field"><label for="port">Port</label><input id="port" type="number" name="port" min="1024" max="65535" value="{port_saved}">
<button class="btn ghost">Save port</button></div></fieldset></form></section>''',
                f'''<section class="panel sect" id="speed"><h2>Speed test</h2>
<p class="note">Measures the network between this device and {esc(HOSTNAME.upper())}. Nothing is read from or written to your drives.</p>
<div class="speed">
<div class="gauge" id="spPing"><b>–</b><small>Ping</small><div class="meter"><i></i></div></div>
<div class="gauge" id="spOne"><b>–</b><small>1 download</small><div class="meter"><i></i></div></div>
<div class="gauge" id="spMany"><b>–</b><small>4 at once</small><div class="meter"><i></i></div></div>
<div class="gauge" id="spUp"><b>–</b><small>Upload</small><div class="meter"><i></i></div></div></div>
<button type="button" class="btn" id="spRun">{icon("gauge")}Run speed test</button>
<p class="note" id="spNote" style="margin-top:12px" aria-live="polite"></p></section>''',
                f'''<section class="panel sect"><h2>Wired connection (fastest)</h2>
<p class="note">{how}</p>{warn}{iface_table}
<p class="note"><b>Megarapid option: a cable straight between the two PCs.</b> Wi-Fi is fine for everyday use, but a cable
is several times faster and steadier:</p>
<ol class="steps"><li>Plug an ordinary network cable into both PCs. Wi-Fi can stay on.</li>
<li>Wait about a minute. With no router on the cable, Windows gives each PC an automatic address starting 169.254.</li>
<li>If Windows calls that network Public, its firewall blocks Beam on it: a warning with a one-click fix appears above.</li>
<li>Open Beam on the other PC as usual. It spots the wired route and offers to switch (look for Cable in the status bar),
or open the cable address from the table yourself.</li></ol>
<p class="note">If both PCs are already plugged into your router by cable, you're all set: there's nothing to change.</p></section>''',
            ],
            "security": [
                f'''<section class="panel sect"><h2>Password</h2>
<p class="note">{"A password is set. Other devices need it to open Beam; this PC never does." if has_pw else
                "No password. Anyone on your home network can open the shared drives while Beam is running."}</p>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="password">
<div class="field"><input type="password" name="password" autocomplete="new-password" placeholder="New password" aria-label="New password" minlength="6">
<input type="password" name="confirm" autocomplete="new-password" placeholder="Type it again" aria-label="Confirm new password" minlength="6"></div>
<div class="field"><button class="btn">{icon("lock")}{"Change password" if has_pw else "Set password"}</button></div></fieldset></form>
{f"""<form method="post" action="/settings" data-confirm="Remove the password? Anyone on your network will be able to open Beam." data-title="Remove password"><fieldset{dis}>
<input type="hidden" name="action" value="nopassword"><div class="field"><button class="btn ghost">Remove password</button></div></fieldset></form>""" if has_pw else ""}
{"""<form method="post" action="/logout"><div class="field"><button class="btn ghost">Sign out on this device</button></div></form>""" if has_pw and not host_pc else ""}
</section>''',
            ],
            "system": [],
        }
        if IS_WINDOWS:
            panes["system"].append(f'''<section class="panel sect"><h2>Start with Windows</h2>
<p class="note">Runs Beam quietly in the background whenever this PC starts, so your bookmark always works.</p>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="autostart">
{sw_row("autostart", "Start Beam automatically", "Stop it any time with the button below.", autostart_enabled())}
<div class="field"><button class="btn">{icon("check")}Save</button></div></fieldset></form></section>''')
        panes["system"].append(f'''<section class="panel sect"><h2>Search index and server</h2>
<p class="note">{st["count"]:,} items {"indexed so far" if st["state"] == "building" else f"indexed, last updated {built}"}.
It refreshes on its own every hour, and uploads are searchable straight away.</p>
<form method="post" action="/settings"><fieldset{dis}><input type="hidden" name="action" value="reindex">
<div class="field"><button class="btn ghost">Rebuild search index now</button></div></fieldset></form>
<form method="post" action="/settings" data-confirm="Stop Beam? Nobody will be able to open it until it's started again on the PC running Beam." data-title="Stop Beam">
<fieldset{dis}><input type="hidden" name="action" value="stop"><div class="field"><button class="btn ghost">{icon("power")}Stop Beam</button></div></fieldset></form>
<p class="note" style="margin-top:14px">Beam {VERSION}. Log file: {esc(str(LOG_PATH))}</p></section>''')

        tabs = "".join(
            f'<a class="tab" role="tab" id="tab-{k}" data-tab="{k}" href="?t={k}" aria-controls="pane-{k}" '
            f'aria-selected="{"true" if k == tab else "false"}" tabindex="{0 if k == tab else -1}">{icon(ico)}{label}</a>'
            for k, label, ico in SETTINGS_TABS)
        body = (f'<div class="head"><div><nav class="crumbs" aria-label="Breadcrumb"><a href="/">Home</a></nav>'
                f'<h1 class="title">{ficon("gear")}Settings</h1></div></div>{flash}'
                f'<div class="tabs" role="tablist" aria-label="Settings">{tabs}</div>'
                + "".join(f'<div class="pane sgrid" id="pane-{k}" role="tabpanel" aria-labelledby="tab-{k}"'
                          f'{"" if k == tab else " hidden"}>{"".join(panes[k])}</div>' for k, _l, _i in SETTINGS_TABS))
        keys = softkeys([("Your drives", "home", "/", None), ("Speed test", "gauge", None, "speedtest"),
                         ("Switch dark/light", "sun", None, "theme")], center=None, back="/")
        self.send_html(200, self.page("Settings", body, keys=keys, kind="settings"))

    def settings_submit(self):
        if not self.can_manage():
            return self.redirect("/settings?e=perm")
        form = self.read_form()
        if form is None:
            return self.error_page(413, "Too much data", "That form was bigger than expected.")
        f1 = lambda k: (form.get(k) or [""])[0]
        action = f1("action")
        back = lambda q: self.redirect(f"/settings?{q}&t={ACTION_TAB.get(action, 'drives')}")

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
            return back("m=saved")

        if action == "add":
            raw = f1("path").strip().strip('"').strip()
            p = os.path.normpath(os.path.abspath(os.path.expanduser(raw))) if raw else ""
            if not p or not os.path.isdir(p):
                return back("e=nopath")
            if normkey(p) in {normkey(s["path"]) for s in settings.shares()}:
                return back("e=dup")
            name = os.path.basename(p.rstrip("\\/")) or p
            for d in detect_drives():
                if normkey(d["path"]) == normkey(p):
                    name = d["display"]
            settings.set(shares=settings.get("shares") + [{"path": p, "name": name[:80]}])
            log.info("Folder shared: %s", p)
            index.schedule(0.5)
            return back("m=added")

        if action == "prefs":
            hidden = f1("show_hidden") == "on"
            changed = hidden != settings.get("show_hidden")
            settings.set(allow_uploads=f1("allow_uploads") == "on", show_hidden=hidden)
            if changed:
                index.schedule(0.5)
            return back("m=saved")

        if action == "port":
            try:
                port = int(f1("port"))
            except ValueError:
                port = -1
            if not 1024 <= port <= 65535:
                return back("e=port")
            settings.set(port=port)
            return back("m=port")

        if action == "password":
            pw, again = f1("password"), f1("confirm")
            if len(pw) < 6 or len(pw) > 256:
                return back("e=pwshort")
            if pw != again:
                return back("e=pwmatch")
            settings.set(password=hash_password(pw))
            log.info("Password set")
            return self.redirect("/settings?m=pwset&t=security", [("Set-Cookie", session_cookie(make_session()))])

        if action == "nopassword":
            settings.set(password=None)
            log.info("Password removed")
            return self.redirect("/settings?m=pwoff&t=security", [("Set-Cookie", CLEAR_SESSION)])

        if action == "autostart":
            on = f1("autostart") == "on"
            try:
                set_autostart(on)
            except OSError as exc:
                log.error("Couldn't change start-with-Windows: %s", exc)
                return back("e=auto")
            return back("m=" + ("auto_on" if on else "auto_off"))

        if action == "netprivate":
            if not (IS_WINDOWS and self.is_host_machine()):
                return back("e=hostonly")
            try:
                idx = int(f1("index"))
            except ValueError:
                return back("e=private")
            if not any(i.get("index") == idx and i.get("category") == "Public" for i in netinfo.cached()):
                return back("e=private")
            try:
                ok = make_network_private(idx)
            except Exception:
                log.exception("Couldn't start the network change")
                ok = False
            log.info("Asked Windows to make network interface %s Private: %s", idx, "prompt shown" if ok else "failed")
            threading.Timer(20, netinfo.refresh_now).start()
            return back("m=private" if ok else "e=private")

        if action == "reindex":
            index.schedule(0)
            return back("m=reindex")

        if action == "stop":
            body = (f'<div class="panel hero">{icon("power", "ic lockic")}<h1 class="title" style="justify-content:center">Beam has stopped</h1>'
                    '<p>Start it again on the PC running Beam with “Start File Transfer.bat”.</p></div>')
            self.close_connection = True
            self.send_html(200, self.page("Stopped", body, nav=False, kind="stopped"))
            log.info("Stopped from Settings by %s", self.client_ip())
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return

        return self.redirect("/settings")


class BeamServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False  # don't wait for open downloads or idle keep-alive connections when stopping
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
    ifaces = netinfo.refresh_now()
    shared = ", ".join(s["name"] for s in settings.shares()) or "nothing yet (open Settings)"
    say(line)
    say(f"  BEAM  |  LAN File Transfer  v{VERSION}")
    say("-" * 66)
    say(f"  Bookmark this on your other PC:  http://{HOSTNAME.lower()}:{real_port}/")
    say(f"  Backup address (can change):     http://{primary_ip()}:{real_port}/")
    for iface in ifaces:
        if is_direct_link(iface):
            for ip in iface["ips"]:
                say(f"  Cable address (fastest):         http://{ip}:{real_port}/")
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
