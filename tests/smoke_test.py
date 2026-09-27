"""
End-to-end smoke test for Beam. Standard library only.

Starts a real Beam server on a free port with a temporary shared folder, then
checks pages, search, upload, download, resume (Range), ZIPs, the speed
features (keep-alive, compression, caching, progress tracking) and the
security checks. Run from the repo root:  python tests/smoke_test.py
"""
import gzip
import hashlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "lan_file_transfer.py"
IS_WINDOWS = os.name == "nt"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    work = Path(tempfile.mkdtemp(prefix="beam-test-"))
    app, share = work / "app", work / "share"
    (share / "Films" / "Inception (2010)").mkdir(parents=True)
    (share / "Films" / "Inception (2010)" / "Inception (2010).mkv").write_bytes(b"0123456789abcdef")
    (share / "Films" / "Amélie – Director's Cut.txt").write_text("café", encoding="utf-8")
    (share / "Films" / "Big.bin").write_bytes(os.urandom(3 * 1024 * 1024 + 7))
    (share / ".secret").mkdir()
    (share / ".secret" / "key.txt").write_text("private")
    (work / "outside.txt").write_text("secret")
    if IS_WINDOWS:  # a Windows "hidden" file must be unreachable too
        import ctypes
        (share / "Films" / "hidden.txt").write_text("hidden")
        ctypes.windll.kernel32.SetFileAttributesW(str(share / "Films" / "hidden.txt"), 0x2)
    app.mkdir()
    shutil.copy(SCRIPT, app / SCRIPT.name)
    port = free_port()
    (app / "beam_settings.json").write_text(json.dumps(
        {"port": port, "shares": [{"path": str(share), "name": "Test (T:)"}]}), encoding="utf-8")

    proc = subprocess.Popen([sys.executable, str(app / SCRIPT.name)], cwd=app,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    host = f"127.0.0.1:{port}"
    origin = {"Origin": f"http://{host}"}

    def req(method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, dict(r.getheaders()), data

    failures = []

    def check(name, ok, detail=""):
        print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail and not ok else ""))
        if not ok:
            failures.append(name)

    try:
        for _ in range(100):
            try:
                if req("GET", "/")[0] == 200:
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("server did not start")

        sid = hashlib.sha1(os.path.normcase(os.path.normpath(str(share))).encode("utf-8")).hexdigest()[:10]
        for _ in range(300):  # wait (up to 30s) for the first index build
            if json.loads(req("GET", "/api/search?q=inception")[2])["results"]:
                break
            time.sleep(0.1)

        # ---- pages and search
        check("home page", req("GET", "/")[0] == 200)
        check("settings page", req("GET", "/settings")[0] == 200)
        for tab in ("drives", "display", "net", "security", "system"):
            check(f"settings tab {tab}", req("GET", f"/settings?t={tab}")[0] == 200)
        check("browse folder", b"Inception (2010)" in req("GET", f"/b/{sid}/Films")[2])
        for q in ("inception", "inseption", "incep", "amelie"):
            res = json.loads(req("GET", "/api/search?q=" + urllib.parse.quote(q))[2])["results"]
            check(f"search '{q}'", bool(res))
        check("search page", req("GET", "/search?q=inception")[0] == 200)

        # ---- speed: keep-alive, compression, caching
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        c.connect()
        sock_before = c.sock
        statuses = []
        for path in ("/", "/api/status", f"/b/{sid}/Films", "/api/search?q=film", "/settings"):
            c.request("GET", path)
            r = c.getresponse()
            r.read()
            statuses.append((r.status, r.getheader("Connection")))
        check("keep-alive: five requests on one connection",
              all(s == 200 and conn != "close" for s, conn in statuses) and c.sock is sock_before, statuses)
        c.close()
        s10 = socket.create_connection(("127.0.0.1", port), timeout=10)
        s10.sendall(f"GET /api/status HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        raw = b""
        while True:
            chunk = s10.recv(65536)
            if not chunk:
                break
            raw += chunk
        s10.close()
        check("HTTP/1.0 clients get their connection closed", raw.startswith(b"HTTP/1.1 200") and b"Connection: close" in raw)
        st, h, body = req("GET", "/", headers={"Accept-Encoding": "gzip"})
        check("pages are compressed", h.get("Content-Encoding") == "gzip" and b"<!DOCTYPE html>" in gzip.decompress(body))
        page = gzip.decompress(body).decode()
        csp = h.get("Content-Security-Policy", "")
        check("no inline script allowed", "script-src 'self';" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0])
        assets = re.findall(r'(?:href|src)="(/static/[^"]+)"', page)
        check("page links its CSS and JS", len(assets) == 2, assets)
        for a in assets:
            st, h, body = req("GET", a, headers={"Accept-Encoding": "gzip"})
            check(f"static asset cached for a year: {a.split('/')[-1][:12]}",
                  st == 200 and "immutable" in h.get("Cache-Control", "") and h.get("Content-Encoding") == "gzip")
        check("unknown static file 404", req("GET", "/static/nope.js")[0] == 404)

        # ---- downloads
        mkv = "/dl/%s/%s" % (sid, urllib.parse.quote("Films/Inception (2010)/Inception (2010).mkv"))
        st, h, body = req("GET", mkv)
        check("download", body == b"0123456789abcdef")
        etag = h.get("ETag")
        st, h, body = req("GET", mkv, headers={"Range": "bytes=4-7"})
        check("resume (Range)", st == 206 and body == b"4567")
        check("304 when unchanged", etag and req("GET", mkv, headers={"If-None-Match": etag})[0] == 304)
        st, _h, body = req("GET", mkv, headers={"Range": "bytes=4-7", "If-Range": etag})
        check("resume with ETag If-Range", st == 206 and body == b"4567")
        st, _h, body = req("GET", mkv, headers={"Range": "bytes=4-7", "If-Range": '"stale"'})
        check("stale If-Range sends the whole file", st == 200 and body == b"0123456789abcdef")
        st, h, body = req("GET", "/dl/%s/%s" % (sid, urllib.parse.quote("Films/Amélie – Director's Cut.txt")))
        check("unicode file name", st == 200 and body.decode("utf-8") == "café")
        big = "/dl/%s/Films/Big.bin" % sid
        st, h, body = req("GET", big + "?tx=abcdefgh12.0")
        check("large download intact", body == (share / "Films" / "Big.bin").read_bytes())
        snap = json.loads(req("GET", "/api/transfers?b=abcdefgh12")[2])["items"]
        check("download progress tracked for the queue", snap.get("0", [0, 0, 0, 0])[1:] == [len(body), len(body), 1], snap)
        check("bad transfer id ignored", json.loads(req("GET", "/api/transfers?b=../../x")[2]) == {"items": {}})

        # ---- uploads
        up = f"/api/upload/{sid}/Films?path=" + urllib.parse.quote("New Folder/note.txt")
        hdr = dict(origin, **{"X-Beam": "1", "Content-Length": "5"})
        check("upload", req("PUT", up, b"hello", hdr)[0] == 200)
        check("upload never overwrites", json.loads(req("PUT", up, b"hello", hdr)[2])["name"] == "note (1).txt")
        check("uploaded file on disk", (share / "Films" / "New Folder" / "note.txt").read_bytes() == b"hello")
        res = json.loads(req("GET", "/api/search?q=note")[2])["results"]
        check("upload searchable immediately", any(r["name"] == "note.txt" for r in res), [r["name"] for r in res])
        check("upload blocked cross-site",
              req("PUT", up, b"x", {"Origin": "http://evil.example", "X-Beam": "1", "Content-Length": "1"})[0] == 403)
        bad = f"/api/upload/{sid}/Films?path=" + urllib.parse.quote("../escape.txt")
        check("upload path traversal blocked", req("PUT", bad, b"x", dict(hdr, **{"Content-Length": "1"}))[0] == 400)
        for name in (".bashrc", "sub/.ssh/authorized_keys", "desktop.ini", "Report.lnk"):
            u = f"/api/upload/{sid}/Films?path=" + urllib.parse.quote(name)
            st, h, _b = req("PUT", u, b"x", dict(hdr, **{"Content-Length": "1"}))
            check(f"upload of {name!r} refused", st == 400 and h.get("Connection") == "close")
        check("refused upload created nothing", not (share / "Films" / "sub").exists())
        st, h, _b = req("PUT", up, b"5\r\nhello\r\n0\r\n\r\n", dict(origin, **{"X-Beam": "1", "Transfer-Encoding": "chunked"}))
        check("chunked upload refused (needs a size)", st == 411)
        if not IS_WINDOWS:
            outside = work / "outside_dir"
            outside.mkdir()
            os.symlink(outside, share / "Films" / "escape")
            u = f"/api/upload/{sid}/Films?path=" + urllib.parse.quote("escape/sneaky/x.txt")
            st, _h, _b = req("PUT", u, b"x", dict(hdr, **{"Content-Length": "1"}))
            check("upload can't escape through a symlink", st in (400, 500) and not (outside / "sneaky").exists(), st)
        check("no temp files left", not list(share.rglob(".beam-*")))

        # ---- ZIPs
        st, h, body = req("GET", f"/zip/{sid}/Films")
        names = zipfile.ZipFile(io.BytesIO(body)).namelist() if st == 200 else []
        check("folder ZIP", any(n.endswith("Inception (2010).mkv") for n in names))
        check("ZIP size announced up front", int(h.get("Content-Length", -1)) == len(body))
        check("ZIP is valid", st == 200 and zipfile.ZipFile(io.BytesIO(body)).testzip() is None)
        check("ZIP leaves out hidden files", not any(".secret" in n for n in names))
        form = urllib.parse.urlencode([("pick", "Big.bin"), ("pick", "Inception (2010)")]).encode()
        fh = dict(origin, **{"Content-Type": "application/x-www-form-urlencoded"})
        st, h, body = req("POST", f"/zip/{sid}/Films", form, fh)
        picked = sorted(zipfile.ZipFile(io.BytesIO(body)).namelist()) if st == 200 else []
        check("ZIP of marked items", picked == ["Films/Big.bin", "Films/Inception (2010)/Inception (2010).mkv"], picked)
        check("marked ZIP refused cross-site",
              req("POST", f"/zip/{sid}/Films", form, {"Origin": "http://evil.example",
                                                      "Content-Type": "application/x-www-form-urlencoded"})[0] == 403)

        # ---- hidden and out-of-share paths
        check("download traversal blocked", req("GET", f"/dl/{sid}/..%2F..%2Foutside.txt")[0] == 404)
        check("hidden file not downloadable", req("GET", f"/dl/{sid}/.secret/key.txt")[0] == 404)
        check("hidden folder not browsable", req("GET", f"/b/{sid}/.secret")[0] == 404)
        check("hidden files not searchable", not json.loads(req("GET", "/api/search?q=key")[2])["results"])
        if IS_WINDOWS:
            check("Windows hidden file not downloadable", req("GET", f"/dl/{sid}/Films/hidden.txt")[0] == 404)
        check("foreign Host header blocked", req("GET", "/", headers={"Host": "evil.example"})[0] == 403)
        check("cross-site settings change blocked",
              req("POST", "/settings", b"action=reindex",
                  {"Origin": "http://evil.example", "Content-Type": "application/x-www-form-urlencoded"})[0] == 403)
        st, h, _b = req("POST", "/settings", b"action=reindex", dict(origin, **{"Content-Type": "application/x-www-form-urlencoded"}))
        check("settings change returns to its tab", st == 303 and "t=system" in h.get("Location", ""), h.get("Location"))

        # ---- speed test, faster-route discovery
        st, h, body = req("GET", "/api/speedtest?bytes=1048577")
        check("speed test download", st == 200 and len(body) == 1048577 and h.get("Cache-Control") == "no-store")
        st, _h, body = req("PUT", "/api/speedtest", b"\0" * 2_000_000, dict(origin, **{"X-Beam": "1"}))
        check("speed test upload", st == 200 and json.loads(body)["bytes"] == 2_000_000)
        check("speed test upload needs Beam's header", req("PUT", "/api/speedtest", b"x", origin)[0] == 403)
        st, h, body = req("GET", "/api/ping")
        check("ping", st == 204 and not body)
        paths = json.loads(req("GET", "/api/paths")[2])
        check("paths API", paths.get("port") == port and isinstance(paths.get("others"), list), paths)

        # ---- with a password: sign-in, handoff between addresses, safe redirects
        pw = urllib.parse.urlencode({"action": "password", "password": "correct horse", "confirm": "correct horse"}).encode()
        check("password set", req("POST", "/settings", pw, fh)[0] == 303)
        token = json.loads(req("GET", "/api/handoff")[2])["token"]
        st, h, _b = req("GET", f"/handoff?t={urllib.parse.quote(token)}&next=/settings&accent=lime")
        cookies = h.get("Set-Cookie", "")
        check("handoff signs this browser in", st == 303 and h.get("Location") == "/settings" and "beam_session=" in cookies, cookies)
        st, h, _b = req("GET", f"/handoff?t={urllib.parse.quote(token)}&next=/settings")
        check("a handoff link works only once", st == 303 and h.get("Location", "").startswith("/login"))
        for nxt in ("/\t/evil.example", "//evil.example", "/x\r\nSet-Cookie:%20a=b"):
            body = urllib.parse.urlencode({"password": "correct horse", "next": nxt}).encode()
            st, h, _b = req("POST", "/login", body, fh)
            check(f"sign-in redirect stays on Beam for {nxt!r}", st == 303 and h.get("Location") == "/", h.get("Location"))
    finally:
        proc.terminate()
        try:
            out = proc.communicate(timeout=10)[0].decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            proc.kill()
            out = proc.communicate()[0].decode("utf-8", "replace")
        if failures:
            print("\n--- server output ---\n" + out)
        shutil.rmtree(work, ignore_errors=True)

    print(f"\n{'ALL PASSED' if not failures else str(len(failures)) + ' FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
