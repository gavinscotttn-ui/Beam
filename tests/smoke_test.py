"""
End-to-end smoke test for Beam. Standard library only.

Starts a real Beam server on a free port with a temporary shared folder, then
checks pages, search, upload, download, resume (Range), ZIP, and the security
checks. Run from the repo root:  python tests/smoke_test.py
"""
import hashlib
import http.client
import io
import json
import os
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
    (work / "outside.txt").write_text("secret")
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

    def check(name, ok):
        print(("PASS  " if ok else "FAIL  ") + name)
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

        check("home page", req("GET", "/")[0] == 200)
        check("settings page", req("GET", "/settings")[0] == 200)
        check("browse folder", b"Inception (2010)" in req("GET", f"/b/{sid}/Films")[2])
        for q in ("inception", "inseption", "incep", "amelie"):
            res = json.loads(req("GET", "/api/search?q=" + urllib.parse.quote(q))[2])["results"]
            check(f"search '{q}'", bool(res))

        mkv = "/dl/%s/%s" % (sid, urllib.parse.quote("Films/Inception (2010)/Inception (2010).mkv"))
        check("download", req("GET", mkv)[2] == b"0123456789abcdef")
        st, h, body = req("GET", mkv, headers={"Range": "bytes=4-7"})
        check("resume (Range)", st == 206 and body == b"4567")
        st, h, body = req("GET", "/dl/%s/%s" % (sid, urllib.parse.quote("Films/Amélie – Director's Cut.txt")))
        check("unicode file name", st == 200 and body.decode("utf-8") == "café")

        up = f"/api/upload/{sid}/Films?path=" + urllib.parse.quote("New Folder/note.txt")
        hdr = dict(origin, **{"X-Beam": "1", "Content-Length": "5"})
        check("upload", req("PUT", up, b"hello", hdr)[0] == 200)
        check("upload never overwrites", json.loads(req("PUT", up, b"hello", hdr)[2])["name"] == "note (1).txt")
        check("uploaded file on disk", (share / "Films" / "New Folder" / "note.txt").read_bytes() == b"hello")
        check("upload blocked cross-site",
              req("PUT", up, b"x", {"Origin": "http://evil.example", "X-Beam": "1", "Content-Length": "1"})[0] == 403)
        bad = f"/api/upload/{sid}/Films?path=" + urllib.parse.quote("../escape.txt")
        check("upload path traversal blocked", req("PUT", bad, b"x", dict(hdr, **{"Content-Length": "1"}))[0] == 400)
        check("no temp files left", not list(share.rglob(".beam-*")))

        check("download traversal blocked", req("GET", f"/dl/{sid}/..%2F..%2Foutside.txt")[0] == 404)
        check("foreign Host header blocked", req("GET", "/", headers={"Host": "evil.example"})[0] == 403)
        check("cross-site settings change blocked",
              req("POST", "/settings", b"action=reindex",
                  {"Origin": "http://evil.example", "Content-Type": "application/x-www-form-urlencoded"})[0] == 403)

        st, h, body = req("GET", f"/zip/{sid}/Films")
        names = zipfile.ZipFile(io.BytesIO(body)).namelist() if st == 200 else []
        check("folder ZIP", any(n.endswith("Inception (2010).mkv") for n in names))
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
