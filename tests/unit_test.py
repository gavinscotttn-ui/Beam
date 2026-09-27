"""
Unit tests for Beam's building blocks. Standard library only.

Run from the repo root:  python tests/unit_test.py
Set BEAM_SLOW_TESTS=1 to add a ZIP64 check that streams a 2.2 GB (sparse) file.
"""
import importlib.util
import io
import json
import os
import random
import shutil
import string
import sys
import tempfile
import time
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("beam", REPO / "lan_file_transfer.py")
beam = importlib.util.module_from_spec(spec)
spec.loader.exec_module(beam)

failures = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def reference_match(qt, vocab_words):
    """Beam 2.0's matcher, scanning every word: the optimised one must agree exactly."""
    n = len(qt)
    maxd = 0 if qt.isdigit() or n < 4 else (1 if n <= 6 else 2)
    qset = set(qt)
    out = []
    for vt in vocab_words:
        vset, vdigit = set(vt), vt.isdigit()
        if vt == qt:
            out.append((vt, 1.0))
        elif vt.startswith(qt):
            out.append((vt, 0.9 if n > 1 else 0.6))
        elif n >= 3 and qt in vt:
            out.append((vt, 0.75))
        elif maxd and not vdigit and len(qset - vset) <= maxd:
            lv = len(vt)
            if abs(lv - n) <= maxd and beam.osa_distance(qt, vt, maxd) <= maxd:
                out.append((vt, 0.7 if beam.osa_distance(qt, vt, 1) <= 1 else 0.55))
            elif lv > n and beam.osa_distance(qt, vt[:n], 1) <= 1:
                out.append((vt, 0.6))
    return sorted(out)


def test_search():
    random.seed(5)
    alpha = string.ascii_lowercase + string.digits
    base = ("breaking bad peaky blinders inception interstellar holiday beach sunset christmas norwich cromer "
            "season episode 1080p x264 s01e01 s04e05 2006 2010 12345 img dsc amelie partridge").split()
    words = set(base)
    while len(words) < 4000:
        w = random.choice(base)
        r = random.random()
        if r < 0.35:
            w += random.choice(alpha)
        elif r < 0.6 and len(w) > 3:
            i = random.randrange(len(w))
            w = w[:i] + random.choice(alpha) + w[i + 1:]
        else:
            w = "".join(random.choice(alpha) for _ in range(random.randint(2, 11)))
        words.add(w)
    vocab = beam.Vocab(words)
    wl = sorted(words)
    queries = {"b", "br", "bre", "inseption", "blindrs", "peeky", "holliday", "s04", "12345", "zzzz", "christmass"}
    for w in random.sample(wl, 120):
        queries.update({w, w[: max(1, len(w) // 2)]})
        if len(w) > 3:
            i = random.randrange(len(w) - 1)
            queries.update({w[:i] + w[i + 1] + w[i] + w[i + 2:], w[:i] + w[i + 1:], w[:i] + "q" + w[i + 1:]})
    bad = [q for q in sorted(queries) if sorted(beam.match_token(q, vocab)) != reference_match(q, wl)]
    check(f"typo matcher agrees with the full scan ({len(queries)} queries)", not bad, ", ".join(bad[:5]))

    for name, kind in (("Inception (2010).mkv", "f"), ("file.tar.gz", "f"), ("a.b-c", "f"), ("Amélie.txt", "f"),
                       ("no extension", "f"), ("Folder.With.Dots", "d"), ("x.MP4", "f"), (".hidden", "f")):
        fast = beam.stem_key(kind, name, beam.tokens(name))
        stem = name.rsplit(".", 1)[0] if kind == "f" and "." in name else name
        check(f"stem key for {name!r}", fast == " ".join(beam.tokens(stem)), fast)

    idx = beam.SearchIndex()
    entries, npost, ppost = [], {}, {}
    titles = ["Pilot", "The Pier", "Low Tide", "The One Where The Crabs Escape", "Fog", "Carnival Night", "Winter Swim",
              "A Very Long Final Episode Title For Testing"]
    for i in range(1, 9):
        name = f"The.Coastline.Chronicles.S02E{i:02d}.{titles[i - 1].replace(' ', '.')}.1080p.mkv"
        ntl = beam.tokens(name)
        entries.append(("f", "sid", f"TV/Season 2/{name}", name, 1, 1.0, beam.stem_key("f", name, ntl)))
        for t in set(ntl):
            npost.setdefault(t, []).append(len(entries) - 1)
        for t in {"season", "2"} - set(ntl):
            ppost.setdefault(t, []).append(len(entries) - 1)
    idx._install(entries, npost, ppost)
    res, total, closest = idx.search("coastline s02", 8)
    order = [r[1][3].split(".")[3] for r in res]
    check("a season's episodes stay in natural order, whatever their titles",
          order == [f"S02E0{i}" for i in range(1, 9)], order)
    for rel in ("Films/Inception (2010)/Inception (2010).mkv",
                "Extras/Inception (2010) - Making of the dream sequences featurette.mkv"):
        name = rel.rsplit("/", 1)[1]
        ntl = beam.tokens(name)
        entries.append(("f", "sid", rel, name, 1, 1.0, beam.stem_key("f", name, ntl)))
        for t in set(ntl):
            npost.setdefault(t, []).append(len(entries) - 1)
    idx._install(entries, npost, ppost)
    res, _t, _c = idx.search("inception", 5)
    check("elsewhere, the shorter (more exact) name comes first", res[0][1][3] == "Inception (2010).mkv",
          [r[1][3] for r in res])
    idx.add("sid", [("d", "Uploads", "Uploads", None, 1.0), ("f", "Uploads/Brand new zebra.txt", "Brand new zebra.txt", 5, 1.0)])
    res, total, _ = idx.search("zebra", 5)
    check("added files are searchable straight away", res and res[0][1][3] == "Brand new zebra.txt")
    res, total, _ = idx.search("uploads zebra", 5)
    check("added files match their folder name too", res and res[0][1][3] == "Brand new zebra.txt")


def test_zip(work: Path):
    src = work / "zipsrc"
    (src / "Season 1" / "Extras").mkdir(parents=True)
    (src / "Amélie.txt").write_text("café" * 500, encoding="utf-8")
    (src / "empty.bin").write_bytes(b"")
    (src / "Season 1" / "E01.mkv").write_bytes(os.urandom(2 * 1024 * 1024 + 5))
    (src / "Season 1" / "Extras" / "日本語.txt").write_text("hi", encoding="utf-8")
    (src / ".hidden").write_text("no")
    plan = beam.zip_plan(str(src), "Top", show_hidden=False)
    check("ZIP plan skips hidden files", not any(".hidden" in p[1] for p in plan))
    zs = beam.ZipStream(plan)
    buf = io.BytesIO()
    sent = zs.stream(buf.write)
    data = buf.getvalue()
    check("ZIP size is known exactly in advance", zs.size == len(data) == sent, f"{zs.size} vs {len(data)}")
    zf = zipfile.ZipFile(io.BytesIO(data))
    check("ZIP is valid", zf.testzip() is None)
    check("ZIP contents round-trip", zf.read("Top/Season 1/E01.mkv") == (src / "Season 1" / "E01.mkv").read_bytes()
          and zf.read("Top/Season 1/Extras/日本語.txt") == b"hi")
    pick = beam.ZipStream(beam.zip_plan(str(src), "Top", False, pick={"Season 1"}))
    pbuf = io.BytesIO()
    pick.stream(pbuf.write)
    names = zipfile.ZipFile(io.BytesIO(pbuf.getvalue())).namelist()
    check("ZIP of marked items holds only those", names and all(n.startswith("Top/Season 1/") for n in names), names)
    plan2 = beam.zip_plan(str(src), "T", False)
    (src / "Season 1" / "E01.mkv").write_bytes(b"shrunk")
    zs2 = beam.ZipStream(plan2)
    b2 = io.BytesIO()
    sent2 = zs2.stream(b2.write)
    bad = zipfile.ZipFile(io.BytesIO(b2.getvalue())).testzip()
    check("a file that changes mid-ZIP keeps the size and is flagged as damaged",
          sent2 == zs2.size and zs2.damaged == 1 and bad == "T/Season 1/E01.mkv", f"{bad} {zs2.damaged}")
    check("ZIP dates clamp to what the format can hold",
          beam._dos_datetime(0) == (33, 0) and beam._dos_datetime(5e9)[0] >> 9 == 127)
    if os.environ.get("BEAM_SLOW_TESTS") == "1":
        big = work / "zip64"
        big.mkdir()
        with open(big / "big.bin", "wb") as f:
            f.truncate(2_300_000_000)
        (big / "after.txt").write_text("after")
        zs3 = beam.ZipStream(beam.zip_plan(str(big), "B", False))
        out = work / "big.zip"
        with open(out, "wb") as f:
            n = zs3.stream(f.write)
        z3 = zipfile.ZipFile(out)
        check("ZIP64 archive (2.3 GB file) is exact and readable",
              n == zs3.size == out.stat().st_size and z3.read("B/after.txt") == b"after"
              and z3.getinfo("B/big.bin").file_size == 2_300_000_000)
        out.unlink()


def test_paths(work: Path):
    check("safe_next keeps plain paths", beam.safe_next("/b/abc/Films?sort=size") == "/b/abc/Films?sort=size")
    for bad in ("//evil.example", "/\t/evil.example", "/\\evil", "http://evil.example", "/x\r\nSet-Cookie: a=b",
                "/%0d%0a", "", "/é", "javascript:alert(1)"):
        ok = beam.safe_next(bad) == "/" or (bad == "/%0d%0a" and beam.safe_next(bad) == bad)
        check(f"safe_next refuses {bad!r}", ok, beam.safe_next(bad))
    check("clean_component makes Windows-safe names", beam.clean_component('a<b>:c?.txt') == "a_b__c_.txt"
          and beam.clean_component("CON.txt") == "_CON.txt" and beam.clean_component("..") is None)
    for name in (".bashrc", ".ssh", "desktop.ini", "Thumbs.db", "evil.lnk", "x.URL", "a.scf", "b.library-ms"):
        check(f"upload of {name!r} refused", beam.upload_name_blocked(name))
    for name in ("photo.jpg", "notes.txt", "movie.mkv", "lnk.txt"):
        check(f"upload of {name!r} allowed", not beam.upload_name_blocked(name))

    share = work / "share"
    (share / "Films").mkdir(parents=True)
    (share / ".ssh").mkdir()
    (share / ".ssh" / "id_rsa").write_text("secret")
    (share / "Films" / "a.txt").write_text("a")
    (share / ".beam-123.part").write_text("partial")
    s = {"path": str(share)}
    check("normal path resolves", beam.resolve_in_share(s, "Films/a.txt", show_hidden=False) is not None)
    check("hidden folder blocked while hidden files are off", beam.resolve_in_share(s, ".ssh/id_rsa", show_hidden=False) is None)
    check("hidden folder allowed when switched on", beam.resolve_in_share(s, ".ssh/id_rsa", show_hidden=True) is not None)
    check("upload temp files never reachable", beam.resolve_in_share(s, ".beam-123.part", show_hidden=True) is None)
    check("'..' blocked", beam.resolve_in_share(s, "Films/../../x", show_hidden=True) is None)
    check("system folders blocked", beam.resolve_in_share(s, "$RECYCLE.BIN", show_hidden=True) is None)

    parent = share / "Films"
    tmp = parent / ".beam-x.part"
    tmp.write_text("new")
    final = beam.place_upload(tmp, parent, "a.txt")
    check("uploads never overwrite", final.name == "a (1).txt" and (parent / "a.txt").read_text() == "a"
          and final.read_text() == "new" and not tmp.exists())
    made, created = beam.make_dirs_within(parent, ["New", "Deeper"])
    check("folders created for an upload", made.is_dir() and created == [0, 1])
    made2, created2 = beam.make_dirs_within(parent, ["New", "Other"])
    check("existing folders reused", created2 == [1])
    outside = work / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, parent / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        print("SKIP  symlink checks (no permission to create symlinks here)")
        return
    try:
        beam.make_dirs_within(parent, ["link", "sneaky"])
        escaped = True
    except PermissionError:
        escaped = False
    check("upload folders can't be created through a symlink", not escaped and not (outside / "sneaky").exists())
    check("symlink out of the share not resolvable", beam.resolve_in_share(s, "Films/link", show_hidden=True) is None)


def test_tokens():
    beam.settings._data.update(secret="x" * 64, password=None)
    tok = beam.make_session()
    check("session token valid", beam.valid_session(tok))
    check("tampered session refused", not beam.valid_session(tok[:-1] + ("0" if tok[-1] != "0" else "1")))
    h = beam.make_handoff()
    check("handoff token isn't a session", not beam.valid_session(h))
    check("session token isn't a handoff", not beam.use_handoff(tok))
    check("handoff works once", beam.use_handoff(h) and not beam.use_handoff(h))
    exp = f"{int(time.time()) - 5}.abcd"
    import hashlib
    import hmac
    sig = hmac.new(beam._session_key(), exp.encode(), hashlib.sha256).hexdigest()
    check("expired session refused", not beam.valid_session(f"{exp}.{sig}"))
    beam.settings._data.update(password=beam.hash_password("hunter22"))
    check("changing the password signs everyone out", not beam.valid_session(tok))
    check("password check", beam.check_password("hunter22", beam.settings.get("password"))
          and not beam.check_password("hunter23", beam.settings.get("password")))


def test_transfers():
    tr = beam.Transfers()
    check("bad transfer ids ignored", tr.begin("../x", 5) is None and tr.begin("short.1", 5) is None)
    a = tr.begin("abcdefgh12.0", 100)
    b = tr.begin("abcdefgh12.0", 100)  # a second connection for the same file (browser splitting it)
    a.add(60)
    b.add(40)
    snap = tr.snapshot("abcdefgh12")
    check("two connections counted", snap["0"][:3] == [2, 100, 100], snap)
    a.end(True)
    check("still running while one connection is open", tr.snapshot("abcdefgh12")["0"][3] == tr.RUNNING)
    b.end(True)
    check("finished when all connections close", tr.snapshot("abcdefgh12")["0"][:1] == [0]
          and tr.snapshot("abcdefgh12")["0"][3] == tr.DONE)
    c = tr.begin("abcdefgh12.1", 50)
    c.end(False)
    check("interrupted download reported", tr.snapshot("abcdefgh12")["1"][3] == tr.FAILED)
    check("unknown batch is empty", tr.snapshot("zzzzzzzzzz") == {})


def test_netinfo():
    sample = {
        "ad": [{"i": 12, "n": "Ethernet 2", "m": "802.3", "s": "Up", "sp": 1e9, "v": False, "h": True},
               {"i": 7, "n": "Wi-Fi", "m": "Native 802.11", "s": "Up", "sp": 866700000, "v": False, "h": True},
               {"i": 30, "n": "vEthernet (WSL)", "m": "802.3", "s": "Up", "sp": 1e10, "v": True, "h": False},
               {"i": 5, "n": "Ethernet", "m": "802.3", "s": "Disconnected", "sp": 0, "v": False, "h": True}],
        "ip": [{"i": 12, "a": "169.254.10.20"}, {"i": 7, "a": "192.168.1.50"}, {"i": 30, "a": "172.20.0.1"},
               {"i": 1, "a": "127.0.0.1"}],
        "pr": [{"i": 12, "c": "Public"}, {"i": 7, "c": "Private"}],
        "gw": [7],
    }
    got = {x["name"]: x for x in beam.parse_win_netinfo(sample)}
    check("Windows adapters parsed", set(got) == {"Ethernet 2", "Wi-Fi", "vEthernet (WSL)"}, list(got))
    check("cable adapter recognised", got["Ethernet 2"]["kind"] == "ethernet" and beam.is_direct_link(got["Ethernet 2"])
          and got["Ethernet 2"]["category"] == "Public" and got["Ethernet 2"]["speed"] == 10 ** 9)
    check("Wi-Fi recognised", got["Wi-Fi"]["kind"] == "wifi" and not beam.is_direct_link(got["Wi-Fi"]))
    check("virtual adapters aren't cables", got["vEthernet (WSL)"]["kind"] == "other")
    single = {"ad": sample["ad"][0], "ip": sample["ip"][0], "pr": None, "gw": None}  # PowerShell unwraps lone items
    check("single-item PowerShell output parsed", [x["name"] for x in beam.parse_win_netinfo(single)] == ["Ethernet 2"])
    check("junk tolerated", beam.parse_win_netinfo("nonsense") == [] and beam.parse_win_netinfo({"ad": [1, None]}) == [])
    ifaces = beam.detect_interfaces()
    check("this machine's interfaces detected without errors", isinstance(ifaces, list)
          and all({"name", "kind", "ips"} <= set(i) for i in ifaces), json.dumps(ifaces)[:200])


def main():
    work = Path(tempfile.mkdtemp(prefix="beam-unit-"))
    try:
        test_search()
        test_zip(work)
        test_paths(work)
        test_tokens()
        test_transfers()
        test_netinfo()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print(f"\n{'ALL PASSED' if not failures else str(len(failures)) + ' FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
