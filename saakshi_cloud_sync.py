#!/usr/bin/env python3
"""
SAAKSHI cloud sync: puts the Mac's verified view of the ledger on the online dashboard.

  python3 saakshi_cloud_sync.py --link sync_...      once: connect this Mac (the code is on the
                                                     online dashboard under Team -> Connect this Mac)
  python3 saakshi_cloud_sync.py                      keep syncing (every 10 s; Ctrl+C to stop)
  python3 saakshi_cloud_sync.py --once               one sync, then stop
  python3 saakshi_cloud_sync.py --site-url https://<site>.netlify.app    where the buyer QR should point

What goes online: what the Mac dashboard shows (it re-checks every hash, link and chip signature
with the same code, saakshi_dashboard.py), the alerts it works out, and a copy of each verified
ledger line. Genuineness is still decided here and on the buyer's phone, never by the database.

The sync link is a password for ONE organisation's data. It lives in saakshi_cloud/sync_link.txt
(git-ignored, readable only by you). To cut a Mac off: Team -> "Disconnect all Macs" online.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import saakshi_dashboard as D                                  # noqa: E402  same checks as the Mac dashboard

CLOUD_DIR = HERE / "saakshi_cloud"
CONFIG = CLOUD_DIR / "config.json"
LINK_FILE = CLOUD_DIR / "sync_link.txt"
# Public by design (the browser uses the same two values); access is decided by the sync link and RLS.
SUPABASE_URL = "https://ktmmnaviwneopwfkvnwh.supabase.co"
SUPABASE_KEY = "sb_publishable_VFfVoVN1tYy5X_YOU2uPaA_1XJHhMjJ"
READINGS_PER_PUSH = 500
POLYGON_EVERY = 60                                             # seconds between on-chain checks (free reads)


def fingerprint(obj):
    return hashlib.sha1(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:16]


def say(msg):
    print(f"{time.strftime('%H:%M:%S')}  {msg}", flush=True)


class SyncError(Exception):
    pass


def rpc(fn, payload, timeout=60):
    cfg = load_config()
    req = urllib.request.Request(
        f"{cfg['supabase_url']}/rest/v1/rpc/{fn}", data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"apikey": cfg["supabase_key"], "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("message", "")
        except Exception:
            msg = ""
        if "SYNC LINK NOT RECOGNISED" in msg:
            raise SyncError("The online dashboard doesn't recognise this Mac's sync link (it was disconnected, "
                            "or belongs to another project). Make a new one under Team -> Connect this Mac, then:\n"
                            "    python3 saakshi_cloud_sync.py --link <code>")
        raise SyncError(f"Supabase said {e.code}: {msg or e.reason}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise SyncError(f"can't reach Supabase ({getattr(e, 'reason', e)}). Is the internet on?")


def load_config():
    cfg = D.load_json(CONFIG, {})
    cfg.setdefault("supabase_url", SUPABASE_URL)
    cfg.setdefault("supabase_key", SUPABASE_KEY)
    cfg.setdefault("site_url", "")
    return cfg


def save_config(cfg):
    CLOUD_DIR.mkdir(exist_ok=True)
    CONFIG.write_text(json.dumps(cfg, indent=2) + "\n")


def read_link():
    try:
        tok = LINK_FILE.read_text().strip()
    except OSError:
        tok = ""
    if not tok.startswith("sync_"):
        sys.exit("This Mac isn't connected yet. On the online dashboard: Team -> Connect this Mac, then run\n"
                 "    python3 saakshi_cloud_sync.py --link <code it shows>")
    return tok


def save_link(tok):
    CLOUD_DIR.mkdir(exist_ok=True)
    LINK_FILE.write_text(tok + "\n")
    os.chmod(LINK_FILE, 0o600)


# ---------------------------------------------------------------- building what goes online
def share_for(store, node, chain, site_url, current=False):
    """Like the Mac dashboard's share box, but pointing at the online site, with the QR drawn here."""
    base = store.share(node, chain)
    keys = D.load_json(store.relay / "view_keys.json", {})
    if node not in keys:
        return {"url": None, "published": base.get("published"),
                "hint": "Run  python3 saakshi_relay.py --publish  on the Mac, then deploy the site, to make the buyer QR."}
    if not site_url:
        return {"url": None, "published": base.get("published"),
                "hint": "Tell the Mac where the site is:  python3 saakshi_cloud_sync.py --site-url https://<site>.netlify.app"}
    # The current trip gets the node's own link: it always opens the most recently locked trip, so a
    # printed or shown QR never lands on an unfinished trip. Older trips keep a link to themselves.
    url = f"{site_url.rstrip('/')}/verify/?n={node}" + ("" if current else f"&c={chain}") + f"#k={keys[node]}"
    return {"url": url, "published": base.get("published"), "qrSvg": D.qr_svg(url), "latest": current}


def ledger_lines(path, first, last):
    """The exact ledger lines for seq first..last (the CSV is append-only and in seq order)."""
    out = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("#", "seq,")):
                continue
            try:
                seq = int(line.split(",", 1)[0])
            except ValueError:
                continue
            if seq > last:
                break
            if seq >= first:
                out.append((seq, line))
    return out


def sync_once(store, tok, cfg, state):
    pull = rpc("sync_pull", {"p_token": tok})
    taken = set(pull.get("taken") or [])
    with store.lock:
        store.state["nodes"] = pull.get("settings") or {}       # settings and acks are edited online
        store.state["acks"] = pull.get("acks") or {}
    store.scan()
    if time.time() - state.get("polygon_at", 0) >= POLYGON_EVERY:
        state["polygon_at"] = time.time()
        D.refresh_polygon(store)

    ov = D.overview(store)
    for n in ov["nodes"]:
        if n["node"] in taken and n["node"] not in state.setdefault("warned", set()):
            state["warned"].add(n["node"])
            say(f"⚠ {n['node']} belongs to another organisation online - not uploaded from this Mac.")
    nodes = [n for n in ov["nodes"] if n["node"] not in taken]
    mine = {n["node"] for n in nodes}
    trips, sent_fps = [], state.setdefault("trip_fps", {})
    now_fps = {}
    for (node, chain) in sorted(store.trips):
        if node not in mine:
            continue
        v = D.trip_view(store, node, chain)
        if not v:
            continue
        v.pop("alerts", None)                                    # the alerts table has them
        current = next((n["currentChain"] for n in nodes if n["node"] == node), None) == chain
        v["share"] = share_for(store, node, chain, cfg["site_url"], current)
        now_fps[(node, chain)] = fingerprint(v)
        if sent_fps.get((node, chain)) != now_fps[(node, chain)]:   # only trips that changed go up again
            trips.append({"node": node, "chain": chain, "view": v})
    alerts = [{k: a[k] for k in a if k != "acked"} for a in store.all_alerts()
              if a.get("node") is None or a.get("node") in mine]
    # The website polls this fingerprint every few seconds and redraws only when it changes.
    status = {"polygon": ov["polygon"], "crypto": ov["crypto"], "siteUrl": cfg["site_url"] or None, "version": 1,
              "fp": fingerprint([nodes, sorted(now_fps.items(), key=str), alerts])}
    res = rpc("sync_push", {"p_token": tok, "p": {
        "nodes": [{"node": n["node"], "view": n} for n in nodes], "trips": trips,
        "alerts": alerts, "status": status}})
    sent_fps.clear()
    sent_fps.update(now_fps)                                     # remembered only once Supabase has them

    # readings: only rows the Mac has verified, and only the ones not online yet
    sent = 0
    have = pull.get("readings") or {}
    for (node, chain), t in sorted(store.trips.items()):
        if node not in mine or not t.rows:
            continue
        done = have.get(f"{node}_{chain}", -1)
        upto = t.rows[-1]["seq"]
        if upto <= done:
            continue
        first_seq = t.rows[0]["seq"]
        by_seq = {r["seq"]: r for r in t.rows[max(0, done + 1 - first_seq):]}
        batch = []
        for seq, line in ledger_lines(t.path, done + 1, upto):
            r = by_seq.get(seq)
            if r is None:
                continue
            fail = r["flags"] & D.F["SENSOR_FAIL"]
            batch.append({"node": node, "chain": chain, "seq": seq, "t": r["t"] or None,
                          "temp": None if fail else r["temp"], "rh": None if fail else r["rh"],
                          "flags": r["flags"], "line": line})
            if len(batch) >= READINGS_PER_PUSH:
                sent += rpc("sync_push", {"p_token": tok, "p": {"readings": batch}}, timeout=120)["readings"]
                batch = []
        if batch:
            sent += rpc("sync_push", {"p_token": tok, "p": {"readings": batch}}, timeout=120)["readings"]
    return pull, res, sent, len(alerts)


def main():
    ap = argparse.ArgumentParser(description="Put this Mac's verified SAAKSHI ledger on the online dashboard.")
    ap.add_argument("--link", metavar="CODE", help="connect this Mac (code from Team -> Connect this Mac)")
    ap.add_argument("--site-url", help="the deployed site, e.g. https://saakshi-aegisx.netlify.app (saved)")
    ap.add_argument("--once", action="store_true", help="sync once and stop")
    ap.add_argument("--every", type=float, default=10, help="seconds between syncs (default 10, like the board)")
    ap.add_argument("--ledger", default=str(HERE / "saakshi_ledger"))
    ap.add_argument("--relay", default=str(HERE / "saakshi_relay"))
    ap.add_argument("--site", default=str(HERE / "saakshi_site"))
    ap.add_argument("--keys", default=str(HERE), help="folder with saakshi_pubkey*.txt")
    args = ap.parse_args()

    cfg = load_config()
    if args.site_url is not None:
        cfg["site_url"] = args.site_url.strip().rstrip("/")
        save_config(cfg)
        say(f"✓ buyer QR links will point to {cfg['site_url'] or '(nothing)'}")
        if not args.link and not args.once:
            return 0
    if args.link:
        tok = args.link.strip()
        if not tok.startswith("sync_") or len(tok) < 40:
            sys.exit("That doesn't look like a sync code. Copy the whole line from Team -> Connect this Mac.")
        try:
            org = rpc("sync_pull", {"p_token": tok})["org"]
        except SyncError as e:
            sys.exit(f"✗ {e}")
        save_link(tok)
        say(f"✓ this Mac is connected to the organisation \"{org['name']}\" (saved in {LINK_FILE.relative_to(HERE)})")
        if not args.once:
            say("  start syncing with:  python3 saakshi_cloud_sync.py")
            return
    tok = read_link()

    if not D.HAVE_CRYPTO:
        say("⚠ the cryptography module is missing, so chip signatures aren't re-checked here "
            "(python3 -m pip install cryptography)")
    store = D.Store(Path(args.keys), Path(args.ledger), Path(args.relay), Path(args.site), CLOUD_DIR / "state")
    print("SAAKSHI cloud sync - the Mac checks, the website shows")
    print(f"  ledger     {args.ledger}")
    print(f"  online     {cfg['supabase_url']}")
    print(f"  buyer QR   {cfg['site_url'] or 'not set yet (--site-url)'}")
    print("  (Ctrl+C to stop)\n", flush=True)

    state, last_note, failing = {}, "", False
    while True:
        try:
            pull, res, sent, n_alerts = sync_once(store, tok, cfg, state)
            note = f"{res['nodes']} node(s), {n_alerts} alert(s)"
            if sent or note != last_note or failing:
                say(f"✓ synced to \"{pull['org']['name']}\": {note}" + (f", {sent} new reading(s)" if sent else ""))
            last_note, failing = note, False
        except SyncError as e:
            state.pop("trip_fps", None)                          # resend everything once it's back
            if "doesn't recognise" in str(e):
                sys.exit(f"✗ {e}")
            if not failing:
                say(f"✗ {e} - will keep trying")
            failing = True
        except Exception as e:                                   # sync must keep running
            state.pop("trip_fps", None)
            say(f"✗ {type(e).__name__}: {e} - will keep trying")
            failing = True
        if args.once:
            return 1 if failing else 0
        try:
            time.sleep(max(5, args.every))
        except KeyboardInterrupt:
            print()
            return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
