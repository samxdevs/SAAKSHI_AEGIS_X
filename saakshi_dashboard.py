#!/usr/bin/env python3
"""
saakshi_dashboard.py - the SAAKSHI dashboard, served from this Mac (next to saakshi_ledger.py).

    python3 saakshi_dashboard.py              open http://localhost:8080 on this Mac
    python3 saakshi_dashboard.py --lan        also reachable from phones on the same WiFi/hotspot

What it shows (read live from the files the ledger and relay already write - it changes none of them):
  - every node and trip: online/offline, last reading, temperature/humidity charts, jolts, stats
  - integrity: each record re-checked here too (hash, link to the one before, chip signature)
  - anchoring: "locked on Polygon up to record X at time T", read straight from SaakshiRegistry
  - alerts: temperature outside the allowed band, jolts, sensor swapped, chip trouble, node offline,
    and anything the ledger refused (saakshi_ledger/alerts.log)
  - the buyer QR for each trip (opens the verification page, which checks everything on the phone)
  - a public landing page with a "request nodes" form

Accounts: the first person to sign up becomes the admin. Everyone after needs the invite code the admin
sees under Team. Accounts, settings and requests are kept in saakshi_dashboard_data/ (keep it out of git).

Needs nothing extra. Optional:  python3 -m pip install cryptography "qrcode"
  (cryptography: re-check chip signatures here too; qrcode: show the buyer QR as an image)
"""

import argparse
import base64
import csv
import hashlib
import hmac
import io
import json
import mimetypes
import os
import re
import secrets
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal, InvalidOperation
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
WEB = HERE / "saakshi_dashboard_web"

CONTRACT = "0xA82128628b7Ae42183d9B76020CD37C007c18c46"
RPCS = ["https://polygon-amoy-bor-rpc.publicnode.com", "https://polygon-amoy.drpc.org",
        "https://rpc-amoy.polygon.technology"]
EXPLORER = "https://amoy.polygonscan.com"
SEL = {"node": "7c97e6ec", "headCount": "d9701e33", "headAt": "7b751af0", "isAnchored": "4f0b5801"}

FILE_RE = re.compile(r"^(SAAKSHI-[0-9A-F]{8})_([0-9a-f]{8})\.csv$")
NODE_RE = re.compile(r"^SAAKSHI-[0-9A-F]{8}$")
CHAIN_RE = re.compile(r"^[0-9a-f]{8}$")
KEY_RE = re.compile(r"04[0-9a-fA-F]{128}")
COLUMNS = ["seq", "boot", "uptime_s", "unix_time", "temp_c", "rh_pct", "pressure_hpa", "gas_kohm",
           "rtc_temp_c", "mpu_temp_c", "peak_g", "moves", "sensor_id", "flags", "prev_hash", "hash", "sig"]
BODY = struct.Struct("<IIIIiiiihhHHIH32s")
NO_TEMP = -32768
F = dict(BOOT=0x1, SENSOR_FAIL=0x2, NO_TIME=0x4, CLOCK_SET=0x8, MOTION=0x10, SHOCK=0x20,
         TEMP_MISMATCH=0x40, SENSOR_CHANGED=0x80, UNSIGNED=0x100, RTC_FAIL=0x200, MPU_FAIL=0x400,
         LID_OPEN=0x800, ETHYLENE=0x1000, ETH_NONE=0x2000, ETH_WARMUP=0x4000)
ETH_ALERT_PPM = 10      # ME3-C2H4: 0.5 ppm resolution, zero drifts up to 10 ppm - a build-up alarm, not trace levels
GENESIS = bytes(32)

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def say(msg):
    print(time.strftime("%H:%M:%S ") + msg, flush=True)


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return default


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)


# ======================================================================== records

class Bad(Exception):
    pass


def _fixed(text, scale):
    try:
        v = Decimal(text) * scale
    except InvalidOperation:
        raise Bad(f"not a number: {text!r}")
    if v != v.to_integral_value():
        raise Bad(f"too many decimals: {text!r}")
    return int(v)


def _hex(text, n):
    t = text[2:] if text[:2] in ("0x", "0X") else text
    try:
        b = bytes.fromhex(t)
    except ValueError:
        raise Bad("not hex")
    if len(b) != n:
        raise Bad(f"{len(b)} bytes, expected {n}")
    return b


def parse_row(cells):
    """One ledger CSV row -> dict, plus the exact 78 bytes the board hashed."""
    if len(cells) != len(COLUMNS):
        raise Bad(f"{len(cells)} columns")
    c = dict(zip(COLUMNS, (x.strip() for x in cells)))
    try:
        seq, boot, up, t = (int(c[k]) for k in ("seq", "boot", "uptime_s", "unix_time"))
        moves, flags, sid = int(c["moves"]), int(c["flags"]), int(c["sensor_id"], 16)
    except ValueError as e:
        raise Bad(str(e))
    tm, rh, pa, gas = (_fixed(c["temp_c"], 1000), _fixed(c["rh_pct"], 1000),
                       _fixed(c["pressure_hpa"], 100), _fixed(c["gas_kohm"], 1000))
    rtc = NO_TEMP if c["rtc_temp_c"] == "" else _fixed(c["rtc_temp_c"], 100)
    mpu = NO_TEMP if c["mpu_temp_c"] == "" else _fixed(c["mpu_temp_c"], 100)
    peak = _fixed(c["peak_g"], 1000)
    prev, h, sig = _hex(c["prev_hash"], 32), _hex(c["hash"], 32), _hex(c["sig"], 64)
    try:
        body = BODY.pack(seq, boot, up, t, tm, rh, pa, gas, rtc, mpu, peak, moves, sid, flags, prev)
    except struct.error as e:
        raise Bad(str(e))
    return {
        "seq": seq, "boot": boot, "t": t, "temp": tm / 1000, "rh": rh / 1000, "press": pa / 100,
        "gas": gas / 1000, "rtc": None if rtc == NO_TEMP else rtc / 100,
        "mpu": None if mpu == NO_TEMP else mpu / 100, "peak": peak / 1000, "moves": moves,
        "sid": sid, "flags": flags, "prev": prev, "hash": h, "sig": sig, "body": body,
        # firmware v8: the uptime field holds ethylene in ppb when the ETHYLENE flag is set
        "eth": up / 1000 if flags & F["ETHYLENE"] and not flags & F["ETH_NONE"] else None,
    }


class NodeKeys:
    """Public keys from saakshi_pubkey*.txt next to the ledger. The node ID is derived from the key."""

    def __init__(self, folder):
        self.folder, self.keys, self.mtimes = folder, {}, {}

    def refresh(self):
        for p in sorted(self.folder.glob("saakshi_pubkey*.txt")):
            m = p.stat().st_mtime
            if self.mtimes.get(p) == m:
                continue
            self.mtimes[p] = m
            for hx in KEY_RE.findall(p.read_text(encoding="utf-8", errors="replace")):
                raw = bytes.fromhex(hx)
                kh = hashlib.sha256(raw).digest()
                node = "SAAKSHI-" + kh[:4].hex().upper()
                pub = None
                if HAVE_CRYPTO:
                    try:
                        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
                    except ValueError:
                        continue
                self.keys[node] = {"raw": raw, "keyHash": kh, "pub": pub}

    def get(self, node):
        return self.keys.get(node)


def sig_ok(pub, digest, sig):
    der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        pub.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


class Trip:
    """One chain file from the ledger, read incrementally and re-checked record by record."""

    def __init__(self, node, chain, path):
        self.node, self.chain, self.path = node, chain, path
        self.offset, self.rows, self.problem = 0, [], None
        self.mtime, self.covered, self.checked_sigs = 0.0, 0, False
        self.expect_prev = None

    def read_more(self, key):
        st = self.path.stat()
        if st.st_size < self.offset:                      # file replaced: start over
            self.__init__(self.node, self.chain, self.path)
        self.mtime = st.st_mtime
        if st.st_size == self.offset or self.problem:
            return False
        with self.path.open("rb") as f:
            f.seek(self.offset)
            data = f.read()
        end = data.rfind(b"\n")
        if end < 0:
            return False                                  # a line still being written
        chunk = data[:end + 1]
        self.offset += len(chunk)
        pub = key["pub"] if key else None
        self.checked_sigs = pub is not None
        for line in chunk.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("seq,"):
                continue
            try:
                r = parse_row(next(csv.reader([line])))
            except (Bad, StopIteration) as e:
                self.problem = f"unreadable line after seq {self.rows[-1]['seq'] if self.rows else '-'}: {e}"
                return True
            want_seq = self.rows[-1]["seq"] + 1 if self.rows else r["seq"]
            if r["seq"] != want_seq:
                self.problem = f"seq {r['seq']} where {want_seq} was expected (records missing or reordered)"
                return True
            if self.rows:
                link_ok = r["prev"].hex() == self.rows[-1]["hash"]
            else:
                link_ok = r["seq"] != 0 or r["prev"] == GENESIS
            if not link_ok:
                self.problem = f"seq {r['seq']} does not link to the record before it"
                return True
            if hashlib.sha256(r["body"]).digest() != r["hash"]:
                self.problem = f"seq {r['seq']}: contents don't match its hash (DATA ALTERED)"
                return True
            if r["flags"] & F["UNSIGNED"]:
                if r["sig"] != bytes(64):
                    self.problem = f"seq {r['seq']} is marked unsigned but carries a signature"
                    return True
            elif pub is not None and not sig_ok(pub, r["hash"], r["sig"]):
                self.problem = f"seq {r['seq']}: SIGNATURE INVALID (not made by this node's chip)"
                return True
            else:
                self.covered = len(self.rows) + 1
            del r["body"], r["prev"], r["sig"]
            r["hash"] = r["hash"].hex()
            self.rows.append(r)
        return True


# ======================================================================== Polygon

class Polygon:
    """Read-only calls to SaakshiRegistry (free). Runs in the background; never blocks a page."""

    def __init__(self, contract, rpcs):
        self.contract, self.rpcs = contract, rpcs
        self.heads = {}          # node -> list of record hashes (hex), oldest first
        self.registered = {}     # node -> block time or 0
        self.stamps = {}         # record hash -> {"seq", "blockTime"}
        self.error, self.checked_at = None, 0
        self.lock = threading.Lock()

    def _call(self, data):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                           "params": [{"to": self.contract, "data": "0x" + data}, "latest"]}).encode()
        last = None
        for url in self.rpcs:
            try:
                req = urllib.request.Request(url, body, {"Content-Type": "application/json",
                                                         "User-Agent": "saakshi-dashboard"})
                with urllib.request.urlopen(req, timeout=12) as r:
                    j = json.loads(r.read())
                if "error" in j:
                    raise RuntimeError(j["error"].get("message", "RPC error"))
                return j["result"][2:]
            except (OSError, ValueError, RuntimeError, urllib.error.URLError) as e:
                last = e
        raise RuntimeError(f"Polygon not reachable ({last})")

    @staticmethod
    def _word(res, i):
        return res[i * 64:(i + 1) * 64]

    def refresh(self, keys):
        try:
            for node, k in list(keys.items()):
                kh = k["keyHash"].hex()
                reg = int(self._word(self._call(SEL["node"] + kh), 2) or "0", 16)
                n = int(self._call(SEL["headCount"] + kh)[:64] or "0", 16)
                with self.lock:
                    have = list(self.heads.get(node, []))
                for i in range(len(have), n):
                    have.append(self._call(SEL["headAt"] + kh + f"{i:064x}")[:64])
                with self.lock:
                    self.registered[node] = reg
                    self.heads[node] = have
            self.error, self.checked_at = None, time.time()
        except RuntimeError as e:
            self.error = str(e)

    def stamp(self, h):
        with self.lock:
            if h in self.stamps:
                return self.stamps[h]
        try:
            r = self._call(SEL["isAnchored"] + h)
        except RuntimeError:
            return None
        s = {"seq": int(self._word(r, 2), 16), "blockTime": int(self._word(r, 4), 16)}
        with self.lock:
            self.stamps[h] = s
        return s


# ======================================================================== the store

def interval_of(rows):
    ts = [r["t"] for r in rows[-60:] if r["t"]]
    d = sorted(b - a for a, b in zip(ts, ts[1:]) if b > a)
    return d[len(d) // 2] if d else 600


def ranges(seqs):
    out, start, prev = [], None, None
    for s in seqs:
        if start is None:
            start = prev = s
        elif s == prev + 1:
            prev = s
        else:
            out.append((start, prev))
            start = prev = s
    if start is not None:
        out.append((start, prev))
    return out


class Store:
    def __init__(self, base, ledger, relay, site, data):
        self.base, self.ledger, self.relay, self.site, self.data = base, ledger, relay, site, data
        self.keys = NodeKeys(base)
        self.trips = {}                                   # (node, chain) -> Trip
        self.lock = threading.RLock()
        self.state = load_json(data / "state.json", {})
        for k, v in (("users", {}), ("nodes", {}), ("acks", {}), ("orders", []),
                     ("invite", secrets.token_hex(4))):
            self.state.setdefault(k, v)
        self.save()
        cfg = load_json(relay / "config.json", {})
        self.polygon = Polygon(cfg.get("contract", CONTRACT),
                               [cfg["rpc"]] + [u for u in RPCS if u != cfg.get("rpc")] if cfg.get("rpc") else RPCS)
        self.ledger_alerts, self.alerts_offset = [], 0

    def save(self):
        with self.lock:
            save_json(self.data / "state.json", self.state)

    # ---------------------------------------------------------------- reading
    def scan(self):
        with self.lock:
            self.keys.refresh()
            if self.ledger.is_dir():
                for p in sorted(self.ledger.glob("*.csv")):
                    m = FILE_RE.match(p.name)
                    if not m:
                        continue
                    k = (m.group(1), m.group(2))
                    t = self.trips.get(k) or self.trips.setdefault(k, Trip(k[0], k[1], p))
                    try:
                        t.read_more(self.keys.get(k[0]))
                    except OSError:
                        pass
            self._read_ledger_alerts()

    def _read_ledger_alerts(self):
        p = self.ledger / "alerts.log"
        try:
            size = p.stat().st_size
        except OSError:
            return
        if size < self.alerts_offset:
            self.ledger_alerts, self.alerts_offset = [], 0
        if size == self.alerts_offset:
            return
        with p.open("rb") as f:
            f.seek(self.alerts_offset)
            data = f.read()
        end = data.rfind(b"\n")
        if end < 0:
            return
        start = self.alerts_offset
        self.alerts_offset += end + 1
        for line in data[:end + 1].decode("utf-8", "replace").splitlines():
            parts = re.split(r"\s{2,}", line.strip(), maxsplit=2)
            if len(parts) < 3 or parts[2].startswith("refused:"):
                continue
            stamp, where, text = parts
            node, chain = (where.split() + [None, None])[:2] if where != "-" else (None, None)
            crit = any(w in text for w in ("REFUSED", "CHANGED AFTER SYNC", "DIFFERENT public key", "fewer records"))
            uid = hashlib.sha1(f"{start}|{line}".encode()).hexdigest()[:12]
            try:
                when = int(time.mktime(time.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S")))
            except ValueError:
                when = 0
            self.ledger_alerts.append({
                "id": f"ledger|{uid}", "type": "ledger", "severity": "critical" if crit else "info",
                "node": node if node and NODE_RE.match(node) else None, "chain": chain, "seq": None,
                "time": when, "title": "Ledger refused a record" if "REFUSED" in text else "Ledger notice",
                "detail": text[:300]})

    # ---------------------------------------------------------------- settings
    def node_settings(self, node):
        s = dict(self.state["nodes"].get(node, {}))
        rng = load_json(self.relay / "config.json", {}).get("range")
        s.setdefault("name", "")
        if "lo" not in s and rng:
            s["lo"], s["hi"] = rng
        s.setdefault("lo", None)
        s.setdefault("hi", None)
        s.setdefault("minutes", 15)
        s.setdefault("offlineMinutes", 0)          # 0 = automatic (3 x the logging interval)
        return s

    # ---------------------------------------------------------------- alerts
    def trip_alerts(self, t, s):
        out = []
        rows, node, chain = t.rows, t.node, t.chain

        def add(kind, sev, r, title, detail, end=None):
            out.append({"id": f"{kind}|{node}|{chain}|{r['seq']}", "type": kind, "severity": sev,
                        "node": node, "chain": chain, "seq": r["seq"], "endSeq": end, "time": r["t"],
                        "title": title, "detail": detail})

        if t.problem:
            out.append({"id": f"integrity|{node}|{chain}", "type": "integrity", "severity": "critical",
                        "node": node, "chain": chain, "seq": None, "time": int(t.mtime),
                        "title": "Ledger file failed the integrity check", "detail": t.problem})
        lo, hi, mins = s["lo"], s["hi"], s["minutes"] or 0
        step = interval_of(rows)
        good = [r for r in rows if not r["flags"] & F["SENSOR_FAIL"]]
        if lo is not None and hi is not None:
            i = 0
            while i < len(good):
                if lo <= good[i]["temp"] <= hi:
                    i += 1
                    continue
                j = i
                while j + 1 < len(good) and not (lo <= good[j + 1]["temp"] <= hi):
                    j += 1
                a, b = good[i], good[j]
                nxt = good[j + 1] if j + 1 < len(good) else None
                if a["t"] and (nxt or b)["t"] and (nxt or b)["t"] >= a["t"]:
                    secs = (nxt or b)["t"] - a["t"] + (0 if nxt else step)
                else:
                    secs = (j - i + 1) * step
                if secs >= mins * 60:
                    worst = max(good[i:j + 1], key=lambda r: abs(r["temp"] - (hi if r["temp"] > hi else lo)))
                    side = "above" if worst["temp"] > hi else "below"
                    add("excursion", "critical" if secs >= 4 * max(mins, 15) * 60 else "serious", a,
                        f"Temperature {side} {hi if side == 'above' else lo:g} °C for {fmt_dur(secs)}",
                        f"Records #{a['seq']}–#{b['seq']}, worst {worst['temp']:.2f} °C at #{worst['seq']}."
                        + ("" if nxt else " Still outside the band."), b["seq"])
                i = j + 1
        shocks = [r for r in rows if r["flags"] & F["SHOCK"]]
        group = []
        for r in shocks + [None]:                     # jolts a few records apart are one event (e.g. loading)
            if group and (r is None or r["seq"] - group[-1]["seq"] > 3):
                top = max(group, key=lambda x: x["peak"])
                n = len(group)
                add("shock", "serious" if top["peak"] >= 2 else "warning", group[0],
                    f"Jolt of {top['peak']:.2f} g" if n == 1 else f"{n} jolts, up to {top['peak']:.2f} g",
                    (f"Record #{top['seq']}" if n == 1 else f"Records #{group[0]['seq']}–#{group[-1]['seq']}")
                    + ". Produce may be bruised; check the crate.", group[-1]["seq"] if n > 1 else None)
                group = []
            if r is not None:
                group.append(r)
        eth = [r for r in rows if r["eth"] is not None and not r["flags"] & F["ETH_WARMUP"]]
        high = [r["seq"] for r in eth if r["eth"] >= ETH_ALERT_PPM]
        by_seq = {r["seq"]: r for r in eth}
        for a, b in ranges(high):
            if b - a + 1 >= 3:                        # three readings in a row: not a one-off blip
                top = max((by_seq[s] for s in range(a, b + 1) if s in by_seq), key=lambda x: x["eth"])
                add("ethylene", "serious" if top["eth"] >= 50 else "warning", by_seq[a],
                    f"Ethylene build-up, up to {top['eth']:.1f} ppm",
                    f"Records #{a}–#{b}. Ripening produce gives off ethylene and speeds up ripening of the rest; "
                    "check ventilation and what is stored nearby. (Hydrogen also registers on this sensor.)", b)
        for r in rows:
            if r["flags"] & F["SENSOR_CHANGED"]:
                add("sensor", "critical", r, "Temperature sensor swapped",
                    f"The BME688's factory fingerprint changed at record #{r['seq']}. "
                    "Someone may have replaced or tampered with the sensor.")
        for kind, flag, minimum, sev, title, why in (
                ("mismatch", "TEMP_MISMATCH", 3, "warning", "Thermometers disagree",
                 "The main sensor differs from both backup thermometers by more than 6 °C."),
                ("unsigned", "UNSIGNED", 6, "warning", "Security chip missed signatures",
                 "Each is still covered by the next signed record, but a long run points to chip trouble."),
                ("sensorfail", "SENSOR_FAIL", 3, "warning", "Climate sensor not answering",
                 "These readings are left out of the charts.")):
            seqs = [r["seq"] for r in rows if r["flags"] & F[flag]]
            for a, b in ranges(seqs):
                if b - a + 1 >= minimum:
                    r = rows[a - rows[0]["seq"]]
                    add(kind, sev, r, f"{title} ({b - a + 1} records)", f"Records #{a}–#{b}. {why}", b)
        return out

    def node_status(self, node, trips, s, now):
        latest = max(trips, key=lambda t: t.mtime) if trips else None
        if not latest or not latest.rows:
            return {"state": "never", "lastHeard": None, "interval": None}
        step = interval_of(latest.rows)
        limit = (s["offlineMinutes"] * 60) if s["offlineMinutes"] else max(3 * step, 120)
        age = now - latest.mtime
        return {"state": "online" if age <= limit else "offline", "lastHeard": int(latest.mtime),
                "interval": step, "offlineAfter": limit}

    def all_alerts(self, now=None):
        now = now or time.time()
        with self.lock:
            out = []
            by_node = {}
            for t in self.trips.values():
                by_node.setdefault(t.node, []).append(t)
            for node, trips in by_node.items():
                s = self.node_settings(node)
                for t in trips:
                    out += self.trip_alerts(t, s)
                st = self.node_status(node, trips, s, now)
                if st["state"] == "offline":
                    out.append({"id": f"offline|{node}|{st['lastHeard']}", "type": "offline", "severity": "serious",
                                "node": node, "chain": None, "seq": None, "time": st["lastHeard"],
                                "title": "Node offline",
                                "detail": f"Nothing received for {fmt_dur(now - st['lastHeard'])}. "
                                          "It keeps logging and chaining; records arrive when it reconnects."})
            out += self.ledger_alerts
            for a in out:
                ack = self.state["acks"].get(a["id"])
                a["acked"] = ack
            rank = {"critical": 0, "serious": 1, "warning": 2, "info": 3}
            out.sort(key=lambda a: (bool(a["acked"]), rank.get(a["severity"], 4), -(a["time"] or 0)))
            return out

    # ---------------------------------------------------------------- anchors
    def anchor_for(self, t):
        heads = set(self.polygon.heads.get(t.node, []))
        posted = {p["hash"]: p for p in load_json(self.relay / "posted.json", []) if isinstance(p, dict)}
        best = None
        for i in range(t.covered - 1, -1, -1):
            h = t.rows[i]["hash"]
            if h in heads or (not heads and h in posted):
                best = i
                break
        res = {"source": "polygon" if heads else ("relay" if posted else None),
               "error": self.polygon.error, "checkedAt": int(self.polygon.checked_at) or None,
               "registered": self.polygon.registered.get(t.node), "signedUpTo": t.rows[t.covered - 1]["seq"] if t.covered else None}
        if best is None:
            return res
        h = t.rows[best]["hash"]
        with self.polygon.lock:
            stamp = self.polygon.stamps.get(h) if heads else None
        p = posted.get(h)
        res.update({"seq": t.rows[best]["seq"], "hash": h,
                    "time": (stamp or {}).get("blockTime") or (p or {}).get("time"),
                    "tx": (p or {}).get("tx"), "behind": t.covered - 1 - best})
        return res

    # ---------------------------------------------------------------- share
    def share(self, node, chain):
        keys = load_json(self.relay / "view_keys.json", {})
        site = load_json(self.relay / "config.json", {}).get("site_url", "http://localhost:8000").rstrip("/")
        idx = load_json(self.site / "verify" / "data" / "index.json", {}).get("nodes", {}).get(node, [])
        pub = next((e for e in idx if e.get("chain") == chain), None)
        if node not in keys:
            return {"url": None, "published": pub, "hint": "Run  python3 saakshi_relay.py --publish  to make the buyer QR."}
        url = f"{site}/verify/?n={node}&c={chain}#k={keys[node]}"
        return {"url": url, "published": pub, "local": site.startswith("http://localhost")}


def fmt_dur(s):
    s = int(max(0, s))
    if s < 90:
        return f"{s} s"
    d, h, m = s // 86400, s % 86400 // 3600, s % 3600 // 60
    if d:
        return f"{d} d {h} h"
    if h:
        return f"{h} h {m} min"
    return f"{m} min"


# ======================================================================== views

def summarise(rows, s):
    good = [r for r in rows if not r["flags"] & F["SENSOR_FAIL"]]
    timed = [r["t"] for r in rows if r["t"]]

    def st(vals):
        return {"min": min(vals), "max": max(vals), "avg": sum(vals) / len(vals)} if vals else None
    out = {"records": len(rows), "from": timed[0] if timed else None, "to": timed[-1] if timed else None,
           "temp": st([r["temp"] for r in good]), "rh": st([r["rh"] for r in good]),
           "shocks": sum(1 for r in rows if r["flags"] & F["SHOCK"]),
           "maxG": max((r["peak"] for r in rows), default=0),
           "restarts": sum(1 for r in rows[1:] if r["flags"] & F["BOOT"]),
           "unsigned": sum(1 for r in rows if r["flags"] & F["UNSIGNED"]),
           "noTime": sum(1 for r in rows if not r["t"]),
           "sensorFail": len(rows) - len(good),
           "mpuMissing": bool(rows) and all(r["flags"] & F["MPU_FAIL"] for r in rows[-20:]),
           "eth": st([r["eth"] for r in rows if r["eth"] is not None and not r["flags"] & F["ETH_WARMUP"]]),
           # none: no v8 records or no sensor; warmup: first 48 h powered; ok: settled readings
           "ethState": ("ok" if rows and rows[-1]["eth"] is not None and not rows[-1]["flags"] & F["ETH_WARMUP"]
                        else "warmup" if rows and rows[-1]["eth"] is not None else "none")}
    if s["lo"] is not None and s["hi"] is not None and good:
        step = interval_of(rows)
        out_n, secs = 0, 0
        for a, b in zip(good, good[1:] + [None]):
            if not (s["lo"] <= a["temp"] <= s["hi"]):
                out_n += 1
                secs += (b["t"] - a["t"]) if (b and a["t"] and b["t"] > a["t"]) else step
        out["band"] = {"lo": s["lo"], "hi": s["hi"], "outside": out_n, "outsideSecs": secs}
    return out


def buckets(rows, n=360):
    """Downsample for charts: per bucket min/avg/max, keeping seq and time."""
    if not rows:
        return []
    size = max(1, -(-len(rows) // n))
    out = []
    for i in range(0, len(rows), size):
        part = rows[i:i + size]
        good = [r for r in part if not r["flags"] & F["SENSOR_FAIL"]]
        t = next((r["t"] for r in part if r["t"]), 0)
        b = {"s0": part[0]["seq"], "s1": part[-1]["seq"], "t": t,
             "g": max(r["peak"] for r in part), "shock": any(r["flags"] & F["SHOCK"] for r in part)}
        if good:
            for k in ("temp", "rh"):
                v = [r[k] for r in good]
                b[k] = [round(min(v), 3), round(sum(v) / len(v), 3), round(max(v), 3)]
        e = [r["eth"] for r in part if r["eth"] is not None]
        if e:
            b["eth"] = [round(min(e), 3), round(sum(e) / len(e), 3), round(max(e), 3)]
            if any(r["flags"] & F["ETH_WARMUP"] for r in part):
                b["ethWarm"] = True
        out.append(b)
    return out


def last_reading(r):
    return {k: r[k] for k in ("seq", "t", "temp", "rh", "press", "gas", "rtc", "mpu", "peak", "moves", "flags", "eth")}


def overview(store):
    now = time.time()
    alerts = store.all_alerts(now)
    with store.lock:
        by_node = {}
        for t in store.trips.values():
            by_node.setdefault(t.node, []).append(t)
        nodes = []
        for node in sorted(by_node):
            trips = sorted(by_node[node], key=lambda t: t.rows[0]["t"] if t.rows and t.rows[0]["t"] else t.mtime)
            s = store.node_settings(node)
            latest = max(trips, key=lambda t: t.mtime)
            open_alerts = [a for a in alerts if a["node"] == node and not a["acked"]]
            nodes.append({
                "node": node, "name": s["name"], "settings": s,
                "status": store.node_status(node, trips, s, now),
                "keyKnown": store.keys.get(node) is not None,
                "last": last_reading(latest.rows[-1]) if latest.rows else None,
                "currentChain": latest.chain,
                "trips": [{"chain": t.chain, "records": len(t.rows), "first": t.rows[0]["seq"] if t.rows else None,
                           "last": t.rows[-1]["seq"] if t.rows else None,
                           "from": next((r["t"] for r in t.rows if r["t"]), None),
                           "to": next((r["t"] for r in reversed(t.rows) if r["t"]), None),
                           "problem": t.problem} for t in trips],
                "anchor": store.anchor_for(latest) if latest.rows else None,
                "alerts": {"open": len(open_alerts),
                           "worst": open_alerts[0]["severity"] if open_alerts else None},
            })
    return {"nodes": nodes, "now": int(now), "crypto": HAVE_CRYPTO,
            "polygon": {"error": store.polygon.error, "checkedAt": int(store.polygon.checked_at) or None,
                        "contract": store.polygon.contract, "explorer": EXPLORER},
            "openAlerts": sum(1 for a in alerts if not a["acked"])}


def trip_view(store, node, chain):
    with store.lock:
        t = store.trips.get((node, chain))
        if not t:
            return None
        s = store.node_settings(node)
        rows = t.rows
        recent = [last_reading(r) for r in rows[-25:]][::-1]
        return {
            "node": node, "chain": chain, "settings": s,
            "integrity": {"records": len(rows), "problem": t.problem, "signaturesChecked": t.checked_sigs,
                          "covered": t.covered, "unsigned": sum(1 for r in rows if r["flags"] & F["UNSIGNED"])},
            "stats": summarise(rows, s), "series": buckets(rows), "recent": recent,
            "anchor": store.anchor_for(t) if rows else None,
            "share": store.share(node, chain),
            "alerts": [a for a in store.all_alerts() if a["node"] == node and (a["chain"] in (chain, None))],
        }


# ======================================================================== auth

def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 240_000).hex()


class Auth:
    def __init__(self, store, setup_code=None):
        self.store, self.sessions, self.fails = store, {}, {}
        self.setup_code = setup_code          # when online: the first (admin) sign-up must give this code
        self.lock = threading.Lock()

    def user_count(self):
        return len(self.store.state["users"])

    def signup(self, email, name, pw, invite):
        email = email.strip().lower()
        if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,24}", email):
            raise ValueError("Enter a valid email address.")
        if len(pw) < 8:
            raise ValueError("Use at least 8 characters for the password.")
        if not name.strip() or len(name) > 80:
            raise ValueError("Enter your name.")
        with self.store.lock:
            users = self.store.state["users"]
            first = not users
            if first and self.setup_code and not hmac.compare_digest(invite.strip().lower(), self.setup_code):
                raise ValueError("That setup code isn't right. It's printed in the server's log when it starts.")
            if not first and not hmac.compare_digest(invite.strip().lower(), self.store.state["invite"]):
                raise ValueError("That invite code isn't right. Ask your admin for the code under Team.")
            if email in users:
                raise ValueError("An account with this email already exists. Log in instead.")
            salt = os.urandom(16)
            users[email] = {"name": name.strip(), "salt": salt.hex(), "hash": hash_pw(pw, salt),
                            "role": "admin" if first else "member", "created": int(time.time())}
            self.store.save()
        return self.new_session(email)

    def login(self, email, pw, ip):
        email = email.strip().lower()
        with self.lock:
            recent = [t for t in self.fails.get(ip, []) if time.time() - t < 600]
            self.fails[ip] = recent
            if len(recent) >= 8:
                raise ValueError("Too many attempts. Wait 10 minutes and try again.")
        u = self.store.state["users"].get(email)
        ok = u is not None and hmac.compare_digest(hash_pw(pw, bytes.fromhex(u["salt"])), u["hash"])
        if not ok:
            with self.lock:
                self.fails[ip].append(time.time())
            raise ValueError("Email or password is wrong.")
        return self.new_session(email)

    def new_session(self, email):
        tok = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[tok] = (email, time.time() + 7 * 86400)
        return tok

    def user(self, tok):
        with self.lock:
            s = self.sessions.get(tok or "")
            if not s or s[1] < time.time():
                return None
        u = self.store.state["users"].get(s[0])
        return dict(u, email=s[0]) if u else None

    def logout(self, tok):
        with self.lock:
            self.sessions.pop(tok or "", None)


# ======================================================================== HTTP

STATIC = {"/": "index.html", "/app": "app.html", "/static/app.js": "app.js", "/static/app.css": "app.css",
          "/static/landing.css": "landing.css", "/static/theme.js": "theme.js"}
ORDER_HITS = {}


class Handler(BaseHTTPRequestHandler):
    server_version = "SAAKSHI"
    store: Store = None
    auth: Auth = None

    def log_message(self, fmt, *args):
        pass

    # ---------------------------------------------------------------- helpers
    def send_json(self, obj, code=200, headers=None):
        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_security()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_security(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def fail(self, code, msg):
        self.send_json({"error": msg}, code)

    def cookie_token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "saakshi_session":
                return v
        return None

    def current_user(self):
        return self.auth.user(self.cookie_token())

    def read_body(self, limit=8192):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise ValueError("too large")
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise ValueError("bad request")

    behind_proxy = False

    def client_ip(self):
        ip = self.client_address[0]
        if self.behind_proxy and ip in ("127.0.0.1", "::1"):       # only trust the header from our own proxy
            fwd = (self.headers.get("X-Forwarded-For") or "").split(",")[-1].strip()
            if fwd:
                return fwd
        return ip

    def session_cookie(self, tok, max_age=7 * 86400):
        secure = "; Secure" if self.behind_proxy else ""
        return {"Set-Cookie": f"saakshi_session={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}"}

    # ---------------------------------------------------------------- GET
    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(url.query)
        path = url.path.rstrip("/") or "/"
        if path in STATIC:
            return self.send_file(WEB / STATIC[path])
        if path == "/verify" or path.startswith("/verify/"):
            return self.send_site(url.path)
        if not path.startswith("/api/"):
            return self.fail(404, "not found")
        if path == "/api/me":
            u = self.current_user()
            return self.send_json({"user": {"name": u["name"], "email": u["email"], "role": u["role"]} if u else None,
                                   "firstUser": self.auth.user_count() == 0,
                                   "needsSetupCode": self.auth.user_count() == 0 and bool(self.auth.setup_code)})
        u = self.current_user()
        if not u:
            return self.fail(401, "log in first")
        if path == "/api/overview":
            return self.send_json(overview(self.store))
        if path == "/api/trip":
            node, chain = (q.get("node") or [""])[0], (q.get("chain") or [""])[0]
            if not NODE_RE.match(node) or not CHAIN_RE.match(chain):
                return self.fail(400, "bad node or chain")
            v = trip_view(self.store, node, chain)
            return self.send_json(v) if v else self.fail(404, "no such trip")
        if path == "/api/alerts":
            return self.send_json({"alerts": self.store.all_alerts()})
        if path == "/api/export":
            node, chain = (q.get("node") or [""])[0], (q.get("chain") or [""])[0]
            t = self.store.trips.get((node, chain))
            if not t:
                return self.fail(404, "no such trip")
            return self.send_file(t.path, download=f"{node}_{chain}.csv")
        if path == "/api/qr":
            node, chain = (q.get("node") or [""])[0], (q.get("chain") or [""])[0]
            sh = self.store.share(node, chain) if NODE_RE.match(node) and CHAIN_RE.match(chain) else {}
            svg = qr_svg(sh.get("url")) if sh.get("url") else None
            if not svg:
                return self.fail(404, "no QR")
            data = svg.encode()
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Cache-Control", "no-store")
            self.send_security()
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        if path == "/api/team":
            if u["role"] != "admin":
                return self.fail(403, "admins only")
            st = self.store.state
            return self.send_json({"invite": st["invite"],
                                   "users": [{"email": e, "name": x["name"], "role": x["role"], "created": x["created"]}
                                             for e, x in sorted(st["users"].items())]})
        if path == "/api/orders":
            if u["role"] != "admin":
                return self.fail(403, "admins only")
            return self.send_json({"orders": self.store.state["orders"][::-1]})
        return self.fail(404, "not found")

    def send_site(self, raw):
        """The static buyer page from saakshi_site/verify/. It checks everything in the buyer's browser."""
        if raw == "/verify":                                       # keep its relative links (core.js, data/) working
            q = urllib.parse.urlsplit(self.path).query
            self.send_response(301)
            self.send_header("Location", "/verify/" + ("?" + q if q else ""))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        root = (self.store.site / "verify").resolve()
        rel = urllib.parse.unquote(raw)[len("/verify/"):] or "index.html"
        target = (root / rel).resolve()
        if root not in target.parents or not target.is_file():
            return self.fail(404, "not found")
        return self.send_file(target)

    def send_file(self, p, download=None):
        try:
            data = p.read_bytes()
        except OSError:
            return self.fail(404, "not found")
        ctype = "text/csv" if download else (mimetypes.guess_type(p.name)[0] or "application/octet-stream")
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-cache")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.send_security()
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---------------------------------------------------------------- POST
    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path.rstrip("/")
        if self.headers.get("X-Requested-With") != "saakshi":      # blocks cross-site form posts
            return self.fail(403, "forbidden")
        try:
            body = self.read_body()
        except ValueError as e:
            return self.fail(400, str(e))
        g = lambda k, n=200: str(body.get(k) or "")[:n]
        ip = self.client_ip()
        try:
            if path == "/api/signup":
                tok = self.auth.signup(g("email"), g("name", 80), g("password"), g("invite", 40))
                return self.send_json({"ok": True}, headers=self.session_cookie(tok))
            if path == "/api/login":
                tok = self.auth.login(g("email"), g("password"), ip)
                return self.send_json({"ok": True}, headers=self.session_cookie(tok))
            if path == "/api/logout":
                self.auth.logout(self.cookie_token())
                return self.send_json({"ok": True}, headers=self.session_cookie("", 0))
            if path == "/api/orders":
                hits = [t for t in ORDER_HITS.get(ip, []) if time.time() - t < 3600]
                if len(hits) >= 5:
                    return self.fail(429, "Too many requests from this device. Try again later.")
                name, contact = g("name", 80).strip(), g("contact", 120).strip()
                if not name or not contact:
                    return self.fail(400, "Please give your name and a phone number or email.")
                try:
                    count = max(1, min(10000, int(body.get("nodes") or 1)))
                except (TypeError, ValueError):
                    count = 1
                ORDER_HITS[ip] = hits + [time.time()]
                with self.store.lock:
                    self.store.state["orders"].append({
                        "id": secrets.token_hex(4), "time": int(time.time()), "name": name,
                        "company": g("company", 120).strip(), "contact": contact, "nodes": count,
                        "product": g("product", 120).strip(), "note": g("note", 600).strip(), "status": "new"})
                    self.store.save()
                return self.send_json({"ok": True})
        except ValueError as e:
            return self.fail(400, str(e))

        u = self.current_user()
        if not u:
            return self.fail(401, "log in first")
        if path == "/api/alerts/ack":
            aid = g("id", 200)
            with self.store.lock:
                if body.get("undo"):
                    self.store.state["acks"].pop(aid, None)
                else:
                    self.store.state["acks"][aid] = {"by": u["name"], "at": int(time.time())}
                self.store.save()
            return self.send_json({"ok": True})
        if path == "/api/nodes/settings":
            node = g("node", 20)
            if not NODE_RE.match(node):
                return self.fail(400, "bad node")
            cur = dict(self.store.state["nodes"].get(node, {}))
            if "name" in body:
                cur["name"] = g("name", 60).strip()
            try:
                for k in ("lo", "hi"):
                    if k in body:
                        v = body[k]
                        cur[k] = None if v in (None, "") else round(float(v), 2)
                if cur.get("lo") is not None and cur.get("hi") is not None and cur["lo"] >= cur["hi"]:
                    return self.fail(400, "The lowest temperature must be below the highest.")
                for k, top in (("minutes", 1440), ("offlineMinutes", 1440)):
                    if k in body:
                        cur[k] = max(0, min(top, int(body[k] or 0)))
            except (TypeError, ValueError):
                return self.fail(400, "Numbers only, please.")
            with self.store.lock:
                self.store.state["nodes"][node] = cur
                self.store.save()
            return self.send_json({"ok": True, "settings": self.store.node_settings(node)})
        if path == "/api/anchors/refresh":
            threading.Thread(target=refresh_polygon, args=(self.store,), daemon=True).start()
            return self.send_json({"ok": True})
        if path == "/api/team/invite" and u["role"] == "admin":
            with self.store.lock:
                self.store.state["invite"] = secrets.token_hex(4)
                self.store.save()
            return self.send_json({"invite": self.store.state["invite"]})
        if path == "/api/orders/status" and u["role"] == "admin":
            oid, status = g("id", 20), g("status", 20)
            if status not in ("new", "contacted", "done"):
                return self.fail(400, "bad status")
            with self.store.lock:
                for o in self.store.state["orders"]:
                    if o["id"] == oid:
                        o["status"] = status
                self.store.save()
            return self.send_json({"ok": True})
        return self.fail(404, "not found")


def qr_svg(url):
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return None
    try:
        img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, border=2)
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue().decode()
    except Exception:                                  # an unexpected qrcode version: show the link only
        return None


def refresh_polygon(store):
    """Network calls happen here, outside the store lock, so pages never wait on Polygon."""
    with store.lock:
        keys = dict(store.keys.keys)
    if not keys:
        return
    store.polygon.refresh(keys)
    with store.lock:
        want = []
        for t in store.trips.values():
            heads = set(store.polygon.heads.get(t.node, []))
            for i in range(t.covered - 1, -1, -1):
                if t.rows[i]["hash"] in heads:
                    want.append(t.rows[i]["hash"])
                    break
    for h in want:
        store.polygon.stamp(h)


def background(store, every_scan, every_chain):
    last_chain = 0
    while True:
        try:
            store.scan()
            if time.time() - last_chain >= every_chain:
                last_chain = time.time()
                refresh_polygon(store)
        except Exception as e:                       # the dashboard must keep running
            say(f"background: {type(e).__name__}: {e}")
        time.sleep(every_scan)


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="SAAKSHI dashboard on this Mac.")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--lan", action="store_true", help="let phones on the same WiFi open it")
    ap.add_argument("--ledger", type=Path, default=HERE / "saakshi_ledger")
    ap.add_argument("--relay", type=Path, default=HERE / "saakshi_relay")
    ap.add_argument("--site", type=Path, default=HERE / "saakshi_site")
    ap.add_argument("--data", type=Path, default=HERE / "saakshi_dashboard_data")
    ap.add_argument("--keys", type=Path, default=HERE, help="folder with saakshi_pubkey*.txt (default: next to this script)")
    ap.add_argument("--offline", action="store_true", help="don't contact Polygon")
    ap.add_argument("--behind-proxy", action="store_true",
                    help="on a server behind Caddy/HTTPS: secure cookies, real client IPs, setup code for the admin")
    args = ap.parse_args()

    if not (WEB / "app.html").exists():
        sys.exit(f"{WEB} is missing - unzip saakshi_dashboard.zip so that folder sits next to this script.")
    store = Store(args.keys, args.ledger, args.relay, args.site, args.data)
    store.scan()
    if args.offline:
        store.polygon.error = "Polygon not checked (--offline)"
    setup_code = None
    if args.behind_proxy and not store.state["users"]:
        setup_code = secrets.token_hex(4)
    Handler.store, Handler.auth = store, Auth(store, setup_code)
    Handler.behind_proxy = args.behind_proxy
    threading.Thread(target=background, args=(store, 5, 10**9 if args.offline else 60), daemon=True).start()

    host = "0.0.0.0" if args.lan else "127.0.0.1"
    try:
        srv = ThreadingHTTPServer((host, args.port), Handler)
    except OSError as e:
        sys.exit(f"Can't use port {args.port} ({e}). Try:  python3 saakshi_dashboard.py --port 8090")
    n_rec = sum(len(t.rows) for t in store.trips.values())
    print("SAAKSHI dashboard")
    print(f"  ledger        {args.ledger}  ({len(store.trips)} trip(s), {n_rec} records)")
    print(f"  signatures    {'re-checked here' if HAVE_CRYPTO else 'not re-checked (pip install cryptography)'}")
    print(f"  open          http://localhost:{args.port}")
    if args.lan:
        print(f"  on phones     http://{lan_ip() or '<this Mac IP>'}:{args.port}  (same WiFi/hotspot)")
    if not store.state["users"]:
        print("  first sign-up becomes the admin" + (f" - it needs this setup code: {setup_code}" if setup_code else ""))
    print("  (Ctrl+C to stop)\n", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
