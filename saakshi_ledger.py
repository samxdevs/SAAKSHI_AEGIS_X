#!/usr/bin/env python3
"""
saakshi_ledger.py - the laptop end of SAAKSHI sync (node firmware v6, v7, v7.1).

Nodes send every record over MQTT. The ledger checks each one before keeping it:
  - its contents still match its hash,
  - it links to the record before it, and
  - its signature was made by this node's ATECC608 (checked against saakshi_pubkey.txt).
Only records that pass are stored, one CSV per chain, in the folder saakshi_ledger/. Anything else is
refused and noted in saakshi_ledger/alerts.log. After any dropout the ledger tells the node exactly
where its copy ends, so nothing is lost or doubled.

    python3 saakshi_ledger.py --tls                 encrypted: your own broker on this Mac (firmware v7.1,
                                                    after  python3 saakshi_broker.py setup  and  ... run)
    python3 saakshi_ledger.py                       public test broker, NOT encrypted (firmware v7)
    python3 saakshi_ledger.py --broker localhost    plain mosquitto on this Mac, NOT encrypted

Leave it running; Ctrl+C stops it, and next time it carries on from its files.
Needs saakshi_pull.py and saakshi_pubkey.txt in the same folder, and:  python3 -m pip install paho-mqtt

A ledger file is an ordinary chain CSV:
    python3 saakshi_pull.py --file saakshi_ledger/<file>.csv   check and chart the ledger's copy
    python3 saakshi_pull.py --against ledger                   compare what the board holds now with it
"""

import argparse
import hashlib
import re
import json
import socket
import ssl
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path

try:
    import paho.mqtt.client as mqtt
except ImportError:
    sys.exit("paho-mqtt is not installed. Run:  python3 -m pip install paho-mqtt")

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import saakshi_pull as sp
except ImportError:
    sys.exit("saakshi_pull.py must be in the same folder as saakshi_ledger.py")

NODE_RE = re.compile(r"^SAAKSHI-[0-9A-F]{8}$")
CHAIN_RE = re.compile(r"^[0-9a-f]{8}$")
KEY_RE = re.compile(r"^04[0-9a-fA-F]{128}$")
HEADER_LINE = ",".join(sp.HEADER_V4)
LOCAL = {"localhost", "127.0.0.1", "::1"}
DEFAULT_BROKER = "broker.hivemq.com"


_before_say = []                                # called before each line: prints grouped refusals first


def say(msg):
    for hook in _before_say:
        hook()
    print(f"{datetime.now():%H:%M:%S}  {msg}", flush=True)


def lan_ip():
    """This Mac's address on the network the board would use (no traffic is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def events(r):
    out = []
    if r.flags & sp.F_BOOT:
        out.append("power-up")
    if r.flags & sp.F_CLOCK_SET:
        out.append("clock set")
    if r.flags & sp.F_SHOCK:
        out.append(f"SHOCK {r.peak_mg / 1000:.2f} g")
    elif r.flags & sp.F_MOTION:
        out.append("moved")
    if r.flags & sp.F_TEMP_MISMATCH:
        out.append("THERMOMETERS DISAGREE")
    if r.flags & sp.F_SENSOR_CHANGED:
        out.append("SENSOR REPLACED")
    if r.flags & sp.F_SENSOR_FAIL:
        out.append("BME688 failed")
    if r.flags & sp.F_RTC_FAIL:
        out.append("clock chip failed")
    if r.flags & sp.F_MPU_FAIL:
        out.append("motion sensor failed")
    return out


def describe(r):
    when = sp._when(r.unix_time) if r.unix_time else "time not set        "
    if r.flags & sp.F_SENSOR_FAIL:
        reading = "no BME688 reading"
    else:
        reading = (f"{r.temp_mc / 1000:6.2f} °C  {r.rh_mpct / 1000:5.1f} %RH  "
                   f"{r.press_pa / 100:7.2f} hPa  {r.gas_ohm / 1000:6.1f} kΩ")
    ev = events(r)
    return f"{when}  {reading}" + (f"   [{', '.join(ev)}]" if ev else "")


class Chain:
    """What the ledger holds for one chain from one node."""

    def __init__(self, folder, node, chain):
        self.node, self.chain = node, chain
        self.path = folder / f"{node}_{chain}.csv"
        self.next, self.tip = 0, sp.GENESIS     # next seq expected, and the hash it must link to
        self.hashes = {}                        # seq -> hash, to spot a record changed after sync
        self.last = None                        # last stored row
        self.pending = []                       # (row, line): not signed themselves, waiting to be covered
        self.ahead = {}                         # seq -> (row, line, signed): arrived early, waiting for a hole
        self.refused_at = {}                    # seq -> hash of the board's record there that was refused
        self.gap, self.gap_tries, self.last_resend = None, 0, 0.0
        self.backlog_to = None                  # records up to this seq are a backlog: summarise them
        self.unacked = 0                        # records stored since the last reply to the node
        self.refusals = None                    # [status, detail, seqs, time]: a run of refusals, printed as one
        self.changed_new, self.changed_told = set(), set()   # held records the board resent, changed
        self.changed_at = 0.0
        self.noted = set()
        self.stored = self.refused = 0          # this session
        self.new = not self.path.exists()
        if self.new:
            self.path.write_text(HEADER_LINE + "\n", encoding="utf-8")
        else:
            rows = sp.parse_rows(self.path.read_text(encoding="utf-8"))
            _, self.tip, self.next = sp.walk(rows)   # signatures were checked when the records arrived
            self.hashes = {r.seq: r.hash for r in rows if r.seq is not None and r.hash is not None}
            self.last = rows[-1] if rows else None

    @property
    def vnext(self):                            # counting the records held back, waiting to be covered
        return self.next + len(self.pending)

    @property
    def vtip(self):
        return self.pending[-1][0].hash if self.pending else self.tip

    def holds(self):
        return "nothing yet" if not self.hashes else f"seq {min(self.hashes)}..{self.next - 1}"


class Burst:
    """A backlog arriving after a dropout: summarised instead of one line per record."""

    def __init__(self, now):
        self.first = self.last = None
        self.count = self.problems = 0
        self.started = self.last_print = self.last_seen = now
        self.paused = False
        self.notes = []


class Ledger:
    def __init__(self, client, folder, key, key_path):
        self.client, self.folder = client, folder
        self.key, self.key_path = key, key_path
        self.adopted = {}                       # node -> key it reported (only when there is no key file)
        self.chains = {}
        self.lock = threading.RLock()
        self.alerts = folder / "alerts.log"
        self.bursts = {}                        # chain -> Burst while a backlog is coming in
        self.recent = {}                        # chain -> arrival times of the last few records
        self.warned = set()
        _before_say.append(self._flush_locked)

    def _flush_locked(self):
        with self.lock:                          # say() is also called from the MQTT thread
            self.flush_refusals()

    # ------------------------------------------------------------ bookkeeping
    def log(self, ch, text):
        stamp = datetime.now().isoformat(timespec="seconds")
        where = f"{ch.node} {ch.chain}" if ch else "-"
        with self.alerts.open("a", encoding="utf-8") as f:
            f.write(f"{stamp}  {where}  {text}\n")

    def alert(self, ch, text):
        say(f"⚠ {text}")
        self.log(ch, text)
        self.problem_in_burst(ch)

    def problem_in_burst(self, ch):
        b = self.bursts.get((ch.node, ch.chain)) if ch else None
        if b is not None:
            b.problems += 1

    def key_for(self, node):
        if self.key is not None and sp.node_id(self.key) == node:
            return self.key
        return self.adopted.get(node)

    def check_key(self, node, key_hex):
        if not key_hex or not KEY_RE.match(key_hex):
            return
        point = bytes.fromhex(key_hex)
        pinned = self.key is not None and sp.node_id(self.key) == node
        if pinned:
            if point != self.key and node not in self.warned:
                self.warned.add(node)
                self.alert(None, f"{node} reports a DIFFERENT public key from {self.key_path.name} - "
                                 f"its chip was replaced; its records will be refused")
        elif node not in self.adopted and sp.node_id(point) == node:
            self.adopted[node] = point
            why = (f"{self.key_path.name} belongs to {sp.node_id(self.key)}" if self.key is not None
                   else f"no {sp.KEY_FILE} next to this script")
            say(f"⚠ {why} - trusting the key {node} reports. Put its key file here to pin it.")

    def chain(self, node, chain):
        k = (node, chain)
        if k in self.chains:
            return self.chains[k]
        others = sorted((p for p in self.folder.glob(f"{node}_*.csv") if p.stem != f"{node}_{chain}"),
                        key=lambda p: p.stat().st_mtime)
        ch = self.chains[k] = Chain(self.folder, node, chain)
        if not ch.new:
            say(f"opened {ch.path.name}: {len(ch.hashes):,} records ({ch.holds()})")
        elif others:
            prev = others[-1]
            try:
                rows = sp.parse_rows(prev.read_text(encoding="utf-8"))
            except SystemExit:
                rows = []
            info = f"{len(rows):,} records"
            if rows and rows[-1].seq is not None:
                info += f", seq {rows[0].seq}..{rows[-1].seq}"
                if rows[-1].unix_time:
                    info += f", last one {sp._when(rows[-1].unix_time)}"
            self.alert(ch, f"NEW CHAIN {chain} from {node}. Its previous chain {prev.stem.split('_')[-1]} "
                           f"({info}) stays in the ledger untouched. A new chain means the board's records "
                           f"were cleared or wiped, or its first record was replaced.")
        else:
            say(f"new ledger file {ch.path.name}")
        return ch

    # ------------------------------------------------------------ messages to the node
    def soon_ack(self, ch):
        """Reply after every 10th record, or at the next tick (a quarter second): a public broker
        slows down clients that publish a message for every single record."""
        ch.unacked += 1
        if ch.unacked >= 10:
            self.ack(ch)

    def ack(self, ch):
        ch.unacked = 0
        self.client.publish(f"saakshi/{ch.node}/ack",
                            f"next={ch.vnext} chain={ch.chain} head={ch.vtip[:8].hex()}", qos=1, retain=True)

    def resend(self, ch):
        now = time.time()
        if now - ch.last_resend < 2:            # one request at a time
            return False
        ch.last_resend = now
        self.client.publish(f"saakshi/{ch.node}/cmd", f"resend={ch.vnext} chain={ch.chain}", qos=1)
        return True

    # ------------------------------------------------------------ messages from the node
    def on_status(self, node, text, retained=False):
        words = text.split()
        if not words:
            return
        fields = dict(w.split("=", 1) for w in words[1:] if "=" in w)
        chain = fields.get("chain", "")
        if not CHAIN_RE.match(chain):
            return
        if words[0] == "online":
            self.check_key(node, fields.get("key"))
            ch = self.chain(node, chain)
            try:
                board_next = int(fields.get("next", "0"))
            except ValueError:
                board_next = 0
            if retained:        # kept by the broker since the node connected: its count may be old
                say(f"● {node} online - chain {chain}; the ledger holds {ch.holds()}")
            else:
                say(f"● {node} online - chain {chain}: the board holds seq 0..{board_next - 1}, "
                    f"the ledger holds {ch.holds()}")
                if board_next < ch.next and ("fewer", chain) not in ch.noted:
                    ch.noted.add(("fewer", chain))
                    self.alert(ch, f"the board now holds fewer records than the ledger: seq {board_next}.."
                                   f"{ch.next - 1} are gone from the board. The ledger's copy is kept.")
            if board_next - ch.next > 5 and (node, chain) not in self.bursts:
                ch.backlog_to = board_next - 1
                self.bursts[(node, chain)] = Burst(time.monotonic())
                say(f"⇣ {board_next - ch.next:,} record(s) to catch up on - checking every one ...")
            self.ack(ch)
            self.client.publish(f"saakshi/{node}/cmd", f"time={int(time.time())}", qos=1)
        elif words[0] == "offline" and (node, chain) in self.chains:
            self.end_burst(self.chains[(node, chain)])
            say(f"○ {node} offline - it keeps logging, and its records come in when it's back")

    def refuse(self, ch, r, line, status, detail):
        seq = r.seq if r is not None else None
        what = f"seq {seq}" if seq is not None else "a message"
        self.log(ch, f"{what} REFUSED - {status}: {detail}")
        self.log(ch, f"   refused: {line[:400]}")
        if seq is not None and seq < ch.next and seq in ch.hashes:
            # the ledger already holds a genuine copy of this seq: the board's copy changed since sync
            if seq not in ch.changed_told:
                ch.changed_new.add(seq)
                ch.changed_at = time.monotonic()
            return None
        ch.refused += 1
        self.problem_in_burst(ch)
        g = ch.refusals
        if g and g[0] == status and g[1] == detail and seq is not None and g[2] and seq == g[2][-1] + 1:
            g[2].append(seq)
            g[3] = time.monotonic()
            return None
        self.flush_refusals()
        ch.refusals = [status, detail, [seq] if seq is not None else [], time.monotonic()]
        return None

    def flush_refusals(self, quiet_for=0.0):
        """Print waiting refusals: one line for a run of consecutive seqs refused for the same reason."""
        now = time.monotonic()
        for ch in self.chains.values():
            g = ch.refusals
            if g and now - g[3] >= quiet_for:
                ch.refusals = None
                what = sp._ranges(g[2]) if g[2] else "a message"
                print(f"{datetime.now():%H:%M:%S}  ✗ {what} REFUSED - {g[0]}: {g[1]}. Not stored.", flush=True)
            if ch.changed_new and now - ch.changed_at >= max(quiet_for, 1.0):
                seqs = sorted(ch.changed_new)
                ch.changed_told |= ch.changed_new
                ch.changed_new = set()
                text = (f"the board sent {sp._ranges(seqs)} again, but they no longer match what the ledger "
                        f"received - changed on the board after sync. The ledger keeps its original copies.")
                print(f"{datetime.now():%H:%M:%S}  ⚠ {text}", flush=True)
                self.log(ch, text)

    def store(self, ch, r, line):
        with ch.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        ch.hashes[r.seq] = r.hash
        ch.tip, ch.next, ch.last = r.hash, r.seq + 1, r
        ch.stored += 1

    def on_record(self, node, chain, line):
        ch = self.chain(node, chain)
        line = line.strip()
        checked = self.genuine(ch, line)
        if checked is None:
            return
        r, signed = checked
        self.consider(ch, r, line, signed)
        self.drain(ch)

    def genuine(self, ch, line):
        """Hash and signature. Returns (row, signed), or None if the record is refused."""
        try:
            rows = sp.parse_rows(HEADER_LINE + "\n" + line + "\n")
        except SystemExit:
            rows = []
        if len(rows) != 1 or rows[0].seq is None:
            return self.refuse(ch, None, line, "UNREADABLE", "not a SAAKSHI record")
        r = rows[0]
        if r.error:
            return self.refuse(ch, r, line, "DATA ALTERED", r.error)
        body = sp.packed(r)
        if body is None or hashlib.sha256(body).digest() != r.hash:
            return self.refuse(ch, r, line, "DATA ALTERED", "its contents don't match its hash")
        signed = not (r.flags & sp.F_UNSIGNED)
        key = self.key_for(ch.node)
        if signed and key is None:
            return self.refuse(ch, r, line, "NO KEY", f"no public key for {ch.node} to check its signature")
        if signed and not sp.signature_ok(key, r.hash, r.sig):
            if r.seq >= ch.vnext:
                ch.refused_at[r.seq] = r.hash       # the next genuine record may follow this one
            return self.refuse(ch, r, line, "SIGNATURE INVALID", "not signed by this node's chip")
        return r, signed

    def consider(self, ch, r, line, signed):
        """A genuine record (or an unsigned one, not proven yet): where does it go?"""
        if r.seq < ch.next:                                     # a resend of something already held
            held = ch.hashes.get(r.seq)
            if held is not None and held != r.hash and signed and r.seq not in ch.noted:
                ch.noted.add(r.seq)
                self.alert(ch, f"seq {r.seq} CHANGED AFTER SYNC - the node signed a different record "
                               f"for a seq the ledger already holds. The ledger keeps its first copy.")
            return
        if r.seq < ch.vnext:                                    # inside the stretch waiting to be covered
            i = r.seq - ch.next
            if ch.pending[i][0].hash == r.hash or not signed:
                return
            dropped = ch.pending[i:]
            ch.pending = ch.pending[:i]
            self.alert(ch, f"dropped unproven {sp._ranges([p.seq for p, _ in dropped])} - "
                           f"a signed record for seq {r.seq} arrived instead")
        if r.seq > ch.vnext:
            bad = ch.refused_at.get(ch.vnext)
            if signed and r.seq == ch.vnext + 1 and bad is not None and r.prev_hash == bad:
                # the board's own record before this one was refused: it isn't genuine, don't wait for it
                return self.accept(ch, r, line, signed,
                                   missing=f"seq {ch.vnext} on the board is not genuine - it was refused")
            if len(ch.ahead) < 1000:
                ch.ahead[r.seq] = (r, line, signed)
            if ch.gap != ch.vnext:
                ch.gap, ch.gap_tries = ch.vnext, 0
            if ch.gap_tries < 2 and self.resend(ch):
                ch.gap_tries += 1
                say(f"… seq {ch.vnext} didn't arrive (got {r.seq}) - asked the board to send it again")
            return
        self.accept(ch, r, line, signed)

    def drain(self, ch):
        """Records that arrived early, now that the hole before them is filled."""
        for s in [s for s in ch.ahead if s < ch.vnext]:
            del ch.ahead[s]
        while ch.vnext in ch.ahead:
            r, line, signed = ch.ahead.pop(ch.vnext)
            self.consider(ch, r, line, signed)
        for s in [s for s in ch.refused_at if s < ch.next]:
            del ch.refused_at[s]

    def give_up_gaps(self, ch):
        """Asked twice and the missing record still isn't there: the board doesn't have a genuine one.
        Carry on from the earliest record that did arrive, and flag the hole."""
        if not ch.ahead or ch.gap != ch.vnext or ch.gap_tries < 2 or time.time() - ch.last_resend < 4:
            return
        r, line, signed = ch.ahead.pop(min(ch.ahead))
        self.accept(ch, r, line, signed, missing=f"{sp._ranges(range(ch.vnext, r.seq))} never arrived - "
                                                 f"deleted on the board, or refused as not genuine")
        self.drain(ch)

    def accept(self, ch, r, line, signed, missing=None):
        if not signed:
            if missing is None and r.seq == ch.vnext and r.prev_hash == ch.vtip:
                ch.pending.append((r, line))
                self.soon_ack(ch)
                say(f"… seq {r.seq:<6} not signed by the chip - held until the next signature covers it")
                return
            return self.refuse(ch, r, line, "UNSIGNED",
                               "not signed, and it doesn't follow the ledger's copy - it can't be proven")
        status, detail = "OK", ""
        if missing:
            status, detail = "RECORDS MISSING", missing
        elif r.prev_hash != ch.vtip:
            status = "LINK BROKEN"
            detail = (f"it doesn't follow the ledger's copy of seq {r.seq - 1}: the board's history "
                      f"was changed after sync")
        covered = []
        if ch.pending:
            if status == "OK":                                  # this signature covers every one of them
                covered = ch.pending
                for pr, pl in ch.pending:
                    self.store(ch, pr, pl)
            else:
                self.alert(ch, f"dropped unproven {sp._ranges([p.seq for p, _ in ch.pending])} - "
                               f"no signature covers them")
            ch.pending = []
        self.store(ch, r, line)
        ch.gap = None
        self.soon_ack(ch)
        if status != "OK":
            self.alert(ch, f"seq {r.seq} {status} - {detail}. Stored and flagged (the record itself is genuine).")
            return
        if covered:
            say(f"✓ {sp._ranges([p.seq for p, _ in covered])} not signed themselves - covered by "
                f"seq {r.seq}'s signature")
        self.show(ch, r)

    # ------------------------------------------------------------ display
    def show(self, ch, r):
        """One line per live record; a backlog is summarised instead. A backlog is known from the
        board's own count when it comes online, or noticed when records arrive faster than live."""
        k = (ch.node, ch.chain)
        now = time.monotonic()
        b = self.bursts.get(k)
        if b is not None and ch.backlog_to is None and b.count and now - b.last_seen > 0.6:
            self.end_burst(ch, latest=False)                    # live pace again: this one is live
            b = None
        recent = self.recent.setdefault(k, deque(maxlen=4))
        recent.append(now)
        if b is None:
            if len(recent) < 4 or now - recent[0] > 1.0:
                say(f"✓ seq {r.seq:<6} {describe(r)}")
                return
            b = self.bursts[k] = Burst(now)
            say(f"⇣ {ch.node} is sending a backlog - checking every record ...")
        if b.first is None:
            b.first = r.seq
        if b.paused:
            b.paused = False
            say("   … records are coming in again")
        b.last, b.last_seen = r.seq, now
        b.count += 1
        for e in events(r):
            if len(b.notes) < 12:
                b.notes.append(f"{e} at seq {r.seq}")
        if ch.backlog_to is not None and r.seq >= ch.backlog_to:
            self.end_burst(ch)
        elif now - b.last_print >= 2.0:
            b.last_print = now
            upto = f" of {ch.backlog_to}" if ch.backlog_to is not None else ""
            say(f"   … {b.count:,} checked and stored so far (up to seq {r.seq}{upto})")

    def end_burst(self, ch, latest=True):
        b = self.bursts.pop((ch.node, ch.chain), None)
        target, ch.backlog_to = ch.backlog_to, None
        self.recent.pop((ch.node, ch.chain), None)              # start counting the pace afresh
        if b is None or b.count == 0:
            return
        secs = b.last_seen - b.started
        took = "under a second" if secs < 1 else f"{secs:.0f} s"
        verdict = ("every signature valid" if b.problems == 0
                   else f"{b.problems} problem(s), shown above and in alerts.log")
        if target is not None and b.last < target:
            say(f"   … stopped for now: {b.count:,} record(s), seq {b.first}..{b.last}, checked and stored - "
                f"{verdict}. The rest (up to seq {target}) comes when the board is back.")
            return
        say(f"✓ caught up: {b.count:,} record(s), seq {b.first}..{b.last}, checked and stored in "
            f"{took} - {verdict}")
        if b.notes:
            say(f"   events in them: {'; '.join(b.notes)}")
        if latest and ch.last is not None:
            say(f"✓ seq {ch.last.seq:<6} {describe(ch.last)}   (latest)")

    def tick(self):
        now = time.monotonic()
        for k, b in list(self.bursts.items()):
            ch = self.chains[k]
            idle = now - b.last_seen
            if ch.backlog_to is None and b.count and idle > 1.5:
                self.end_burst(ch)
            elif ch.backlog_to is not None and idle > 20 and not b.paused:
                b.paused = True
                say(f"   … paused at seq {b.last if b.last is not None else '-'} of {ch.backlog_to} - "
                    f"nothing new for 20 s. Waiting for the board (type w on it to see why).")
        for ch in self.chains.values():
            if ch.unacked:
                self.ack(ch)
            self.give_up_gaps(ch)
        self.flush_refusals(quiet_for=0.5)

    def summary(self):
        self.flush_refusals()
        for ch in self.chains.values():
            ch.changed_at = 0.0
        self.flush_refusals()
        for ch in self.chains.values():
            self.end_burst(ch)
        if not self.chains:
            return
        print()
        for ch in self.chains.values():
            print(f"  {ch.path.name}: holds {ch.holds()}  (this run: {ch.stored:,} stored, {ch.refused} refused)")
        print(f"\n  check or chart the ledger's copy:  python3 saakshi_pull.py --file "
              f"{self.folder.name}/{next(iter(self.chains.values())).path.name}")
        print("  compare the board with it:        python3 saakshi_pull.py --against ledger")


def main():
    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass
    ap = argparse.ArgumentParser(description="SAAKSHI ledger: receive, verify and keep node records.")
    ap.add_argument("--broker", default=DEFAULT_BROKER,
                    help=f"MQTT broker (default: {DEFAULT_BROKER}, the board's default)")
    ap.add_argument("--port", type=int, help="default 8883 with --tls, else 1883")
    ap.add_argument("--tls", action="store_true",
                    help="encrypted connection to the broker set up by saakshi_broker.py (default broker: localhost)")
    ap.add_argument("--ca", help="certificate authority for --tls (default saakshi_broker/ca.crt)")
    ap.add_argument("--user", help="broker login (with --tls: 'ledger' from saakshi_broker/credentials.json)")
    ap.add_argument("--password", help="broker password (with --tls: from saakshi_broker/credentials.json)")
    ap.add_argument("--dir", default="saakshi_ledger", help="folder for the ledger's files")
    ap.add_argument("--key", help=f"public key file (default: {sp.KEY_FILE} in this folder)")
    args = ap.parse_args()
    here = Path(__file__).resolve().parent
    if args.tls:
        if args.broker == DEFAULT_BROKER:
            args.broker = "localhost"
        ca = Path(args.ca) if args.ca else here / "saakshi_broker" / "ca.crt"
        if not ca.exists():
            sys.exit(f"{ca} not found. Set up the encrypted broker first:  python3 saakshi_broker.py setup")
        if not args.user:
            try:
                creds = json.loads((here / "saakshi_broker" / "credentials.json").read_text())
                args.user, args.password = "ledger", args.password or creds.get("ledger")
            except (FileNotFoundError, ValueError):
                sys.exit("No saakshi_broker/credentials.json - run  python3 saakshi_broker.py setup  or give --user/--password")
    if args.port is None:
        args.port = 8883 if args.tls else 1883

    folder = Path(args.dir).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    key, key_path = sp.load_key(args.key)
    cid = f"saakshi-ledger-{uuid.uuid4().hex[:8]}"
    if hasattr(mqtt, "CallbackAPIVersion"):
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid)
    else:
        client = mqtt.Client(client_id=cid)
    ledger = Ledger(client, folder, key, key_path)
    if args.user:
        client.username_pw_set(args.user, args.password)
    if args.tls:
        client.tls_set(ca_certs=str(ca), cert_reqs=ssl.CERT_REQUIRED)   # checks the broker's certificate and name

    def on_connect(c, userdata, flags, rc, *rest):
        failed = rc.is_failure if hasattr(rc, "is_failure") else rc != 0
        if failed:
            hint = " - check the ledger login (saakshi_broker/credentials.json)" if "auth" in str(rc).lower() or str(rc) in ("4", "5") else ""
            say(f"the broker refused the connection: {rc}{hint}")
            return
        c.subscribe([("saakshi/+/status", 1), ("saakshi/+/rec/+", 1)])
        say(f"connected to {args.broker}:{args.port}{' (encrypted, TLS)' if args.tls else ' (NOT encrypted)'} - waiting for nodes")

    def on_disconnect(c, userdata, *rest):
        say("lost the broker - reconnecting ...")

    def on_message(c, userdata, msg):
        parts = msg.topic.split("/")
        if len(parts) < 3 or not NODE_RE.match(parts[1]):
            return
        text = msg.payload.decode("utf-8", "replace")
        with ledger.lock:
            try:
                if parts[2] == "status" and len(parts) == 3:
                    ledger.on_status(parts[1], text, bool(msg.retain))
                elif parts[2] == "rec" and len(parts) == 4 and CHAIN_RE.match(parts[3]):
                    for line in text.splitlines():       # v7 sends a few records per message
                        if line.strip():
                            ledger.on_record(parts[1], parts[3], line)
            except Exception as e:                   # one bad message must never stop the ledger
                say(f"✗ skipped a message on {msg.topic}: {e}")

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    client.reconnect_delay_set(1, 10)

    print("SAAKSHI ledger - every record is checked before it is kept")
    if key is not None:
        print(f"  signatures checked against  {key_path.name} ({sp.node_id(key)})")
    else:
        print(f"  ⚠ no {sp.KEY_FILE} here - each node's own reported key will be trusted")
    print(f"  ledger files                {folder}")
    print(f"  broker                      {args.broker}:{args.port}  "
          f"{'encrypted (TLS), login ' + args.user if args.tls else 'NOT encrypted'}")
    if args.broker in LOCAL:
        ip = lan_ip()
        print(f"  on the board, type once:    broker {ip or '<this Mac IP>'}"
              + ("   (and  mqttpass <its password>  - see  python3 saakshi_broker.py show)" if args.tls else ""))
    print("  (Ctrl+C to stop)\n", flush=True)

    try:
        client.connect(args.broker, args.port, keepalive=30)
    except ssl.SSLError as e:
        sys.exit(f"The broker's certificate was refused ({e}). If this Mac's IP changed:  python3 saakshi_broker.py renew")
    except OSError as e:
        if args.broker in LOCAL:
            sys.exit("No MQTT broker is running on this Mac. Start one in another Terminal window:\n"
                     + ("    python3 saakshi_broker.py run" if args.tls else "    mosquitto -c saakshi_mosquitto.conf"))
        sys.exit(f"Can't reach {args.broker}: {e}. Check this laptop's internet connection.")
    client.loop_start()
    try:
        while True:
            time.sleep(0.25)
            with ledger.lock:
                ledger.tick()
    except KeyboardInterrupt:
        print("\nstopping - the ledger files are kept; run this again to carry on")
    finally:
        client.loop_stop()
        client.disconnect()
        with ledger.lock:
            ledger.summary()


if __name__ == "__main__":
    main()
