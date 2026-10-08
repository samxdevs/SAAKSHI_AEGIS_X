#!/usr/bin/env python3
"""
saakshi_pull.py - pull the SAAKSHI chain off the node, verify it on this laptop, save it as a CSV
and plot it. For firmware v4 it also checks every record's signature and sets the board's clock.

    python3 saakshi_pull.py                         pull from the board (port found automatically)
    python3 saakshi_pull.py /dev/cu.usbmodem101     pull from a specific port
    python3 saakshi_pull.py --file chain.csv        re-verify a saved or edited CSV
    python3 saakshi_pull.py --against ledger        also compare the board with saakshi_ledger.py's copy
    python3 saakshi_pull.py --against LEDGER.csv    ... or with a particular ledger file
    python3 saakshi_pull.py --no-plot               skip the chart
    python3 saakshi_pull.py --no-clock              don't touch the board's clock

One-time setup:   python3 -m pip install pyserial matplotlib
Close Arduino's Serial Monitor first - only one program can hold the port.

Signatures are checked against the public key saved at setup, in saakshi_pubkey.txt (in this folder
or next to this script). The board's own claim about its key is never trusted on its own.

Verification does not trust the board: every record's bytes are rebuilt from the CSV in the
firmware's exact layout, SHA-256 is recomputed here, every link and every signature is checked.
--file also accepts text copied out of Arduino's Serial Monitor after typing x. Reads chains from
firmware v2, v3 and v4.
"""

import argparse
import csv
import hashlib
import io
import re
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Optional

HEADER_V2 = ["seq", "boot", "uptime_s", "temp_c", "rh_pct",
             "pressure_hpa", "gas_kohm", "flags", "prev_hash", "hash"]
HEADER_V3 = ["seq", "boot", "uptime_s", "unix_time", "temp_c", "rh_pct",
             "pressure_hpa", "gas_kohm", "flags", "prev_hash", "hash"]
HEADER_V4 = ["seq", "boot", "uptime_s", "unix_time", "temp_c", "rh_pct", "pressure_hpa", "gas_kohm",
             "rtc_temp_c", "mpu_temp_c", "peak_g", "moves", "sensor_id", "flags", "prev_hash", "hash", "sig"]
HEADERS = {2: HEADER_V2, 3: HEADER_V3, 4: HEADER_V4}
GENESIS = bytes(32)
KEY_FILE = "saakshi_pubkey.txt"

F_BOOT, F_SENSOR_FAIL, F_NO_TIME, F_CLOCK_SET = 0x01, 0x02, 0x04, 0x08
F_MOTION, F_SHOCK, F_TEMP_MISMATCH, F_SENSOR_CHANGED = 0x10, 0x20, 0x40, 0x80
F_UNSIGNED, F_RTC_FAIL, F_MPU_FAIL = 0x100, 0x200, 0x400
NO_TEMP = -32768                  # a thermometer that did not answer (empty in the CSV)

# struct Record in the firmware, packed little-endian. These fields plus prev_hash (32) are the
# bytes the device hashes: 61 in v2, 65 in v3, 78 in v4. v4 then signs that hash.
LAYOUT = struct.Struct("<IIIiiiiB")
LAYOUT_V3 = struct.Struct("<IIIIiiiiB")
LAYOUT_V4 = struct.Struct("<IIIIiiiihhHHIH")

# (attribute, CSV column, scale from CSV units to device integer units)
FIELDS = [("seq", "seq", 1), ("boot", "boot", 1), ("uptime_s", "uptime_s", 1),
          ("temp_mc", "temp_c", 1000), ("rh_mpct", "rh_pct", 1000),
          ("press_pa", "pressure_hpa", 100), ("gas_ohm", "gas_kohm", 1000),
          ("flags", "flags", 1)]
TIME_FIELD = ("unix_time", "unix_time", 1)
V4_FIELDS = [("peak_mg", "peak_g", 1000), ("moves", "moves", 1)]

METRICS = [("Temperature", "°C", lambda r: r.temp_mc / 1000),
           ("Humidity", "%RH", lambda r: r.rh_mpct / 1000),
           ("Pressure", "hPa", lambda r: r.press_pa / 100),
           ("Gas resistance", "kΩ", lambda r: r.gas_ohm / 1000)]

EVENTS = [(F_SHOCK, "shock", "a jolt of more than 1 g"),
          (F_MOTION, "moved", "the box was moving"),
          (F_TEMP_MISMATCH, "thermometers disagree", "BME688 more than 6 °C from both other thermometers"),
          (F_SENSOR_CHANGED, "sensor replaced", "the BME688's fingerprint changed"),
          (F_CLOCK_SET, "clock set", "the board's clock was set"),
          (F_SENSOR_FAIL, "sensor failed", "no BME688 reading"),
          (F_RTC_FAIL, "clock failed", "DS3231 not answering"),
          (F_MPU_FAIL, "motion sensor failed", "MPU-6050 not answering")]

USB_IDS = {0x303A: "ESP32-S3 native USB", 0x1A86: "WCH USB-serial", 0x10C4: "CP210x USB-serial"}
TIMESTAMP = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d{3}\s*->\s?")    # Serial Monitor timestamps


@dataclass
class Row:
    line: int
    ver: int = 2
    seq: Optional[int] = None
    boot: Optional[int] = None
    uptime_s: Optional[int] = None
    unix_time: Optional[int] = None  # v3+; 0 = logged before the board's clock was set
    temp_mc: Optional[int] = None
    rh_mpct: Optional[int] = None
    press_pa: Optional[int] = None
    gas_ohm: Optional[int] = None
    rtc_temp_cc: int = NO_TEMP       # v4: DS3231's thermometer
    mpu_temp_cc: int = NO_TEMP       # v4: MPU-6050's thermometer
    peak_mg: int = 0                 # v4: biggest jolt since the last record
    moves: int = 0                   # v4: 20 ms moments with movement
    sensor_id: int = 0               # v4: BME688 fingerprint
    flags: int = 0
    prev_hash: Optional[bytes] = None
    hash: Optional[bytes] = None
    sig: Optional[bytes] = None      # v4: ATECC608 signature over hash
    covered_by: Optional[int] = None  # v4: unsigned, but a later record's signature covers it
    error: Optional[str] = None      # a value the device could not have written
    status: str = "OK"
    detail: str = ""

    @property
    def label(self):
        return f"seq {self.seq}" if self.seq is not None else f"line {self.line}"

    @property
    def has_reading(self):
        return self.error is None and not (self.flags & F_SENSOR_FAIL)


# ---------------------------------------------------------------- signatures (ECDSA P-256)

_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5, 1)
_INF = (0, 1, 0)


def _on_curve(point):
    if len(point) != 65 or point[0] != 4:
        return False
    x, y = int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:], "big")
    return x < _P and y < _P and (y * y - x ** 3 + 3 * x - _B) % _P == 0


def _dbl(p):
    x, y, z = p
    if z == 0 or y == 0:
        return _INF
    delta, gamma = z * z % _P, y * y % _P
    beta, alpha = x * gamma % _P, 3 * (x - delta) * (x + delta) % _P
    x3 = (alpha * alpha - 8 * beta) % _P
    z3 = ((y + z) ** 2 - gamma - delta) % _P
    return (x3, (alpha * (4 * beta - x3) - 8 * gamma * gamma) % _P, z3)


def _add(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1, z2z2 = z1 * z1 % _P, z2 * z2 % _P
    u1, u2 = x1 * z2z2 % _P, x2 * z1z1 % _P
    s1, s2 = y1 * z2 * z2z2 % _P, y2 * z1 * z1z1 % _P
    if u1 == u2:
        return _dbl(p) if s1 == s2 else _INF
    h = (u2 - u1) % _P
    i = 4 * h * h % _P
    j, r, v = h * i % _P, 2 * (s2 - s1) % _P, u1 * i % _P
    x3 = (r * r - j - 2 * v) % _P
    return (x3, (r * (v - x3) - 2 * s1 * j) % _P, ((z1 + z2) ** 2 - z1z1 - z2z2) * h % _P)


def _verify_pure(point, digest, sig):
    """ECDSA P-256 verification in plain Python (used when the cryptography package isn't installed)."""
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < _N and 0 < s < _N):
        return False
    w = pow(s, -1, _N)
    u1, u2 = int.from_bytes(digest, "big") * w % _N, r * w % _N
    q = (int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:], "big"), 1)
    both, acc = _add(_G, q), _INF
    for bit in range(256, -1, -1):                       # u1*G + u2*Q in one pass
        acc = _dbl(acc)
        a, b = (u1 >> bit) & 1, (u2 >> bit) & 1
        if a or b:
            acc = _add(acc, both if a and b else _G if a else q)
    if acc[2] == 0:
        return False
    return acc[0] * pow(acc[2] * acc[2] % _P, -1, _P) % _P % _N == r


def _make_verifier():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError:
        return _verify_pure
    keys = {}

    def fast(point, digest, sig):
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        if not (0 < r < _N and 0 < s < _N):
            return False
        if point not in keys:
            keys[point] = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        try:
            keys[point].verify(utils.encode_dss_signature(r, s), digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            return True
        except InvalidSignature:
            return False
    return fast


signature_ok = _make_verifier()


def node_id(point):
    return "SAAKSHI-" + hashlib.sha256(point).hexdigest()[:8].upper()


def load_key(path_arg):
    """The public key saved at setup -> (65-byte point, path), or (None, None) if there is no key file."""
    here = Path(__file__).resolve().parent
    if path_arg:
        candidates = [Path(path_arg)]
    else:                   # also finds 'saakshi_pubkey (1).txt' and the like, left by a browser download
        candidates = [d / KEY_FILE for d in (Path.cwd(), here)]
        candidates += sorted(set(Path.cwd().glob("saakshi_pubkey*.txt")) | set(here.glob("saakshi_pubkey*.txt")))
    for p in candidates:
        if p.exists():
            m = re.search(r"(?<![0-9a-fA-F])04[0-9a-fA-F]{128}(?![0-9a-fA-F])", p.read_text(errors="replace"))
            if not m:
                sys.exit(f"{p} has no public key in it (a line of 130 characters starting with 04).")
            point = bytes.fromhex(m.group(0))
            if not _on_curve(point):
                sys.exit(f"The key in {p} is not a valid public key - copy it again from the setup screen.")
            return point, p
    if path_arg:
        sys.exit(f"No such key file: {path_arg}")
    return None, None


# ---------------------------------------------------------------- parsing

def _scaled(text, scale, name):
    """'29.17' with scale 1000 -> 29170, exactly. Rejects anything the device can't produce."""
    t = text.strip()
    try:
        value = Decimal(t) * scale
    except InvalidOperation:
        raise ValueError(f"{name} '{t}' is not a number")
    if not value.is_finite() or value != value.to_integral_value():
        raise ValueError(f"{name} '{t}' has more decimals than the device records")
    return int(value)


def _hex_bytes(text, name, size):
    t = text.strip().lower()
    t = t[2:] if t.startswith("0x") else t
    try:
        b = bytes.fromhex(t)
    except ValueError:
        raise ValueError(f"{name} is not hex")
    if len(b) != size:
        raise ValueError(f"{name} is {len(b)} bytes, not {size}")
    return b


def extract_export(text):
    """If this is text copied out of the Serial Monitor, keep only the last export block.
    Returns (csv text, the #BEGIN_CSV line or '')."""
    lines = [TIMESTAMP.sub("", ln) for ln in text.lstrip("﻿").splitlines()]
    starts = [i for i, ln in enumerate(lines) if ln.strip().startswith("#BEGIN_CSV")]
    if not starts:
        return "\n".join(lines) + "\n", ""
    body = []
    for ln in lines[starts[-1] + 1:]:
        if ln.strip().startswith("#END_CSV"):
            return "\n".join(body) + "\n", lines[starts[-1]].strip()
        body.append(ln)
    sys.exit("The pasted export has no #END_CSV line - type x again and copy all of it.")


def export_meta(begin_line):
    """'#BEGIN_CSV count=5 node=SAAKSHI-.. key=04..' -> {'count': '5', 'node': ..., 'key': ...}"""
    return dict(re.findall(r"(\w+)=(\S+)", begin_line or ""))


def parse_rows(text):
    """CSV text -> rows. Works on the device export and on a copy re-saved by Numbers or Excel."""
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    rows, col, ver, fields = [], None, 2, []
    for line_no, cells in enumerate(reader, start=1):
        if not any(c.strip() for c in cells):
            continue
        if col is None:
            names = [c.strip().lower() for c in cells]
            ver = 4 if "sig" in names else 3 if "unix_time" in names else 2
            missing = [h for h in HEADERS[ver] if h not in names]
            if missing:
                sys.exit(f"Not a SAAKSHI chain CSV - missing column(s): {', '.join(missing)}")
            col = {h: names.index(h) for h in HEADERS[ver]}
            fields = FIELDS + ([TIME_FIELD] if ver >= 3 else []) + (V4_FIELDS if ver == 4 else [])
            continue

        def cell(name):
            i = col[name]
            return cells[i] if i < len(cells) else ""

        r = Row(line=line_no, ver=ver)
        for attr, name, scale in fields:
            try:
                setattr(r, attr, _scaled(cell(name), scale, name))
            except ValueError as e:
                r.error = r.error or str(e)
        parts = [("prev_hash", 32), ("hash", 32)] + ([("sig", 64)] if ver == 4 else [])
        for attr, size in parts:
            try:
                setattr(r, attr, _hex_bytes(cell(attr), attr, size))
            except ValueError as e:
                r.error = r.error or str(e)
        if ver == 4:
            for attr, name in (("rtc_temp_cc", "rtc_temp_c"), ("mpu_temp_cc", "mpu_temp_c")):
                try:
                    setattr(r, attr, NO_TEMP if not cell(name).strip() else _scaled(cell(name), 100, name))
                except ValueError as e:
                    r.error = r.error or str(e)
            try:
                r.sensor_id = int.from_bytes(_hex_bytes(cell("sensor_id"), "sensor_id", 4), "big")
            except ValueError as e:
                r.error = r.error or str(e)
        rows.append(r)
    if col is None:
        sys.exit("The CSV is empty.")
    return rows


# ---------------------------------------------------------------- verification

def packed(r):
    """The exact bytes the firmware hashed for this record, or None if a value can't fit."""
    try:
        if r.ver == 4:
            head = LAYOUT_V4.pack(r.seq, r.boot, r.uptime_s, r.unix_time, r.temp_mc, r.rh_mpct, r.press_pa,
                                  r.gas_ohm, r.rtc_temp_cc, r.mpu_temp_cc, r.peak_mg, r.moves, r.sensor_id, r.flags)
        elif r.ver == 3:
            head = LAYOUT_V3.pack(r.seq, r.boot, r.uptime_s, r.unix_time, r.temp_mc,
                                  r.rh_mpct, r.press_pa, r.gas_ohm, r.flags)
        else:
            head = LAYOUT.pack(r.seq, r.boot, r.uptime_s, r.temp_mc, r.rh_mpct,
                               r.press_pa, r.gas_ohm, r.flags)
    except (struct.error, TypeError):
        return None
    return head + r.prev_hash


def check(r, expect_prev, expect_seq, key=None):
    """Judge one record against the chain so far. Same rules as verifyChain() in the firmware.
    Sets r.status / r.detail; returns False if the record should not become the new tip."""
    r.status, r.detail = "OK", ""
    if r.error:
        r.status, r.detail = "DATA ALTERED", r.error
        return True
    body = packed(r)
    if body is None:
        r.status, r.detail = "DATA ALTERED", "a value is outside what the device can store"
    elif hashlib.sha256(body).digest() != r.hash:
        r.status, r.detail = "DATA ALTERED", "contents changed after the hash was made"
    elif r.prev_hash != expect_prev:
        if r.seq > expect_seq:
            gap = (f"seq {expect_seq}" if r.seq - expect_seq == 1
                   else f"seq {expect_seq}..{r.seq - 1}")
            r.status, r.detail = "RECORDS DELETED", f"{gap} missing before this one"
        elif r.seq < expect_seq:
            r.status, r.detail = "REPLAYED", "sequence went backwards - an old record was re-inserted"
            return False            # an inserted extra: keep judging against the real chain
        elif r.seq == 0:
            r.status, r.detail = "LINK BROKEN", "first record does not start from genesis"
        else:
            r.status, r.detail = ("LINK BROKEN",
                                  f"seq {r.seq - 1} was edited and re-hashed, or this record is forged")
    elif r.ver == 4 and r.flags & F_UNSIGNED:
        r.status, r.detail = "UNSIGNED", "the chip did not sign this record"
    elif r.ver == 4 and key is not None and not signature_ok(key, r.hash, r.sig):
        r.status, r.detail = "SIGNATURE INVALID", "not signed by this node's chip - changed or made elsewhere"
    elif r.seq != expect_seq:
        r.status, r.detail = "SEQUENCE ERROR", f"expected seq {expect_seq}"
    return True


def walk(rows, expect_prev=GENESIS, expect_seq=0, key=None):
    """Check rows in order. Returns (problems, hash the next record must link to, next seq)."""
    pending = []            # unsigned records waiting for a later signature to cover them
    for r in rows:
        advance = check(r, expect_prev, expect_seq, key)
        if r.status == "UNSIGNED":
            pending.append(r)
        elif r.status != "OK":
            for p in pending:
                p.detail = "not signed, and the record after it failed its check"
            pending = []
        elif r.ver == 4 and key is not None and pending:
            # this signature covers a hash that includes every earlier record's hash
            for p in pending:
                p.status, p.detail, p.covered_by = "OK", f"not signed itself - covered by seq {r.seq}'s signature", r.seq
            pending = []
        # judge the next record against what is stored, so one edit is reported once
        if advance:
            if r.hash is not None:
                expect_prev = r.hash
            expect_seq = r.seq + 1 if r.seq is not None else expect_seq + 1
    for p in pending:
        p.detail = "not signed, and no later signature covers it yet"
    return sum(1 for r in rows if r.status != "OK"), expect_prev, expect_seq


def verify(rows, key=None):
    """Marks each row; returns the problem count."""
    return walk(rows, key=key)[0]


def compare(board, ledger):
    """Board rows vs the ledger's copy of the same chain -> (changed pairs, missing ledger rows)."""
    held = {r.seq: r for r in ledger if r.seq is not None and r.hash is not None}
    on_board = set()
    changed = []
    for r in board:
        if r.seq is None:
            continue
        on_board.add(r.seq)
        copy = held.get(r.seq)
        if copy is not None and (copy.hash != r.hash or packed(copy) != packed(r)):   # re-hashed, or edited
            changed.append((r, copy))
    missing = [held[s] for s in sorted(held) if s not in on_board]
    return changed, missing


# ---------------------------------------------------------------- serial

def _need_pyserial():
    sys.exit("pyserial is not installed. Run:  python3 -m pip install pyserial\n"
             "(or type x in Arduino's Serial Monitor, copy the output into a file,\n"
             " and run:  python3 saakshi_pull.py --file thatfile.txt)")


def find_port():
    try:
        from serial.tools import list_ports
    except ImportError:
        _need_pyserial()
    found = [p for p in list_ports.comports() if p.vid in USB_IDS]
    if len(found) == 1:
        return found[0].device
    if not found:
        sys.exit("No ESP32 found. Plug it in, or name the port:\n"
                 "  python3 saakshi_pull.py /dev/cu.usbmodem101")
    listing = "\n".join(f"  {p.device}   {USB_IDS[p.vid]}" for p in found)
    sys.exit(f"More than one board is connected - name the one you want:\n{listing}")


def _count(line):
    m = re.search(r"count=(\d+)", line)
    return int(m.group(1)) if m else None


class _Lines:
    """Reads whole lines from the port, keeping partial ones for the next call."""

    def __init__(self, ser):
        self.ser, self.buf = ser, b""

    def next(self, timeout):
        end = time.time() + timeout
        while b"\n" not in self.buf:
            if time.time() > end:
                return None
            chunk = self.ser.read(self.ser.in_waiting or 1)
            if chunk:
                self.buf += chunk
        raw, self.buf = self.buf.split(b"\n", 1)
        return raw.decode("utf-8", "replace").strip()


def _wait_for(lines, prefixes, timeout):
    end = time.time() + timeout
    while time.time() < end:
        line = lines.next(max(0.05, end - time.time()))
        if line is not None and line.startswith(prefixes):
            return line
    return None


def _open(port):
    try:
        import serial
    except ImportError:
        _need_pyserial()
    try:
        return serial.Serial(port, 115200, timeout=0.2)
    except serial.SerialException as e:
        if "busy" in str(e).lower() or "errno 16" in str(e).lower():
            sys.exit(f"{port} is busy - close Arduino's Serial Monitor, then run this again.")
        sys.exit(f"Could not open {port}: {e}")


def _export(ser, lines, stall_s=8.0):
    """Send x, collect the lines between #BEGIN_CSV and #END_CSV. Log lines around it are ignored."""
    ser.reset_input_buffer()
    lines.buf = b""
    body, begin, attempts, sent_at, last_rx = None, "", 0, 0.0, time.time()
    while True:
        now = time.time()
        if body is None and now - sent_at > 4:           # board may be rebooting: ask again
            if attempts == 3:
                sys.exit("The board is not answering. Check that the SAAKSHI firmware is uploaded,\n"
                         "then press RST and run this again.")
            ser.write(b"x\n")
            ser.flush()
            attempts, sent_at = attempts + 1, now
        if body is not None and now - last_rx > stall_s:
            sys.exit("The transfer stopped part-way. Run this again.")
        line = lines.next(0.3)
        if line is None:
            continue
        last_rx = time.time()
        if line.startswith("#BEGIN_CSV"):
            body, begin = [], line
        elif line.startswith("#END_CSV") and body is not None:
            return body, begin, _count(line)
        elif body is not None:
            body.append(line)


def _sync_clock(ser, lines, allowed):
    """v4 only: read the board's clock and set it from this laptop if it is unset or off by > 2 s."""
    ser.write(b"clock\n")
    ser.flush()
    line = _wait_for(lines, ("#CLOCK ",), 4)
    if line is None:
        return "board clock: no answer"
    board = int(line.split()[1])
    now = int(time.time())
    if board and abs(board - now) <= 2:
        return f"board clock: ok ({_when(board)})"
    if not allowed:
        return "board clock: NOT SET" if not board else f"board clock: {board - now:+d} s off"
    ser.write(f"clock {now}\n".encode())
    ser.flush()
    line = _wait_for(lines, ("#CLOCK_SET", "#CLOCK_FAIL"), 4)
    if not line or line.startswith("#CLOCK_FAIL"):
        return "board clock: could not be set"
    if not board:
        return f"board clock: was not set - set it to {_when(now)} (the next record is marked 'clock set')"
    return f"board clock: was {board - now:+d} s off - corrected (the next record is marked 'clock set')"


def pull(port, set_clock=True):
    """Export the chain; on v4 firmware also check the board's clock. Only sends 'clock' once the
    export shows v4 firmware - older firmware reads a 'c' as 'clear the chain'."""
    ser = _open(port)
    with ser:
        time.sleep(0.3)
        lines = _Lines(ser)
        body, begin, end_count = _export(ser, lines)
        clock_msg = None
        if body and body[0].strip().lower() == ",".join(HEADER_V4):
            clock_msg = _sync_clock(ser, lines, set_clock)
    return body, begin, end_count, clock_msg


# ---------------------------------------------------------------- report

def _when(ts):
    return datetime.fromtimestamp(ts).strftime("%d %b %Y %H:%M:%S")


def _ranges(seqs):
    """[5,6,7,9] -> 'seq 5..7, 9'"""
    out, start, prev = [], None, None
    for s in seqs:
        if start is None:
            start = prev = s
        elif s == prev + 1:
            prev = s
        else:
            out.append(f"{start}..{prev}" if prev > start else f"{start}")
            start = prev = s
    if start is not None:
        out.append(f"{start}..{prev}" if prev > start else f"{start}")
    return "seq " + ", ".join(out)


def _grouped(bad):
    """Consecutive records with the same verdict and detail -> one line each."""
    groups = []
    for r in bad:
        if (groups and r.seq is not None and groups[-1][0].seq is not None
                and r.status == groups[-1][0].status and r.detail == groups[-1][0].detail
                and r.seq == groups[-1][-1].seq + 1):
            groups[-1].append(r)
        else:
            groups.append([r])
    return groups


def report(rows, problems, source, saved=None, key_info=None):
    n = len(rows)
    v4 = any(r.ver == 4 for r in rows)
    print(f"\n{n:,} records from {source}")
    if saved:
        print(f"saved   {saved}")

    print("\nVerifying on this laptop: every record rebuilt and re-hashed here"
          + (", every signature checked" if v4 and key_info and key_info[0] else ""))
    bad = [r for r in rows if r.status != "OK"]
    groups = _grouped(bad)
    for g in groups[:30]:
        who = _ranges([r.seq for r in g]) if len(g) > 1 else g[0].label
        print(f"  ✗ {who:<13} {g[0].status:<18} {g[0].detail}")
    if len(groups) > 30:
        print(f"  ... and {len(groups) - 30} more")
    if n == 0:
        print("  chain is empty")
    elif problems == 0:
        signed = f", every signature from {key_info[1]}" if v4 and key_info and key_info[0] else ""
        print(f"  ✓ CHAIN INTACT - all {n:,} records verified{signed}")
    else:
        print(f"  ✗ CHAIN INVALID - {problems} problem(s) in {n:,} records")
    covered = [r.seq for r in rows if r.covered_by is not None]
    if covered:
        print(f"  ✓ {len(covered)} record(s) the chip didn't sign ({_ranges(covered)}) are covered by the"
              f" next record's signature")
    if v4 and key_info:
        print(f"  {key_info[2]}")

    good = [r for r in rows if r.has_reading]
    if good:
        print(f"\nReadings ({len(good):,} samples)                min        max")
        for name, unit, get in METRICS:
            vals = [get(r) for r in good]
            print(f"  {name:<21} {unit:<5} {min(vals):>10.2f} {max(vals):>10.2f}")
        for name, attr in (("DS3231 thermometer", "rtc_temp_cc"), ("MPU-6050 thermometer", "mpu_temp_cc")):
            vals = [getattr(r, attr) / 100 for r in rows if r.error is None and r.ver == 4
                    and getattr(r, attr) != NO_TEMP]
            if vals:
                print(f"  {name:<21} {'°C':<5} {min(vals):>10.2f} {max(vals):>10.2f}")

    boots = {r.boot for r in rows if r.boot is not None}
    fails = sum(1 for r in rows if r.error is None and r.flags & F_SENSOR_FAIL)
    if not v4:
        print(f"\npower-ups {len(boots)}    sensor-fail records {fails}")
    else:
        print(f"\nEvents (power-ups: {len(boots)})")
        any_event = False
        for bit, name, meaning in EVENTS:
            hit = [r.seq for r in rows if r.error is None and r.ver == 4 and r.flags & bit]
            if hit:
                any_event = True
                extra = ""
                if bit == F_SHOCK:
                    peak = max(r.peak_mg for r in rows if r.error is None and r.flags & F_SHOCK)
                    extra = f"  (biggest {peak / 1000:.2f} g)"
                if bit == F_MOTION:
                    secs = sum(r.moves for r in rows if r.error is None and r.flags & F_MOTION) * 0.02
                    extra = f"  (about {secs:.1f} s of movement)"
                print(f"  {name:<22} {len(hit):>4}  {_ranges(hit)}{extra}")
        if not any_event:
            print("  none - no shocks, no movement, thermometers agreed, same sensor throughout")
        sensors = [r.sensor_id for r in rows if r.error is None and r.ver == 4 and r.sensor_id]
        if sensors:
            ids = list(dict.fromkeys(sensors))
            print(f"  BME688 fingerprint{'s' if len(ids) > 1 else ''}: " + ", ".join(f"{i:08x}" for i in ids))

    if any(r.ver >= 3 for r in rows):
        stamped = [r.unix_time for r in rows if r.error is None and r.unix_time]
        unset = sum(1 for r in rows if r.error is None and not r.unix_time)
        if stamped:
            print(f"time    {_when(min(stamped))}  to  {_when(max(stamped))}")
        if unset:
            print(f"        {unset} record(s) logged while the board's clock was not set")
    if rows and rows[-1].hash is not None:
        print(f"head    seq {rows[-1].seq}  0x{rows[-1].hash.hex()}")


def _what_changed(b, l):
    for name, unit, key, fmt in (("temperature", "°C", lambda r: r.temp_mc / 1000, "{:.3f}"),
                                 ("humidity", "%RH", lambda r: r.rh_mpct / 1000, "{:.3f}"),
                                 ("pressure", "hPa", lambda r: r.press_pa / 100, "{:.2f}"),
                                 ("gas", "kΩ", lambda r: r.gas_ohm / 1000, "{:.3f}")):
        if b.error is None and l.error is None and key(b) != key(l):
            return f"{name} {fmt.format(key(l))} on the ledger, {fmt.format(key(b))} on the board"
    return None


def report_against(rows, ledger_path):
    """Compare the board's chain with the ledger's copy: shows history changed after sync."""
    path = Path(ledger_path)
    if not path.exists():
        sys.exit(f"No such ledger file: {path}")
    ledger = parse_rows(extract_export(path.read_text(encoding="utf-8-sig", errors="replace"))[0])
    changed, missing = compare(rows, ledger)
    ledger_top = max((r.seq for r in ledger if r.seq is not None), default=-1)
    newer = sum(1 for r in rows if r.seq is not None and r.seq > ledger_top)

    print(f"\nComparing with the ledger's copy: {path.name} ({len(ledger):,} records)")
    edited = [(b, l, _what_changed(b, l)) for b, l in changed]
    for b, l, what in [e for e in edited if e[2]][:10]:
        print(f"  ✗ seq {b.seq:<8} changed after sync: {what}")
    rehashed = [b.seq for b, l, what in edited if not what]
    if rehashed:
        print(f"  ✗ {_ranges(rehashed)}  re-hashed after sync (readings unchanged)")
    if missing:
        print(f"  ✗ {_ranges([l.seq for l in missing])}  on the ledger but gone from the board")
    if changed and len(changed) == len([r for r in rows if r.seq is not None and r.seq <= ledger_top]):
        print("    (every shared record differs - is this the ledger file for this chain?)")
    if not changed and not missing:
        print("  ✓ every record the ledger holds matches the board")
    else:
        print(f"  ✗ {len(changed) + len(missing)} record(s) on the board no longer match what the"
              f" ledger received - its history was changed after sync")
    if newer:
        print(f"    {newer} newer record(s) on the board are not on the ledger yet")
    return len(changed) + len(missing)


# ---------------------------------------------------------------- chart

INK, INK_2, MUTED = "#0b0b0b", "#52514e", "#898781"
SURFACE, GRID, AXIS = "#fcfcfb", "#e1e0d9", "#c3c2b7"
SERIES, SERIES_2, SERIES_3, CRITICAL = "#2a78d6", "#eb6834", "#1baf7a", "#d03b3b"
EVENT_SHORT = {F_SHOCK: "shock", F_TEMP_MISMATCH: "thermometers disagree", F_SENSOR_CHANGED: "sensor replaced",
               F_CLOCK_SET: "clock set"}


def _series(rows, key, valid=lambda r: r.has_reading):
    """x = seq, y = value; NaN breaks the line at failures and at missing seq numbers."""
    xs, ys, prev = [], [], None
    for r in rows:
        if r.error is not None or r.seq is None:
            continue
        if prev is not None and r.seq != prev + 1:
            xs.append(float("nan"))
            ys.append(float("nan"))
        prev = r.seq
        xs.append(r.seq)
        ys.append(key(r) if valid(r) else float("nan"))
    return xs, ys


def _place_labels(ax, items, y0, dy, renderer, color=INK_2, fontsize=7.5):
    """items: [(x, text)] in x order. Left-aligned under x (right-aligned near the right edge), on up to
    three lines, measured with the real renderer so no two labels overlap."""
    edge = ax.get_window_extent(renderer)
    placed = [[], [], []]
    for x, text in items:
        for line in range(3):
            t = ax.text(x, y0 - line * dy, text, fontsize=fontsize, color=color, ha="left", va="top")
            bb = t.get_window_extent(renderer)
            if bb.x1 > edge.x1 + 30:
                t.set_ha("right")
                bb = t.get_window_extent(renderer)
            pad = bb.expanded(1.0, 1.0)
            pad.x0 -= 6
            pad.x1 += 6
            if line == 2 or not any(pad.overlaps(o) for o in placed[line]):
                placed[line].append(pad)
                break
            t.remove()


def _event_runs(parsed):
    """Consecutive records with the same event -> one run: [(first seq, last seq, name)] sorted by seq."""
    runs = []
    for bit, name in EVENT_SHORT.items():
        seqs = [r.seq for r in parsed if r.ver == 4 and r.flags & bit]
        start = prev = None
        for s in seqs + [None]:
            if start is not None and (s is None or s != prev + 1):
                runs.append((start, prev, name))
                start = None
            if s is not None:
                start = s if start is None else start
                prev = s
    return sorted(runs)


def _end_labels(ax, ends, fig, fontsize=7.5):
    """Direct labels at the right end of each line, nudged apart so they never overlap."""
    gap = fontsize * 1.3                                   # points
    placed = []
    for x, y, text in sorted(ends, key=lambda e: e[1]):
        py = ax.transData.transform((x, y))[1] * 72 / fig.dpi
        want = max(py, placed[-1][0] + gap) if placed else py
        placed.append((want, py, x, y, text))
    for want, py, x, y, text in placed:
        ax.annotate(text, xy=(x, y), xytext=(8, want - py), textcoords="offset points",
                    fontsize=fontsize, color=INK_2, va="center", annotation_clip=False)


def plot(rows, problems, png_path):
    try:
        import matplotlib.pyplot as plt
        from matplotlib.ticker import FuncFormatter, MaxNLocator
    except ImportError:
        print("chart   skipped - install it with:  python3 -m pip install matplotlib")
        return None

    parsed = [r for r in rows if r.seq is not None and r.error is None]
    if not parsed:
        return None
    v4 = any(r.ver == 4 for r in parsed)
    bad = [r for r in rows if r.status != "OK" and r.seq is not None]
    boot_starts = [cur.seq for prev, cur in zip(parsed, parsed[1:]) if cur.boot != prev.boot]
    lo, hi = min(r.seq for r in parsed), max(r.seq for r in parsed)
    span = max(hi - lo, 1)

    fig, axes = plt.subplots(len(METRICS) + 1, 1, sharex=True, figsize=(11, 10 if v4 else 9.2),
                             gridspec_kw={"height_ratios": [0.62 if v4 else 0.42] + [1] * len(METRICS)},
                             facecolor=SURFACE)
    fig.subplots_adjust(left=0.08, right=0.9 if v4 else 0.97, top=0.88, bottom=0.07, hspace=0.55)
    axes[-1].set_xlim(lo - span * 0.01 - 0.5, hi + span * 0.01 + 0.5)   # shared: set before placing labels

    # header: what this is, and the verdict in words (the markers below carry the colour)
    fig.text(0.08, 0.955, f"SAAKSHI chain  ·  {len(rows):,} records  ·  seq {lo:,}–{hi:,}",
             fontsize=13, fontweight="semibold", color=INK)
    if problems == 0:
        verdict = "✓ Intact: every record re-hashed on this laptop and every link checked"
        if v4:
            verdict = "✓ Intact: every record re-hashed, every link and every signature checked on this laptop"
    else:
        named = "  ·  ".join(f"{r.label} {r.status.lower()}" for r in bad[:3])
        more = f"  ·  +{len(bad) - 3} more" if len(bad) > 3 else ""
        verdict = f"✗ {problems} problem{'s' if problems != 1 else ''}:  {named}{more}"
    fig.text(0.08, 0.925, verdict, fontsize=10, color=INK_2)

    # track on the same seq axis, one row per kind so labels never collide:
    #   verification failures (red X) / events (v4) / power-ups (grey tick)
    track = axes[0]
    track.set_facecolor(SURFACE)
    track.set_ylim(0, 1)
    track.set_yticks([])
    track.tick_params(axis="x", length=0)
    for side in ("top", "right", "left", "bottom"):
        track.spines[side].set_visible(False)
    track.set_title("Chain check" + ("  ·  events" if v4 else ""), loc="left", fontsize=10, color=INK_2, pad=4)
    prob_y, event_y, boot_y = (0.8, 0.47, 0.08) if v4 else (0.62, None, 0.16)
    track.axhline(prob_y, color=GRID, lw=0.8)

    groups = []                                   # failures close enough to share one label
    for r in bad:
        if groups and r.seq - groups[-1][-1] <= span * 0.06:
            groups[-1].append(r.seq)
        else:
            groups.append([r.seq])
    for g in groups:
        for s in g:
            track.plot([s], [prob_y], marker="X", ms=9, color=CRITICAL,
                       markeredgecolor=SURFACE, markeredgewidth=1.5, clip_on=False, zorder=3)
        label = (_ranges(g)[4:] if len(g) > 3 else ", ".join(str(s) for s in g))
        at_right = g[0] > lo + span * 0.85
        track.text(g[-1] if at_right else g[0], prob_y + 0.1, label, fontsize=8, color=INK,
                   ha="right" if at_right else "left", va="bottom")

    if v4:
        runs = _event_runs(parsed)
        for first, last, _ in runs:
            track.plot(list(range(first, last + 1)), [event_y] * (last - first + 1), linestyle="none",
                       marker="v", ms=6.5, color=INK_2, markeredgecolor=SURFACE, markeredgewidth=1.0,
                       clip_on=False, zorder=3)
        renderer = fig.canvas.get_renderer()
        _place_labels(track, [(first, name) for first, _, name in runs], event_y - 0.1, 0.16, renderer)

    boot_groups = []                              # power-ups close enough to share one label
    for s in boot_starts:
        if boot_groups and s - boot_groups[-1][-1] <= span * 0.12:
            boot_groups[-1].append(s)
        else:
            boot_groups.append([s])
    for g in boot_groups:
        for s in g:
            track.plot([s - 0.5, s - 0.5], [boot_y - 0.08, boot_y + 0.08], color=AXIS, lw=1.0)
        at_right = g[-1] > lo + span * 0.85      # label outside the group's ticks
        anchor = (g[0] if at_right else g[-1]) - 0.5
        nudge = span * 0.005 * (-1 if at_right else 1)
        track.text(anchor + nudge, boot_y, "power-up" if len(g) == 1 else f"{len(g)} power-ups",
                   fontsize=7.5, color=MUTED, ha="right" if at_right else "left", va="center")

    for i, (ax, (name, unit, key)) in enumerate(zip(axes[1:], METRICS)):
        ax.set_facecolor(SURFACE)
        lines = [(name if i or not v4 else "BME688", SERIES, _series(rows, key))]
        if i == 0 and v4:                         # temperature: all three thermometers
            for label, color, attr in (("DS3231 (clock)", SERIES_2, "rtc_temp_cc"),
                                       ("MPU-6050", SERIES_3, "mpu_temp_cc")):
                lines.append((label, color, _series(rows, lambda r, a=attr: getattr(r, a) / 100,
                                                    lambda r, a=attr: r.ver == 4 and getattr(r, a) != NO_TEMP)))
        ends = []
        for label, color, (xs, ys) in lines:
            finite = [(x, y) for x, y in zip(xs, ys) if y == y]
            ax.plot(xs, ys, color=color, lw=1.6 if color == SERIES else 1.2, solid_capstyle="round",
                    solid_joinstyle="round", marker="o" if len(finite) < 2 else None, ms=4, label=label)
            if finite:
                ends.append((finite[-1][0], finite[-1][1], label))
        for r in bad:
            ax.axvline(r.seq, color=CRITICAL, lw=0.9, alpha=0.85)
        for s in boot_starts:
            ax.axvline(s - 0.5, color=AXIS, lw=0.8)
        title = f"{name}  ·  {unit}" + ("  ·  three thermometers" if i == 0 and v4 else "")
        ax.set_title(title, loc="left", fontsize=10, color=INK_2, pad=4)
        if len(lines) > 1:                        # legend on the title line, labels at the line ends
            leg = ax.legend(loc="lower left", bbox_to_anchor=(0.42, 1.0), ncol=3, fontsize=7.5, frameon=False,
                            handlelength=1.6, borderaxespad=0.2)
            for t in leg.get_texts():
                t.set_color(INK_2)
            ax.relim()
            ax.autoscale_view()
            _end_labels(ax, ends, fig)
        ax.grid(axis="y", color=GRID, lw=0.5)
        ax.set_axisbelow(True)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color(AXIS)
        ax.spines["bottom"].set_linewidth(0.6)
        ax.tick_params(colors=MUTED, labelsize=8.5, length=0)
        ax.yaxis.set_major_locator(MaxNLocator(nbins=4))
        ax.ticklabel_format(axis="y", useOffset=False, style="plain")

    bottom = axes[-1]
    bottom.xaxis.set_major_locator(MaxNLocator(integer=True, nbins=10))
    bottom.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{int(v):,}"))
    bottom.set_xlabel("record (seq)", fontsize=9, color=MUTED)

    fig.savefig(png_path, dpi=150, facecolor=SURFACE)
    print(f"chart   {png_path}")
    if plt.get_backend().lower() != "agg":
        plt.show()
    plt.close(fig)
    return png_path


# ---------------------------------------------------------------- main

def _key_for(rows, meta, key_arg):
    """Pick the key to check signatures with -> (point or None, node ID text, one-line note)."""
    if not any(r.ver == 4 for r in rows):
        return None
    pinned, path = load_key(key_arg)
    board = meta.get("key", "")
    board_point = bytes.fromhex(board) if re.fullmatch(r"04[0-9a-fA-F]{128}", board) else None
    if pinned:
        note = f"signatures checked against {path.name} ({node_id(pinned)})"
        if board_point and board_point != pinned:
            note += (f"\n  ⚠ the board's chip now reports a DIFFERENT key ({node_id(board_point)}):"
                     f" records it signs will fail this check")
        return pinned, node_id(pinned), note
    if board_point and _on_curve(board_point):
        return (board_point, node_id(board_point),
                f"⚠ no {KEY_FILE} found: checked against the key the board reports ({node_id(board_point)}).\n"
                f"    That shows the records match each other, not that they came from YOUR node -\n"
                f"    put the public key from the setup screen into {KEY_FILE}.")
    return None, "", f"⚠ signatures NOT checked - no {KEY_FILE} found (put the key from the setup screen in it)"


def _ledger_file(rows, meta, key_info):
    """'--against ledger': the copy saakshi_ledger.py keeps of this board's chain."""
    node = meta.get("node") or (key_info[1] if key_info else "")
    if not rows or rows[0].hash is None or not re.fullmatch(r"SAAKSHI-[0-9A-F]{8}", node or ""):
        sys.exit("Can't tell which ledger file belongs to this chain - give the file's path instead of 'ledger'.")
    name = f"{node}_{rows[0].hash[:4].hex()}.csv"          # a chain is named after its first record
    folders = [d for d in (Path.cwd() / "saakshi_ledger", Path(__file__).resolve().parent / "saakshi_ledger")
               if d.is_dir()]
    for d in folders:
        if (d / name).exists():
            return str(d / name)
    others = sorted((p for d in folders for p in d.glob(f"{node}_*.csv")), key=lambda p: p.stat().st_mtime)
    if others:
        print(f"\n⚠ the ledger has no chain named like this board's first record ({name}) - the board's"
              f" chain was restarted or its first record replaced. Comparing with the ledger's latest copy.")
        return str(others[-1])
    sys.exit(f"The ledger has no copy of this node's chain yet (looked for saakshi_ledger/{name}).\n"
             f"Run saakshi_ledger.py and let the board sync first.")


def main():
    try:
        sys.stdout.reconfigure(errors="replace")   # ✓/✗ on consoles without UTF-8
    except AttributeError:
        pass

    ap = argparse.ArgumentParser(description="Pull, verify and plot the SAAKSHI chain.")
    ap.add_argument("port", nargs="?", help="serial port, e.g. /dev/cu.usbmodem101 (found automatically if left out)")
    ap.add_argument("--file", help="verify a saved or edited CSV (or a Serial Monitor copy) instead")
    ap.add_argument("--key", help=f"public key file (default: {KEY_FILE} here or next to this script)")
    ap.add_argument("--against", metavar="LEDGER_CSV",
                    help="also compare with the ledger's copy: 'ledger' finds saakshi_ledger.py's file for this chain")
    ap.add_argument("--no-plot", action="store_true", help="skip the chart")
    ap.add_argument("--no-clock", action="store_true", help="don't set the board's clock")
    args = ap.parse_args()

    saved, clock_msg = None, None
    if args.file:
        path = Path(args.file)
        if not path.exists():
            sys.exit(f"No such file: {path}")
        text, begin = extract_export(path.read_text(encoding="utf-8-sig", errors="replace"))
        source, stem = str(path), path.with_suffix("")
    else:
        port = args.port or find_port()
        print(f"pulling the chain from {port} ...")
        lines, begin, end_count, clock_msg = pull(port, set_clock=not args.no_clock)
        begin_count = _count(begin)
        if not lines or lines[0].strip().lower() not in {",".join(h) for h in HEADERS.values()}:
            sys.exit("Unexpected export format - is the SAAKSHI firmware uploaded?")
        received = len(lines) - 1
        if not (begin_count == end_count == received):
            sys.exit(f"Transfer incomplete: the board announced {begin_count} records, "
                     f"sent {end_count}, {received} arrived. Run this again.")
        text = "\n".join(lines) + "\n"
        stem = Path(f"saakshi_chain_{datetime.now():%Y%m%d_%H%M%S}")
        saved = stem.with_suffix(".csv").resolve()
        saved.write_text(text, encoding="utf-8")
        source = port

    rows = parse_rows(text)
    key_info = _key_for(rows, export_meta(begin), args.key)
    problems = verify(rows, key_info[0] if key_info else None)
    report(rows, problems, source, saved, key_info)
    if clock_msg:
        print(clock_msg)
    against = args.against
    if against and against.lower() == "ledger":
        against = _ledger_file(rows, export_meta(begin), key_info)
    mismatches = report_against(rows, against) if against else 0
    if rows and not args.no_plot:
        plot(rows, problems, stem.with_suffix(".png"))
    print()
    sys.exit(0 if problems == 0 and mismatches == 0 else 2)


if __name__ == "__main__":
    main()
