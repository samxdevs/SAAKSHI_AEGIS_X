#!/usr/bin/env python3
"""
saakshi_relay.py - posts SAAKSHI chip-signed records ("heads") to SaakshiRegistry on Polygon Amoy.

Anyone can run this beside their own copy of the ledger: the exporter, the buyer, FSSAI, an insurer.
The contract checks the ATECC608B's signature itself, so a relay cannot post anything the chip did
not sign. Running several relays only makes the system harder to stop; none of them is trusted.

Each round, for every chain in the ledger folder, it:
  1. re-checks every record (hash, link to the record before, chip signature),
  2. takes the newest SIGNED record - its hash locks in every record before it,
  3. posts it if it is not anchored yet (every 50 new records, or every 15 min if fewer came in).

Before deploying anything:
    python3 -m pip install web3 cryptography
    python3 saakshi_relay.py --check              check the ledger, show what would be posted (offline)
    python3 saakshi_relay.py --precompile         test Polygon's P-256 checker on Amoy with a real
                                                  signature from your node (internet, no wallet)
    python3 saakshi_relay.py --deploy             (if Remix fails) compile + deploy from this Mac;
                                                  needs relay_key.txt and: pip install py-solc-x
After deploying SaakshiRegistry.sol:
    python3 saakshi_relay.py --contract 0x... --selftest   same test, through the contract
    python3 saakshi_relay.py --once               register the node if needed, post the newest head
    python3 saakshi_relay.py                      keep running beside the ledger
    python3 saakshi_relay.py --status             what is anchored on-chain for this node
    python3 saakshi_relay.py --prove 1500         when record 1500 became impossible to change
    python3 saakshi_relay.py --fake               try to post a forged head (the contract must refuse)
    python3 saakshi_relay.py --publish            encrypt the records for the QR verification page

Wallet: any MetaMask account with free Amoy test POL. Put its private key in relay_key.txt next to
this script (chmod 600, keep it out of git), or export SAAKSHI_RELAY_KEY=... .
Never paste the key or the seed phrase into a chat.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import sys
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
except ImportError:
    sys.exit("cryptography is not installed. Run:  python3 -m pip install cryptography")

HERE = Path(__file__).resolve().parent
STATE_DIR = HERE / "saakshi_relay"
CONFIG_FILE = STATE_DIR / "config.json"
POSTED_FILE = STATE_DIR / "posted.json"
KEY_FILE = HERE / "relay_key.txt"
PUBKEY_FILE = HERE / "saakshi_pubkey.txt"

AMOY_RPC = "https://rpc-amoy.polygon.technology"
AMOY_CHAIN_ID = 80002
EXPLORER = "https://amoy.polygonscan.com"
P256_PRECOMPILE = "0x0000000000000000000000000000000000000100"
PUBLIC_RPCS = ["https://polygon-amoy-bor-rpc.publicnode.com", "https://polygon-amoy.drpc.org",
               "https://rpc-amoy.polygon.technology"]
MIN_TIP_GWEI = 30                       # Polygon refuses tips below 25 gwei
MAX_FEE_GWEI = 500                      # refuse to send above this (testnet fee spikes)

FILE_RE = re.compile(r"^(SAAKSHI-[0-9A-F]{8})_([0-9a-f]{8})\.csv$")
KEY_RE = re.compile(r"04[0-9a-fA-F]{128}")
GENESIS = bytes(32)
NO_TEMP = -32768
F_UNSIGNED = 0x0100
F_SENSOR_FAIL, F_SHOCK, F_TEMP_MISMATCH, F_SENSOR_CHANGED = 0x0002, 0x0020, 0x0040, 0x0080
# Moments a buyer or insurer would ask about: anchored straight away instead of waiting for the next batch.
EVENT_FLAGS = ((F_SHOCK, "a jolt over 1 g"), (F_SENSOR_CHANGED, "the temperature sensor was swapped"),
               (F_TEMP_MISMATCH, "the thermometers disagree"))


def first_event(rows, band):
    """The first important moment among these new records, as text, or None."""
    prev_out = None
    for r in rows:
        for bit, what in EVENT_FLAGS:
            if r.flags & bit:
                return f"{what} (seq {r.seq})"
        if band and not r.flags & F_SENSOR_FAIL:
            out = not band[0] <= r.temp_mc / 1000 <= band[1]
            if out and prev_out is False:                # only the moment it leaves the band, not every record after
                return f"temperature left {band[0]}-{band[1]} °C: {r.temp_mc / 1000:.2f} °C (seq {r.seq})"
            prev_out = out
    return None
COLUMNS = ["seq", "boot", "uptime_s", "unix_time", "temp_c", "rh_pct", "pressure_hpa", "gas_kohm",
           "rtc_temp_c", "mpu_temp_c", "peak_g", "moves", "sensor_id", "flags", "prev_hash", "hash", "sig"]
BODY = struct.Struct("<IIIIiiiihhHHIH32s")          # the firmware's Record up to (not incl.) hash
assert BODY.size == 78

ABI = json.loads("""[
 {"type":"function","name":"register","stateMutability":"nonpayable",
  "inputs":[{"name":"x","type":"bytes32"},{"name":"y","type":"bytes32"},{"name":"body","type":"bytes"},
            {"name":"r","type":"bytes32"},{"name":"s","type":"bytes32"}],
  "outputs":[{"name":"keyHash","type":"bytes32"}]},
 {"type":"function","name":"submitHead","stateMutability":"nonpayable",
  "inputs":[{"name":"keyHash","type":"bytes32"},{"name":"body","type":"bytes"},
            {"name":"r","type":"bytes32"},{"name":"s","type":"bytes32"}],
  "outputs":[]},
 {"type":"function","name":"keyHashOf","stateMutability":"pure",
  "inputs":[{"name":"x","type":"bytes32"},{"name":"y","type":"bytes32"}],
  "outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"node","stateMutability":"view",
  "inputs":[{"name":"keyHash","type":"bytes32"}],
  "outputs":[{"name":"x","type":"bytes32"},{"name":"y","type":"bytes32"},{"name":"registered","type":"uint64"}]},
 {"type":"function","name":"isAnchored","stateMutability":"view",
  "inputs":[{"name":"recordHash","type":"bytes32"}],
  "outputs":[{"name":"anchored","type":"bool"},{"name":"keyHash","type":"bytes32"},
             {"name":"seq","type":"uint32"},{"name":"nodeTime","type":"uint32"},
             {"name":"blockTime","type":"uint64"},{"name":"relayer","type":"address"}]},
 {"type":"function","name":"headCount","stateMutability":"view",
  "inputs":[{"name":"keyHash","type":"bytes32"}],"outputs":[{"name":"","type":"uint256"}]},
 {"type":"function","name":"headAt","stateMutability":"view",
  "inputs":[{"name":"keyHash","type":"bytes32"},{"name":"index","type":"uint256"}],
  "outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"verifySignature","stateMutability":"view",
  "inputs":[{"name":"h","type":"bytes32"},{"name":"r","type":"bytes32"},{"name":"s","type":"bytes32"},
            {"name":"x","type":"bytes32"},{"name":"y","type":"bytes32"}],
  "outputs":[{"name":"","type":"bool"}]},
 {"type":"error","name":"BadBody","inputs":[{"name":"length","type":"uint256"}]},
 {"type":"error","name":"BadSignature","inputs":[]},
 {"type":"error","name":"AlreadyRegistered","inputs":[{"name":"keyHash","type":"bytes32"}]},
 {"type":"error","name":"NotRegistered","inputs":[{"name":"keyHash","type":"bytes32"}]},
 {"type":"error","name":"AlreadyAnchored","inputs":[{"name":"recordHash","type":"bytes32"}]}
]""")


def say(msg=""):
    print(time.strftime("%H:%M:%S ") + msg if msg else "", flush=True)


# ---------------- records: read the ledger's CSV and re-check it ----------------

class Bad(Exception):
    pass


class Rec:
    __slots__ = ("seq", "flags", "unix_time", "temp_mc", "prev", "hash", "sig", "body")


def _fixed(text, scale, what):
    """'29.170' with scale 1000 -> 29170, exactly (no floats)."""
    try:
        v = Decimal(text) * scale
    except InvalidOperation:
        raise Bad(f"{what} is not a number: {text!r}")
    if v != v.to_integral_value():
        raise Bad(f"{what} has too many decimals: {text!r}")
    return int(v)


def _hex(text, n, what):
    t = text[2:] if text[:2] in ("0x", "0X") else text
    try:
        b = bytes.fromhex(t)
    except ValueError:
        raise Bad(f"{what} is not hex")
    if len(b) != n:
        raise Bad(f"{what} should be {n} bytes, found {len(b)}")
    return b


def parse_row(cells):
    """One CSV row -> Rec, rebuilding the exact 78 bytes the board hashed."""
    if len(cells) != len(COLUMNS):
        raise Bad(f"{len(cells)} columns, expected {len(COLUMNS)}")
    c = dict(zip(COLUMNS, (x.strip() for x in cells)))
    r = Rec()
    try:
        r.seq, boot, uptime, r.unix_time = (int(c[k]) for k in ("seq", "boot", "uptime_s", "unix_time"))
        moves, r.flags = int(c["moves"]), int(c["flags"])
        sensor_id = int(c["sensor_id"], 16)
    except ValueError as e:
        raise Bad(f"not a whole number ({e})")
    r.temp_mc = _fixed(c["temp_c"], 1000, "temp_c")
    rh = _fixed(c["rh_pct"], 1000, "rh_pct")
    press = _fixed(c["pressure_hpa"], 100, "pressure_hpa")
    gas = _fixed(c["gas_kohm"], 1000, "gas_kohm")
    rtc = NO_TEMP if c["rtc_temp_c"] == "" else _fixed(c["rtc_temp_c"], 100, "rtc_temp_c")
    mpu = NO_TEMP if c["mpu_temp_c"] == "" else _fixed(c["mpu_temp_c"], 100, "mpu_temp_c")
    peak = _fixed(c["peak_g"], 1000, "peak_g")
    r.prev = _hex(c["prev_hash"], 32, "prev_hash")
    r.hash = _hex(c["hash"], 32, "hash")
    r.sig = _hex(c["sig"], 64, "sig")
    try:
        r.body = BODY.pack(r.seq, boot, uptime, r.unix_time, r.temp_mc, rh, press, gas,
                           rtc, mpu, peak, moves, sensor_id, r.flags, r.prev)
    except struct.error as e:
        raise Bad(f"a value is out of range ({e})")
    return r


def read_csv(path):
    """Rows of a chain CSV. A last line still being written by the ledger (no newline yet) is left out."""
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    if not text.endswith("\n"):
        lines = lines[:-1]
    rows = []
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("seq,"):
            continue
        try:
            rows.append(parse_row(line.split(",")))
        except Bad as e:
            raise Bad(f"{path.name} line {n}: {e}")
    return rows


# ---------------- node key ----------------

class NodeKey:
    def __init__(self, path):
        if not path.exists():
            sys.exit(f"{path.name} not found. Put it next to this script (it holds the node's public key).")
        m = KEY_RE.search(path.read_text(encoding="utf-8"))
        if not m:
            sys.exit(f"No public key (04 + 128 hex digits) found in {path.name}.")
        raw = bytes.fromhex(m.group(0))
        self.x, self.y = raw[1:33], raw[33:65]
        self.key_hash = hashlib.sha256(raw).digest()          # = keyHashOf(x, y) in the contract
        self.node = "SAAKSHI-" + self.key_hash[:4].hex().upper()
        self.pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def signature_ok(pub, digest, sig):
    if sig == bytes(64):
        return False
    der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        pub.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


def verify_chain(rows, pub):
    """Check every record. Returns how many records, from the start, are covered by a signature
    (an unsigned record counts once a later signed record links to it). Raises Bad on any fault."""
    covered = 0
    expect_seq = rows[0].seq if rows else 0
    expect_prev = GENESIS if (rows and rows[0].seq == 0) else (rows[0].prev if rows else GENESIS)
    for i, r in enumerate(rows):
        if r.seq != expect_seq:
            raise Bad(f"seq {r.seq} where seq {expect_seq} was expected: records missing or out of order")
        if r.prev != expect_prev:
            raise Bad(f"seq {r.seq} does not link to the record before it")
        if hashlib.sha256(r.body).digest() != r.hash:
            raise Bad(f"seq {r.seq}: contents do not match its hash (DATA ALTERED)")
        if r.flags & F_UNSIGNED:
            if r.sig != bytes(64):
                raise Bad(f"seq {r.seq} is marked unsigned but carries a signature")
        elif not signature_ok(pub, r.hash, r.sig):
            raise Bad(f"seq {r.seq}: SIGNATURE INVALID (not made by this node's ATECC608)")
        else:
            covered = i + 1
        expect_seq, expect_prev = r.seq + 1, r.hash
    return covered


def streams(ledger_dir, nk):
    if not ledger_dir.is_dir():
        sys.exit(f"Ledger folder {ledger_dir} not found. Run this next to saakshi_ledger.py, or use --ledger.")
    found = []
    for p in sorted(ledger_dir.glob("*.csv")):
        m = FILE_RE.match(p.name)
        if not m:
            continue
        if m.group(1) != nk.node:
            say(f"  skipping {p.name}: not the node in {PUBKEY_FILE.name} ({nk.node})")
            continue
        found.append((m.group(2), p))
    return found


def checked(path, pub):
    rows = read_csv(path)
    return rows, (verify_chain(rows, pub) if rows else 0)


def newest_signed(ledger_dir, nk):
    """The newest signed record across this node's chains - used for the signature tests."""
    best = None
    for chain, path in streams(ledger_dir, nk):
        rows, covered = checked(path, nk.pub)
        if covered:
            r = rows[covered - 1]
            if best is None or r.unix_time >= best[1].unix_time:
                best = (chain, r)
    if not best:
        sys.exit("No signed record found in the ledger folder to test with.")
    return best


# ---------------- local state ----------------

def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def save_json(path, data):
    STATE_DIR.mkdir(exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_key():
    key = os.environ.get("SAAKSHI_RELAY_KEY", "").strip()
    if not key and KEY_FILE.exists():
        if KEY_FILE.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            say(f"note: {KEY_FILE.name} can be read by other users. Fix with:  chmod 600 {KEY_FILE.name}")
        key = KEY_FILE.read_text(encoding="utf-8").strip()
    if not key:
        sys.exit(f"No wallet key. Put it in {KEY_FILE.name} (one line) or set SAAKSHI_RELAY_KEY.")
    if not re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", key):
        sys.exit("The wallet key should be 64 hex digits (MetaMask: Account details > Show private key).")
    return key


# ---------------- Polygon ----------------

class Polygon:
    def __init__(self, rpc, contract=None, key=None):
        try:
            from web3 import Web3
        except ImportError:
            sys.exit("web3 is not installed. Run:  python3 -m pip install web3")
        self.W = Web3
        self.w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
        poa = None                               # Polygon blocks carry extra data; web3 v7+/v6
        try:
            from web3.middleware import ExtraDataToPOAMiddleware as poa
        except ImportError:
            try:
                from web3.middleware import geth_poa_middleware as poa
            except ImportError:
                pass                             # not needed for what this script does
        if poa is not None:
            try:
                self.w3.middleware_onion.inject(poa, layer=0)
            except Exception:
                pass
        try:
            cid = self.w3.eth.chain_id
        except Exception as e:
            sys.exit(f"Can't reach {rpc}\n  reason: {type(e).__name__}: {str(e)[:300]}\n"
                     "  Try another free Amoy server, e.g.:\n"
                     "    --rpc https://polygon-amoy-bor-rpc.publicnode.com\n"
                     "    --rpc https://polygon-amoy.drpc.org")
        if cid != AMOY_CHAIN_ID:
            sys.exit(f"{rpc} is chain {cid}, not Polygon Amoy ({AMOY_CHAIN_ID}).")
        self.c = None
        if contract:
            addr = Web3.to_checksum_address(contract)
            if self.w3.eth.get_code(addr) in (b"", b"\x00"):
                sys.exit(f"No contract at {contract} on Amoy. Check the address Remix showed after deploying.")
            self.c = self.w3.eth.contract(address=addr, abi=ABI)
        self.acct = self.w3.eth.account.from_key(key) if key else None

    def precompile(self, h, r, s, x, y):
        out = self.w3.eth.call({"to": self.W.to_checksum_address(P256_PRECOMPILE), "data": h + r + s + x + y})
        return len(out) == 32 and int.from_bytes(out, "big") == 1

    def fees(self):
        """(maxFeePerGas, maxPriorityFeePerGas) in wei. Base fee from the latest block plus a fixed
        tip; never trusts a server's 'suggested tip', which can be wildly high on testnets."""
        W = self.W
        tip = W.to_wei(MIN_TIP_GWEI, "gwei")
        base = None
        try:
            base = self.w3.eth.get_block("latest").get("baseFeePerGas")
        except Exception:
            pass
        if not base:
            try:
                base = self.w3.eth.fee_history(1, "latest")["baseFeePerGas"][-1]
            except Exception:
                pass
        if not base:
            base = max(self.w3.eth.gas_price - tip, W.to_wei(1, "gwei"))
        max_fee = base * 2 + tip
        cap = W.to_wei(MAX_FEE_GWEI, "gwei")
        if max_fee > cap:
            raise RuntimeError(f"Amoy fees are unusually high right now (base {base / 1e9:.0f} gwei). "
                               "Try again in a few minutes.")
        return max_fee, tip, base

    def send(self, fn, want_receipt=False):
        max_fee, tip, base = self.fees()
        addr = self.acct.address
        try:
            gas = int(fn.estimate_gas({"from": addr}) * 1.2)
        except Exception as e:
            raise RuntimeError(f"the network refused this transaction: {why(e)}")
        cost = gas * max_fee / 1e18
        bal = self.w3.eth.get_balance(addr) / 1e18
        say(f"  fee: base {base / 1e9:.1f} + tip {tip / 1e9:.0f} gwei, up to {cost:.4f} POL "
            f"(balance {bal:.4f})")
        if cost > bal:
            raise RuntimeError(f"not enough test POL: need up to {cost:.4f}, have {bal:.4f}. "
                               "Get more at https://faucet.polygon.technology")
        tx = fn.build_transaction({
            "from": addr,
            "nonce": self.w3.eth.get_transaction_count(addr, "pending"),
            "chainId": AMOY_CHAIN_ID,
            "gas": gas,
            "maxPriorityFeePerGas": tip,
            "maxFeePerGas": max_fee,
        })
        signed = self.acct.sign_transaction(tx)
        raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
        txh = self.w3.eth.send_raw_transaction(raw)
        rcpt = self.w3.eth.wait_for_transaction_receipt(txh, timeout=240)
        txh = "0x" + bytes(txh).hex()
        if rcpt.status != 1:
            raise RuntimeError(f"transaction failed: {EXPLORER}/tx/{txh}")
        if want_receipt:
            return txh, rcpt
        return txh, rcpt.blockNumber

    # contract calls
    def registered(self, nk):
        return self.c.functions.node(nk.key_hash).call()[2] != 0

    def register(self, nk, rec):
        return self.send(self.c.functions.register(nk.x, nk.y, rec.body, rec.sig[:32], rec.sig[32:]))

    def submit(self, nk, rec):
        return self.send(self.c.functions.submitHead(nk.key_hash, rec.body, rec.sig[:32], rec.sig[32:]))

    def stamp(self, h):
        a, kh, seq, nt, bt, who = self.c.functions.isAnchored(h).call()
        return {"anchored": a, "key": bytes(kh), "seq": seq, "nodeTime": nt, "blockTime": bt, "relayer": who}

    def heads(self, nk, start=0):
        n = self.c.functions.headCount(nk.key_hash).call()
        return [bytes(self.c.functions.headAt(nk.key_hash, i).call()) for i in range(start, n)]

    def verify(self, h, r, s, x, y):
        return self.c.functions.verifySignature(h, r, s, x, y).call()


ERROR_CODES = {                         # first 4 bytes of keccak256 of each SaakshiRegistry error
    "0x5cd5d233": "BadSignature",
    "0xd3b8f3ef": "BadBody",
    "0x77caf672": "AlreadyRegistered",
    "0x8cc00d16": "NotRegistered",
    "0x30d23813": "AlreadyAnchored",
}


def why(e):
    """Short reason from a refused contract call (web3 may give the error's name or only its code)."""
    text = str(e)
    for name in ERROR_CODES.values():
        if name in text:
            return name
    low = text.lower()
    for code, name in ERROR_CODES.items():
        if code in low:
            return name
    return f"{type(e).__name__}: {text[:200]}"


def when(t):
    return time.strftime("%d %b %Y %H:%M:%S", time.localtime(t)) if t else "clock not set"


# ---------------- jobs ----------------

def run_check(args, nk):
    say(f"node {nk.node}  ledger {args.ledger}")
    posted = load_json(POSTED_FILE, [])
    ok = True
    for chain, path in streams(args.ledger, nk):
        try:
            rows, covered = checked(path, nk.pub)
        except Bad as e:
            say(f"✗ chain {chain}: {e}")
            ok = False
            continue
        if not rows:
            say(f"  chain {chain}: empty")
            continue
        tail = len(rows) - covered
        say(f"✓ chain {chain}: seq {rows[0].seq}..{rows[-1].seq}, every record checks out"
            + (f" ({tail} unsigned at the end, waiting for a signed record)" if tail else ""))
        if covered:
            head = rows[covered - 1]
            mine = [p for p in posted if p["chain"] == chain]
            done = f"; this laptop last posted seq {mine[-1]['seq']}" if mine else ""
            say(f"  newest signed record: seq {head.seq}, hash {head.hash.hex()[:16]}…{done}")
    return ok


def run_sigtest(args, nk, pg, through_contract):
    chain, rec = newest_signed(args.ledger, nk)
    r, s = rec.sig[:32], rec.sig[32:]
    bad = bytearray(rec.hash)
    bad[0] ^= 1
    test = (lambda h: pg.verify(h, r, s, nk.x, nk.y)) if through_contract else \
           (lambda h: pg.precompile(h, r, s, nk.x, nk.y))
    where = "SaakshiRegistry.verifySignature()" if through_contract else "Polygon's P-256 checker (0x100)"
    say(f"testing {where} with chain {chain} seq {rec.seq}, signed by {nk.node}")
    good_ok, bad_ok = test(rec.hash), test(bytes(bad))
    say(f"  real signature    -> {'VALID' if good_ok else 'rejected'}   (must be VALID)")
    say(f"  one bit changed   -> {'VALID' if bad_ok else 'rejected'}   (must be rejected)")
    if good_ok and not bad_ok:
        say("✓ the chain checks your ATECC608B signatures correctly"
            + ("" if through_contract else " - safe to deploy SaakshiRegistry.sol"))
        return True
    say("✗ test failed - do not rely on the contract yet; send this output to Claude")
    return False


def run_relay(args, nk, pg, watch):
    bal = pg.w3.eth.get_balance(pg.acct.address) / 1e18
    say(f"relay wallet {pg.acct.address}  balance {bal:.4f} POL")
    if bal < 0.01:
        say("  low on test POL: get more free at https://faucet.polygon.technology (pick Amoy)")
    posted = load_json(POSTED_FILE, [])
    anchored, seen = set(), 0                  # every head of this node on-chain, read incrementally
    last_post, last_err, last_event = {}, {}, {}
    band = load_json(CONFIG_FILE, {}).get("range")              # set with --publish --range 2,8
    while True:
        try:
            new = pg.heads(nk, seen)
            anchored.update(new)
            seen += len(new)
            registered = pg.registered(nk)
        except Exception as e:
            say(f"✗ can't read the contract: {why(e)}")
            if not watch:
                raise
            time.sleep(args.poll)
            continue
        for chain, path in streams(args.ledger, nk):
            try:
                rows, covered = checked(path, nk.pub)
                if not covered:
                    continue
                by_hash = {r.hash: i for i, r in enumerate(rows)}
                for p in posted:                   # what we anchored for this chain must still be here
                    if p["chain"] == chain and bytes.fromhex(p["hash"]) not in by_hash:
                        raise Bad(f"seq {p['seq']} was anchored ({p['tx']}) but is no longer in the "
                                  "ledger file: the file was changed after anchoring")
                head = rows[covered - 1]
                if not registered:
                    say(f"registering {nk.node} on-chain (proof: chain {chain} seq {head.seq}) ...")
                    txh, block = pg.register(nk, head)
                    registered = True
                    say(f"✓ registered in block {block}: {EXPLORER}/tx/{txh}")
                if head.hash in anchored:
                    continue
                last_i = max((by_hash[h] for h in anchored if h in by_hash), default=-1)
                waiting = covered - 1 - last_i
                event = None
                if watch and args.event_gap > 0 and time.time() - last_event.get(chain, 0) >= args.event_gap:
                    event = first_event(rows[last_i + 1:covered], band)
                if watch and not event and waiting < args.min_records and \
                        time.time() - last_post.get(chain, 0) < args.max_wait:
                    continue
                if pg.stamp(head.hash)["anchored"]:    # another relay got there first: fine
                    anchored.add(head.hash)
                    continue
                say(f"posting chain {chain} head seq {head.seq} (locks in {waiting} new record(s))"
                    + (f" straight away: {event}" if event else "") + " ...")
                try:
                    txh, block = pg.submit(nk, head)
                except Exception as e:
                    if why(e) == "AlreadyAnchored":
                        anchored.add(head.hash)
                        say("  already anchored by another relay - nothing to do")
                        continue
                    raise
                anchored.add(head.hash)
                posted.append({"chain": chain, "seq": head.seq, "hash": head.hash.hex(), "tx": txh,
                               "block": block, "time": int(time.time())})
                save_json(POSTED_FILE, posted)
                last_post[chain] = time.time()
                if event:
                    last_event[chain] = time.time()
                last_err.pop(chain, None)
                say(f"✓ anchored in block {block}: {EXPLORER}/tx/{txh}")
            except Bad as e:
                if last_err.get(chain) != str(e):
                    say(f"✗ chain {chain}: {e}  -  NOT posted")
                last_err[chain] = str(e)
            except Exception as e:
                say(f"✗ chain {chain}: {e if isinstance(e, RuntimeError) else why(e)}")
                if not watch:
                    sys.exit(1)
        if not watch:
            return
        time.sleep(args.poll)


def run_status(args, nk, pg):
    reg = pg.c.functions.node(nk.key_hash).call()[2]
    say(f"{nk.node}: " + (f"registered {when(reg)}" if reg else "NOT registered yet"))
    hs = pg.heads(nk)
    say(f"{len(hs)} head(s) anchored")
    for h in hs[-15:]:
        t = pg.stamp(h)
        say(f"  seq {t['seq']:<7} anchored {when(t['blockTime'])}  by {t['relayer'][:10]}…  {h.hex()[:16]}…")


def run_prove(args, nk, pg):
    for chain, path in streams(args.ledger, nk):
        if args.chain and chain != args.chain:
            continue
        rows, covered = checked(path, nk.pub)
        idx = next((i for i, r in enumerate(rows) if r.seq == args.prove), None)
        if idx is None:
            continue
        rec = rows[idx]
        anchored = set(pg.heads(nk))             # one read of this node's heads, not one per record
        for j in range(idx, covered):            # first anchored signed record at or after it
            if rows[j].hash not in anchored:
                continue
            t = pg.stamp(rows[j].hash)
            if t["anchored"] and t["key"] == nk.key_hash:
                say(f"chain {chain} seq {rec.seq}  hash {rec.hash.hex()}")
                say(f"  recorded by the node at {when(rec.unix_time)}")
                say(f"  locked in by head seq {rows[j].seq}, anchored on Polygon at {when(t['blockTime'])}")
                say(f"  link: {j - idx} hash step(s) from this record to the head, all checked here")
                say(f"  head on-chain: {EXPLORER}/address/{pg.c.address}#readContract  "
                    f"isAnchored(0x{rows[j].hash.hex()})")
                say("  => this record cannot have been changed after that time")
                return
        sys.exit(f"seq {args.prove} exists but no anchored head covers it yet - run --once first.")
    sys.exit(f"seq {args.prove} not found in the ledger.")


def run_fake(args, nk, pg):
    """Demo: a relay tries to anchor a record the chip never signed. Uses estimate only - costs nothing."""
    chain, rec = newest_signed(args.ledger, nk)
    forged = bytearray(rec.body)
    forged[16:20] = struct.pack("<i", 2000)    # temp_mc -> 2.000 °C: a 'nicer' cold-chain reading
    fn = pg.c.functions.submitHead(nk.key_hash, bytes(forged), rec.sig[:32], rec.sig[32:])
    say(f"forging chain {chain} seq {rec.seq}: temperature changed to 2.000 °C, old signature kept")
    try:
        fn.estimate_gas({"from": pg.acct.address if pg.acct else "0x000000000000000000000000000000000000dEaD"})
        say("✗ the contract would ACCEPT it - something is wrong, send this to Claude")
    except Exception as e:
        say(f"✓ contract refused it: {why(e)}")


# ---------------- publishing for the verification page ----------------

VIEW_KEYS_FILE = STATE_DIR / "view_keys.json"


def view_key(node):
    """The node's QR key (32 random bytes, base64url). Made once and kept, so the QR on the box
    stays valid. Lives only in saakshi_relay/ on this Mac - never in the site folder."""
    import base64
    keys = load_json(VIEW_KEYS_FILE, {})
    if node not in keys:
        keys[node] = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        save_json(VIEW_KEYS_FILE, keys)
        try:
            os.chmod(VIEW_KEYS_FILE, 0o600)
        except OSError:
            pass
    return keys[node]


def run_publish(args, nk, cfg, rpc):
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if "contract" not in cfg:
        sys.exit("No contract address yet - deploy SaakshiRegistry first.")
    site = args.site
    page = site / "verify" / "index.html"
    if not page.exists():
        say(f"note: {page} not found - unzip saakshi_site.zip here so the page files are in place")
    data_dir = site / "verify" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    rng = None
    if args.range:
        try:
            lo, hi = (float(x) for x in args.range.split(","))
            rng = [lo, hi]
        except ValueError:
            sys.exit("--range should look like 2,8 (lowest,highest °C allowed)")
        cfg["range"] = rng
        save_json(CONFIG_FILE, cfg)
    else:
        rng = cfg.get("range")
    if args.site_url:
        cfg["site_url"] = args.site_url.rstrip("/")
        save_json(CONFIG_FILE, cfg)
    b = lambda x: base64.b64encode(x).decode()
    key_b64 = view_key(nk.node)
    key = base64.urlsafe_b64decode(key_b64 + "=" * (-len(key_b64) % 4))
    posted = load_json(POSTED_FILE, [])
    index = load_json(data_dir / "index.json", {"nodes": {}})
    for chain, path in streams(args.ledger, nk):
        rows, covered = checked(path, nk.pub)        # refuses (Bad) if anything is wrong
        if not rows:
            continue
        aad = f"{nk.node}|{chain}|{rows[0].seq}|{len(rows)}"
        iv = os.urandom(12)
        bundle = {
            "format": "saakshi-bundle/1",
            "node": nk.node, "chain": chain,
            "pubkey": (b"\x04" + nk.x + nk.y).hex(),
            "firstSeq": rows[0].seq, "count": len(rows),
            "hashes": b(b"".join(r.hash for r in rows)),
            "sigs": b(b"".join(r.sig for r in rows)),
            "enc": {"alg": "AES-256-GCM", "iv": b(iv), "aad": aad,
                    "data": b(AESGCM(key).encrypt(iv, b"".join(r.body for r in rows), aad.encode()))},
            "registry": {"address": cfg["contract"], "chainId": AMOY_CHAIN_ID, "explorer": EXPLORER,
                         "rpc": [rpc] + [u for u in PUBLIC_RPCS if u != rpc]},
            "range": rng,
            "anchors": [{"seq": p["seq"], "hash": p["hash"], "tx": p["tx"]} for p in posted if p["chain"] == chain],
            "published": int(time.time()),
        }
        fname = f"{nk.node}_{chain}.json"
        (data_dir / fname).write_text(json.dumps(bundle, separators=(",", ":")), encoding="utf-8")
        lst = [e for e in index["nodes"].get(nk.node, []) if e["chain"] != chain]
        lst.append({"chain": chain, "file": f"data/{fname}", "count": len(rows),
                    "firstSeq": rows[0].seq, "published": bundle["published"]})
        index["nodes"][nk.node] = lst
        say(f"✓ chain {chain}: {len(rows)} records checked, encrypted and written to {data_dir / fname}")
    (data_dir / "index.json").write_text(json.dumps(index, indent=1), encoding="utf-8")

    base = cfg.get("site_url", "http://localhost:8000")
    url = f"{base}/verify/?n={nk.node}#k={key_b64}"
    say("")
    say("QR link for this node (the part after # is the key - it never reaches the server):")
    print("  " + url, flush=True)
    if "site_url" not in cfg:
        say("  (that is for testing on this Mac; after deploying, run once with --site-url https://yoursite.netlify.app)")
    try:
        import qrcode
        out = STATE_DIR / f"qr_{nk.node}.png"
        qrcode.make(url).save(out)
        say(f"QR image: {out}  (print it for the box lid)")
    except ImportError:
        say("For a QR image: python3 -m pip install 'qrcode[pil]' and publish again")
    say(f"Upload the folder {site} to Netlify. Keep saakshi_relay/view_keys.json private.")


def run_deploy(args, rpc, cfg):
    """Compile SaakshiRegistry.sol on this Mac (solc 0.8.24, EVM paris) and deploy it to Amoy."""
    src_path = HERE / "SaakshiRegistry.sol"
    if not src_path.exists():
        sys.exit(f"{src_path.name} not found next to this script.")
    src = src_path.read_text(encoding="utf-8")
    if "_store(" not in src:
        sys.exit(f"{src_path.name} is the OLD version (no _store). Download the newest one from Claude.")
    try:
        import solcx
    except ImportError:
        sys.exit("py-solc-x is not installed. Run:  python3 -m pip install py-solc-x")
    version = "0.8.24"
    if version not in [str(v) for v in solcx.get_installed_solc_versions()]:
        say(f"downloading the Solidity compiler {version} (once) ...")
        solcx.install_solc(version)
    say("compiling SaakshiRegistry.sol (EVM paris) ...")
    out = solcx.compile_standard({
        "language": "Solidity",
        "sources": {"SaakshiRegistry.sol": {"content": src}},
        "settings": {"evmVersion": "paris", "optimizer": {"enabled": False},
                     "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}}},
    }, solc_version=version)
    errors = [e for e in out.get("errors", []) if e.get("severity") == "error"]
    if errors:
        sys.exit("compile failed:\n" + "\n".join(e.get("formattedMessage", str(e)) for e in errors))
    art = out["contracts"]["SaakshiRegistry.sol"]["SaakshiRegistry"]
    bytecode = art["evm"]["bytecode"]["object"]
    say(f"✓ compiled ({len(bytecode) // 2} bytes)")

    pg = Polygon(rpc, None, load_key())
    bal = pg.w3.eth.get_balance(pg.acct.address) / 1e18
    say(f"wallet {pg.acct.address}  balance {bal:.4f} POL")
    factory = pg.w3.eth.contract(abi=art["abi"], bytecode=bytecode)
    say("deploying ...")
    try:
        txh, rcpt = pg.send(factory.constructor(), want_receipt=True)
    except RuntimeError as e:
        sys.exit(f"✗ {e}")
    addr = rcpt.contractAddress
    cfg["contract"] = addr
    save_json(CONFIG_FILE, cfg)
    say(f"✓ SaakshiRegistry deployed at {addr}")
    say(f"  transaction: {EXPLORER}/tx/{txh}")
    say(f"  contract:    {EXPLORER}/address/{addr}")
    say("  saved - next: python3 saakshi_relay.py --selftest")


def main():
    ap = argparse.ArgumentParser(description="Post SAAKSHI chip-signed heads to SaakshiRegistry on Polygon Amoy.")
    ap.add_argument("--ledger", type=Path, default=HERE / "saakshi_ledger", help="the ledger's folder")
    ap.add_argument("--check", action="store_true", help="check the ledger and show the newest head; offline")
    ap.add_argument("--precompile", action="store_true", help="test Polygon's P-256 checker before deploying")
    ap.add_argument("--selftest", action="store_true", help="test the deployed contract's signature check")
    ap.add_argument("--once", action="store_true", help="register if needed, post the newest head, stop")
    ap.add_argument("--status", action="store_true", help="what is anchored for this node")
    ap.add_argument("--prove", type=int, metavar="SEQ", help="when one record became impossible to change")
    ap.add_argument("--chain", help="with --prove: which chain (8 hex digits), if there are several")
    ap.add_argument("--fake", action="store_true", help="demo: try to post a forged head (free)")
    ap.add_argument("--deploy", action="store_true", help="compile + deploy SaakshiRegistry.sol from this Mac")
    ap.add_argument("--publish", action="store_true", help="write encrypted records for the verification page")
    ap.add_argument("--site", type=Path, default=HERE / "saakshi_site", help="with --publish: the site folder")
    ap.add_argument("--site-url", help="with --publish: the deployed site, e.g. https://saakshi.netlify.app")
    ap.add_argument("--range", help="with --publish: allowed temperature band in °C, e.g. 2,8")
    ap.add_argument("--contract", help="SaakshiRegistry address (saved for next time)")
    ap.add_argument("--rpc", help=f"Amoy RPC (default {AMOY_RPC})")
    ap.add_argument("--min-records", type=int, default=50, help="keep running: post at this many new records")
    ap.add_argument("--max-wait", type=int, default=900, help="keep running: or after this many seconds")
    ap.add_argument("--poll", type=int, default=20, help="keep running: look for new records this often (s)")
    ap.add_argument("--event-gap", type=int, default=300,
                    help="keep running: anchor at once after a jolt, sensor swap or temperature alarm, "
                         "at most this often per trip (s; 0 = off)")
    args = ap.parse_args()

    cfg = load_json(CONFIG_FILE, {})
    if args.contract:
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", args.contract):
            sys.exit("--contract should look like 0x followed by 40 hex digits.")
        cfg["contract"] = args.contract
    if args.rpc:
        cfg["rpc"] = args.rpc
    if args.contract or args.rpc:
        save_json(CONFIG_FILE, cfg)
    rpc = cfg.get("rpc", AMOY_RPC)
    nk = NodeKey(PUBKEY_FILE)

    try:
        if args.check:
            sys.exit(0 if run_check(args, nk) else 1)
        if args.precompile:
            sys.exit(0 if run_sigtest(args, nk, Polygon(rpc), False) else 1)
        if args.deploy:
            run_deploy(args, rpc, cfg)
            return
        if args.publish:
            run_publish(args, nk, cfg, rpc)
            return
        if "contract" not in cfg:
            sys.exit("No contract address yet. Deploy SaakshiRegistry.sol, then run once with --contract 0x...")
        if args.selftest:
            sys.exit(0 if run_sigtest(args, nk, Polygon(rpc, cfg["contract"]), True) else 1)
        if args.status:
            run_status(args, nk, Polygon(rpc, cfg["contract"]))
        elif args.prove is not None:
            run_prove(args, nk, Polygon(rpc, cfg["contract"]))
        elif args.fake:
            key = load_key() if (KEY_FILE.exists() or os.environ.get("SAAKSHI_RELAY_KEY")) else None
            run_fake(args, nk, Polygon(rpc, cfg["contract"], key))
        else:
            pg = Polygon(rpc, cfg["contract"], load_key())
            say(f"SaakshiRegistry {cfg['contract']} on Polygon Amoy, node {nk.node}")
            run_relay(args, nk, pg, watch=not args.once)
    except Bad as e:
        sys.exit(f"✗ {e}")
    except KeyboardInterrupt:
        say("stopped")


if __name__ == "__main__":
    main()
