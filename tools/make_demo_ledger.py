#!/usr/bin/env python3
"""
make_demo_ledger.py - builds a realistic TEST ledger in firmware v7's exact record format, so the dashboard,
relay checks and buyer page can be developed without the board.

    python3 tools/make_demo_ledger.py demo_env          # writes everything into ./demo_env/
    cd demo_env && python3 ../saakshi_dashboard.py --offline --keys . --ledger saakshi_ledger --relay saakshi_relay --site saakshi_site --data dash_data

What it makes (all SIMULATED - never mix it with the real ledger, never anchor it on Polygon):
  node A: a 30 h chilled trip (2-8 C) with a ~2 h excursion, 3 jolts while loading, a run of 7 unsigned
          records, a restart and a sensor swap at record 240
  node B: a short bench trip, offline for 3 h, no motion sensor
  plus  : the two public keys, a ledger alerts.log with one refusal, relay config/posted/view key files
Records are signed with deterministic TEST keys (not any real chip).
"""
import base64, hashlib, json, math, os, random, struct, sys, time
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

BODY = struct.Struct("<IIIIiiiihhHHIH32s")
HDR = ("seq,boot,uptime_s,unix_time,temp_c,rh_pct,pressure_hpa,gas_kohm,rtc_temp_c,mpu_temp_c,peak_g,moves,"
       "sensor_id,flags,prev_hash,hash,sig")


def fx(v, d, dec):
    a = abs(v)
    return f"{'-' if v < 0 else ''}{a // d}.{a % d:0{dec}d}"


def build(keyseed, n, start, step, temp_fn, extra):
    key = ec.derive_private_key(keyseed, ec.SECP256R1())
    pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    node = "SAAKSHI-" + hashlib.sha256(pub).hexdigest()[:8].upper()
    prev, lines, chain, boot, hs = bytes(32), [], None, 1, []
    for i in range(n):
        flags, peak, sid = extra(i)
        if i == 0:
            flags |= 1
        if flags & 1 and i:
            boot += 1
        t = 0 if flags & 4 else start + i * step
        temp = temp_fn(i)
        tm = int(round(temp * 1000))
        rh = int(round((88 - (temp - 4) * 1.5 + random.uniform(-1, 1)) * 1000))
        pa, gas = 100800 + random.randint(-60, 60), 52000 + random.randint(-900, 900)
        rtc = tm // 10 + random.randint(-30, 30)
        mpu = -32768 if flags & 0x400 else tm // 10 + random.randint(-40, 40)
        moves = random.randint(0, 40) if peak > 150 else 0
        if flags & 2:
            tm = rh = pa = gas = 0
        body = BODY.pack(i, boot, i * step, t, tm, rh, pa, gas, rtc, mpu, peak, moves, sid, flags, prev)
        h = hashlib.sha256(body).digest()
        if flags & 0x100:
            sig = bytes(64)
        else:
            r, s = utils.decode_dss_signature(key.sign(h, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        chain = chain or h.hex()[:8]
        mt = "" if mpu == -32768 else fx(mpu, 100, 2)
        lines.append(f"{i},{boot},{i*step},{t},{fx(tm,1000,3)},{fx(rh,1000,3)},{fx(pa,100,2)},{fx(gas,1000,3)},"
                     f"{fx(rtc,100,2)},{mt},{fx(peak,1000,3)},{moves},0x{sid:08x},{flags},0x{prev.hex()},0x{h.hex()},0x{sig.hex()}")
        hs.append(h.hex())
        prev = h
    return node, chain, pub.hex(), lines, hs


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "demo_env")
    if out.exists() and any(out.iterdir()):
        sys.exit(f"{out} is not empty - pick a new folder name (this never overwrites anything).")
    out.mkdir(parents=True, exist_ok=True)
    random.seed(4)
    now = int(time.time())
    step, n = 300, 360
    start = now - n * step + 120

    def t_a(i):
        base = 4.2 + 0.6 * math.sin(i / 25)
        if 160 <= i < 186:
            base = 8 + (i - 160) * 0.18 if i < 175 else 10.5 - (i - 175) * 0.4
        return base + random.uniform(-0.15, 0.15)

    def e_a(i):
        f, p, sid = 0, random.randint(20, 120), 0x1A2B3C4D
        if i in (158, 159, 161):
            f |= 0x20
            p = {158: 1450, 159: 2650, 161: 1180}[i]
        if 90 <= i <= 96:
            f |= 0x100
        if i == 240:
            f |= 0x80
        if i >= 240:
            sid = 0x5E5E5E5E
        if i == 120:
            f |= 1
        return f, p, sid

    node_a, chain_a, pub_a, lines_a, h_a = build(11111, n, start, step, t_a, e_a)
    node_b, chain_b, pub_b, lines_b, _ = build(22222, 120, now - 6 * 3600, 75, lambda i: 28.6 + random.uniform(-0.3, 0.3),
                                              lambda i: (0x400 | (4 if i < 3 else 0), 0, 0x77AA77AA))
    led = out / "saakshi_ledger"
    led.mkdir()
    (led / f"{node_a}_{chain_a}.csv").write_text(HDR + "\n" + "\n".join(lines_a) + "\n")
    pb = led / f"{node_b}_{chain_b}.csv"
    pb.write_text(HDR + "\n" + "\n".join(lines_b) + "\n")
    os.utime(pb, (now - 3 * 3600, now - 3 * 3600))
    (out / "saakshi_pubkey.txt").write_text(pub_a + "\n")
    (out / "saakshi_pubkey_bench.txt").write_text(pub_b + "\n")
    ts = lambda s: time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(s))
    (led / "alerts.log").write_text(
        f"{ts(now-4000)}  {node_a} {chain_a}  NEW CHAIN {chain_a} from {node_a}.\n"
        f"{ts(now-2000)}  {node_a} {chain_a}  seq 201 REFUSED - SIGNATURE INVALID: not signed by this node's chip\n")
    rel = out / "saakshi_relay"
    rel.mkdir()
    (rel / "config.json").write_text(json.dumps({"contract": "0xA82128628b7Ae42183d9B76020CD37C007c18c46",
                                                 "site_url": "http://localhost:8000", "range": [2, 8]}))
    (rel / "posted.json").write_text(json.dumps([{"chain": chain_a, "seq": 300, "hash": h_a[300],
                                                  "tx": "0x" + "ab" * 32, "block": 1, "time": now - 3600}]))
    (rel / "view_keys.json").write_text(json.dumps({node_a: base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()}))
    print(f"SIMULATED test environment in {out}/")
    print(f"  {node_a}  chain {chain_a}  360 records (excursion, jolts, unsigned run, sensor swap)")
    print(f"  {node_b}  chain {chain_b}  120 records (offline, no motion sensor)")


if __name__ == "__main__":
    main()
