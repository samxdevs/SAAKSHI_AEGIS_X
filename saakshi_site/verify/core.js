/*
 * SAAKSHI verification core. Runs in the browser (and in Node 18+ for tests).
 * Trusts nothing it is given: every hash, link and ATECC608B signature is recomputed here, and the
 * anchor is read straight from SaakshiRegistry on Polygon Amoy.
 */
(function (root) {
  "use strict";
  const subtle = root.crypto.subtle;
  const enc = new TextEncoder();

  const FLAGS = {
    BOOT: 0x0001, SENSOR_FAIL: 0x0002, NO_TIME: 0x0004, CLOCK_SET: 0x0008, MOTION: 0x0010,
    SHOCK: 0x0020, TEMP_MISMATCH: 0x0040, SENSOR_CHANGED: 0x0080, UNSIGNED: 0x0100,
    RTC_FAIL: 0x0200, MPU_FAIL: 0x0400, LID_OPEN: 0x0800,
    ETHYLENE: 0x1000, ETH_NONE: 0x2000, ETH_WARMUP: 0x4000,   // firmware v8: bytes 8-11 hold ethylene in ppb
  };
  const BODY = 78;
  const SEL = {                    // first 4 bytes of keccak256(signature); match the deployed bytecode
    node: "7c97e6ec", headCount: "d9701e33", headAt: "7b751af0", isAnchored: "4f0b5801",
  };

  // ---------- bytes ----------
  function b64(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = root.atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
  function unhex(h) {
    h = h.replace(/^0x/, "");
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }
  function same(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }
  const isZero = (u8) => u8.every((b) => b === 0);
  const sha256 = async (u8) => new Uint8Array(await subtle.digest("SHA-256", u8));

  // ---------- one record (firmware v7 Record, little-endian) ----------
  function parseRecord(b) {
    const v = new DataView(b.buffer, b.byteOffset, BODY);
    const NO_TEMP = -32768;
    const rtc = v.getInt16(32, true), mpu = v.getInt16(34, true);
    return {
      seq: v.getUint32(0, true), boot: v.getUint32(4, true), uptime: v.getUint32(8, true),
      time: v.getUint32(12, true), eth: null,
      temp: v.getInt32(16, true) / 1000, rh: v.getInt32(20, true) / 1000,
      pressure: v.getInt32(24, true) / 100, gas: v.getInt32(28, true) / 1000,
      rtcTemp: rtc === NO_TEMP ? null : rtc / 100, mpuTemp: mpu === NO_TEMP ? null : mpu / 100,
      peakG: v.getUint16(36, true) / 1000, moves: v.getUint16(38, true),
      sensorId: v.getUint32(40, true), flags: v.getUint16(44, true),
      prev: b.subarray(46, 78),
    };
  }
  // Firmware v8 puts ethylene (ppb) where older records kept uptime; the ETHYLENE flag says which.
  function withEthylene(r) {
    if ((r.flags & FLAGS.ETHYLENE) && !(r.flags & FLAGS.ETH_NONE)) r.eth = r.uptime / 1000;
    return r;
  }

  // ---------- Polygon (read-only JSON-RPC) ----------
  function makeRpc(urls) {
    let id = 1;
    return async function call(to, data) {
      let last;
      for (const url of urls) {
        try {
          const r = await root.fetch(url, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ jsonrpc: "2.0", id: id++, method: "eth_call",
              params: [{ to, data: "0x" + data }, "latest"] }),
          });
          const j = await r.json();
          if (j.error) throw new Error(j.error.message || "RPC error");
          return j.result.replace(/^0x/, "");
        } catch (e) { last = e; }
      }
      throw last || new Error("no RPC");
    };
  }
  const word = (res, i) => res.substr(i * 64, 64);
  const wordInt = (res, i) => parseInt(word(res, i), 16);
  const pad32 = (n) => n.toString(16).padStart(64, "0");

  async function readAnchors(rpc, address, keyHashHex, wantHashes) {
    const reg = await rpc(address, SEL.node + keyHashHex);
    const registered = wordInt(reg, 2);
    if (!registered) return { registered: 0, heads: [] };
    const n = wordInt(await rpc(address, SEL.headCount + keyHashHex), 0);
    const from = Math.max(0, n - 200);               // newest 200 heads are plenty for a shipment
    const heads = await Promise.all(
      Array.from({ length: n - from }, (_, k) => rpc(address, SEL.headAt + keyHashHex + pad32(from + k))));
    const set = new Set(heads.map((h) => h.substr(0, 64)));
    let best = -1;
    for (let i = wantHashes.length - 1; i >= 0; i--) {
      if (set.has(wantHashes[i])) { best = i; break; }
    }
    let stamp = null;
    if (best >= 0) {
      const r = await rpc(address, SEL.isAnchored + wantHashes[best]);
      stamp = { seq: wordInt(r, 2), nodeTime: wordInt(r, 3), blockTime: wordInt(r, 4),
        relayer: "0x" + word(r, 5).substr(24) };
    }
    return { registered, total: n, index: best, stamp };
  }

  // ---------- the whole check ----------
  async function verify(bundle, keyB64, opts = {}) {
    // The bundle is untrusted input: its numbers must be numbers before anything uses or shows them.
    const whole = (x) => Number.isSafeInteger(x) && x >= 0;
    const R = { node: String(bundle.node || ""), chain: String(bundle.chain || ""),
      count: whole(bundle.count) ? bundle.count : 0, firstSeq: whole(bundle.firstSeq) ? bundle.firstSeq : 0,
      steps: [], records: null, problem: null, anchor: null, mode: keyB64 ? "full" : "public" };
    const step = (id, ok, text, extra) => { R.steps.push(Object.assign({ id, ok, text }, extra || {})); return ok; };
    const fail = (id, text, extra) => { step(id, false, text, extra); R.problem = R.problem || { id, text }; };
    if (!whole(bundle.count) || !whole(bundle.firstSeq) || !/^[0-9a-f]{8}$/.test(R.chain)) {
      fail("format", "The published file is not a valid SAAKSHI record.");
      R.verdict = "tampered";
      return R;
    }

    // 1. identity: the node ID printed on the box is the hash of this public key
    const pub = unhex(bundle.pubkey);
    const keyHash = await sha256(pub);
    const derived = "SAAKSHI-" + hex(keyHash.subarray(0, 4)).toUpperCase();
    if (derived !== bundle.node) fail("identity", `The public key belongs to ${derived}, not ${bundle.node}.`);
    else step("identity", true, `Public key matches node ${bundle.node}.`);

    const hashes = b64(bundle.hashes), sigs = b64(bundle.sigs);
    const n = bundle.count;
    if (hashes.length !== n * 32 || sigs.length !== n * 64) fail("format", "The published file is incomplete.");
    const hashHex = Array.from({ length: n }, (_, i) => hex(hashes.subarray(i * 32, i * 32 + 32)));

    // 2-5. full check with the QR key
    let covered = n;
    if (keyB64 && !R.problem) {
      let plain;
      try {
        const key = await subtle.importKey("raw", b64(keyB64), "AES-GCM", false, ["decrypt"]);
        plain = new Uint8Array(await subtle.decrypt(
          { name: "AES-GCM", iv: b64(bundle.enc.iv), additionalData: enc.encode(bundle.enc.aad) },
          key, b64(bundle.enc.data)));
      } catch (e) {
        fail("decrypt", "The readings could not be unlocked. Either this QR key is for another node, or the published file was changed.");
      }
      if (plain && plain.length !== n * BODY) fail("decrypt", "The unlocked data has the wrong size.");
      if (plain && !R.problem) {
        step("decrypt", true, `${n.toLocaleString()} records unlocked with the QR key.`);
        const ecKey = await subtle.importKey("raw", pub, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
        const recs = [];
        let lastSigned = -1, unsignedCount = 0;
        for (let i = 0; i < n && !R.problem; i++) {
          const body = plain.subarray(i * BODY, i * BODY + BODY);
          const h = await sha256(body);
          const r = withEthylene(parseRecord(body));
          r.hash = hashHex[i];
          if (!same(h, hashes.subarray(i * 32, i * 32 + 32)))
            { fail("hashes", `Record #${r.seq} was changed after it was recorded.`, { seq: r.seq }); break; }
          if (r.seq !== bundle.firstSeq + i)
            { fail("links", `Record #${bundle.firstSeq + i} is missing or out of order.`, { seq: bundle.firstSeq + i }); break; }
          const prevOk = i === 0 ? (r.seq !== 0 || isZero(r.prev)) : same(r.prev, hashes.subarray((i - 1) * 32, i * 32));
          if (!prevOk) { fail("links", `Record #${r.seq} does not follow the record before it.`, { seq: r.seq }); break; }
          const sig = sigs.subarray(i * 64, i * 64 + 64);
          if (r.flags & FLAGS.UNSIGNED) {
            if (!isZero(sig)) { fail("signatures", `Record #${r.seq} is marked unsigned but carries a signature.`, { seq: r.seq }); break; }
            unsignedCount++;
          } else {
            // WebCrypto hashes the body itself: SHA-256(body) is exactly the digest the chip signed.
            const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, ecKey, sig, body);
            if (!ok) { fail("signatures", `Record #${r.seq} was not signed by this node's security chip.`, { seq: r.seq }); break; }
            lastSigned = i;
          }
          recs.push(r);
          if (opts.onProgress && i % 200 === 0) opts.onProgress(i / n);
        }
        if (!R.problem) {
          covered = lastSigned + 1;
          step("hashes", true, "Every reading matches its fingerprint.");
          step("links", true, "Every record links to the one before it: nothing missing, nothing reordered.");
          step("signatures", true, `Every record is covered by the node's security chip signature` +
            (unsignedCount ? ` (${unsignedCount} logged while the chip was busy, each covered by the next signed record).` : "."));
          if (covered < n) step("tail", true, n - covered === 1 ? "The newest record is waiting for the next signed record." :
            `The ${n - covered} newest records are waiting for the next signed record.`, { info: true });
          R.records = recs;
          R.summary = summarise(recs, bundle.range);
        }
      }
    }

    // 6. Polygon anchor (both modes)
    if (!R.problem || opts.anchorEvenIfBroken) {
      try {
        const rpc = opts.rpc || makeRpc(bundle.registry.rpc);
        const a = await readAnchors(rpc, bundle.registry.address, hex(keyHash), hashHex.slice(0, covered));
        R.anchor = a;
        if (!a.registered) step("anchor", null, "This node is not registered on Polygon yet.", { warn: true });
        else if (a.index < 0) step("anchor", null, "No record of this trip has been anchored on Polygon yet.", { warn: true });
        else {
          const seq = bundle.firstSeq + a.index;
          a.seq = seq;
          a.allAnchored = a.index === covered - 1;
          const newer = covered - 1 - a.index, what = keyB64 ? "signed" : "published";
          step("anchor", true, `Records up to #${seq} were locked on Polygon on ${fmtTime(a.stamp.blockTime)}. ` +
            "Polygon checked the chip's signature itself before accepting them." +
            (a.allAnchored ? "" : newer === 1 ? ` The newest record is ${what} but not anchored yet.` :
              ` The ${newer} newest records are ${what} but not anchored yet.`));
        }
      } catch (e) {
        R.anchor = { error: String(e && e.message || e) };
        step("anchor", null, "Polygon could not be reached, so the anchor was not checked. The other checks still stand.", { warn: true });
      }
    }

    R.verdict = !R.problem ? (R.anchor && R.anchor.index >= 0 ? (R.anchor.allAnchored || R.mode === "public" ? "genuine" : "partly") : "unanchored") : "tampered";
    return R;
  }

  // ---------- trip summary ----------
  function summarise(recs, range) {
    const good = recs.filter((r) => !(r.flags & FLAGS.SENSOR_FAIL));
    const timed = recs.filter((r) => r.time > 0);
    const s = { records: recs.length, from: timed.length ? timed[0].time : 0,
      to: timed.length ? timed[timed.length - 1].time : 0 };
    const stat = (arr) => arr.length ? { min: Math.min(...arr), max: Math.max(...arr),
      avg: arr.reduce((a, b) => a + b, 0) / arr.length } : null;
    s.temp = stat(good.map((r) => r.temp));
    s.rh = stat(good.map((r) => r.rh));
    s.eth = stat(recs.filter((r) => r.eth != null && !(r.flags & FLAGS.ETH_WARMUP)).map((r) => r.eth));
    s.shocks = recs.filter((r) => r.flags & FLAGS.SHOCK).length;
    s.maxG = recs.length ? Math.max(...recs.map((r) => r.peakG)) : 0;
    s.restarts = recs.filter((r, i) => i > 0 && (r.flags & FLAGS.BOOT)).length;
    s.sensorChanged = recs.filter((r) => r.flags & FLAGS.SENSOR_CHANGED).map((r) => r.seq);
    s.sensorFail = recs.length - good.length;
    s.mismatch = recs.filter((r) => r.flags & FLAGS.TEMP_MISMATCH).length;
    if (range && good.length) {
      const [lo, hi] = range;
      let outside = 0, outsideSecs = 0;
      for (let i = 0; i < good.length; i++) {
        const r = good[i];
        if (r.temp < lo || r.temp > hi) {
          outside++;
          const nxt = good[i + 1];
          if (nxt && r.time && nxt.time > r.time) outsideSecs += nxt.time - r.time;
        }
      }
      s.range = { lo, hi, outside, outsideSecs };
    }
    return s;
  }

  function fmtTime(t) {
    if (!t) return "an unknown time";
    return new Date(t * 1000).toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric",
      hour: "2-digit", minute: "2-digit" });
  }

  const api = { verify, parseRecord, summarise, fmtTime, FLAGS, SEL, b64, hex, unhex, makeRpc };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.SaakshiCore = api;
})(typeof globalThis !== "undefined" ? globalThis : window);
