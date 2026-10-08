/* SAAKSHI verification page: loads the published record, runs core.js on this device, shows the result. */
(function (root) {
  "use strict";
  const C = root.SaakshiCore || (typeof require !== "undefined" ? require("./core.js") : null);

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (v, d = 1) => (v == null || isNaN(v)) ? "–" : Number(v).toLocaleString(undefined, { minimumFractionDigits: d, maximumFractionDigits: d });
  const short = (t) => t ? new Date(t * 1000).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "";
  const full = (t) => C.fmtTime(t);
  function duration(s) {
    if (!s || s < 60) return "under a minute";
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d) return `${d} day${d > 1 ? "s" : ""}${h ? ` ${h} h` : ""}`;
    if (h) return `${h} h${m ? ` ${m} min` : ""}`;
    return `${m} min`;
  }

  // ---------- the seal ----------
  const GLYPH = {
    genuine: '<path d="M43 59l10.5 10.5L74 48" fill="none" stroke="currentColor" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>',
    tampered: '<path d="M46 46l24 24M70 46L46 70" fill="none" stroke="currentColor" stroke-width="6" stroke-linecap="round"/>',
    partly: '<path d="M58 44v15l10 7" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>',
    unanchored: '<path d="M58 44v15l10 7" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>',
    locked: '<rect x="45" y="55" width="26" height="19" rx="3" fill="currentColor"/><path d="M50 55v-6a8 8 0 0 1 16 0v6" fill="none" stroke="currentColor" stroke-width="4.5"/>',
  };
  function seal(kind, node, ring) {
    return `<svg class="seal ${kind} stamp" viewBox="0 0 116 116" role="img" aria-label="${esc(ring)}">
      <defs><path id="ring" d="M58,58 m-44,0 a44,44 0 1,1 88,0 a44,44 0 1,1 -88,0"/></defs>
      <circle cx="58" cy="58" r="55" fill="none" stroke="currentColor" stroke-width="2.5"/>
      <circle cx="58" cy="58" r="32" fill="none" stroke="currentColor" stroke-width="1.5"/>
      <text font-size="9" font-weight="700" fill="currentColor" font-family="Archivo, system-ui, sans-serif">
        <textPath href="#ring" textLength="272" lengthAdjust="spacing">${esc(node)} ✦ ${esc(ring)} ✦</textPath></text>
      ${GLYPH[kind] || ""}</svg>`;
  }

  // ---------- charts ----------
  function chart(points, { unit, band, small, digits = 1 }) {
    if (points.length < 2) return `<p class="muted">Not enough readings to draw this.</p>`;
    const H = small ? 110 : 190, W = 1000;
    const xs = points.map((p) => p.x), x0 = Math.min(...xs), x1 = Math.max(...xs) || x0 + 1;
    const nb = Math.min(320, points.length), buckets = [];
    for (const p of points) {
      const k = Math.min(nb - 1, Math.floor(((p.x - x0) / (x1 - x0 || 1)) * nb));
      const b = buckets[k] || (buckets[k] = { x: 0, n: 0, min: Infinity, max: -Infinity, sum: 0 });
      b.x += p.x; b.n++; b.sum += p.y; b.min = Math.min(b.min, p.y); b.max = Math.max(b.max, p.y);
    }
    const bs = buckets.filter(Boolean).map((b) => ({ x: b.x / b.n, min: b.min, max: b.max, avg: b.sum / b.n }));
    let lo = Math.min(...bs.map((b) => b.min)), hi = Math.max(...bs.map((b) => b.max));
    if (band) { lo = Math.min(lo, band[0]); hi = Math.max(hi, band[1]); }
    const pad = (hi - lo || 1) * 0.08; lo -= pad; hi += pad;
    const X = (x) => ((x - x0) / (x1 - x0 || 1)) * W, Y = (y) => H - ((y - lo) / (hi - lo)) * H;
    const env = bs.map((b) => `${X(b.x).toFixed(1)},${Y(b.max).toFixed(1)}`).join(" ") + " " +
      bs.slice().reverse().map((b) => `${X(b.x).toFixed(1)},${Y(b.min).toFixed(1)}`).join(" ");
    const line = bs.map((b) => `${X(b.x).toFixed(1)},${Y(b.avg).toFixed(1)}`).join(" ");
    const bandSvg = band ? `<rect x="0" y="${Y(band[1]).toFixed(1)}" width="${W}" height="${(Y(band[0]) - Y(band[1])).toFixed(1)}" fill="var(--band)"/>
      <line x1="0" x2="${W}" y1="${Y(band[1]).toFixed(1)}" y2="${Y(band[1]).toFixed(1)}" stroke="var(--ok)" stroke-dasharray="6 6" vector-effect="non-scaling-stroke" opacity=".7"/>
      <line x1="0" x2="${W}" y1="${Y(band[0]).toFixed(1)}" y2="${Y(band[0]).toFixed(1)}" stroke="var(--ok)" stroke-dasharray="6 6" vector-effect="non-scaling-stroke" opacity=".7"/>` : "";
    const timeAxis = points[0].t;
    return `<div class="chart${small ? " small" : ""}">
      <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">${bandSvg}
        <polygon points="${env}" fill="var(--cold-soft)"/>
        <polyline points="${line}" fill="none" stroke="var(--cold)" stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round"/></svg>
      <span class="ylab" style="top:-2px">${num(hi - pad, digits)} ${unit}</span>
      <span class="ylab" style="top:${H - 14}px">${num(lo + pad, digits)} ${unit}</span>
      <div class="xlab"><span>${timeAxis ? short(x0) : "#" + x0}</span><span>${timeAxis ? short(x1) : "#" + x1}</span></div></div>`;
  }
  function series(recs, field) {
    const good = recs.filter((r) => !(r.flags & C.FLAGS.SENSOR_FAIL));
    const timed = good.length && good.every((r) => r.time > 0);
    return good.map((r) => ({ x: timed ? r.time : r.seq, y: r[field], t: timed }));
  }

  // ---------- the report ----------
  function verdictCopy(R) {
    const n = R.count.toLocaleString(), a = R.anchor || {}, when = a.stamp ? full(a.stamp.blockTime) : "";
    if (R.verdict === "tampered") {
      const locked = R.problem && R.problem.id === "decrypt";
      return { kind: "tampered", ring: locked ? "NOT UNLOCKED" : "ALTERED", h: locked ? "Can't unlock this record" : "Record altered",
        lede: `${esc(R.problem.text)} Don't rely on this data.` };
    }
    if (R.mode === "public") {
      if (R.verdict === "genuine") return { kind: "locked", ring: "ANCHORED ON POLYGON", h: "Anchored record",
        lede: `<strong>${n} records</strong> from ${esc(R.node)} were locked on Polygon on ${when}. The readings are encrypted: scan the QR on the box to unlock them and check every one.` };
      return { kind: "unanchored", ring: "NOT ANCHORED YET", h: "Not anchored yet",
        lede: a.error ? "Polygon could not be reached to check this record. Try again with a connection." :
          `${esc(R.node)} has published ${n} records, but none are locked on Polygon yet. Scan the QR on the box to check the readings.` };
    }
    if (R.verdict === "genuine") return { kind: "genuine", ring: "CHECKED ON THIS PHONE", h: "Genuine record",
      lede: `<strong>${n} readings</strong> from ${esc(R.node)}, unchanged since they were locked on Polygon on ${when}.` };
    if (R.verdict === "partly") return { kind: "partly", ring: "PARTLY ANCHORED", h: "Genuine, partly anchored",
      lede: `All ${n} readings check out. Records up to #${a.seq} were locked on Polygon on ${when}; the newest are signed by the chip but not anchored yet.` };
    if (a.error) return { kind: "unanchored", ring: "ANCHOR NOT CHECKED", h: "Signed, anchor not checked",
      lede: `All ${n} readings are signed by the node's security chip. Polygon could not be reached, so the anchor was not confirmed. Try again with a connection.` };
    return { kind: "unanchored", ring: "NOT ANCHORED YET", h: "Signed, not yet anchored",
      lede: `All ${n} readings are signed by the node's security chip, but none are locked on Polygon yet.` };
  }

  function tripSection(R, bundle) {
    const s = R.summary, recs = R.records;
    if (!s) return "";
    const when = s.from ? `From ${esc(full(s.from))} to ${esc(full(s.to))}, ${duration(s.to - s.from)}.` :
      `${s.records.toLocaleString()} records. The node's clock was not set, so they are shown in order.`;
    const band = bundle.range && bundle.range.length === 2 ? bundle.range.map(Number) : null;
    const figs = [
      ["Lowest", s.temp ? `${num(s.temp.min)} °C` : "–"], ["Average", s.temp ? `${num(s.temp.avg)} °C` : "–"],
      ["Highest", s.temp ? `${num(s.temp.max)} °C` : "–"],
      ["Humidity", s.rh ? `${num(s.rh.min, 0)}–${num(s.rh.max, 0)} %` : "–"],
      ["Jolts over 1 g", s.shocks.toLocaleString(), s.shocks > 0],
    ];
    if (s.restarts) figs.push(["Restarts", s.restarts.toLocaleString(), true]);
    if (s.range) figs.splice(3, 0, [`Outside ${num(s.range.lo, 0)}–${num(s.range.hi, 0)} °C`,
      s.range.outside ? (s.range.outsideSecs ? duration(s.range.outsideSecs) : `${s.range.outside} readings`) : "Never", s.range.outside > 0]);
    return `<section><h2>The trip</h2><div class="trip">
      <p class="when">${when}</p>
      <div class="chart-title"><b>Temperature</b>${band ? `<span class="muted">allowed ${num(band[0], 0)}–${num(band[1], 0)} °C</span>` : ""}</div>
      ${chart(series(recs, "temp"), { unit: "°C", band })}
      <div class="chart-title"><b>Humidity</b></div>
      ${chart(series(recs, "rh"), { unit: "%", small: true, digits: 0 })}
      <div class="figs">${figs.map(([k, v, alert]) => `<div class="fig${alert ? " alert" : ""}"><div class="v">${esc(v)}</div><div class="k">${esc(k)}</div></div>`).join("")}</div>
    </div></section>`;
  }

  function eventsSection(R) {
    const s = R.summary, recs = R.records;
    if (!s) return "";
    const items = [];
    for (const seq of s.sensorChanged.slice(0, 3))
      items.push(`<li><span class="w">The temperature sensor's fingerprint changed at record #${seq}.</span> The sensor may have been replaced.</li>`);
    const jolts = recs.filter((r) => r.flags & C.FLAGS.SHOCK).sort((a, b) => b.peakG - a.peakG).slice(0, 3);
    for (const r of jolts) items.push(`<li>Jolt of ${num(r.peakG, 2)} g at record #${r.seq}${r.time ? `, ${esc(short(r.time))}` : ""}.</li>`);
    if (s.mismatch) items.push(`<li>${s.mismatch} reading(s) where the main thermometer disagreed with both backups.</li>`);
    if (s.sensorFail) items.push(`<li>${s.sensorFail} reading(s) where the climate sensor did not answer; they are left out of the charts.</li>`);
    if (!items.length) return "";
    return `<section><h2>Worth knowing</h2><ul class="events">${items.join("")}</ul></section>`;
  }

  function checksSection(R) {
    const cls = (s) => s.ok === true ? (s.info ? "info" : "ok") : s.ok === false ? "bad" : "warn";
    return `<section><h2>What your phone checked</h2><ol class="checks">
      ${R.steps.map((s) => `<li class="${cls(s)}">${esc(s.text)}</li>`).join("")}</ol>
      ${R.mode === "public" ? `<p class="note">The readings stay encrypted until you scan the QR code on the box. The code holds the key, and the key is never sent to this website.</p>` : ""}
    </section>`;
  }

  function detailsSection(R, bundle, list, entry) {
    const reg = bundle.registry || {}, a = R.anchor || {};
    const exp = /^https:\/\/[a-z0-9.-]+$/i.test(reg.explorer || "") ? reg.explorer : "https://amoy.polygonscan.com";
    const addrOk = /^0x[0-9a-fA-F]{40}$/.test(reg.address || "");
    const headHash = a.index >= 0 && R.records ? R.records[a.index].hash : null;
    const tx = headHash && (bundle.anchors || []).find((x) => x.hash === headHash && /^0x[0-9a-f]{64}$/i.test(x.tx || ""));
    const last = R.firstSeq + R.count - 1;
    const chains = list.length > 1 ? `<dt>Trip</dt><dd><select id="chain" aria-label="Choose a trip">${list.slice().sort((x, y) => y.published - x.published)
      .map((e) => `<option value="${esc(e.chain)}"${e.chain === entry.chain ? " selected" : ""}>Chain ${esc(e.chain)} (${Number(e.count).toLocaleString()} records)</option>`).join("")}</select></dd>` : "";
    return `<details><summary>Technical details</summary><dl>
      <dt>Node</dt><dd>${esc(R.node)}</dd>${chains}
      <dt>Chain</dt><dd>${esc(R.chain)}</dd>
      <dt>Records</dt><dd>#${R.firstSeq} to #${last}</dd>
      <dt>Published</dt><dd>${esc(full(bundle.published))}</dd>
      ${addrOk ? `<dt>Smart contract</dt><dd><a href="${exp}/address/${reg.address}#readContract" rel="noopener">${reg.address.slice(0, 10)}…${reg.address.slice(-6)}</a> on Polygon Amoy</dd>` : ""}
      ${a.stamp ? `<dt>Locked on Polygon</dt><dd>${esc(full(a.stamp.blockTime))}, record #${a.stamp.seq}</dd>` : ""}
      ${tx ? `<dt>Anchor transaction</dt><dd><a href="${exp}/tx/${tx.tx}" rel="noopener">View on PolygonScan</a></dd>` : ""}
      ${headHash ? `<dt>Anchored record</dt><dd class="hash">${headHash}</dd>` : ""}
      </dl>
      <p class="note">Each SAAKSHI node signs every reading with a security chip whose key can't be copied, and each reading contains the fingerprint of the one before it. Anyone can post the newest signed reading to a smart contract on Polygon, and the contract checks the chip's signature before accepting it. This page re-does every check on your phone: it trusts neither this website nor whoever runs it.</p>
    </details>`;
  }

  function renderReport(R, bundle, list, entry) {
    const v = verdictCopy(R);
    return `<div class="verdict">${seal(v.kind, R.node, v.ring)}<div><h1>${v.h}</h1><p class="lede">${v.lede}</p></div></div>
      ${tripSection(R, bundle)}${eventsSection(R)}${checksSection(R)}${detailsSection(R, bundle, list, entry)}
      <footer>Checked on this device at ${esc(new Date().toLocaleString())}.</footer>`;
  }

  function renderMessage(h, text) {
    return `<div class="verdict">${seal("unanchored", "SAAKSHI", "RECORD CHECK")}<div><h1>${esc(h)}</h1><p class="lede">${esc(text)}</p></div></div>`;
  }

  // ---------- page glue ----------
  async function getJSON(url, fresh) {
    const r = await root.fetch(url, { cache: fresh ? "no-store" : "default" });
    if (!r.ok) throw new Error(r.status);
    return r.json();
  }

  async function main() {
    const app = root.document.getElementById("app");
    const q = new URLSearchParams(root.location.search);
    const node = q.get("n"), chainQ = q.get("c");
    const key = new URLSearchParams(root.location.hash.slice(1)).get("k");
    if (!node || !/^SAAKSHI-[0-9A-F]{8}$/.test(node))
      { app.innerHTML = renderMessage("Scan a SAAKSHI box", "Open this page by scanning the QR code on a SAAKSHI node."); return; }
    let index;
    try { index = await getJSON("data/index.json", true); }
    catch (e) { app.innerHTML = renderMessage("Record not available", "The published records could not be loaded. Check your connection and scan again."); return; }
    const list = ((index && index.nodes) || {})[node] || [];
    const entry = chainQ ? list.find((e) => e.chain === chainQ) : list.slice().sort((a, b) => b.published - a.published)[0];
    if (!entry || !/^data\/[A-Za-z0-9_-]+\.json$/.test(entry.file))
      { app.innerHTML = renderMessage("No record yet", `${node} has not published a record here yet.`); return; }

    const lede = app.querySelector(".lede");
    lede.textContent = `Checking ${Number(entry.count).toLocaleString()} records from ${node} on this device…`;
    const bar = root.document.createElement("div");
    bar.className = "progress"; bar.innerHTML = "<i></i>";
    lede.after(bar);

    let bundle;
    try { bundle = await getJSON(entry.file + "?v=" + encodeURIComponent(entry.published)); }
    catch (e) { app.innerHTML = renderMessage("Record not available", "The record file could not be loaded. Scan again in a moment."); return; }
    const R = await C.verify(bundle, key, { onProgress: (p) => { bar.firstChild.style.width = Math.round(p * 100) + "%"; } });
    app.innerHTML = renderReport(R, bundle, list, entry);
    const sel = root.document.getElementById("chain");
    if (sel) sel.addEventListener("change", () => {
      const u = new URL(root.location.href);
      u.searchParams.set("c", sel.value);
      root.location.href = u.toString();
    });
  }

  const api = { renderReport, renderMessage, chart, verdictCopy, esc };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else if (root.document) main();
})(typeof globalThis !== "undefined" ? globalThis : window);
