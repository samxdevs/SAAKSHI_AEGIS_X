/* SAAKSHI dashboard - single page app. All data shown is inserted as text, never as HTML. */
(function () {
  "use strict";
  const $view = document.getElementById("view");
  const TZ = "Asia/Kolkata";
  let me = null, route = "", timer = null, lastOverview = null;

  // ---------------------------------------------------------------- tiny DOM helpers
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  const SVGNS = "http://www.w3.org/2000/svg";
  function s(tag, attrs) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null) el.setAttribute(k, v);
    return el;
  }
  const ICONS = {   // static markup only
    critical: '<path d="M12 3 2 20h20L12 3Z" fill="currentColor"/><path d="M12 9v5M12 17h.01" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/>',
    serious: '<circle cx="12" cy="12" r="10" fill="currentColor"/><path d="M12 7v6M12 16.5h.01" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/>',
    warning: '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2.4"/><path d="M12 7.5v5.5M12 16.5h.01" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/>',
    info: '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 11v6M12 7.5h.01" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>',
    ok: '<circle cx="12" cy="12" r="10" fill="currentColor"/><path d="m7.5 12.3 3 3 6-6.4" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>',
    bad: '<circle cx="12" cy="12" r="10" fill="currentColor"/><path d="m8.5 8.5 7 7M15.5 8.5l-7 7" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/>',
    wait: '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2.2"/><path d="M12 7.5V12l3 2" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>',
    lock: '<rect x="5" y="10.5" width="14" height="10" rx="2" fill="currentColor"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" fill="none" stroke="currentColor" stroke-width="2.2"/>',
  };
  function icon(name) {
    const el = document.createElementNS(SVGNS, "svg");
    el.setAttribute("viewBox", "0 0 24 24");
    el.setAttribute("aria-hidden", "true");
    el.innerHTML = ICONS[name] || "";
    return el;
  }
  const SEV_LABEL = { critical: "Critical", serious: "Serious", warning: "Warning", info: "Notice" };
  const sev = (k) => h("span", { class: `sev ${k}` }, icon(k), SEV_LABEL[k] || k);

  // ---------------------------------------------------------------- formatting
  const num = (v, d = 1) => (v == null || isNaN(v)) ? "–" :
    Number(v).toLocaleString("en-IN", { minimumFractionDigits: d, maximumFractionDigits: d });
  const when = (t, opts) => t ? new Date(t * 1000).toLocaleString("en-IN", Object.assign(
    { timeZone: TZ, day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }, opts || {})) : "";
  const whenLong = (t) => when(t, { year: "numeric" });
  function ago(t, now) {
    if (!t) return "never";
    const s = Math.max(0, (now || Date.now() / 1000) - t);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min ago`;
    return `${Math.floor(s / 86400)} d ago`;
  }
  function dur(s) {
    s = Math.max(0, Math.round(s || 0));
    if (s < 90) return `${s} s`;
    const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d) return `${d} d ${hh} h`;
    if (hh) return `${hh} h ${m} min`;
    return `${m} min`;
  }
  const displayName = (n) => n.name || n.node;

  // ---------------------------------------------------------------- API
  // Online (Netlify + Supabase) the same calls go to cloud.js; on the Mac, to saakshi_dashboard.py.
  const CLOUD = window.SaakshiCloud || null;
  async function api(path, body) {
    if (CLOUD) {
      try { return await CLOUD.api(path, body); }
      catch (e) {
        if (e.status === 401 && path !== "/api/login") { me = null; showAuth(); throw new Error("log in"); }
        throw e;
      }
    }
    const opts = body === undefined ? {} : {
      method: "POST", headers: { "Content-Type": "application/json", "X-Requested-With": "saakshi" },
      body: JSON.stringify(body) };
    const r = await fetch(path, Object.assign({ credentials: "same-origin", cache: "no-store" }, opts));
    let j = {};
    try { j = await r.json(); } catch (e) { /* empty */ }
    if (r.status === 401 && path !== "/api/login") { me = null; showAuth(); throw new Error("log in"); }
    if (!r.ok) throw new Error(j.error || `request failed (${r.status})`);
    return j;
  }

  // ---------------------------------------------------------------- shell
  function setTabs(openAlerts, newOrders) {
    const tabs = document.getElementById("tabs");
    tabs.replaceChildren();
    const cur = (route.split("/")[1] || "nodes");
    const add = (key, label, count) => tabs.append(h("a", {
      href: `#/${key}`, "aria-current": (cur === key || (key === "nodes" && cur === "node")) ? "page" : null },
      label, count ? h("span", { class: "count", text: count, "aria-label": `${count} open` }) : null));
    add("nodes", "Nodes");
    add("alerts", "Alerts", openAlerts);
    if (canSeeRequests()) add("requests", "Requests", newOrders);
    if (me && me.role === "admin") add("team", "Team");
  }
  // On the Mac the admin handles node requests; online, only AEGIS_X staff see them (not every customer's admin).
  const canSeeRequests = () => !!me && (CLOUD ? !!me.staff : me.role === "admin");

  function showShell() {
    document.getElementById("top").hidden = false;
    document.getElementById("who").textContent = me.name;
  }

  document.getElementById("logout").addEventListener("click", async () => {
    try { await api("/api/logout", {}); } catch (e) { /* ignore */ }
    me = null; showAuth();
  });

  // ---------------------------------------------------------------- auth
  async function showAuth(mode) {
    clearInterval(timer);
    document.getElementById("top").hidden = true;
    let first = false, needsCode = false;
    try { const m = await api("/api/me"); first = m.firstUser; needsCode = m.needsSetupCode; } catch (e) { /* ignore */ }
    mode = first ? "signup" : (mode || "login");
    const err = h("p", { class: "err", role: "alert" });
    const f = {};
    const field = (k, label, type, auto) => h("label", {}, label,
      f[k] = h("input", { type, name: k, autocomplete: auto, required: true }));
    const form = h("form", { novalidate: true },
      mode === "signup" ? field("name", "Your name", "text", "name") : null,
      field("email", "Email", "email", "email"),
      field("password", "Password", "password", mode === "signup" ? "new-password" : "current-password"),
      mode === "signup" && !first ? field("invite", CLOUD ? "Invite code from your team (leave empty to start your own organisation)"
        : "Invite code (from your admin, under Team)", "text", "off") : null,
      needsCode ? field("invite", "Setup code (printed in the server's log when it started)", "text", "off") : null,
      err,
      h("button", { class: "btn primary", type: "submit", text: mode === "signup" ? "Create account" : "Log in" }));
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      err.textContent = "";
      const body = {};
      for (const k in f) body[k] = f[k].value;
      try {
        await api(mode === "signup" ? "/api/signup" : "/api/login", body);
        await boot();
      } catch (x) { err.textContent = x.message; }
    });
    const themeBtn = window.saakshiThemeButton ? window.saakshiThemeButton() : null;
    if (themeBtn) themeBtn.classList.add("auth-theme");
    $view.replaceChildren(themeBtn || "", h("div", { class: "auth" },
      h("a", { class: "mark", href: "/" }, h("b", {}, "SAAK", h("span", { text: "SHI" }))),
      h("h1", { text: first ? "Set up your dashboard" : (mode === "signup" ? "Create your account" : "Log in") }),
      h("p", { class: "muted", text: first ? "You're the first person here, so this account becomes the admin."
        : (mode === "signup" ? "Your admin can give you the invite code." : "See your nodes, trips and alerts.") }),
      form,
      first ? null : h("p", { class: "switch" }, mode === "signup" ? "Already have an account? " : "New to this team? ",
        h("button", { type: "button", text: mode === "signup" ? "Log in" : "Create an account",
          onclick: () => showAuth(mode === "signup" ? "login" : "signup") }))));
    (f.name || f.email).focus();
  }

  // ---------------------------------------------------------------- router
  async function render(quiet) {
    route = location.hash.slice(1) || "/nodes";
    const parts = route.split("/").filter(Boolean);
    if (!quiet) $view.classList.add("loading");
    try {
      if (parts[0] === "node" && parts[1]) await viewNode(decodeURIComponent(parts[1]), parts[2] && decodeURIComponent(parts[2]));
      else if (parts[0] === "alerts") await viewAlerts();
      else if (parts[0] === "requests" && canSeeRequests()) await viewRequests();
      else if (parts[0] === "team" && me.role === "admin") await viewTeam();
      else await viewNodes();
    } catch (e) {
      if (e.message !== "log in") $view.replaceChildren(h("div", { class: "banner critical" }, icon("critical"),
        h("div", {}, h("b", { text: "Couldn't load this page. " }), e.message)));
    } finally {
      $view.classList.remove("loading");
    }
  }
  window.addEventListener("hashchange", () => { render(); window.scrollTo(0, 0); });

  const busy = () => {
    const a = document.activeElement;
    return (a && /INPUT|SELECT|TEXTAREA/.test(a.tagName)) || document.hidden;   // never wipe what someone is typing
  };
  function startPolling() {
    clearInterval(timer);
    if (CLOUD) {
      // Online: ask every 3 s whether the Mac pushed anything new (a few bytes) and redraw only then;
      // once a minute anyway, so "x min ago" and Online/Offline stay current.
      let seen = null, drawn = Date.now();
      timer = setInterval(async () => {
        if (busy()) return;
        let fp = null;
        try { fp = await CLOUD.pulse(); } catch (e) { /* offline for a moment: try again next tick */ }
        const changed = fp && seen !== null && fp !== seen;
        if (fp) seen = fp;
        if (changed || Date.now() - drawn > 60000) { drawn = Date.now(); render(true); }
      }, 3000);
      return;
    }
    timer = setInterval(() => { if (!busy()) render(true); }, 10000);
  }
  // Online only: shows whether the Mac is pushing right now.
  function liveBadge(o) {
    if (!o.cloud) return null;
    const live = o.syncedAt && o.now - o.syncedAt < 60;
    return h("span", { class: `state ${live ? "online" : "offline"} live`,
      title: live ? "New readings appear here by themselves within seconds" : "The Mac isn't sending updates right now" },
      h("i"), live ? "Live" : "Updates paused");
  }

  async function boot() {
    const r = await api("/api/me");
    me = r.user;
    if (!me) return showAuth();
    showShell();
    if (CLOUD && !me.org) return viewOnboard();
    await render();
    startPolling();
  }

  // Online only: an account belongs to one organisation. A new account starts one or joins one.
  function viewOnboard() {
    clearInterval(timer);
    document.getElementById("tabs").replaceChildren();
    const card = (title, sub, label, k, value, button, path) => {
      const err = h("p", { class: "err", role: "alert" });
      const input = h("input", { type: "text", name: k, value: value || "", maxlength: 80, required: true, autocomplete: "off" });
      const form = h("form", { novalidate: true }, h("label", {}, label, input), err,
        h("button", { class: "btn primary", type: "submit", text: button }));
      form.addEventListener("submit", async (e) => {
        e.preventDefault(); err.textContent = "";
        try { await api(path, { [k]: input.value }); await boot(); } catch (x) { err.textContent = x.message; }
      });
      return h("section", { class: "card panel" }, h("h2", { text: title }), h("p", { class: "muted", text: sub }), form);
    };
    $view.replaceChildren(pageHead("Welcome to SAAKSHI", "Your account isn't part of an organisation yet."),
      h("div", { class: "onboard" },
        card("Start an organisation", "For an exporter or farm group with its own nodes. You become its admin.",
          "Organisation name", "name", "", "Start organisation", "/api/org/create"),
        card("Join your team", "Your admin finds the code on their Team page.",
          "Invite code", "invite", "", "Join", "/api/org/join")));
  }

  // ---------------------------------------------------------------- shared bits
  async function getOverview() {
    lastOverview = await api("/api/overview");
    const newOrders = canSeeRequests() ? (await api("/api/orders")).orders.filter((o) => o.status === "new").length : 0;
    setTabs(lastOverview.openAlerts, newOrders);
    return lastOverview;
  }
  function stateBadge(st) {
    const label = { online: "Online", offline: "Offline", never: "No data yet" }[st.state] || st.state;
    return h("span", { class: `state ${st.state}` }, h("i"), label);
  }
  function anchorLine(a) {
    if (!a) return h("span", { class: "muted", text: "No records yet" });
    if (a.seq != null) return h("span", { class: "lock" }, icon("lock"),
      `Locked on Polygon up to #${a.seq}${a.time ? ", " + when(a.time) : ""}${a.behind ? ` · ${a.behind} newer not yet` : ""}`);
    if (a.error && a.source == null) return h("span", { class: "lock" }, icon("wait"), "Polygon not reachable right now");
    return h("span", { class: "lock" }, icon("wait"), "Not anchored on Polygon yet");
  }
  function pageHead(title, sub, right) {
    return h("div", { class: "head" }, h("div", {}, h("h1", { text: title }), sub ? h("p", {}, sub) : null), right || null);
  }

  // ---------------------------------------------------------------- nodes
  async function viewNodes() {
    const o = await getOverview();
    const online = o.nodes.filter((n) => n.status.state === "online").length;
    const out = [pageHead("Your nodes", "Every reading is signed by the node's security chip and checked again before it's shown.", liveBadge(o))];
    if (!o.crypto) out.push(h("div", { class: "banner info" }, icon("info"), h("div", {},
      "Chip signatures were checked by the ledger but aren't re-checked here. To re-check them on this Mac too, run ",
      h("code", { class: "mono", text: "python3 -m pip install cryptography" }), " and restart the dashboard.")));
    if (o.cloud && o.syncedAt && o.now - o.syncedAt > 180) out.push(h("div", { class: "banner warning" }, icon("warning"), h("div", {},
      h("b", { text: `Last update from the Mac ${ago(o.syncedAt, o.now)}. ` }),
      "What you see is as of then. On the Mac that runs the ledger, start ",
      h("code", { class: "mono", text: "bash saakshi_start.sh" }), " for live data.")));
    if (!o.nodes.length && o.cloud) {
      out.push(h("div", { class: "card empty" }, h("h2", { text: "No nodes here yet" }),
        h("p", {}, me.role === "admin" ? "Connect the Mac that runs the ledger: open " : "Ask your admin to connect the Mac that runs the ledger (Team → Connect this Mac).",
          me.role === "admin" ? h("a", { href: "#/team", text: "Team → Connect this Mac" }) : null,
          me.role === "admin" ? ". Its nodes appear here within a minute." : "")));
      return $view.replaceChildren(...out);
    }
    if (!o.nodes.length) {
      out.push(h("div", { class: "card empty" }, h("h2", { text: "No records yet" }),
        h("p", {}, "The dashboard reads the ledger's folder (saakshi_ledger/). Start the ledger with ",
          h("code", { class: "mono", text: "python3 saakshi_ledger.py --tls" }),
          " and power the node: it appears here as soon as its first record arrives.")));
      return $view.replaceChildren(...out);
    }
    // fleet at a glance
    const records = o.nodes.reduce((sum, n) => sum + n.trips.reduce((a, t) => a + t.records, 0), 0);
    const anchored = o.nodes.map((n) => n.anchor).filter((a) => a && a.seq != null).sort((a, b) => (b.time || 0) - (a.time || 0))[0];
    const crit = o.nodes.filter((n) => n.alerts.worst === "critical").length;
    out.push(h("div", { class: "fleet" },
      stat("Online now", `${online} / ${o.nodes.length}`, online === o.nodes.length ? "every node reporting" : "some nodes are quiet", online < o.nodes.length ? "warn" : "good"),
      stat("Records verified", records.toLocaleString("en-IN"), "hash, link and chip signature"),
      stat("Open alerts", o.openAlerts.toLocaleString("en-IN"), crit ? `${crit} node${crit === 1 ? "" : "s"} with a critical one` : "nothing critical", crit ? "bad" : null, "#/alerts"),
      stat("Locked on Polygon", anchored ? `#${anchored.seq}` : "–", anchored && anchored.time ? `newest anchor ${ago(anchored.time, o.now)}` : "no anchor yet", anchored ? "good" : null)));
    out.push(h("div", { class: "nodes" }, o.nodes.map((n) => {
      const L = n.last;
      const hasT = L && !(L.flags & 2);
      const cfg = n.settings || {}, band = cfg.lo != null && cfg.hi != null ? [cfg.lo, cfg.hi] : null;
      const out_ = hasT && band && (L.temp < band[0] || L.temp > band[1]);
      const temps = (n.spark || []).map((x) => x[1]).filter((x) => x != null);
      return h("a", { class: `card node${out_ ? " out" : ""}`, href: `#/node/${encodeURIComponent(n.node)}` },
        h("div", { class: "id" }, h("div", {}, h("div", { class: "name", text: displayName(n) }),
          h("div", { class: "nid", text: n.name ? n.node : `${n.trips.length} trip${n.trips.length === 1 ? "" : "s"}` })),
          stateBadge(n.status)),
        h("div", { class: "reading" },
          h("div", { class: "t" }, hasT ? num(L.temp, 1) : "–", h("small", { text: "°C" })),
          h("div", { class: "chips" },
            h("span", { class: "chip" }, hasT ? num(L.rh, 0) : "–", h("small", { text: " % RH" })),
            L && L.eth != null ? h("span", { class: "chip" }, num(L.eth, 1), h("small", { text: " ppm C₂H₄" })) : null)),
        temps.length > 2 ? spark(temps, { band, height: 46, label: "Temperature, newest readings" }) : null,
        h("div", { class: "meta" },
          h("span", {}, `Last heard ${ago(n.status.lastHeard, o.now)}${L && L.t ? ` · reading from ${when(L.t)}` : ""}`),
          anchorLine(n.anchor),
          n.alerts.open ? h("span", {}, sev(n.alerts.worst), ` ${n.alerts.open} open alert${n.alerts.open === 1 ? "" : "s"}`)
            : h("span", { text: "No open alerts" })));
    })));
    $view.replaceChildren(...out);
  }

  function stat(k, v, sub, tone, href) {
    return h(href ? "a" : "div", { class: `card stat${tone ? " " + tone : ""}`, href: href || null },
      h("div", { class: "k", text: k }), h("div", { class: "v num", text: v }), sub ? h("div", { class: "s", text: sub }) : null);
  }

  // A tiny trend line: no axes, just the shape of the newest readings (and the allowed band, if any).
  function spark(vals, opts) {
    const W = 120, H = opts.height || 30;
    const el = s("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", class: "spark", role: "img", "aria-label": opts.label || "trend" });
    if (vals.length < 2) return el;
    let lo = Math.min(...vals), hi = Math.max(...vals);
    if (opts.band) { lo = Math.min(lo, opts.band[0]); hi = Math.max(hi, opts.band[1]); }
    const pad = (hi - lo || 1) * 0.12; lo -= pad; hi += pad;
    const X = (i) => (i / (vals.length - 1)) * W, Y = (v) => H - ((v - lo) / (hi - lo)) * H;
    if (opts.band) el.append(s("rect", { x: 0, width: W, y: Y(opts.band[1]), height: Math.max(0, Y(opts.band[0]) - Y(opts.band[1])), fill: "var(--band)" }));
    const pts = vals.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`);
    el.append(s("polygon", { points: `0,${H} ${pts.join(" ")} ${W},${H}`, fill: "var(--cold-soft)" }));
    el.append(s("polyline", { points: pts.join(" "), fill: "none", stroke: "var(--cold)", "stroke-width": 1.6, "vector-effect": "non-scaling-stroke", "stroke-linejoin": "round" }));
    return el;
  }

  // ---------------------------------------------------------------- charts
  function niceTicks(lo, hi, n) {
    const span = hi - lo || 1, raw = span / n, mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((x) => x >= raw) || raw;
    const out = [];
    for (let v = Math.ceil(lo / step) * step; v <= hi + 1e-9; v += step) out.push(+v.toFixed(6));
    return out;
  }

  function lineChart(series, key, opts) {
    const wrap = h("div", { class: "plot", tabindex: "0", role: "img",
      "aria-label": `${opts.title} chart. Use the left and right arrow keys to read values.` });
    const tip = h("div", { class: "tip", role: "status" });
    wrap.append(tip);
    const pts = series.map((b, i) => ({ i, b, v: b[key] })).filter((p) => p.v);
    function draw() {
      wrap.querySelector("svg") && wrap.querySelector("svg").remove();
      const W = Math.max(280, wrap.clientWidth || 600), H = opts.height, L = 46, R = 8, T = 20, B = 24;
      const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, height: H });
      if (!pts.length) { wrap.prepend(svg); return; }
      const x0 = series[0].s0, x1 = series[series.length - 1].s1 || x0 + 1;
      let lo = Math.min(...pts.map((p) => p.v[0])), hi = Math.max(...pts.map((p) => p.v[2]));
      if (opts.band) { lo = Math.min(lo, opts.band[0]); hi = Math.max(hi, opts.band[1]); }
      const pad = (hi - lo || 1) * 0.08; lo -= pad; hi += pad;
      const X = (b) => L + (((b.s0 + b.s1) / 2 - x0) / ((x1 - x0) || 1)) * (W - L - R);
      const Y = (v) => T + (1 - (v - lo) / (hi - lo)) * (H - T - B);
      const g = s("g", { class: "grid" }), ax = s("g", { class: "axis" });
      for (const v of niceTicks(lo, hi, 4)) {
        g.append(s("line", { x1: L, x2: W - R, y1: Y(v), y2: Y(v) }));
        const t = s("text", { x: L - 8, y: Y(v) + 4, "text-anchor": "end" }); t.textContent = `${num(v, opts.digits)}`;
        ax.append(t);
      }
      const unit = s("text", { x: L - 8, y: T - 9, "text-anchor": "end" }); unit.textContent = opts.unit; ax.append(unit);
      // x labels: time if known, else record number
      const lab = (b) => b.t ? when(b.t) : `#${b.s0}`;
      [[series[0], "start"], W >= 560 ? [series[Math.floor(series.length / 2)], "middle"] : null, [series[series.length - 1], "end"]].filter(Boolean).forEach(([b, a]) => {
        const t = s("text", { x: a === "start" ? L : a === "end" ? W - R : X(b), y: H - 4, "text-anchor": a });
        t.textContent = lab(b); ax.append(t);
      });
      svg.append(g);
      if (opts.band) {
        svg.append(s("rect", { x: L, width: W - L - R, y: Y(opts.band[1]), height: Math.max(0, Y(opts.band[0]) - Y(opts.band[1])), fill: "var(--band)" }));
        for (const v of opts.band) svg.append(s("line", { x1: L, x2: W - R, y1: Y(v), y2: Y(v), stroke: "var(--band-line)", "stroke-dasharray": "5 5", "stroke-width": 1.2 }));
      }
      // where the trip was locked on Polygon: everything up to that record can no longer change
      for (const m of opts.marks || []) {
        if (m.s < x0 || m.s > x1) continue;
        const xm = X({ s0: m.s, s1: m.s });
        svg.append(s("line", { class: "anchor-mark", x1: xm, x2: xm, y1: T, y2: H - B }));
        const lt = s("text", { class: "anchor-label", x: xm - 3, y: T + 11, "text-anchor": "end" }); lt.textContent = `#${m.s}`;
        svg.append(lt);
      }
      // split into runs where data exists (sensor failures leave gaps, never drawn as zero)
      const runs = []; let cur = [];
      series.forEach((b) => { if (b[key]) cur.push(b); else if (cur.length) { runs.push(cur); cur = []; } });
      if (cur.length) runs.push(cur);
      for (const r of runs) {
        const env = r.map((b) => `${X(b).toFixed(1)},${Y(b[key][2]).toFixed(1)}`).concat(
          r.slice().reverse().map((b) => `${X(b).toFixed(1)},${Y(b[key][0]).toFixed(1)}`)).join(" ");
        svg.append(s("polygon", { points: env, fill: "var(--cold-soft)" }));
        svg.append(s("polyline", { points: r.map((b) => `${X(b).toFixed(1)},${Y(b[key][1]).toFixed(1)}`).join(" "),
          fill: "none", stroke: "var(--cold)", "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }));
      }
      svg.append(ax);
      const xh = s("line", { class: "xh", y1: T, y2: H - B, visibility: "hidden" });
      const dot = s("circle", { r: 4.5, fill: "var(--cold)", stroke: "var(--surface)", "stroke-width": 2, visibility: "hidden" });
      svg.append(xh, dot);
      wrap.prepend(svg);
      let at = -1;
      function show(i) {
        at = Math.max(0, Math.min(pts.length - 1, i));
        const p = pts[at], x = X(p.b);
        xh.setAttribute("x1", x); xh.setAttribute("x2", x); xh.setAttribute("visibility", "visible");
        dot.setAttribute("cx", x); dot.setAttribute("cy", Y(p.v[1])); dot.setAttribute("visibility", "visible");
        tip.replaceChildren(
          h("div", { class: "row" }, h("span", { class: "key" }), h("span", { class: "tv", text: `${num(p.v[1], opts.digits + 1)} ${opts.unit}` })),
          h("div", { class: "tk", text: p.v[0] !== p.v[2] ? `range ${num(p.v[0], opts.digits + 1)}–${num(p.v[2], opts.digits + 1)} ${opts.unit}` : opts.title }),
          h("div", { class: "tk", text: `${p.b.t ? when(p.b.t) + " · " : ""}record${p.b.s1 > p.b.s0 ? "s" : ""} #${p.b.s0}${p.b.s1 > p.b.s0 ? "–" + p.b.s1 : ""}` }));
        tip.style.display = "block";
        const tw = tip.offsetWidth, scale = wrap.clientWidth / W;
        tip.style.left = `${Math.min(Math.max(0, x * scale + 12), wrap.clientWidth - tw)}px`;
      }
      function hide() { at = -1; tip.style.display = "none"; xh.setAttribute("visibility", "hidden"); dot.setAttribute("visibility", "hidden"); }
      svg.addEventListener("pointermove", (e) => {
        const r = svg.getBoundingClientRect(), x = (e.clientX - r.left) * (W / r.width);
        let best = 0, bd = Infinity;
        pts.forEach((p, k) => { const d = Math.abs(X(p.b) - x); if (d < bd) { bd = d; best = k; } });
        show(best);
      });
      svg.addEventListener("pointerleave", hide);
      wrap.onkeydown = (e) => {
        if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
          e.preventDefault();
          const step = Math.max(1, Math.round(pts.length / 60));
          show(at < 0 ? (e.key === "ArrowRight" ? 0 : pts.length - 1) : at + (e.key === "ArrowRight" ? step : -step));
        } else if (e.key === "Escape") hide();
      };
      wrap.onblur = hide;
    }
    requestAnimationFrame(draw);
    wrap._draw = draw;
    return wrap;
  }

  function joltChart(series) {
    const wrap = h("div", { class: "plot", tabindex: "0", role: "img", "aria-label": "Jolts chart. Use the arrow keys to read values." });
    const tip = h("div", { class: "tip", role: "status" });
    wrap.append(tip);
    function draw() {
      wrap.querySelector("svg") && wrap.querySelector("svg").remove();
      const W = Math.max(280, wrap.clientWidth || 600), H = 120, L = 46, R = 8, T = 10, B = 24;
      const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, height: H });
      const top = Math.max(1.5, ...series.map((b) => b.g)) * 1.1;
      const Y = (v) => T + (1 - v / top) * (H - T - B);
      const bw = (W - L - R) / series.length;
      const g = s("g", { class: "grid" }), ax = s("g", { class: "axis" });
      for (const v of niceTicks(0, top, 3)) {
        g.append(s("line", { x1: L, x2: W - R, y1: Y(v), y2: Y(v) }));
        const t = s("text", { x: L - 8, y: Y(v) + 4, "text-anchor": "end" }); t.textContent = `${num(v, 1)} g`; ax.append(t);
      }
      svg.append(g);
      series.forEach((b, i) => {
        if (b.g <= 0) return;
        svg.append(s("rect", { x: L + i * bw + Math.min(1, bw * 0.15), width: Math.max(1, bw - Math.min(2, bw * 0.3)),
          y: Y(b.g), height: Math.max(1, Y(0) - Y(b.g)), rx: Math.min(2, bw / 3), fill: "var(--cold)" }));
        if (b.shock) {
          const cx = L + (i + 0.5) * bw, cy = Y(b.g) - 6;
          svg.append(s("path", { d: `M${cx} ${cy + 4} l-4 -7 h8 z`, fill: "var(--serious-ink)" }));
        }
      });
      svg.append(s("line", { x1: L, x2: W - R, y1: Y(1), y2: Y(1), stroke: "var(--serious-ink)", "stroke-dasharray": "4 4", "stroke-width": 1 }));
      const lt = s("text", { x: W - R, y: Y(1) - 5, "text-anchor": "end", fill: "var(--serious-ink)", "font-size": 12 });
      lt.textContent = "1 g = shock"; svg.append(lt);
      const lab = (b) => b.t ? when(b.t) : `#${b.s0}`;
      [[series[0], L, "start"], [series[series.length - 1], W - R, "end"]].forEach(([b, x, a]) => {
        const t = s("text", { x, y: H - 4, "text-anchor": a }); t.textContent = lab(b); ax.append(t);
      });
      svg.append(ax);
      wrap.prepend(svg);
      let at = -1;
      const show = (i) => {
        at = Math.max(0, Math.min(series.length - 1, i));
        const b = series[at];
        tip.replaceChildren(h("div", { class: "tv", text: `${num(b.g, 2)} g${b.shock ? "  · shock" : ""}` }),
          h("div", { class: "tk", text: `${b.t ? when(b.t) + " · " : ""}#${b.s0}${b.s1 > b.s0 ? "–" + b.s1 : ""}` }));
        tip.style.display = "block";
        const scale = wrap.clientWidth / W;
        tip.style.left = `${Math.min(Math.max(0, (L + (at + 0.5) * bw) * scale + 10), wrap.clientWidth - tip.offsetWidth)}px`;
      };
      svg.addEventListener("pointermove", (e) => {
        const r = svg.getBoundingClientRect();
        show(Math.floor(((e.clientX - r.left) * (W / r.width) - L) / bw));
      });
      svg.addEventListener("pointerleave", () => { tip.style.display = "none"; });
      wrap.onkeydown = (e) => {
        if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
          e.preventDefault();
          const step = Math.max(1, Math.round(series.length / 60));
          show(at < 0 ? 0 : at + (e.key === "ArrowRight" ? step : -step));
        }
      };
      wrap.onblur = () => { tip.style.display = "none"; };
    }
    requestAnimationFrame(draw);
    wrap._draw = draw;
    return wrap;
  }
  let resizeT;
  window.addEventListener("resize", () => {
    clearTimeout(resizeT);
    resizeT = setTimeout(() => document.querySelectorAll(".plot").forEach((p) => p._draw && p._draw()), 150);
  });

  // ---------------------------------------------------------------- node / trip
  const FLAG_NAMES = [[0x20, "SHOCK", 1], [0x80, "SENSOR SWAP", 1], [0x40, "MISMATCH", 1], [0x2, "SENSOR FAIL", 1],
    [0x100, "UNSIGNED", 0], [0x1, "BOOT", 0], [0x4, "NO TIME", 0], [0x400, "MPU FAIL", 0], [0x200, "RTC FAIL", 0],
    [0x4000, "C₂H₄ WARM-UP", 0]];

  // The live view uses the newest records one by one; "whole trip" uses the averaged steps.
  let tripRange = "live";
  try { tripRange = localStorage.getItem("saakshi.range") || "live"; } catch (e) { /* private window */ }
  function liveSeries(live) {
    return live.map((r) => {
      const b = { s0: r.s, s1: r.s, t: r.t, g: r.g || 0, shock: !!(r.f & 0x20) };
      for (const k of ["temp", "rh", "press", "gas", "eth"]) if (r[k] != null) b[k] = [r[k], r[k], r[k]];
      return b;
    });
  }

  // "Right now": the newest value of each sensor, how it moved in 10 minutes, and its last hour.
  function nowTiles(v, band) {
    const L = v.live || [];
    const newest = (k) => { for (let i = L.length - 1; i >= 0; i--) if (L[i][k] != null) return L[i]; return null; };
    const before = (k, r) => {
      for (let i = L.length - 1; i >= 0; i--) {
        const x = L[i];
        if (x === r || x[k] == null) continue;
        if (r.t && x.t ? r.t - x.t >= 600 : r.s - x.s >= 60) return x;
      }
      return null;
    };
    const tile = (label, k, unit, digits, o) => {
      o = o || {};
      const r = newest(k), p = r ? before(k, r) : null, d = r && p ? r[k] - p[k] : null;
      const trend = d == null ? (r ? "steady data needed" : "") :
        `${Math.abs(d) < (o.flat || 0.05) ? "→ steady" : (d > 0 ? "↑ +" : "↓ ") + num(d, digits)} in 10 min`;
      const vals = L.map((x) => x[k]).filter((x) => x != null);
      const hot = r && o.hot && o.hot(r[k]);
      return h("div", { class: `tile${hot ? " hot" : ""}` },
        h("div", { class: "k", text: label }),
        h("div", { class: "v num" }, r ? num(r[k], digits) : "–", h("small", { text: r ? ` ${unit}` : "" })),
        h("div", { class: "s", text: r ? trend : (o.none || "no reading") }),
        vals.length > 2 ? spark(vals, { band: o.band, label: `${label}, last hour` }) : null);
    };
    const jolts = L.filter((x) => !(x.f & 0x400)).map((x) => x.g);
    return h("div", { class: "tiles" },
      tile("Temperature", "temp", "°C", 1, { band, hot: band ? (x) => x < band[0] || x > band[1] : null, flat: 0.1 }),
      tile("Humidity", "rh", "%", 0, { flat: 0.5 }),
      tile("Ethylene", "eth", "ppm", 1, { none: "sensor not connected", hot: (x) => x >= 10, flat: 0.5 }),
      tile("Pressure", "press", "hPa", 1, { flat: 0.1 }),
      tile("VOC gas", "gas", "kΩ", 1, { flat: 0.3 }),
      h("div", { class: `tile${jolts.some((g) => g >= 1) ? " hot" : ""}` },
        h("div", { class: "k", text: "Biggest jolt" }),
        h("div", { class: "v num" }, jolts.length ? num(Math.max(...jolts), 2) : "–", h("small", { text: jolts.length ? " g" : "" })),
        h("div", { class: "s", text: jolts.length ? "in the last hour" : "motion sensor not answering" }),
        jolts.length > 2 ? spark(jolts, { label: "Jolts, last hour" }) : null));
  }

  async function viewNode(nodeId, chain) {
    const o = await getOverview();
    const n = o.nodes.find((x) => x.node === nodeId);
    if (!n) { $view.replaceChildren(pageHead("Node not found", "It isn't in the ledger folder.")); return; }
    chain = chain && n.trips.some((t) => t.chain === chain) ? chain : n.currentChain;
    const v = await api(`/api/trip?node=${encodeURIComponent(nodeId)}&chain=${encodeURIComponent(chain)}`);
    const st = v.stats, band = v.settings.lo != null && v.settings.hi != null ? [v.settings.lo, v.settings.hi] : null;
    const live = tripRange === "live" && v.live && v.live.length > 1;
    const ser = live ? liveSeries(v.live) : v.series;
    const marks = (v.anchors || []).map((a) => ({ s: a.seq }));

    const tripSel = h("select", { "aria-label": "Trip" }, n.trips.slice().reverse().map((t) => h("option", {
      value: t.chain, selected: t.chain === chain || null,
      text: `Trip ${t.chain}${t.from ? " · " + when(t.from, { hour: undefined, minute: undefined }) : ""} · ${t.records.toLocaleString("en-IN")} records${t.chain === n.currentChain ? " (current)" : ""}` })));
    tripSel.addEventListener("change", () => { location.hash = `#/node/${encodeURIComponent(nodeId)}/${tripSel.value}`; });
    const range = h("div", { class: "segmented", role: "group", "aria-label": "Chart range" },
      [["live", "Last hour"], ["trip", "Whole trip"]].map(([k, l]) => h("button", { type: "button", "aria-pressed": tripRange === k ? "true" : "false", text: l,
        onclick: () => { tripRange = k; try { localStorage.setItem("saakshi.range", k); } catch (e) { /* fine */ } render(true); } })));

    const kp = (k, val, alert) => h("div", { class: `kpi${alert ? " hot" : ""}` }, h("div", { class: "v num", text: val }), h("div", { class: "k", text: k }));
    const kpis = h("div", { class: "card kpis" },
      kp("Lowest", st.temp ? `${num(st.temp.min)} °C` : "–"),
      kp("Average", st.temp ? `${num(st.temp.avg)} °C` : "–"),
      kp("Highest", st.temp ? `${num(st.temp.max)} °C` : "–"),
      st.band ? kp(`Outside ${num(st.band.lo, 0)}–${num(st.band.hi, 0)} °C`, st.band.outside ? dur(st.band.outsideSecs) : "Never", st.band.outside > 0)
        : kp("Humidity", st.rh ? `${num(st.rh.min, 0)}–${num(st.rh.max, 0)} %` : "–"),
      kp("Jolts over 1 g", st.mpuMissing ? "No sensor" : st.shocks.toLocaleString("en-IN"), st.shocks > 0),
      kp("Restarts", st.restarts.toLocaleString("en-IN"), st.restarts > 0));

    const span = live ? `Newest ${ser.length} readings, one by one${ser[0].t ? `, from ${when(ser[0].t)}` : ""}.`
      : st.from ? `${whenLong(st.from)} to ${whenLong(st.to)}, ${dur(st.to - st.from)}.` : "Clock not set on these records.";
    const hasEth = ser.some((b) => b.eth);
    const card = (title, legend, body, note) => h("section", { class: "card" },
      h("div", { class: "chart-head" }, h("h2", { text: title }), legend ? h("div", { class: "legend" }, legend) : null), body, note || null);
    const main = h("div", { class: "charts" },
      card("Temperature", [h("span", {}, h("i", { class: "ln" }), live ? "reading" : "average"), live ? null : h("span", {}, h("i", { class: "env" }), "range in each step"),
          band ? h("span", {}, h("i", { class: "bd" }), `allowed ${num(band[0], 0)}–${num(band[1], 0)} °C`) : null,
          marks.length ? h("span", {}, h("i", { class: "am" }), "locked on Polygon") : null],
        lineChart(ser, "temp", { title: "Temperature", unit: "°C", digits: 0, height: 230, band, marks }),
        h("p", { class: "chart-note" }, `${span} `, !live && st.noTime ? `${st.noTime} records had no clock time and are placed by record number. ` : "",
          st.sensorFail ? `${st.sensorFail} failed readings are left out.` : "")),
      card("Humidity", null, lineChart(ser, "rh", { title: "Humidity", unit: "%", digits: 0, height: 150 })),
      card("Ethylene gas", null,
        hasEth ? lineChart(ser, "eth", { title: "Ethylene gas", unit: "ppm", digits: 1, height: 150 }) : h("p", { class: "muted", text: "Sensor not connected." }),
        hasEth && st.ethState === "warmup" ? h("p", { class: "chart-note", text: "Warming up: the sensor needs 48 hours powered before its readings settle. Until then they aren't used for alerts." })
          : hasEth && st.ethState === "none" ? h("p", { class: "chart-note", text: "Sensor not connected right now." }) : null),
      h("div", { class: "pair" },
        card("Pressure", null, lineChart(ser, "press", { title: "Pressure", unit: "hPa", digits: 1, height: 120 })),
        card("VOC gas", h("span", { text: "lower = more gases" }), lineChart(ser, "gas", { title: "VOC gas resistance", unit: "kΩ", digits: 2, height: 120 }))),
      card("Jolts", h("span", { text: live ? "each reading" : "biggest knock in each step" }),
        st.mpuMissing ? h("p", { class: "muted", text: "The motion sensor (MPU-6050) isn't answering on this node, so there's no jolt data. Check its wiring (address 0x69, AD0 to 3V3)." })
          : joltChart(ser)));
    const csv = h("a", { class: "btn small", href: `/api/export?node=${encodeURIComponent(nodeId)}&chain=${chain}`, text: "Download CSV" });
    if (CLOUD) csv.addEventListener("click", async (e) => {
      e.preventDefault();
      csv.textContent = "Preparing…";
      try {
        const url = URL.createObjectURL(new Blob([await CLOUD.exportCsv(nodeId, chain)], { type: "text/csv" }));
        const a = h("a", { href: url, download: `${nodeId}_${chain}.csv` });
        document.body.append(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
        csv.textContent = "Download CSV";
      } catch (x) { csv.textContent = "Download failed, try again"; }
    });
    const lower = h("div", { class: "lower" },
      alertsCard(v.alerts.filter((a) => !a.acked), "Alerts on this trip", true, 4),
      recentCard(v.recent));
    const side = h("div", { class: "side" }, integrityCard(v, o), shareCard(v), settingsCard(n, v));

    $view.replaceChildren(
      h("div", { class: "crumbs" }, h("a", { href: "#/nodes", text: "← All nodes" })),
      h("div", { class: "titlebar" }, h("h1", { text: displayName(n) }), stateBadge(n.status), liveBadge(o)),
      h("p", { class: "muted" }, n.name ? `${n.node} · ` : "", `Last heard ${ago(n.status.lastHeard, o.now)}`,
        n.status.interval ? ` · logs every ${dur(n.status.interval)}` : ""),
      nowTiles(v, band),
      h("div", { class: "filters" }, h("label", {}, "Trip", tripSel), range, csv),
      kpis,
      h("div", { class: "layout" }, main, side, lower));
  }

  function integrityCard(v, o) {
    const it = v.integrity, a = v.anchor || {};
    const row = (kind, text, extra) => h("div", { class: `check ${kind}` }, icon(kind), h("div", {}, text, extra || null));
    const rows = [];
    if (it.problem) rows.push(row("bad", `Integrity check failed: ${it.problem}`));
    else rows.push(row("ok", `${it.records.toLocaleString("en-IN")} records re-checked here: every fingerprint matches and every record links to the one before it.`));
    if (!it.problem) rows.push(it.signaturesChecked
      ? row("ok", `Every record is covered by the node's security-chip signature${it.unsigned ? ` (${it.unsigned} logged while the chip was busy, each covered by the next signed one)` : ""}.`)
      : row("wait", "Chip signatures were checked by the ledger; not re-checked here (no public key file or no cryptography module)."));
    if (a.seq != null) {
      rows.push(row("ok", `Locked on Polygon up to record #${a.seq}${a.time ? ` on ${whenLong(a.time)}` : ""}. Polygon checked the chip's signature itself.`,
        a.behind ? h("div", { class: "muted" }, CLOUD ? `${a.behind} newer records go into the next automatic anchor.`
          : `${a.behind} newer signed records aren't anchored yet. `, CLOUD ? null : "Run ",
          CLOUD ? null : h("code", { class: "mono", text: "python3 saakshi_relay.py --once" }), CLOUD ? null : ".") : null));
    } else if (a.error && !a.source) rows.push(row("wait", "Polygon couldn't be reached, so the anchor wasn't checked. The checks above still stand."));
    else if (CLOUD) rows.push(row("wait", "Not anchored on Polygon yet. It happens automatically: every 30 minutes, and straight away after a jolt or a temperature alarm."));
    else rows.push(row("wait", "Nothing from this trip is anchored on Polygon yet. Run ",
      h("code", { class: "mono", text: "python3 saakshi_relay.py --once" })));
    const refresh = h("button", { class: "btn small", type: "button", text: "Check Polygon now" });
    refresh.addEventListener("click", async () => {
      refresh.disabled = true; refresh.textContent = "Checking…";
      try { await api("/api/anchors/refresh", {}); } catch (e) { /* ignore */ }
      setTimeout(() => render(true), 5000);
    });
    const links = h("p", { class: "muted", style: "font-size:13px;margin:10px 0 0" },
      a.tx ? h("a", { href: `${o.polygon.explorer}/tx/${a.tx}`, target: "_blank", rel: "noopener", text: "Anchor transaction" }) : null,
      a.tx ? " · " : null,
      h("a", { href: `${o.polygon.explorer}/address/${o.polygon.contract}`, target: "_blank", rel: "noopener", text: "SaakshiRegistry contract" }),
      o.polygon.checkedAt ? ` · checked ${ago(o.polygon.checkedAt, o.now)}` : "");
    const hist = (v.anchors || []).slice().reverse();
    const history = hist.length ? h("div", { class: "anchors" },
      h("div", { class: "k", text: `Anchors on Polygon for this trip (${hist.length})` }),
      h("ol", {}, hist.slice(0, 5).map((x) => h("li", {},
        h("span", { class: "num", text: `#${x.seq}` }), h("span", { class: "muted", text: x.time ? when(x.time) : "" }),
        x.tx ? h("a", { href: `${o.polygon.explorer}/tx/${x.tx}`, target: "_blank", rel: "noopener noreferrer", text: `block ${x.block || "tx"}` }) : null))),
      hist.length > 5 ? h("div", { class: "muted", style: "font-size:13px", text: `and ${hist.length - 5} earlier` }) : null) : null;
    return h("section", { class: "card panel" }, h("h2", { text: "Trust & blockchain" }), ...rows, history, links,
      CLOUD ? h("p", { class: "muted", style: "font-size:13px;margin:8px 0 0", text: "Anchoring is automatic; this panel re-checks Polygon every minute." })
        : h("div", { style: "margin-top:10px" }, refresh));
  }

  function shareCard(v) {
    const sh = v.share || {};
    const body = [];
    if (!sh.url) {
      body.push(h("p", { class: "muted" }, sh.hint || "No buyer link yet."));
    } else {
      const img = h("img", { src: sh.qrSvg ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(sh.qrSvg)}`
        : `/api/qr?node=${encodeURIComponent(v.node)}&chain=${v.chain}`, alt: "QR code for the buyer's verification page", width: 190, height: 190 });
      const fallback = h("p", { class: "muted", hidden: true }, "For the QR image here, run ",
        h("code", { class: "mono", text: 'python3 -m pip install "qrcode"' }), " and restart.");
      img.addEventListener("error", () => { img.hidden = true; fallback.hidden = false; });
      const copy = h("button", { class: "btn small", type: "button", text: "Copy link" });
      copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(sh.url); copy.textContent = "Copied"; }
        catch (e) { copy.textContent = "Select the link to copy"; }
        setTimeout(() => { copy.textContent = "Copy link"; }, 2000);
      });
      body.push(h("div", { class: "qr" }, img, fallback, h("div", { class: "link", text: sh.url }), copy));
      const p = sh.published;
      if (!p) body.push(h("p", { class: "muted", style: "font-size:13px" }, "This trip isn't on the verification site yet. Run ",
        h("code", { class: "mono", text: "python3 saakshi_relay.py --publish" }),
        CLOUD ? " on the Mac, then " : " and upload saakshi_site to Netlify.",
        CLOUD ? h("code", { class: "mono", text: "bash saakshi_cloud/deploy.sh" }) : null, CLOUD ? "." : null));
      else if (p.count < v.integrity.records) body.push(h("p", { class: "muted", style: "font-size:13px" },
        `The site has ${p.count.toLocaleString("en-IN")} of ${v.integrity.records.toLocaleString("en-IN")} records (published ${when(p.published)}). Run `,
        h("code", { class: "mono", text: "--publish" }), " again to include the newest."));
      else body.push(h("p", { class: "muted", style: "font-size:13px", text: `All ${p.count.toLocaleString("en-IN")} records are on the site (published ${when(p.published)}).` }));
      if (sh.local) body.push(h("p", { class: "muted", style: "font-size:13px" }, "This link points to this Mac. After putting the site on Netlify, run ",
        h("code", { class: "mono", text: "--publish --site-url https://<your-site>.netlify.app" }), " once."));
    }
    return h("section", { class: "card panel" }, h("h2", { text: "Share with the buyer" }),
      h("p", { class: "muted", style: "font-size:14px;margin-top:-4px", text: "Scanning opens the trip on the buyer's phone, which checks every reading and the Polygon anchor itself. No login, and it doesn't depend on this dashboard." }),
      ...body);
  }

  function settingsCard(n, v) {
    const s = v.settings;
    const f = {};
    const inp = (k, label, type, val, attrs, full) => h("label", { class: full ? "full" : null }, label,
      f[k] = h("input", Object.assign({ type, value: val == null ? "" : val }, attrs || {})));
    const msg = h("p", { class: "saved", role: "status" });
    const form = h("form", {},
      h("div", { class: "form-grid" },
        inp("name", "Name for this node", "text", s.name, { maxlength: 60, placeholder: "e.g. Mango crate 1" }, true),
        inp("lo", "Lowest allowed °C", "number", s.lo, { step: "0.1" }),
        inp("hi", "Highest allowed °C", "number", s.hi, { step: "0.1" }),
        inp("minutes", "Alert after (minutes outside)", "number", s.minutes, { min: 0, step: 1 }),
        inp("offlineMinutes", "Offline after (minutes, 0 = auto)", "number", s.offlineMinutes, { min: 0, step: 1 })),
      h("p", { class: "muted", style: "font-size:13px", text: "Typical bands: chilled produce 2–8 °C, bananas 13–15 °C, frozen −25 to −18 °C. Leave both empty for no temperature alerts." }),
      h("div", { style: "display:flex;gap:12px;align-items:center" }, h("button", { class: "btn primary small", type: "submit", text: "Save" }), msg));
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      msg.className = "saved"; msg.textContent = "";
      const body = { node: n.node };
      for (const k in f) body[k] = f[k].value;
      try { await api("/api/nodes/settings", body); msg.textContent = "Saved"; document.activeElement.blur(); setTimeout(() => render(true), 400); }
      catch (x) { msg.className = "err"; msg.textContent = x.message; }
    });
    return h("section", { class: "card panel" }, h("h2", { text: "Settings" }), form);
  }

  let showRows = 10;
  function recentCard(all) {
    const rows = all.slice(0, showRows);
    const flags = (fl) => FLAG_NAMES.filter(([b]) => fl & b).map(([, name, hot]) => h("span", { class: `flag${hot ? " hot" : ""}`, text: name }));
    const more = all.length > 10 ? h("button", { class: "btn small more", type: "button", text: showRows > 10 ? "Show fewer" : `Show ${all.length}`,
      onclick: () => { showRows = showRows > 10 ? 10 : all.length; render(true); } }) : null;
    return h("section", { class: "card" }, h("div", { class: "chart-head" }, h("h2", { text: "Latest readings" }), more),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Record", "Time", "Temp °C", "RH %", "Pressure hPa", "Gas kΩ", "C₂H₄ ppm", "Jolt g", "Flags"].map((t) => h("th", { scope: "col", text: t })))),
        h("tbody", {}, rows.map((r) => h("tr", {},
          h("td", { text: `#${r.seq}` }), h("td", { text: r.t ? when(r.t, { second: "2-digit" }) : "no time" }),
          h("td", { text: r.flags & 2 ? "–" : num(r.temp, 2) }), h("td", { text: r.flags & 2 ? "–" : num(r.rh, 1) }),
          h("td", { text: r.flags & 2 ? "–" : num(r.press, 1) }), h("td", { text: r.flags & 2 ? "–" : num(r.gas, 1) }),
          h("td", { text: r.eth == null ? "–" : num(r.eth, 1) }),
          h("td", { text: r.flags & 0x400 ? "–" : num(r.peak, 2) }), h("td", { class: "wrap" }, flags(r.flags))))))));
  }

  // ---------------------------------------------------------------- alerts
  function alertRow(a, compact) {
    const btn = h("button", { class: "btn small", type: "button", text: a.acked ? "Reopen" : "Acknowledge" });
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try { await api("/api/alerts/ack", { id: a.id, undo: !!a.acked }); } finally { render(true); }
    });
    const where = [];
    if (!compact && a.node) where.push(a.node);
    if (a.chain && !compact) where.push(`trip ${a.chain}`);
    if (a.time) where.push(when(a.time));
    if (a.acked) where.push(`acknowledged by ${a.acked.by}, ${when(a.acked.at)}`);
    const title = !compact && a.node ? h("a", { href: `#/node/${encodeURIComponent(a.node)}${a.chain ? "/" + a.chain : ""}`, text: a.title }) : a.title;
    return h("div", { class: `alert${a.acked ? " acked" : ""}` }, sev(a.severity),
      h("div", {}, h("div", { class: "title" }, title), h("div", { class: "detail", text: a.detail }),
        where.length ? h("div", { class: "where", text: where.join(" · ") }) : null),
      a.type === "offline" && !a.acked ? h("span") : btn);
  }

  const openLists = new Set();
  function alertsCard(list, title, compact, limit) {
    const folded = limit && list.length > limit && !openLists.has(title);
    const more = limit && list.length > limit ? h("button", { class: "btn small more", type: "button", text: folded ? `Show all ${list.length}` : "Show fewer",
      onclick: () => { if (folded) openLists.add(title); else openLists.delete(title); render(true); } }) : null;
    return h("section", { class: "card", style: "padding:0" },
      h("div", { class: "chart-head", style: "padding:16px 16px 0" }, h("h2", { text: title }), more),
      list.length ? h("div", { class: "alerts" }, (folded ? list.slice(0, limit) : list).map((a) => alertRow(a, compact)))
        : h("p", { class: "muted", style: "padding:0 16px 16px", text: "Nothing needs attention." }));
  }

  let alertFilter = "open";
  async function viewAlerts() {
    const [, r] = await Promise.all([getOverview(), api("/api/alerts")]);
    const list = r.alerts.filter((a) => alertFilter === "all" || !a.acked);
    const seg = h("div", { class: "segmented", role: "group", "aria-label": "Show" },
      [["open", "Open"], ["all", "All"]].map(([k, l]) => h("button", { type: "button", "aria-pressed": alertFilter === k ? "true" : "false", text: l,
        onclick: () => { alertFilter = k; render(true); } })));
    $view.replaceChildren(pageHead("Alerts", "Worked out from every verified record, the ledger's own log, and when each node was last heard."),
      h("div", { class: "filters" }, seg),
      alertsCard(list, alertFilter === "open" ? `${list.length} open` : `${list.length} in total`, false));
  }

  // ---------------------------------------------------------------- admin
  async function viewRequests() {
    const [, r] = await Promise.all([getOverview(), api("/api/orders")]);
    const rows = r.orders.map((o) => {
      const sel = h("select", { "aria-label": "Status" }, ["new", "contacted", "done"].map((s) => h("option", { value: s, selected: o.status === s || null, text: s[0].toUpperCase() + s.slice(1) })));
      sel.addEventListener("change", async () => { await api("/api/orders/status", { id: o.id, status: sel.value }); sel.blur(); render(true); });
      return h("tr", {}, h("td", { text: when(o.time) }), h("td", { text: o.name }), h("td", { text: o.company || "–" }),
        h("td", { text: o.contact }), h("td", { text: o.nodes }), h("td", { text: o.product || "–" }),
        h("td", { class: "wrap", text: o.note || "–" }), h("td", {}, sel));
    });
    $view.replaceChildren(pageHead("Node requests", "Sent from the public page's request form."),
      h("section", { class: "card" }, rows.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Received", "Name", "Company", "Contact", "Nodes", "Produce", "Note", "Status"].map((t) => h("th", { scope: "col", text: t })))),
        h("tbody", {}, rows))) : h("p", { class: "muted", text: "No requests yet. The form is on the public page at /." })));
  }

  async function viewTeam() {
    const [, r] = await Promise.all([getOverview(), api("/api/team")]);
    const code = h("code", { class: "mono", style: "font-size:20px", text: r.invite });
    const rotate = h("button", { class: "btn small", type: "button", text: "Make a new code" });
    rotate.addEventListener("click", async () => { const j = await api("/api/team/invite", {}); code.textContent = j.invite; });
    $view.replaceChildren(pageHead("Team", CLOUD && r.org ? `Everyone in ${r.org} sees every node of this organisation.` : "Everyone here sees every node on this dashboard."),
      CLOUD ? connectCard(r) : "",
      h("section", { class: "card", style: "margin-bottom:18px" }, h("h2", { text: "Invite code" }),
        h("p", { class: "muted", text: "A teammate needs this code to create an account. Make a new code to stop the old one working." }),
        h("div", { style: "display:flex;gap:14px;align-items:center;flex-wrap:wrap" }, code, rotate)),
      h("section", { class: "card" }, h("h2", { text: "Members" }), h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Name", "Email", "Role", "Joined"].map((t) => h("th", { scope: "col", text: t })))),
        h("tbody", {}, r.users.map((u) => h("tr", {}, h("td", { text: u.name }), h("td", { text: u.email }),
          h("td", { text: u.role === "admin" ? "Admin" : "Member" }), h("td", { text: when(u.created) }))))))));
  }

  // Online only: the Mac that runs the ledger pushes its verified view here with a sync code.
  function connectCard(r) {
    const out = h("div");
    const make = h("button", { class: "btn primary small", type: "button", text: r.links ? "Make another sync code" : "Make a sync code" });
    make.addEventListener("click", async () => {
      make.disabled = true;
      try {
        const { code } = await api("/api/sync/link", {});
        const cmd = `python3 saakshi_cloud_sync.py --link ${code}`;
        const copy = h("button", { class: "btn small", type: "button", text: "Copy command" });
        copy.addEventListener("click", async () => {
          try { await navigator.clipboard.writeText(cmd); copy.textContent = "Copied"; } catch (e) { copy.textContent = "Select it to copy"; }
        });
        out.replaceChildren(
          h("p", {}, "In Terminal on that Mac, in the SAAKSHI folder, run this once:"),
          h("div", { class: "link mono", style: "user-select:all;word-break:break-all;margin:8px 0", text: cmd }), copy,
          h("p", { class: "muted", style: "font-size:13px" }, "Then keep ",
            h("code", { class: "mono", text: "python3 saakshi_cloud_sync.py" }),
            " running next to the ledger. This code is shown only once and works like a password for your organisation's data: don't post it in chats or screenshots."));
      } catch (x) { out.replaceChildren(h("p", { class: "err", text: x.message })); }
      make.disabled = false;
    });
    const revoke = h("button", { class: "btn small", type: "button", text: "Disconnect all Macs" });
    revoke.addEventListener("click", async () => {
      if (!confirm("Disconnect every Mac from this organisation? They stop syncing until you make a new code.")) return;
      try { const j = await api("/api/sync/revoke", {}); out.replaceChildren(h("p", { class: "saved", text: `Disconnected ${j.count}.` })); }
      catch (x) { out.replaceChildren(h("p", { class: "err", text: x.message })); }
    });
    return h("section", { class: "card", style: "margin-bottom:18px" }, h("h2", { text: "Connect this Mac" }),
      h("p", { class: "muted" }, "The Mac running the ledger checks every record and chip signature, then sends what you see here. ",
        r.lastSync ? `Last update ${ago(r.lastSync)}.` : "Nothing received yet.",
        r.links ? ` ${r.links} sync code${r.links === 1 ? "" : "s"} active.` : ""),
      h("div", { style: "display:flex;gap:10px;flex-wrap:wrap" }, make, r.links ? revoke : null), out);
  }

  boot().catch(() => showAuth());
})();
