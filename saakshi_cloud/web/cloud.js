/* SAAKSHI online dashboard: answers app.js's /api/... calls from Supabase instead of the Mac.
   app.js stays one file for both; when window.SaakshiCloud exists it routes every call here.
   The Mac (saakshi_cloud_sync.py) does all checking; this file only reads what it pushed,
   plus what people do here (settings, acknowledgements, team, requests). Row-level security
   in the database decides what each account may see. */
(function () {
  "use strict";
  const CFG = window.SAAKSHI_CLOUD || {};
  let sb = null, ctx = null;

  function client() {
    if (!sb) {
      if (!window.supabase || !window.supabase.createClient) throw new Error("The page didn't finish loading. Reload it.");
      sb = window.supabase.createClient(CFG.url, CFG.key, { auth: { persistSession: true, autoRefreshToken: true } });
    }
    return sb;
  }
  function fail(message, status) { const e = new Error(message); if (status) e.status = status; return e; }
  function check(res) {
    if (res.error) {
      const m = res.error.message || "request failed";
      if (/JWT|not authenticated|permission denied/i.test(m) && !ctx) throw fail("log in", 401);
      throw fail(m === "Invalid login credentials" ? "Wrong email or password." : m);
    }
    return res.data;
  }
  const epoch = (iso) => (iso ? Math.floor(new Date(iso).getTime() / 1000) : null);
  const now = () => Math.floor(Date.now() / 1000);

  async function context() {
    const { data } = await client().auth.getSession();
    if (!data.session) { ctx = null; return null; }
    ctx = check(await client().rpc("my_context"));
    if (ctx) ctx.uid = data.session.user.id;
    return ctx;
  }
  async function needLogin() {
    if (!ctx && !(await context())) throw fail("log in", 401);
    if (!ctx.org) throw fail("Join or start an organisation first.");
    return ctx;
  }

  // ---------------------------------------------------------------- the shared picture
  const RANK = { critical: 0, serious: 1, warning: 2, info: 3 };
  const DEFAULTS = { name: "", lo: null, hi: null, minutes: 15, offlineMinutes: 0 };

  async function load() {
    await needLogin();
    const c = client();
    const [views, nodes, alerts, acks, status] = await Promise.all([
      c.from("node_views").select("node,data"), c.from("nodes").select("node,settings"),
      c.from("alerts").select("id,node,data"), c.from("alert_acks").select("alert_id,by_name,at"),
      c.from("sync_status").select("data,synced_at").maybeSingle()]);
    const settings = Object.fromEntries(check(nodes).map((r) => [r.node, r.settings || {}]));
    const ackMap = Object.fromEntries(check(acks).map((a) => [a.alert_id, { by: a.by_name, at: epoch(a.at) }]));
    const st = check(status);
    const t = now();
    const list = check(views).map((r) => {
      const n = r.data;
      const s = Object.assign({}, DEFAULTS, n.settings, settings[n.node]);
      n.settings = s; n.name = s.name || "";
      const sv = n.status || {};
      if (sv.lastHeard) {            // judged now, not when the Mac last synced
        const limit = s.offlineMinutes ? s.offlineMinutes * 60 : Math.max(3 * (sv.interval || 0), 120);
        n.status = Object.assign({}, sv, { offlineAfter: limit, state: t - sv.lastHeard <= limit ? "online" : "offline" });
      }
      return n;
    }).sort((a, b) => a.node.localeCompare(b.node));

    const all = check(alerts).map((r) => r.data);
    for (const n of list) {          // the Mac adds "offline" alerts only while it runs; add them here too
      if (n.status.state === "offline" && !all.some((a) => a.type === "offline" && a.node === n.node)) {
        all.push({ id: `offline|${n.node}|${n.status.lastHeard}`, type: "offline", severity: "serious", node: n.node,
          chain: null, seq: null, time: n.status.lastHeard, title: "Node offline",
          detail: "Nothing received since then. It keeps logging and chaining; records arrive when it reconnects." });
      }
    }
    for (const a of all) a.acked = ackMap[a.id] || null;
    all.sort((a, b) => (!!a.acked - !!b.acked) || ((RANK[a.severity] ?? 4) - (RANK[b.severity] ?? 4)) || ((b.time || 0) - (a.time || 0)));
    for (const n of list) {
      const open = all.filter((a) => a.node === n.node && !a.acked);
      n.alerts = { open: open.length, worst: open.length ? open[0].severity : null };
    }
    const sd = (st && st.data) || {};
    return {
      overview: { nodes: list, now: t, crypto: sd.crypto !== false, cloud: true,
        syncedAt: st ? epoch(st.synced_at) : null,
        polygon: sd.polygon || { error: null, checkedAt: null, contract: "0xA82128628b7Ae42183d9B76020CD37C007c18c46", explorer: "https://amoy.polygonscan.com" },
        openAlerts: all.filter((a) => !a.acked).length },
      alerts: all, settings };
  }

  async function trip(node, chain) {
    const [pic, res] = await Promise.all([load(),
      client().from("trip_views").select("data").eq("node", node).eq("chain", chain).maybeSingle()]);
    const row = check(res);
    if (!row) throw fail("no such trip");
    const v = row.data;
    v.settings = Object.assign({}, DEFAULTS, v.settings, pic.settings[node]);
    v.alerts = pic.alerts.filter((a) => a.node === node && (a.chain === chain || a.chain == null));
    return v;
  }

  async function orders() {
    const rows = check(await client().from("orders").select("*").order("created_at", { ascending: false }));
    return rows.map((o) => ({ id: o.id, time: epoch(o.created_at), name: o.name, company: o.company, contact: o.contact,
      nodes: o.nodes, product: o.product, note: o.note, status: o.status }));
  }

  // The public request form must work without the Supabase library (it isn't loaded on the landing page).
  async function sendOrder(b) {
    const name = String(b.name || "").trim().slice(0, 80), contact = String(b.contact || "").trim().slice(0, 120);
    if (!name || contact.length < 3) throw fail("Please give your name and a phone number or email.");
    let nodes = parseInt(b.nodes, 10);
    nodes = Number.isFinite(nodes) ? Math.max(1, Math.min(10000, nodes)) : 1;
    const r = await fetch(`${CFG.url}/rest/v1/orders`, { method: "POST",
      headers: { apikey: CFG.key, "Content-Type": "application/json", Prefer: "return=minimal" },
      body: JSON.stringify({ name, contact, nodes, company: String(b.company || "").trim().slice(0, 120),
        product: String(b.product || "").trim().slice(0, 120), note: String(b.note || "").trim().slice(0, 600) }) });
    if (!r.ok) throw fail("Couldn't send. Try again.");
    return { ok: true };
  }

  // ---------------------------------------------------------------- the router app.js talks to
  async function api(path, body) {
    const u = new URL(path, location.origin), q = u.searchParams, p = u.pathname;
    const c = () => client();
    switch (p) {
      case "/api/orders":
        if (body !== undefined) return sendOrder(body);
        await needLogin(); return { orders: await orders() };
      case "/api/me": {
        const x = await context();
        return { user: x ? Object.assign({}, x.user, { org: x.org }) : null, firstUser: false, needsSetupCode: false };
      }
      case "/api/login":
        check(await c().auth.signInWithPassword({ email: String(body.email || "").trim(), password: body.password || "" }));
        await context(); return { ok: true };
      case "/api/signup": {
        const name = String(body.name || "").trim(), email = String(body.email || "").trim();
        if (!name) throw fail("Enter your name.");
        if ((body.password || "").length < 8) throw fail("Use at least 8 characters for the password.");
        const r = check(await c().auth.signUp({ email, password: body.password, options: { data: { name } } }));
        if (!r.session) throw fail("Account made. Check your email to confirm it, then log in.");
        await context();
        if (String(body.invite || "").trim()) {
          try { ctx = check(await c().rpc("join_org", { p_code: body.invite })); }
          catch (e) { /* the account exists; the next screen lets them retry or start their own */ }
        }
        return { ok: true };
      }
      case "/api/logout": ctx = null; await c().auth.signOut(); return { ok: true };
      case "/api/org/create": await context(); ctx = check(await c().rpc("create_org", { p_name: body.name })); return { ok: true };
      case "/api/org/join": await context(); ctx = check(await c().rpc("join_org", { p_code: body.invite })); return { ok: true };
      case "/api/overview": return (await load()).overview;
      case "/api/alerts": return { alerts: (await load()).alerts };
      case "/api/trip": return trip(q.get("node"), q.get("chain"));
      case "/api/alerts/ack": {
        const x = await needLogin();
        if (body.undo) check(await c().from("alert_acks").delete().eq("alert_id", body.id));
        else check(await c().from("alert_acks").insert({ org_id: x.org.id, alert_id: body.id, by_user: x.uid, by_name: x.user.name }));
        return { ok: true };
      }
      case "/api/nodes/settings": {
        await needLogin();
        const s = Object.assign({}, body); delete s.node;
        return { ok: true, settings: check(await c().rpc("save_node_settings", { p_node: body.node, p_settings: s })) };
      }
      case "/api/anchors/refresh": return { ok: true };       // the Mac checks Polygon every 5 minutes
      case "/api/orders/status":
        await needLogin(); check(await c().from("orders").update({ status: body.status }).eq("id", body.id)); return { ok: true };
      case "/api/team": await needLogin(); return check(await c().rpc("team"));
      case "/api/team/invite": await needLogin(); return { invite: check(await c().rpc("rotate_invite")) };
      case "/api/sync/link": await needLogin(); return { code: check(await c().rpc("create_sync_link")) };
      case "/api/sync/revoke": await needLogin(); return { count: check(await c().rpc("revoke_sync_links")) };
      default: throw fail("not found");
    }
  }

  // The exact ledger file: header + the verified lines the Mac uploaded, in order.
  const HEADER = "seq,boot,uptime_s,unix_time,temp_c,rh_pct,pressure_hpa,gas_kohm,rtc_temp_c,mpu_temp_c,peak_g,moves,sensor_id,flags,prev_hash,hash,sig";
  async function exportCsv(node, chain) {
    await needLogin();
    const lines = [HEADER];
    for (let from = 0; ; from += 1000) {
      const rows = check(await client().from("readings").select("line").eq("node", node).eq("chain", chain)
        .order("seq").range(from, from + 999));
      for (const r of rows) lines.push(r.line);
      if (rows.length < 1000) break;
    }
    return lines.join("\n") + "\n";
  }

  window.SaakshiCloud = { api, exportCsv };
})();
