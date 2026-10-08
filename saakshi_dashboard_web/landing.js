/* SAAKSHI landing page: the "Request nodes" form. A separate file so the pages can forbid inline scripts. */
(function () {
  "use strict";
  document.getElementById("order").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target, msg = document.getElementById("order-msg"), btn = f.querySelector("button");
    const body = Object.fromEntries(new FormData(f));
    msg.className = ""; msg.textContent = "";
    if (!body.name.trim() || !body.contact.trim()) { msg.className = "err"; msg.textContent = "Please give your name and a phone number or email."; return; }
    btn.disabled = true;
    try {
      if (window.SaakshiCloud) await window.SaakshiCloud.api("/api/orders", body);   // the online site
      else {
        const r = await fetch("/api/orders", { method: "POST", headers: { "Content-Type": "application/json", "X-Requested-With": "saakshi" }, body: JSON.stringify(body) });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || "Couldn't send. Try again.");
      }
      f.reset(); msg.className = "saved"; msg.textContent = "Request sent. We'll be in touch.";
    } catch (x) { msg.className = "err"; msg.textContent = x.message; }
    btn.disabled = false;
  });
})();
