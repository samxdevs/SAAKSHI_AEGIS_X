#!/usr/bin/env python3
"""
Build the online SAAKSHI site (Netlify) into saakshi_cloud/site_build/:

  /            landing page + "Request nodes" form      (saakshi_dashboard_web/index.html)
  /app         the dashboard, reading from Supabase     (saakshi_dashboard_web/app.* + web/cloud.js)
  /verify/     the buyer page and its encrypted bundles (buyer_verification_page/, after relay --publish)

The dashboard files are shared with the Mac dashboard; the build only adds the Supabase pieces.
Run:  python3 saakshi_cloud/build_site.py      then deploy with  saakshi_cloud/deploy.sh
"""
from pathlib import Path
import hashlib
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parent.parent
CLOUD = ROOT / "saakshi_cloud"
WEB = ROOT / "saakshi_dashboard_web"
OUT = CLOUD / "site_build"
VENDOR = CLOUD / "web" / "vendor" / "supabase-2.117.3.js"
VENDOR_SHA384 = "0567239bd39d16d87d4db842c593dd9be800394300cd0cbd9e64ecd768a85dd09c6d59c968f327f9f314a1008bb7ad11"
SUPABASE_URL = "https://ktmmnaviwneopwfkvnwh.supabase.co"
SUPABASE_KEY = "sb_publishable_VFfVoVN1tYy5X_YOU2uPaA_1XJHhMjJ"      # public by design; RLS decides access

HEADERS = f"""/*
  Referrer-Policy: no-referrer
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Strict-Transport-Security: max-age=63072000; includeSubDomains
  Cross-Origin-Opener-Policy: same-origin
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; connect-src 'self' {SUPABASE_URL} https://polygon-amoy-bor-rpc.publicnode.com https://polygon-amoy.drpc.org https://rpc-amoy.polygon.technology; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
/static/*
  Cache-Control: no-cache
/verify/data/*
  Cache-Control: no-cache
  Access-Control-Allow-Origin: *
"""


def inject(html, before, tags):
    if html.count(before) != 1:
        sys.exit(f"build: expected exactly one '{before}' in the page; the HTML changed, update build_site.py")
    return html.replace(before, "".join(t + "\n" for t in tags) + before)


def main():
    got = hashlib.sha384(VENDOR.read_bytes()).hexdigest()
    if got != VENDOR_SHA384:
        sys.exit(f"build: {VENDOR.name} doesn't match its pinned hash - re-download it, don't edit it")
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "static").mkdir(parents=True)

    for name in ("app.js", "app.css", "landing.css", "landing.js", "theme.js"):
        shutil.copy2(WEB / name, OUT / "static" / name)
    shutil.copy2(CLOUD / "web" / "cloud.js", OUT / "static" / "cloud.js")
    shutil.copy2(VENDOR, OUT / "static" / "supabase.js")
    (OUT / "static" / "config.js").write_text(
        "window.SAAKSHI_CLOUD = " + json.dumps({"url": SUPABASE_URL, "key": SUPABASE_KEY}) + ";\n")

    cfg = '<script src="/static/config.js"></script>'
    app = inject((WEB / "app.html").read_text(), '<script src="/static/app.js"></script>',
                 [cfg, '<script src="/static/supabase.js"></script>', '<script src="/static/cloud.js"></script>'])
    (OUT / "app.html").write_text(app)
    landing = inject((WEB / "index.html").read_text(), '<script src="/static/landing.js"></script>',
                     [cfg, '<script src="/static/cloud.js"></script>'])
    (OUT / "index.html").write_text(landing)

    verify = ROOT / "buyer_verification_page"
    shutil.copytree(verify, OUT / "verify", ignore=shutil.ignore_patterns("README.txt", ".DS_Store"))
    bundles = sorted(p.name for p in (OUT / "verify" / "data").glob("SAAKSHI-*.json"))

    (OUT / "_headers").write_text(HEADERS)
    (OUT / "_redirects").write_text("/app  /app.html  200\n/verify  /verify/  301\n")
    print(f"built {OUT.relative_to(ROOT)}: landing, dashboard, buyer page with {len(bundles)} published trip(s)")
    for b in bundles:
        print(f"  verify/data/{b}")
    if not bundles:
        print("  (no trips published yet: run  python3 saakshi_relay.py --publish  first)")


if __name__ == "__main__":
    main()
