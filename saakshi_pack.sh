#!/bin/bash
# saakshi_pack.sh - run on the Mac, in ~/Downloads. Packs everything the cloud server needs into
# saakshi_cloud_bundle.tar.gz: the scripts, the ledger, the relay's state (anchors, QR keys), the broker's
# certificate authority + logins (so the board's broker_ca.h and password keep working), the buyer site
# and the dashboard.
#
#     cd ~/Downloads && bash saakshi_pack.sh
#
# The bundle contains secrets (wallet key, CA key, passwords, QR keys): send it only to your own server
# with scp, never by chat, email or GitHub.
set -euo pipefail
cd "$(dirname "$0")"

want=(saakshi_ledger.py saakshi_pull.py saakshi_relay.py saakshi_broker.py saakshi_dashboard.py
      saakshi_dashboard_web SaakshiRegistry.sol saakshi_ledger saakshi_relay saakshi_broker saakshi_site
      saakshi_dashboard_data relay_key.txt)
need=(saakshi_ledger.py saakshi_pull.py saakshi_relay.py saakshi_broker.py saakshi_dashboard.py
      saakshi_dashboard_web saakshi_ledger saakshi_broker)

for f in "${need[@]}"; do
  if [ ! -e "$f" ]; then
    echo "✗ $f is missing here ($(pwd)). Put it in this folder first." >&2
    exit 1
  fi
done
if [ ! -f saakshi_site/verify/index.html ]; then
  echo "✗ saakshi_site/verify/index.html is missing - unzip saakshi_site.zip here first." >&2
  exit 1
fi

files=()
for f in "${want[@]}"; do [ -e "$f" ] && files+=("$f"); done
for f in saakshi_pubkey*.txt; do [ -e "$f" ] && files+=("$f"); done

COPYFILE_DISABLE=1 tar --exclude='.DS_Store' --exclude='__pycache__' -czf saakshi_cloud_bundle.tar.gz "${files[@]}"
chmod 600 saakshi_cloud_bundle.tar.gz
echo "✓ saakshi_cloud_bundle.tar.gz ($(du -h saakshi_cloud_bundle.tar.gz | cut -f1)) with:"
printf '    %s\n' "${files[@]}"
[ -e relay_key.txt ] || echo "  (no relay_key.txt: the server will not anchor on Polygon until you add one)"
