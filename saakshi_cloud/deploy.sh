#!/bin/bash
# Build the online SAAKSHI site and publish it to its own Netlify site.
# Never deploys to amazing-starlight-cdd997 (the printed deck QR's site): that one is checked and refused.
#
# First time only (opens the browser to log in to Netlify, then makes the site):
#   npx netlify-cli login
#   npx netlify-cli sites:create --name saakshi-aegisx        # any free name; it links this folder
# Every time after:
#   bash saakshi_cloud/deploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."
python3 saakshi_cloud/build_site.py

if [ ! -f .netlify/state.json ]; then
  echo
  echo "Not linked to a Netlify site yet. Run once:"
  echo "  npx netlify-cli login"
  echo "  npx netlify-cli sites:create --name saakshi-aegisx"
  exit 1
fi
SITE_ID=$(python3 -c 'import json; print(json.load(open(".netlify/state.json"))["siteId"])')
NAME=$(npx -y netlify-cli api getSite --data "{\"site_id\":\"$SITE_ID\"}" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("name",""))')
if [ "$NAME" = "amazing-starlight-cdd997" ]; then
  echo "✗ This folder is linked to amazing-starlight-cdd997, the deck QR's site. Refusing to overwrite it."
  echo "  Unlink (rm .netlify/state.json) and create a separate site."
  exit 1
fi
echo "deploying to $NAME ..."
npx -y netlify-cli deploy --prod --dir saakshi_cloud/site_build --message "saakshi site $(date '+%d %b %H:%M')"
