#!/bin/bash
# saakshi_cloud_setup.sh - turns a fresh Ubuntu 22.04/24.04 server into the SAAKSHI back end:
#
#   broker     Mosquitto, MQTT over TLS on port 8883 (nodes connect here from any WiFi, hotspot or 4G)
#   ledger     saakshi_ledger.py: checks every record's signature, keeps the chain files
#   relay      saakshi_relay.py: anchors the newest signed head on Polygon (at most about once an hour)
#   publish    every 10 min: encrypts the records for the buyer page (/verify/)
#   dashboard  saakshi_dashboard.py, behind Caddy with a free HTTPS certificate
#
# Works on Google Cloud, Azure, AWS, DigitalOcean - any Ubuntu 22.04/24.04 server.
# Run it as the normal login user (it uses sudo where needed), next to saakshi_cloud_bundle.tar.gz:
#     bash saakshi_cloud_setup.sh
# Safe to run again (e.g. after uploading a newer bundle): it keeps the server's ledger and accounts.
set -euo pipefail

HOME_DIR="$HOME"
APP="$HOME_DIR/saakshi"
BUNDLE="$HOME_DIR/saakshi_cloud_bundle.tar.gz"
ME="$(id -un)"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\n✗ %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "Run this as your normal user (e.g. azureuser), not root. It uses sudo itself."
[ -f "$BUNDLE" ] || die "$BUNDLE not found. Upload it first:  scp saakshi_cloud_bundle.tar.gz <user>@<server-ip>:~"
command -v apt-get >/dev/null || die "This script is for Ubuntu."

say "1/8 Public IP and web address"
PUBLIC_IP="${PUBLIC_IP:-$(curl -fsS --max-time 10 https://api.ipify.org || true)}"
[[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Couldn't find this server's public IP. Run again with:  PUBLIC_IP=1.2.3.4 bash saakshi_cloud_setup.sh"
DOMAIN="${DOMAIN:-${PUBLIC_IP//./-}.sslip.io}"     # sslip.io: a free name that always points to this IP
echo "   public IP  $PUBLIC_IP"
echo "   web        https://$DOMAIN"

say "2/8 Packages (Mosquitto, Caddy, Python)"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mosquitto mosquitto-clients caddy python3-venv python3-pip curl ufw >/dev/null
# our own broker unit runs Mosquitto with the SAAKSHI config; the package's default one must not take the port
sudo systemctl disable --now mosquitto >/dev/null 2>&1 || true

# small servers (1 GB, e.g. Google e2-micro / Azure B1s): add 1 GB of swap so pip installs can't run out of memory
if [ "$(awk '/MemTotal/ {print $2}' /proc/meminfo)" -lt 1600000 ] && [ "$(swapon --show --noheadings | wc -l)" -eq 0 ]; then
  sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile >/dev/null && sudo swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
  echo "   added 1 GB swap (small server)"
fi

say "3/8 Files"
mkdir -p "$APP"
KEEP=()
# on a re-run, the server's own data wins over the bundle's older copy
for d in saakshi_ledger saakshi_dashboard_data; do
  if [ -d "$APP/$d" ] && [ -n "$(ls -A "$APP/$d" 2>/dev/null)" ]; then KEEP+=("--exclude=$d"); fi
done
tar "${KEEP[@]}" -xzf "$BUNDLE" -C "$APP"
chmod 700 "$APP"
[ -f "$APP/relay_key.txt" ] && chmod 600 "$APP/relay_key.txt"
[ ${#KEEP[@]} -gt 0 ] && echo "   kept the server's existing: ${KEEP[*]//--exclude=/}"

say "4/8 Python environment"
python3 -m venv "$APP/.venv"
"$APP/.venv/bin/pip" install -q --upgrade pip
"$APP/.venv/bin/pip" install -q paho-mqtt web3 cryptography qrcode
PY="$APP/.venv/bin/python"

say "5/8 Encrypted broker for $PUBLIC_IP"
cd "$APP"
if [ -f saakshi_broker/ca.key ]; then
  "$PY" saakshi_broker.py renew --ip "$PUBLIC_IP"      # same CA as before: the board's broker_ca.h stays valid
else
  "$PY" saakshi_broker.py setup --ip "$PUBLIC_IP"
  echo "   NEW certificate authority: copy saakshi_broker/broker_ca.h into the sketch folder and re-upload v7.1"
fi

say "6/8 Services"
unit() {   # name, description, command, extra [Unit] lines
  sudo tee "/etc/systemd/system/$1.service" >/dev/null <<EOF
[Unit]
Description=$2
After=network-online.target $4
Wants=network-online.target
[Service]
User=$ME
WorkingDirectory=$APP
Environment=PYTHONUNBUFFERED=1
ExecStart=$3
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
}
unit saakshi-broker    "SAAKSHI MQTT broker (TLS 8883)"   "$PY $APP/saakshi_broker.py run" ""
unit saakshi-ledger    "SAAKSHI ledger"                   "$PY $APP/saakshi_ledger.py --tls" "saakshi-broker.service"
unit saakshi-dashboard "SAAKSHI dashboard"                "$PY $APP/saakshi_dashboard.py --port 8080 --behind-proxy" ""
SERVICES=(saakshi-broker saakshi-ledger saakshi-dashboard)
if [ -f "$APP/relay_key.txt" ] && [ -f "$APP/saakshi_relay/config.json" ]; then
  unit saakshi-relay "SAAKSHI relay (Polygon anchor)" "$PY $APP/saakshi_relay.py --min-records 500 --max-wait 3600 --poll 60" "saakshi-ledger.service"
  SERVICES+=(saakshi-relay)
else
  echo "   relay not started: relay_key.txt or saakshi_relay/config.json missing"
fi
sudo tee /etc/systemd/system/saakshi-publish.service >/dev/null <<EOF
[Unit]
Description=SAAKSHI publish records for the buyer page
[Service]
Type=oneshot
User=$ME
WorkingDirectory=$APP
ExecStart=$PY $APP/saakshi_relay.py --publish --site-url https://$DOMAIN
EOF
sudo tee /etc/systemd/system/saakshi-publish.timer >/dev/null <<EOF
[Unit]
Description=SAAKSHI publish every 10 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload
for s in "${SERVICES[@]}"; do sudo systemctl enable "$s" >/dev/null 2>&1; sudo systemctl restart "$s"; done
sudo systemctl enable --now saakshi-publish.timer >/dev/null 2>&1

say "7/8 HTTPS (Caddy) and firewall"
sudo tee /etc/caddy/Caddyfile >/dev/null <<EOF
$DOMAIN {
	encode gzip
	reverse_proxy 127.0.0.1:8080
}
EOF
sudo systemctl enable caddy >/dev/null 2>&1
sudo systemctl restart caddy
sudo ufw allow OpenSSH >/dev/null
sudo ufw allow 80/tcp >/dev/null
sudo ufw allow 443/tcp >/dev/null
sudo ufw allow 8883/tcp >/dev/null
sudo ufw --force enable >/dev/null

say "8/8 Check"
sleep 6
"$PY" "$APP/saakshi_relay.py" --publish --site-url "https://$DOMAIN" >/dev/null 2>&1 || echo "   (first publish didn't run yet - the timer retries every 10 min)"
ok=1
for s in "${SERVICES[@]}" caddy; do
  if systemctl is-active --quiet "$s"; then echo "   ✓ $s"; else echo "   ✗ $s  ->  journalctl -u $s -n 40"; ok=0; fi
done
CODE="$(sudo journalctl -u saakshi-dashboard --no-pager -n 50 | grep -o 'setup code: [0-9a-f]*' | tail -1 | cut -d' ' -f3 || true)"

cat <<EOF

────────────────────────────────────────────────────────────────────
 Dashboard     https://$DOMAIN
               (the HTTPS certificate can take a minute on the first visit)
 Buyer page    https://$DOMAIN/verify/?n=<NODE>   (the QR link is in the dashboard)
EOF
if [ -n "$CODE" ]; then
  echo " Admin setup   open the dashboard, Log in -> it asks for the setup code: $CODE"
fi
cat <<EOF

 On the board (Serial Monitor, 115200, New Line):
     broker $PUBLIC_IP
 (and the same  mqttpass ...  as before - see:  $PY saakshi_broker.py show)
 The board can now be on ANY WiFi or hotspot with internet.

 In the cloud provider's firewall / network settings, open inbound TCP 80, 443 and 8883.
 Logs:  journalctl -u saakshi-ledger -f     (or saakshi-broker / saakshi-relay / saakshi-dashboard)
────────────────────────────────────────────────────────────────────
EOF
[ "$ok" -eq 1 ] || exit 1
