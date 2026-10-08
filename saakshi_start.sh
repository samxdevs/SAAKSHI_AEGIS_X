#!/bin/bash
# SAAKSHI on this Mac, with one command: broker, ledger, relay (automatic Polygon anchoring) and website sync.
#
#   bash saakshi_start.sh          start all four; important lines show here; Ctrl+C stops all four
#
# Anchoring is automatic: every 30 minutes (or 180 new records), and straight away after a jolt,
# a sensor swap or the temperature leaving its band. Full logs: saakshi_logs/<part>.log
set -u
cd "$(dirname "$0")"

PY=python3
NEED="import paho.mqtt.client, web3, cryptography"
if ! $PY -c "$NEED" 2>/dev/null && [ -x /opt/anaconda3/bin/python3 ]; then PY=/opt/anaconda3/bin/python3; fi
if ! $PY -c "$NEED" 2>/dev/null; then
  echo "✗ this python3 is missing packages. Run:  python3 -m pip install paho-mqtt web3 cryptography qrcode"
  exit 1
fi

# Never two of anything: two ledgers would store every record twice, two brokers can't share port 8883.
for part in "mosquitto -c .*saakshi_broker/mosquitto.conf" "python[0-9.]* -u saakshi_ledger.py" \
            "python[0-9.]* -u saakshi_relay.py" "python[0-9.]* -u saakshi_cloud_sync.py" \
            "python[0-9.]* saakshi_ledger.py" "python[0-9.]* saakshi_relay.py" "python[0-9.]* saakshi_cloud_sync.py"; do
  if pgrep -f "$part" >/dev/null; then
    name=$(echo "$part" | sed -E 's/.* (-u )?//; s/\.\*//')
    echo "✗ already running: $name"
    echo "  Stop it first (Ctrl+C in its window, or:  pkill -f $name ), then run this again."
    exit 1
  fi
done

# The board checks the broker's certificate against this Mac's address: renew it if the address moved.
IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)
CERT_IP=$($PY -c "
from cryptography import x509; from cryptography.x509.oid import NameOID
c = x509.load_pem_x509_certificate(open('saakshi_broker/server.crt','rb').read())
print(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)" 2>/dev/null)
if [ -n "$IP" ] && [ "$IP" != "$CERT_IP" ]; then
  echo "This Mac's address changed ($CERT_IP -> $IP): renewing the broker certificate (no re-flash needed)."
  $PY saakshi_broker.py renew --ip "$IP" 2>&1 | grep -E "✓|✗"
  echo "⚠ On the board (Serial Monitor), type once:   broker $IP"
fi

mkdir -p saakshi_logs
PIDS=()
start() {               # start <name> <command...>: runs in the background, log lines tagged with the name
  local name=$1; shift
  "$@" > >(sed -u "s/^/[$name] /" >> "saakshi_logs/$name.log") 2>&1 &
  PIDS+=($!)
}
stop() {
  echo; echo "stopping SAAKSHI ..."
  kill ${PIDS[@]+"${PIDS[@]}"} 2>/dev/null; wait 2>/dev/null
  echo "stopped. The board keeps logging and signing; its records come in when you start again."
  exit 0
}
trap stop INT TERM HUP                 # Ctrl+C, a kill, or closing the Terminal window
trap 'kill ${PIDS[@]+"${PIDS[@]}"} 2>/dev/null' EXIT   # and never leave the four running alone

echo "SAAKSHI starting on ${IP:-this Mac} ..."
start broker $PY -u saakshi_broker.py run
sleep 2
start ledger $PY -u saakshi_ledger.py --tls
start relay  $PY -u saakshi_relay.py --min-records 180 --max-wait 1800 --poll 30 --event-gap 900
start sync   $PY -u saakshi_cloud_sync.py
echo "  broker   encrypted MQTT on port 8883"
echo "  ledger   checks every record and chip signature"
echo "  relay    anchors on Polygon automatically (every 30 min; at once on a jolt / alarm, at most every 15 min)"
echo "  sync     keeps https://saakshi-aegisx.netlify.app/app live"
echo "Ctrl+C stops all four. Full logs: saakshi_logs/"
echo

# Show what matters from all four as it happens (passwords never appear in these lines).
tail -n 0 -F saakshi_logs/ledger.log saakshi_logs/relay.log saakshi_logs/sync.log saakshi_logs/broker.log 2>/dev/null |
  grep --line-buffered -E "\[(ledger|relay|sync)\] .*(✓|✗|⚠|…|REFUSED|connected|offline|posting|balance|low on)|Error|error:" |
  grep --line-buffered -viE "mqttpass|password" &
PIDS+=($!)
wait
