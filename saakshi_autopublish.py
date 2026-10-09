#!/usr/bin/env python3
"""
SAAKSHI auto-publisher: keeps the buyer's QR page current without anyone running a command.

  python3 saakshi_autopublish.py            keep going (saakshi_start.sh runs it for you)
  python3 saakshi_autopublish.py --once     publish and deploy once, then stop

It re-publishes the encrypted trips (saakshi_relay.py --publish) and deploys the site
(saakshi_cloud/deploy.sh) within a minute of every new Polygon anchor. The buyer page holds only
records that are locked on Polygon, so that is the only time it changes, and every scan, any day,
reads "Genuine record". The QR key is never printed or logged here.
"""
from pathlib import Path
import argparse
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
LEDGER = HERE / "saakshi_ledger"
POSTED = HERE / "saakshi_relay" / "posted.json"
DATA = HERE / "saakshi_site" / "verify" / "data"


def say(msg):
    print(f"{time.strftime('%H:%M:%S')}  {msg}", flush=True)


def fingerprint():
    """What the buyer page depends on: the ledger files and the list of anchors."""
    ledger = tuple(sorted((p.name, p.stat().st_size) for p in LEDGER.glob("*.csv"))) if LEDGER.is_dir() else ()
    anchors = POSTED.stat().st_mtime if POSTED.exists() else 0
    return ledger, anchors


def run(cmd, timeout):
    """Run a step and keep its output to ourselves: the publish step prints the QR key."""
    try:
        p = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "took too long"
    if p.returncode != 0:
        lines = [l for l in (p.stdout + p.stderr).splitlines() if l.strip() and "#k=" not in l]
        return False, (lines[-1] if lines else f"exit code {p.returncode}")[:200]
    return True, p.stdout


def publish_and_deploy():
    ok, out = run([sys.executable, "saakshi_relay.py", "--publish"], 300)
    if not ok:
        return f"publish failed: {out}"
    trips = sum(1 for line in out.splitlines() if "encrypted and written" in line)
    ok, out = run(["bash", "saakshi_cloud/deploy.sh"], 600)
    if not ok:
        return f"deploy failed: {out}"
    return f"✓ buyer page updated: {trips} trip(s) published and live"


def main():
    ap = argparse.ArgumentParser(description="Keep the buyer's QR page current automatically.")
    ap.add_argument("--once", action="store_true", help="publish and deploy once, then stop")
    ap.add_argument("--poll", type=int, default=60, help="look for changes this often (s, default 60)")
    args = ap.parse_args()
    if not (HERE / ".netlify" / "state.json").exists():
        sys.exit("✗ this folder isn't linked to the Netlify site yet: run  npx netlify-cli login  and "
                 "npx netlify-cli sites:create --name saakshi-aegisx  once (see saakshi_cloud/deploy.sh)")

    last_fp, last_anchor, last_pub, failing = None, None, 0.0, False
    while True:
        fp = fingerprint()
        new_anchor = last_anchor is not None and fp[1] != last_anchor
        due = last_fp is None or new_anchor
        if due:
            why = "starting" if last_fp is None else "new Polygon anchor"
            result = publish_and_deploy()
            if result.startswith("✓"):
                say(f"{result} ({why})")
                last_fp, last_anchor, last_pub, failing = fp, fp[1], time.time(), False
            else:
                if not failing:
                    say(f"✗ {result} - will try again")
                failing = True
                last_anchor = fp[1] if last_anchor is None else last_anchor
        if args.once:
            return 0 if not failing else 1
        try:
            time.sleep(args.poll)
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
