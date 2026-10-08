#!/usr/bin/env python3
"""
saakshi_broker.py - sets up an encrypted MQTT broker (Mosquitto + TLS) on this Mac for SAAKSHI.

    python3 saakshi_broker.py setup      once: certificates, logins, access rules, broker_ca.h
    python3 saakshi_broker.py run        start the broker (leave it running)
    python3 saakshi_broker.py renew      the hotspot gave this Mac a new IP: new broker certificate
    python3 saakshi_broker.py add-node SAAKSHI-XXXXXXXX      a login for another node
    python3 saakshi_broker.py show       what to type on each board

What it makes, in saakshi_broker/ next to this script:
    ca.crt / ca.key          your own certificate authority. The board only accepts a broker whose
                             certificate this authority signed - so nobody can pose as your broker.
                             ca.key is the one file that must never leave this Mac.
    server.crt / server.key  the broker's certificate, for this Mac's current IP
    passwd, acl              logins (one per node + one for the ledger) and who may use which topic:
                             a node can only publish its own records, never another node's
    mosquitto.conf           encrypted only (port 8883), no anonymous access
    credentials.json         the passwords (keep private)
and broker_ca.h for the sketch folder (the CA certificate - public, not a secret).

Needs:  brew install mosquitto     and     python3 -m pip install cryptography
"""

import argparse
import datetime as dt
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError:
    sys.exit("cryptography is not installed. Run:  python3 -m pip install cryptography")

HERE = Path(__file__).resolve().parent
DIR = HERE / "saakshi_broker"
SKETCH_DIR = HERE / "saakshi_node_v8"
PORT = 8883
# Valid from 1970 on purpose: a board whose clock is not set yet must still accept the certificate.
NOT_BEFORE = dt.datetime(1970, 1, 2, tzinfo=dt.timezone.utc)


def say(msg=""):
    print(msg, flush=True)


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))            # no packet is sent; just picks the outgoing interface
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def private(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def write_key(path, key):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    private(path)


def load_key(path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    host = socket.gethostname().split(".")[0][:40] or "mac"
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"SAAKSHI broker CA ({host})")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOT_BEFORE).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    write_key(DIR / "ca.key", key)
    (DIR / "ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert, key


def make_server(ip, ca_cert, ca_key):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    # The board connects by IP. The IP is listed both as an IP entry and as a name entry, so every
    # TLS library matches it (the ESP32's mbedTLS, Python, Mosquitto clients); localhost is for the ledger.
    alt = [x509.DNSName(ip), x509.IPAddress(ipaddress.ip_address(ip)),
           x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOT_BEFORE).not_valid_after(now + dt.timedelta(days=1825))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    write_key(DIR / "server.key", key)
    (DIR / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def write_ca_header(ca_pem):
    lines = [l for l in ca_pem.decode().strip().splitlines()]
    body = "\n".join(f'"{l}\\n"' for l in lines)
    text = (f"// broker_ca.h - made by saakshi_broker.py on {dt.date.today()} for {socket.gethostname()}.\n"
            "// The certificate authority the broker's certificate must be signed by. Public: not a secret.\n"
            "#pragma once\n"
            f"static const char SAAKSHI_BROKER_CA[] =\n{body};\n"
            "#define BROKER_CA_PEM SAAKSHI_BROKER_CA\n")
    out = DIR / "broker_ca.h"
    out.write_text(text)
    copies = [out]
    if SKETCH_DIR.is_dir():
        (SKETCH_DIR / "broker_ca.h").write_text(text)
        copies.append(SKETCH_DIR / "broker_ca.h")
    return copies


def node_from_pubkey():
    p = HERE / "saakshi_pubkey.txt"
    if not p.exists():
        return None
    import hashlib
    import re
    m = re.search(r"04[0-9a-fA-F]{128}", p.read_text())
    return "SAAKSHI-" + hashlib.sha256(bytes.fromhex(m.group(0))).hexdigest()[:8].upper() if m else None


def find_tool(name):
    t = shutil.which(name)
    if t:
        return t
    for d in ("/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/sbin"):
        if Path(d, name).exists():
            return str(Path(d, name))
    return None


def load_creds():
    try:
        return json.loads((DIR / "credentials.json").read_text())
    except FileNotFoundError:
        return {"ledger": None, "nodes": {}}


def save_creds(c):
    (DIR / "credentials.json").write_text(json.dumps(c, indent=1) + "\n")
    private(DIR / "credentials.json")


def write_passwd(creds):
    tool = find_tool("mosquitto_passwd")
    if not tool:
        sys.exit("mosquitto_passwd not found. Install Mosquitto first:  brew install mosquitto")
    pf = DIR / "passwd"
    if pf.exists():
        pf.unlink()
    pf.touch()
    private(pf)
    users = [("ledger", creds["ledger"])] + sorted(creds["nodes"].items())
    for user, pw in users:
        r = subprocess.run([tool, "-b", str(pf), user, pw], capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"mosquitto_passwd failed for {user}: {r.stderr.strip() or r.stdout.strip()}")
    private(pf)


def write_acl_and_conf():
    acl = DIR / "acl"
    acl.write_text(
        "# The ledger reads every node's records and answers each node.\n"
        "user ledger\n"
        "topic readwrite saakshi/#\n\n"
        "# Every node may only use its own topics (%u = its login name = its node ID).\n"
        "pattern write saakshi/%u/status\n"
        "pattern write saakshi/%u/rec/#\n"
        "pattern read saakshi/%u/ack\n"
        "pattern read saakshi/%u/cmd\n")
    private(acl)
    conf = DIR / "mosquitto.conf"
    conf.write_text(
        "# SAAKSHI broker - encrypted only. Made by saakshi_broker.py.\n"
        f"listener {PORT}\n"
        f"cafile {DIR / 'ca.crt'}\n"
        f"certfile {DIR / 'server.crt'}\n"
        f"keyfile {DIR / 'server.key'}\n"
        "tls_version tlsv1.2\n"
        "allow_anonymous false\n"
        f"password_file {DIR / 'passwd'}\n"
        f"acl_file {acl}\n")


def board_steps(creds, ip, nodes=None):
    say("On each board (Serial Monitor, 115200, New Line), type once:")
    for node, pw in sorted(creds["nodes"].items()):
        if nodes and node not in nodes:
            continue
        say(f"  {node}:   broker {ip}      then      mqttpass {pw}")


def cmd_setup(args):
    DIR.mkdir(exist_ok=True)
    ip = args.ip or lan_ip()
    if not ip:
        sys.exit("Couldn't find this Mac's IP. Join the hotspot first, or give it:  --ip 192.168.x.x")
    if (DIR / "ca.crt").exists() and (DIR / "ca.key").exists():
        ca_cert = x509.load_pem_x509_certificate((DIR / "ca.crt").read_bytes())
        ca_key = load_key(DIR / "ca.key")
        say("✓ keeping your existing certificate authority (boards already flashed with it stay valid)")
    else:
        ca_cert, ca_key = make_ca()
        say("✓ made your certificate authority: saakshi_broker/ca.crt (ca.key stays on this Mac)")
    make_server(ip, ca_cert, ca_key)
    say(f"✓ broker certificate for this Mac's IP {ip}")
    creds = load_creds()
    creds["ledger"] = creds.get("ledger") or secrets.token_hex(12)
    node = args.node or node_from_pubkey()
    if node and node not in creds["nodes"]:
        creds["nodes"][node] = secrets.token_hex(12)
    save_creds(creds)
    write_passwd(creds)
    write_acl_and_conf()
    say(f"✓ logins: ledger + {', '.join(sorted(creds['nodes'])) or '(no node yet - add-node SAAKSHI-...)'}")
    copies = write_ca_header(ca_cert.public_bytes(serialization.Encoding.PEM))
    say(f"✓ broker_ca.h written to {copies[-1]}")
    if len(copies) == 1:
        say("  copy it into the sketch folder saakshi_node_v8/ (next to saakshi_node_v8.ino)")
    say("")
    say("Next:")
    say("  1. Upload saakshi_node_v8 to the board (with secrets.h and broker_ca.h in its folder)")
    say("  2. Start the broker:     python3 saakshi_broker.py run")
    say("  3. Start the ledger:     python3 saakshi_ledger.py --tls")
    board_steps(creds, ip)


def cmd_renew(args):
    if not (DIR / "ca.key").exists():
        sys.exit("No setup yet - run:  python3 saakshi_broker.py setup")
    ip = args.ip or lan_ip()
    if not ip:
        sys.exit("Couldn't find this Mac's IP. Join the hotspot first, or give it:  --ip 192.168.x.x")
    make_server(ip, x509.load_pem_x509_certificate((DIR / "ca.crt").read_bytes()), load_key(DIR / "ca.key"))
    write_acl_and_conf()                       # paths in mosquitto.conf follow this machine (e.g. after moving to a server)
    say(f"✓ new broker certificate for {ip} (no need to re-flash the boards)")
    say("  Restart the broker (Ctrl+C in its window, then  python3 saakshi_broker.py run)")
    board_steps(load_creds(), ip)


def cmd_add_node(args):
    if not args.node or not args.node.startswith("SAAKSHI-") or len(args.node) != 16:
        sys.exit("Give the node ID, e.g.:  python3 saakshi_broker.py add-node SAAKSHI-25D8016E")
    creds = load_creds()
    if not creds.get("ledger"):
        sys.exit("No setup yet - run:  python3 saakshi_broker.py setup")
    creds["nodes"].setdefault(args.node, secrets.token_hex(12))
    save_creds(creds)
    write_passwd(creds)
    say(f"✓ login for {args.node}. Restart the broker so it reads the new login.")
    board_steps(creds, args.ip or lan_ip() or "<this Mac's IP>", [args.node])


def cmd_show(args):
    creds = load_creds()
    if not creds.get("ledger"):
        sys.exit("No setup yet - run:  python3 saakshi_broker.py setup")
    cert = x509.load_pem_x509_certificate((DIR / "server.crt").read_bytes())
    cert_ip = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    ip = lan_ip()
    say(f"broker certificate is for {cert_ip}; this Mac's IP now: {ip or 'unknown'}")
    if ip and ip != cert_ip:
        say("  they differ - run:  python3 saakshi_broker.py renew")
    board_steps(creds, cert_ip)


def cmd_run(args):
    conf = DIR / "mosquitto.conf"
    if not conf.exists():
        sys.exit("No setup yet - run:  python3 saakshi_broker.py setup")
    tool = find_tool("mosquitto")
    if not tool:
        sys.exit("mosquitto not found. Install it:  brew install mosquitto  (Ubuntu: sudo apt install mosquitto)")
    cert = x509.load_pem_x509_certificate((DIR / "server.crt").read_bytes())
    cert_ip = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    ip = lan_ip()
    on_lan = ipaddress.ip_address(cert_ip).is_private      # a public IP = a cloud server, where this check doesn't apply
    if on_lan and ip and ip != cert_ip:
        say(f"⚠ the broker certificate is for {cert_ip}, but this Mac is now {ip}: the board will refuse it.")
        say("  Run  python3 saakshi_broker.py renew  first, then type  broker " + ip + "  on the board.")
    say(f"SAAKSHI broker on port {PORT}, encrypted, logins required. Ctrl+C stops it.\n")
    os.execv(tool, [tool, "-c", str(conf), "-v"])


def main():
    ap = argparse.ArgumentParser(description="Encrypted MQTT broker for SAAKSHI on this Mac.")
    ap.add_argument("command", choices=["setup", "run", "renew", "add-node", "show"])
    ap.add_argument("node", nargs="?", help="add-node: the node ID (setup: default from saakshi_pubkey.txt)")
    ap.add_argument("--ip", help="this Mac's IP, if it can't be found automatically")
    args = ap.parse_args()
    {"setup": cmd_setup, "run": cmd_run, "renew": cmd_renew, "add-node": cmd_add_node, "show": cmd_show}[args.command](args)


if __name__ == "__main__":
    main()
