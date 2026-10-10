# SAAKSHI — a tamper-evident cold-chain black box

**Team AEGIS_X · Smart India Hackathon 2026 · PS 26232 (MoFPI, Hardware): Low-Cost IoT Blockchain Nodes for Farm-to-Fork Traceability**

A sealed box rides with the produce. It measures the conditions every 10 seconds, signs every reading inside a
security chip, and locks the history on the Polygon blockchain, so a buyer can check the whole journey on their
own phone, without trusting us.

| | |
|---|---|
| **Live dashboard (view-only, no login)** | https://saakshi-aegisx.netlify.app/app |
| **Buyer check** | scan the node's QR on the dashboard: the phone re-verifies every reading and reads the anchor from Polygon |
| **Smart contract** | [`0xA82128628b7Ae42183d9B76020CD37C007c18c46`](https://amoy.polygonscan.com/address/0xA82128628b7Ae42183d9B76020CD37C007c18c46) on Polygon Amoy testnet |

## How the data stays trustworthy

```
SENSORS ─► SECURITY CHIP ─► ENCRYPTED LINK ─► LEDGER ─► POLYGON ─► BUYER'S PHONE
           signs at source   MQTT over TLS     re-checks   anchors     re-checks everything
```

1. **Signed at the source.** Each reading is hashed (SHA-256) and signed (ECDSA P-256) inside an **ATECC608B**
   chip. The private key never leaves the chip.
2. **Chained.** Every record contains the previous record's hash: editing, deleting or reordering anything breaks the chain.
3. **Encrypted in transit.** MQTT over TLS, our own certificate authority, one login per node, and access rules that
   let each node publish only its own data. Records are kept on flash through network dead zones and sent later.
4. **Verified before storage.** The ledger re-checks every hash, link and chip signature and refuses anything altered.
5. **Anchored on Polygon, automatically.** Every 30 minutes, and straight away after a jolt or a temperature alarm.
   **The smart contract verifies the chip's signature on-chain** (P-256 precompile) and refuses anything else.
   One anchor locks every earlier record.
6. **Checked by the buyer.** The QR opens a page that decrypts the trip (AES-256-GCM; the key is only in the QR)
   and re-checks every record and the Polygon anchor in the phone's browser.

**Attacks we tested — all caught:** editing a reading; editing it and recomputing the hash (the chip signature fails);
forging an "all fine" record with a real signature (refused on-chain, `BadSignature`); deleting a record; flipping one
bit of a signature (rejected on-chain).

**Proof on-chain:** 2,127 records of our first trip locked at block 49371015; today's trips are anchored automatically
(for example block 49658554), all verifiable on PolygonScan.

## What's in this repository

| Path | What it is |
|---|---|
| `saakshi_node_v8/` | ESP32-S3 firmware: sensors, ATECC608B signing, hash chain, flash storage, encrypted MQTT sync |
| `SaakshiRegistry.sol` | Smart contract (deployed): registers nodes, verifies chip signatures on-chain, stores anchors |
| `saakshi_ledger.py` | Receives records over MQTT and keeps only verified ones |
| `saakshi_relay.py` | Anchors the newest signed record on Polygon; publishes encrypted trips for the buyer page |
| `saakshi_broker.py` | Sets up the encrypted Mosquitto broker (own CA, per-node logins, access rules) |
| `saakshi_start.sh` | Starts broker, ledger, relay, website sync and buyer-page publisher with one command |
| `saakshi_cloud_sync.py`, `saakshi_cloud/` | The online dashboard: Supabase (row-level security) + Netlify |
| `saakshi_dashboard.py`, `saakshi_dashboard_web/` | The same dashboard, run locally on the Mac |
| `saakshi_site/verify/` | The buyer verification page (runs entirely in the browser, WebCrypto) |
| `sketches/` | Read-only hardware check sketches (I2C, ATECC608, MPU-6050) |
| `tools/make_demo_ledger.py` | Builds a **simulated** test ledger for development without hardware |

## Honest status

| | |
|---|---|
| ✅ Working | Signing and chaining on the node · encrypted sync · verified ledger · automatic on-chain anchoring with on-chain signature checks · live dashboard · buyer QR verification · temperature, humidity, pressure, VOC gas, shock and movement |
| 🔜 Being integrated | Ethylene (Winsen ME3-C2H4, firmware ready, sensor being fitted and calibrated) · lid-open switch · 4G modem with WiFi fallback · GPS · solar charging |

Polygon **Amoy is a testnet**; a production deployment would use Polygon mainnet.
