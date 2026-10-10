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

## Find your way around

| | Folder / file | What it is |
|---|---|---|
| 🔩 **Device** | [`saakshi_firmware/`](saakshi_firmware) | ESP32-S3 firmware: sensors, ATECC608B signing, hash chain, flash storage, encrypted MQTT sync, ethylene (ready) |
| | [`hardware_tests/`](hardware_tests) | Read-only test sketches for the security chip, I2C bus and motion sensor |
| ⛓️ **Blockchain** | [`smart_contract/SaakshiRegistry.sol`](smart_contract/SaakshiRegistry.sol) | Deployed contract: registers nodes, **verifies chip signatures on-chain**, stores anchors |
| | [`saakshi_relay.py`](saakshi_relay.py) | Anchors the newest signed record on Polygon automatically; publishes encrypted trips for buyers |
| 🔐 **Verification** | [`saakshi_ledger.py`](saakshi_ledger.py) | Receives records over MQTT and keeps only those whose hash, chain link and chip signature check out |
| | [`saakshi_pull.py`](saakshi_pull.py) | Record format and signature checks shared by the tools |
| 📡 **Network** | [`saakshi_broker.py`](saakshi_broker.py) | Sets up the encrypted MQTT broker: own certificate authority, one login per node, access rules |
| 📊 **Dashboard** | [`saakshi_cloud/`](saakshi_cloud), [`saakshi_cloud_sync.py`](saakshi_cloud_sync.py) | Online dashboard: Supabase (row-level security) + Netlify; the sync pushes only verified data |
| | [`saakshi_dashboard_web/`](saakshi_dashboard_web), [`saakshi_dashboard.py`](saakshi_dashboard.py) | Dashboard pages and logic (the online site is built from these; also runs locally) |
| 📱 **Buyer** | [`buyer_verification_page/`](buyer_verification_page) | QR page: decrypts the trip and re-checks every record and the Polygon anchor in the phone's browser |
| ▶️ **Run** | [`saakshi_start.sh`](saakshi_start.sh), [`saakshi_autopublish.py`](saakshi_autopublish.py) | One command starts broker, ledger, relay, dashboard sync and buyer-page publisher |
| 🧪 **Dev** | [`dev_tools/make_demo_ledger.py`](dev_tools/make_demo_ledger.py) | Builds a **simulated** test ledger for development without hardware |

## Honest status

| | |
|---|---|
| ✅ Working | Signing and chaining on the node · encrypted sync · verified ledger · automatic on-chain anchoring with on-chain signature checks · live dashboard · buyer QR verification · temperature, humidity, pressure, VOC gas, shock and movement |
| 🔜 Being integrated | Ethylene (Winsen ME3-C2H4, firmware ready, sensor being fitted and calibrated) · lid-open switch · 4G modem with WiFi fallback · GPS · solar charging |

Polygon **Amoy is a testnet**; a production deployment would use Polygon mainnet.

Released under the [MIT License](LICENSE).
