/*
 * SAAKSHI firmware (node v8): v7.1 + ethylene (Winsen ME3-C2H4 through MCP6002 + ADS1115 at 0x48)
 *
 * New in v8 (the signed record keeps its 174-byte shape, so the ledger, relay, contract and every
 * anchored record stay valid):
 *   - every record carries flag ETHYLENE (0x1000): its uptime_s field now holds ethylene in ppb
 *     (parts per billion, 1 ppm = 1000). Older records lack the flag, so their field still reads as uptime.
 *   - ETH_NONE (0x2000): no ethylene sensor answering - the value is 0 and means "not connected".
 *     The ADS1115 is looked for on every record, so fitting the sensor later needs no code change.
 *   - ETH_WARMUP (0x4000): the sensor has been powered for less than 48 h in total (the datasheet's
 *     preheat) - the reading is logged but not settled yet.
 *   - commands: eth (show voltages and ppm), ethzero (clean air = 0 ppm), ethspan <ppm> (known gas),
 *     ethready (sensor was already warmed up elsewhere)
 *   Wiring: amplifier output -> ADS1115 A0; ADS1115 VDD 3V3, GND, SDA GPIO 8, SCL GPIO 9, ADDR -> GND (0x48).
 *   Default conversion: 0.500 V = 0 ppm, 4 mV per ppm (the amplifier design); ethzero/ethspan refine it.
 *   ME3-C2H4: 0-100 ppm, 0.5 ppm resolution, hydrogen also registers - an alarm for build-up, not trace levels.
 *
 * v7.1 (still true): v7 + encrypted sync (MQTT over TLS) + chip retry + settings out of the code
 *
 * New in v7.1 (record format unchanged - saakshi_pull.py, the ledger and the relay work as before):
 *   - MQTT over TLS (port 8883): every record is encrypted on the way, and the board only talks to
 *     the broker whose certificate was signed by YOUR certificate authority (broker_ca.h)
 *   - per-node login: user = node ID, password set once with  mqttpass <password>  (kept on the board)
 *   - WiFi name/password live in secrets.h, not in this file - safe to put the sketch on GitHub
 *   - the ATECC608 is retried every 20 s if it was missed at boot, so one bad start no longer means
 *     UNSIGNED records until the next reset
 *   - the board takes internet time (NTP) when it can, so records stop showing NO_TIME
 *   - all pins in one place: pick the board in the BOARD block below
 *
 * New in v7 (everything else as v6):
 *   - records go out in batches (about 5 per message), so a busy broker sees far fewer messages
 *   - the board only sends when the connection has room, so a slow link never freezes it
 *   - if a send fails half-way, the board reconnects cleanly instead of carrying on garbled
 *   - when the ledger's replies are late, it sends less, not more
 *   - clearer WiFi messages while joining, at most one every 30 s
 *
 * Everything v4/v5 did (signed, hash-chained records with time, three thermometers, movement and a
 * sensor fingerprint), plus sync: over WiFi and MQTT, every record goes to saakshi_ledger.py, which
 * checks its signature and keeps its own copy. When the network drops, records keep chaining on flash;
 * when it comes back, the board sends exactly the ones the ledger doesn't have yet. If the clock was
 * never set, the ledger sets it.
 *
 * Carries on with the same chain file (/chain4.bin) - nothing on the board is lost by this upload.
 *
 * BEFORE UPLOADING
 *   1. In the sketch folder, next to this file, put:
 *        secrets.h    - copy secrets_example.h to secrets.h and type your hotspot name and password
 *        broker_ca.h  - made by  python3 saakshi_broker.py setup  on the Mac (without it: no TLS)
 *      The board only does 2.4 GHz WiFi: on an iPhone hotspot, turn ON "Maximize Compatibility".
 *   2. Library: PubSubClient by Nick O'Leary (Sketch > Include Library > Manage Libraries).
 *   3. Tools: Partition Scheme = 16M Flash (3MB APP/9.9MB FATFS), PSRAM = OPI PSRAM,
 *      Erase All Flash Before Sketch Upload = Disabled   <-- or the upload wipes the chain
 * Wiring: exactly as for the bus check. Other libraries: Adafruit BME680, ArduinoECCX08.
 *
 * Serial console @ 115200, line ending = New Line
 *   h           help
 *   s           status: records, identity, clock, sensors, network
 *   w           network and sync status
 *   offline     drop WiFi, like losing signal (records keep chaining);  online  reconnects
 *   broker      show the MQTT broker;  broker <address>[:port] changes it (saved)
 *   mqttpass    mqttpass <password> sets this node's broker password (saved);  mqttpass clear
 *   tls         show encryption;  tls on / tls off (saved; off = plain MQTT, for troubleshooting only)
 *   i           this node's identity (node ID and public key)
 *   d [n]       show the last n records (default 10)
 *   x           export the whole chain as CSV (saakshi_pull.py does this for you)
 *   v           verify the whole chain and every signature on the device
 *   clock       show the clock;  clock <unix seconds> sets it (saakshi_pull.py does this for you)
 *   t <seq>     attack 1: lower a temperature by 5 C, leave hash and signature
 *   r <seq>     attack 2: lower it by 5 C and rebuild every hash after it (no chip, so no new signatures)
 *   k <seq>     attack 3: delete a record
 *   f           attack 4: forge an "all fine" record at the end, with a signature copied from another
 *   clear       delete the whole chain
 */

// ======== WiFi and broker settings come from secrets.h and broker_ca.h (see BEFORE UPLOADING) ========
#if __has_include("secrets.h")
#include "secrets.h"
#endif
#if __has_include("broker_ca.h")
#include "broker_ca.h"               // defines BROKER_CA_PEM: the certificate authority the broker must have
#endif
#ifndef WIFI_NAME
#define WIFI_NAME      "YOUR_HOTSPOT_NAME"
#define WIFI_PASSWORD  ""
#endif
#ifndef MQTT_PASSWORD
#define MQTT_PASSWORD  ""            // usually set on the board instead:  mqttpass <password>
#endif

// ======== BOARD: leave exactly one line uncommented ========
#define BOARD_YD_ESP32_S3
// #define BOARD_NODEMCU_32S
// ===========================================================

#include <Wire.h>
#include <FFat.h>
#include <Preferences.h>
#include <Adafruit_BME680.h>
#include <ArduinoECCX08.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <time.h>
#include <stddef.h>
#include <lwip/sockets.h>           // select(): is there room to send without waiting?
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"

#ifndef DEFAULT_BROKER
#define DEFAULT_BROKER "broker.hivemq.com"   // public test broker; change on the board with: broker <address>
#endif
#define PORT_PLAIN     1883
#define PORT_TLS       8883
#define SYNC_WINDOW    30           // at most this many records sent ahead of the ledger's last reply
#define BATCH_BYTES    2200         // records per message: as many as fit here (about 5). The ESP32
                                    // takes about 2.8 KB without waiting, so a batch never blocks.
#define ACK_TIMEOUT_MS 30000        // no reply this long: resend from where the ledger said its copy ends
#define ROW_MAX        448          // one record as a CSV line (the longest possible is about 400)

#if defined(BOARD_YD_ESP32_S3)
#define SDA_PIN        8
#define SCL_PIN        9
#define INT_PIN        7            // MPU-6050 INT
#elif defined(BOARD_NODEMCU_32S)    // the ESP32's usual I2C pins - check them against your wiring
#define SDA_PIN        21
#define SCL_PIN        22
#define INT_PIN        27           // MPU-6050 INT
// NodeMCU-32S has 4 MB flash: Tools > Partition Scheme must include FATFS, and the chain holds far fewer records
#else
#error "Pick a board in the BOARD block near the top"
#endif
#define BUS_HZ         100000       // DS3231 and MPU-6050 max 400 kHz; the ATECC library jumps to 1 MHz
#define BME_ADDR       0x76
#define RTC_ADDR       0x68
#define MPU_ADDR       0x69         // AD0 on 3V3
#define KEY_SLOT       0
#define LOG_PERIOD_MS  10000        // 10 s on the bench; 5-15 min in the field
#define SAMPLE_MS      20           // movement check, 50 times a second
#define MOVE_MG        100          // 0.1 g away from normal gravity = the box is moving
#define SHOCK_MG       1000         // 1 g away from normal gravity = a shock
#define SHOCK_GAP_MS   5000         // a shock writes a record at once, at most every 5 s
#define TEMP_GAP_CC    600          // BME688 more than 6 C from both other thermometers = mismatch
#define TZ_OFFSET_MIN  330          // for display only (IST); records store UTC
#define NO_TEMP        INT16_MIN    // thermometer not answering
#define CHAIN_PATH     "/chain4.bin"
#define TMP_PATH       "/chain4.tmp"

#define F_BOOT           0x0001     // first record after power-on
#define F_SENSOR_FAIL    0x0002     // BME688 reading failed - its four fields are 0
#define F_NO_TIME        0x0004     // clock not set - unix_time is 0
#define F_CLOCK_SET      0x0008     // the clock was set just before this record
#define F_MOTION         0x0010     // the box moved since the last record
#define F_SHOCK          0x0020     // a jolt of more than 1 g since the last record
#define F_TEMP_MISMATCH  0x0040     // BME688 disagrees with both other thermometers
#define F_SENSOR_CHANGED 0x0080     // BME688 fingerprint differs from the previous record
#define F_UNSIGNED       0x0100     // the ATECC608 could not sign this record
#define F_RTC_FAIL       0x0200     // DS3231 not answering
#define F_MPU_FAIL       0x0400     // MPU-6050 not answering
#define F_LID_OPEN       0x0800     // reserved: lid reed switch (not fitted yet)
#define F_ETHYLENE       0x1000     // v8: uptime_s holds ethylene in ppb instead of seconds since boot
#define F_ETH_NONE       0x2000     // no ethylene sensor answering - the value is 0
#define F_ETH_WARMUP     0x4000     // ethylene sensor powered < 48 h in total - not settled yet

// ---------------- ethylene: ME3-C2H4 -> MCP6002 -> ADS1115 (A0) ----------------
#define ADS_ADDR         0x48
#define ETH_WARM_MIN     (48 * 60)  // datasheet: preheat over 48 h before use
#define ETH_MAX_PPB      200000u    // the sensor's maximum range, 200 ppm
static bool     g_adsOk = false;
static float    g_ethZeroV = 0.500f;       // volts at 0 ppm
static float    g_ethVPerPpm = 0.004f;     // volts per ppm
static uint32_t g_ethMinutes = 0;          // total minutes powered with the sensor answering (kept in flash)
static unsigned long g_ethTick = 0;

#pragma pack(push, 1)
struct Record {
  uint32_t seq;             // monotonic, survives reboots
  uint32_t boot_id;         // increments every power-on
  uint32_t uptime_s;        // seconds since this boot
  uint32_t unix_time;       // UTC seconds from the DS3231; 0 = clock not set
  int32_t  temp_mc;         // BME688 milli-degC  - integers, not floats, so the laptop
  int32_t  rh_mpct;         // milli-%RH            can rebuild the exact bytes
  int32_t  press_pa;        // Pa
  int32_t  gas_ohm;         // ohm
  int16_t  rtc_temp_cc;     // DS3231 thermometer, centi-degC (NO_TEMP = not answering)
  int16_t  mpu_temp_cc;     // MPU-6050 thermometer, centi-degC
  uint16_t peak_mg;         // biggest jolt since the last record: milli-g away from normal gravity
  uint16_t moves;           // 20 ms moments with movement since the last record
  uint32_t sensor_id;       // fingerprint of the BME688's factory calibration (0 = unreadable)
  uint16_t flags;
  uint8_t  prev_hash[32];   // SHA-256 of the previous record
  uint8_t  hash[32];        // SHA-256 over every byte above
  uint8_t  sig[64];         // ATECC608 signature (ECDSA P-256) over hash; zeros if F_UNSIGNED
};
#pragma pack(pop)

// saakshi_pull.py rebuilds this exact layout - change one, change both
static_assert(sizeof(Record) == 174, "Record layout changed - update saakshi_pull.py");
static_assert(offsetof(Record, hash) == 78, "Record layout changed - update saakshi_pull.py");

static const size_t REC_SZ  = sizeof(Record);
static const size_t HASH_IN = offsetof(Record, hash);   // bytes covered by the hash

Adafruit_BME680 bme;
Preferences prefs;

uint32_t g_seq = 0;
uint32_t g_boot_id = 0;
uint8_t  g_lastHash[32];
uint16_t g_nextFlags = 0;
uint8_t  g_failStreak = 0;
unsigned long g_lastLog = 0, g_lastSample = 0, g_lastShockLog = 0;
bool     g_bmeOk = false, g_mpuOk = false, g_eccOk = false;
uint8_t  g_mpuWho = 0;
uint8_t  g_pub[64];
char     g_nodeId[20] = "none";
uint32_t g_lastSensorId = 0;
uint16_t g_peakMg = 0, g_moves = 0;
bool     g_shockPending = false;
uint32_t g_signRetries = 0, g_signFails = 0;

// sync
WiFiClient       netPlain;
WiFiClientSecure netTls;
PubSubClient     mqtt;
#ifdef BROKER_CA_PEM
static const char *CA_PEM = BROKER_CA_PEM;
#else
static const char *CA_PEM = nullptr;
#endif
char     g_broker[64] = DEFAULT_BROKER;
bool     g_tls = false;                // encrypted connection (needs broker_ca.h)
uint16_t g_port = PORT_PLAIN;
char     g_mqPass[65] = MQTT_PASSWORD; // username is always the node ID
bool     g_netStarted = false, g_ntpAsked = false, g_ntpDone = false;
unsigned long g_lastEccTry = 0;
char     g_chainHex[9] = "";        // this chain's name: the first 8 hex digits of record 0's hash
char     t_status[48], t_ack[48], t_cmd[48], t_rec[64];
bool     g_netOn = true;            // false after "offline"
bool     g_wifiUp = false, g_haveAck = false, g_cursorOk = false, g_catchingUp = false;
bool     g_brokerNoted = false, g_waitNoted = false, g_stallNoted = false, g_clockNoted = false;
bool     g_everSynced = false;   // have we heard from the ledger at least once this power-on
uint32_t g_ackNext = 0;             // the ledger holds every seq below this
uint32_t g_sendSeq = 0;             // next seq to send
uint32_t g_cursor = 0;              // file position of g_sendSeq
uint32_t g_sentCount = 0;
unsigned long g_lastAckMs = 0, g_lastWifiTry = 0, g_lastMqttTry = 0;
unsigned long g_mqttRetryMs = 5000, g_ackTimeoutMs = ACK_TIMEOUT_MS;
unsigned long g_joinNoteMs = 0;     // last "can't join" message (at most one every 30 s)
uint32_t g_window = SYNC_WINDOW;    // records allowed in flight: shrinks when replies are late
uint32_t g_progressSeq = 0;         // last backlog progress message
uint32_t g_slowNotes = 0;           // sends that didn't fit - the connection was reset
volatile uint8_t g_wifiReason = 0;  // why WiFi last dropped (set by the WiFi driver's event)

static void printNetwork();

// ---------------- I2C helpers ----------------

static bool readRegs(uint8_t addr, uint8_t reg, uint8_t *buf, size_t n) {
  Wire.beginTransmission(addr);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) return false;
  if (Wire.requestFrom(addr, n) != n) return false;
  for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)Wire.read();
  return true;
}

static bool readReg(uint8_t addr, uint8_t reg, uint8_t &val) { return readRegs(addr, reg, &val, 1); }

static bool writeReg(uint8_t addr, uint8_t reg, uint8_t val) {
  Wire.beginTransmission(addr);
  Wire.write(reg);
  Wire.write(val);
  return Wire.endTransmission() == 0;
}

// ---------------- hashing and formatting ----------------

static void sha256(const uint8_t *in, size_t len, uint8_t out[32]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);          // 0 = SHA-256, not SHA-224
  mbedtls_sha256_update(&ctx, in, len);
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
}

static void computeHash(const Record &r, uint8_t out[32]) {
  sha256((const uint8_t *)&r, HASH_IN, out);
}

// first nbytes of h as lowercase hex; out needs 2*nbytes+1 chars
static void hexN(const uint8_t *h, int nbytes, char *out) {
  static const char *H = "0123456789abcdef";
  for (int i = 0; i < nbytes; i++) {
    out[i * 2]     = H[h[i] >> 4];
    out[i * 2 + 1] = H[h[i] & 0x0F];
  }
  out[nbytes * 2] = 0;
}

// exact fixed-point text, no floats: (29170,1000,3) -> "29.170", (-500,1000,3) -> "-0.500"
static void fmtFixed(char *buf, size_t n, int32_t v, uint32_t div, int decimals) {
  uint32_t a = (v < 0) ? (uint32_t)(-(int64_t)v) : (uint32_t)v;
  snprintf(buf, n, "%s%lu.%0*lu", v < 0 ? "-" : "",
           (unsigned long)(a / div), decimals, (unsigned long)(a % div));
}

static void fmtTemp(char *buf, size_t n, int16_t cc) {
  if (cc == NO_TEMP) buf[0] = 0;
  else fmtFixed(buf, n, cc, 100, 2);
}

// ---------------- calendar (UTC seconds <-> date) ----------------

static int64_t daysFromCivil(int y, int m, int d) {
  y -= m <= 2;
  const int era = (y >= 0 ? y : y - 399) / 400;
  const int yoe = y - era * 400;
  const int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return (int64_t)era * 146097 + doe - 719468;
}

static void civilFromDays(int64_t z, int &y, int &m, int &d) {
  z += 719468;
  const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const int doe = (int)(z - era * 146097);
  const int yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const int doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const int mp = (5 * doy + 2) / 153;
  d = doy - (153 * mp + 2) / 5 + 1;
  m = mp < 10 ? mp + 3 : mp - 9;
  y = (int)(yoe + era * 400) + (m <= 2);
}

static void fmtTime(char *buf, size_t n, uint32_t t) {
  if (t == 0) { snprintf(buf, n, "time not set"); return; }
  static const char *MON[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  int64_t local = (int64_t)t + TZ_OFFSET_MIN * 60;
  int y, m, d;
  civilFromDays(local / 86400, y, m, d);
  int rem = (int)(local % 86400);
  snprintf(buf, n, "%02d %s %04d %02d:%02d:%02d", d, MON[m - 1], y, rem / 3600, (rem / 60) % 60, rem % 60);
}

static unsigned bcd(uint8_t v) { return (v >> 4) * 10u + (v & 0x0Fu); }
static uint8_t toBcd(unsigned v) { return (uint8_t)(((v / 10) << 4) | (v % 10)); }

// ---------------- DS3231 clock ----------------

// 1 = time read, 0 = clock never set (or lost power), -1 = not answering
static int rtcRead(uint32_t &t) {
  uint8_t r[7], st;
  if (!readRegs(RTC_ADDR, 0x00, r, 7) || !readReg(RTC_ADDR, 0x0F, st)) return -1;
  if (st & 0x80) return 0;                 // "oscillator stopped": the time is not valid
  unsigned se = bcd(r[0] & 0x7F), mi = bcd(r[1] & 0x7F), ho;
  if (r[2] & 0x40) ho = bcd(r[2] & 0x1F) % 12 + ((r[2] & 0x20) ? 12 : 0);   // 12-hour mode
  else ho = bcd(r[2] & 0x3F);
  unsigned da = bcd(r[4] & 0x3F), mo = bcd(r[5] & 0x1F);
  int ye = 2000 + (int)bcd(r[6]) + ((r[5] & 0x80) ? 100 : 0);
  if (se > 59 || mi > 59 || ho > 23 || da < 1 || da > 31 || mo < 1 || mo > 12) return 0;
  t = (uint32_t)(daysFromCivil(ye, (int)mo, (int)da) * 86400 + ho * 3600 + mi * 60 + se);
  return 1;
}

static bool rtcSet(uint32_t t) {
  int64_t days = t / 86400;
  uint32_t rem = t % 86400;
  int y, m, d;
  civilFromDays(days, y, m, d);
  if (y < 2000 || y > 2099) return false;
  uint8_t regs[8] = {0x00, toBcd(rem % 60), toBcd((rem / 60) % 60), toBcd(rem / 3600),
                     (uint8_t)((days + 4) % 7 + 1),        // weekday 1-7 (1 Jan 1970 was a Thursday)
                     toBcd((unsigned)d), toBcd((unsigned)m), toBcd((unsigned)(y - 2000))};
  Wire.beginTransmission(RTC_ADDR);
  Wire.write(regs, sizeof regs);             // register pointer 0x00, then seconds..year, 24-hour mode
  if (Wire.endTransmission() != 0) return false;
  uint8_t st;
  if (!readReg(RTC_ADDR, 0x0F, st)) return false;
  return writeReg(RTC_ADDR, 0x0F, st & 0x7F);   // clear "oscillator stopped": the time is valid now
}

static bool rtcTemp(int16_t &cc) {
  uint8_t b[2];
  if (!readRegs(RTC_ADDR, 0x11, b, 2)) return false;
  cc = (int16_t)(((int16_t)((b[0] << 8) | b[1]) >> 6) * 25);   // 0.25 C steps
  return true;
}

// ---------------- MPU-6050 movement sensor ----------------

static bool mpuInit() {
  uint8_t who, st;
  g_mpuOk = false;
  if (!readReg(MPU_ADDR, 0x75, who)) return false;
  g_mpuWho = who;
  bool ok = writeReg(MPU_ADDR, 0x6B, 0x00);   // wake up, internal clock
  delay(50);
  ok = ok && writeReg(MPU_ADDR, 0x6C, 0x07)   // gyroscope off - only the accelerometer is used
          && writeReg(MPU_ADDR, 0x1A, 0x03)   // smooth the readings (about 44 Hz)
          && writeReg(MPU_ADDR, 0x1C, 0x11)   // +-8 g; its movement detector ignores steady gravity
          && writeReg(MPU_ADDR, 0x1F, 40)     // movement detector threshold
          && writeReg(MPU_ADDR, 0x20, 1)      // ... held for 1 ms
          && writeReg(MPU_ADDR, 0x37, 0x20)   // INT pin: active high, held until the status is read
          && writeReg(MPU_ADDR, 0x38, 0x40);  // INT pin: raised on movement
  readReg(MPU_ADDR, 0x3A, st);                // clear anything pending
  pinMode(INT_PIN, INPUT_PULLDOWN);
  g_mpuOk = ok;
  return ok;
}

// total acceleration in milli-g (about 1000 when resting)
static bool accelMg(int32_t &mg) {
  uint8_t b[6];
  if (!readRegs(MPU_ADDR, 0x3B, b, 6)) return false;
  float x = (int16_t)((b[0] << 8) | b[1]);
  float y = (int16_t)((b[2] << 8) | b[3]);
  float z = (int16_t)((b[4] << 8) | b[5]);
  mg = (int32_t)lroundf(sqrtf(x * x + y * y + z * z) * 1000.0f / 4096.0f);
  return true;
}

static bool mpuTemp(int16_t &cc) {
  uint8_t b[2];
  if (!readRegs(MPU_ADDR, 0x41, b, 2)) return false;
  int32_t raw = (int16_t)((b[0] << 8) | b[1]);
  if (g_mpuWho == 0x70 || g_mpuWho == 0x71) cc = (int16_t)(raw * 10000 / 33387 + 2100);   // MPU-6500 / 9250
  else cc = (int16_t)(raw * 100 / 340 + 3653);                                               // MPU-6050
  return true;
}

// Runs from loop(): 50 times a second, notes how far acceleration strays from normal gravity.
// The MPU-6050 also latches its INT pin on movement, which catches jolts while the ESP32 is busy.
static void sampleMotion() {
  if (!g_mpuOk || millis() - g_lastSample < SAMPLE_MS) return;
  g_lastSample = millis();
  bool moved = false;
  if (digitalRead(INT_PIN) == HIGH) {
    uint8_t st;
    moved = readReg(MPU_ADDR, 0x3A, st) && (st & 0x40);   // reading the status releases the pin
  }
  int32_t mg;
  if (accelMg(mg)) {
    int32_t dev = mg > 1000 ? mg - 1000 : 1000 - mg;
    if (dev > 65535) dev = 65535;
    if (dev > g_peakMg) g_peakMg = (uint16_t)dev;
    if (dev >= MOVE_MG) moved = true;
    if (dev >= SHOCK_MG) g_shockPending = true;
  }
  if (moved && g_moves < 0xFFFF) g_moves++;
}

// ---------------- BME688 ----------------

static void configureSensor() {
  bme.setTemperatureOversampling(BME680_OS_8X);
  bme.setHumidityOversampling(BME680_OS_2X);
  bme.setPressureOversampling(BME680_OS_4X);
  bme.setIIRFilterSize(BME680_FILTER_SIZE_3);
  bme.setGasHeater(320, 150);
}

// Every BME688 leaves the factory with its own calibration numbers. A short hash of them works as
// a fingerprint: a different sensor gives a different number. Only the calibration bytes are used.
static uint32_t sensorId() {
  uint8_t c[42];
  if (!readRegs(BME_ADDR, 0x8A, c, 23) || !readRegs(BME_ADDR, 0xE1, c + 23, 14) ||
      !readRegs(BME_ADDR, 0x00, c + 37, 5)) return 0;
  c[3] = c[9] = c[16] = c[17] = 0;           // unused bytes inside the calibration block
  c[38] = c[40] = 0;
  c[39] &= 0x30;                             // heater range bits only
  c[41] &= 0xF0;                             // switching error bits only
  uint8_t h[32];
  sha256(c, sizeof c, h);
  uint32_t id = ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | h[3];
  return id ? id : 1;                        // 0 means "unreadable"
}

// ---------------- ATECC608 identity and signing ----------------

static void initIdentity(bool quiet) {
  g_eccOk = false;
  strcpy(g_nodeId, "none");
  bool found = ECCX08.begin();
  bool locked = found && ECCX08.locked();
  bool keyOk = locked && ECCX08.generatePublicKey(KEY_SLOT, g_pub);   // reads the public key, changes nothing
  Wire.setClock(BUS_HZ);
  if (!found) { if (!quiet) Serial.println("ATECC608 not answering - records UNSIGNED until it does (retried every 20 s)"); return; }
  if (!locked) { if (!quiet) Serial.println("ATECC608 not set up - run saakshi_atecc_setup; records will be UNSIGNED"); return; }
  if (!keyOk) { if (!quiet) Serial.println("could not read the ATECC608's key - records UNSIGNED until it answers (retried every 20 s)"); return; }
  g_eccOk = true;

  uint8_t point[65], h[32];
  point[0] = 0x04;
  memcpy(point + 1, g_pub, 64);
  sha256(point, sizeof point, h);
  snprintf(g_nodeId, sizeof g_nodeId, "SAAKSHI-%02X%02X%02X%02X", h[0], h[1], h[2], h[3]);

  uint8_t saved[64];                         // the note written by saakshi_atecc_setup
  if (prefs.begin("saakshi_id", true)) {
    bool have = prefs.getBytesLength("pub") == 64 && prefs.getBytes("pub", saved, 64) == 64;
    prefs.end();
    if (have && memcmp(saved, g_pub, 64) != 0)
      Serial.println("WARNING: the chip's key is not the one created at setup - it was replaced");
  }
}

// Now and then the chip misses a signing (a garbled transfer, or it needs longer than the library
// waits). Then it stays awake holding a half-finished answer, so the retry waits 1.5 s for the chip's
// own watchdog to put it back to sleep - the next wake-up is clean.
static bool signRecord(Record &r) {
  if (!g_eccOk) return false;
  for (int attempt = 0; attempt < 3; attempt++) {
    if (attempt) delay(1500);
    bool ok = ECCX08.ecSign(KEY_SLOT, r.hash, r.sig);
    Wire.setClock(BUS_HZ);
    if (ok) {
      g_signRetries += attempt;
      return true;
    }
  }
  g_signFails++;
  return false;
}

// The check the laptop does, with the ESP32's own crypto library
static bool signatureValid(const Record &r) {
  uint8_t point[65];
  point[0] = 0x04;
  memcpy(point + 1, g_pub, 64);
  mbedtls_ecp_group grp;
  mbedtls_ecp_point q;
  mbedtls_mpi mr, ms;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&q);
  mbedtls_mpi_init(&mr);
  mbedtls_mpi_init(&ms);
  int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (rc == 0) rc = mbedtls_ecp_point_read_binary(&grp, &q, point, sizeof point);
  if (rc == 0) rc = mbedtls_mpi_read_binary(&mr, r.sig, 32);
  if (rc == 0) rc = mbedtls_mpi_read_binary(&ms, r.sig + 32, 32);
  if (rc == 0) rc = mbedtls_ecdsa_verify(&grp, r.hash, 32, &q, &mr, &ms);
  mbedtls_mpi_free(&mr);
  mbedtls_mpi_free(&ms);
  mbedtls_ecp_point_free(&q);
  mbedtls_ecp_group_free(&grp);
  return rc == 0;
}

// ---------------- chain storage ----------------

static uint32_t recordCount() {
  File f = FFat.open(CHAIN_PATH, FILE_READ);
  if (!f) return 0;
  uint32_t n = f.size() / REC_SZ;
  f.close();
  return n;
}

static bool readRecord(uint32_t idx, Record &r) {
  File f = FFat.open(CHAIN_PATH, FILE_READ);
  if (!f) return false;
  if ((size_t)(idx + 1) * REC_SZ > f.size()) { f.close(); return false; }
  f.seek(idx * REC_SZ);
  size_t got = f.read((uint8_t *)&r, REC_SZ);
  f.close();
  return got == REC_SZ;
}

static bool writeRecordAt(uint32_t idx, const Record &r) {
  File f = FFat.open(CHAIN_PATH, "r+");
  if (!f) return false;
  bool ok = f.seek(idx * REC_SZ) && f.write((const uint8_t *)&r, REC_SZ) == REC_SZ;
  f.close();
  return ok;
}

static bool appendRecord(const Record &r) {
  File f = FFat.open(CHAIN_PATH, FILE_APPEND);
  if (!f) return false;
  size_t wrote = f.write((const uint8_t *)&r, REC_SZ);
  f.close();
  return wrote == REC_SZ;
}

// position of a sequence number in the file (seq and position differ after a deletion)
static bool findSeq(uint32_t seq, uint32_t &idx, Record &r) {
  File f = FFat.open(CHAIN_PATH, FILE_READ);
  if (!f) return false;
  uint32_t n = f.size() / REC_SZ;
  for (uint32_t i = 0; i < n; i++) {
    if (f.read((uint8_t *)&r, REC_SZ) != REC_SZ) break;
    if (r.seq == seq) { idx = i; f.close(); return true; }
  }
  f.close();
  return false;
}

static void loadTail() {
  uint32_t n = recordCount();
  Record r;
  if (n == 0 || !readRecord(n - 1, r)) {
    g_seq = 0;
    memset(g_lastHash, 0, 32);               // genesis: prev_hash is all zeros
    return;
  }
  g_seq = r.seq + 1;
  memcpy(g_lastHash, r.hash, 32);
  if (r.sensor_id) g_lastSensorId = r.sensor_id;
}

// A chain is named after its first record: the first 8 hex digits of record 0's hash. Clearing the
// chain (or replacing its first record) gives it a new name, and the ledger keeps each chain in its
// own file - so the old one can never be quietly overwritten.
static void updateChainId() {
  char was[9];
  strcpy(was, g_chainHex);
  Record first;
  if (recordCount() > 0 && readRecord(0, first)) hexN(first.hash, 4, g_chainHex);
  else g_chainHex[0] = 0;
  g_cursorOk = false;                        // the file changed: find the send position again
  if (strcmp(was, g_chainHex) == 0) return;
  snprintf(t_rec, sizeof t_rec, "saakshi/%s/rec/%s", g_nodeId, g_chainHex);
  if (mqtt.connected()) {                    // tell the ledger the old chain is closed, then reconnect
    char msg[40];
    snprintf(msg, sizeof msg, "offline chain=%s", was);
    if (was[0]) mqtt.publish(t_status, msg, true);
    mqtt.disconnect();
  }
  g_haveAck = false;
  g_lastMqttTry = 0;
  g_mqttRetryMs = 5000;
  if (was[0] && g_chainHex[0])
    Serial.printf("[sync] the chain's first record changed - it is now chain %s (was %s)\n", g_chainHex, was);
}

// ---------------- ethylene ----------------

// One single-shot conversion: channel 0-3 against GND, +-4.096 V range (125 uV per step).
static bool adsVolts(uint8_t ch, float &v) {
  uint16_t cfg = 0x8000 | ((0x4 + (ch & 3)) << 12) | (0x1 << 9) | 0x0100 | (0x4 << 5) | 0x3;
  Wire.beginTransmission(ADS_ADDR);
  Wire.write(0x01); Wire.write(cfg >> 8); Wire.write(cfg & 0xFF);
  if (Wire.endTransmission() != 0) return false;
  for (int i = 0; i < 20; i++) {                     // 128 samples/s: ready in about 8 ms
    delay(2);
    Wire.beginTransmission(ADS_ADDR);
    Wire.write(0x01);
    if (Wire.endTransmission(false) != 0 || Wire.requestFrom((uint8_t)ADS_ADDR, (uint8_t)2) != 2) return false;
    uint16_t st = (Wire.read() << 8) | Wire.read();
    if (st & 0x8000) break;                          // conversion finished
  }
  Wire.beginTransmission(ADS_ADDR);
  Wire.write(0x00);
  if (Wire.endTransmission(false) != 0 || Wire.requestFrom((uint8_t)ADS_ADDR, (uint8_t)2) != 2) return false;
  int16_t raw = (int16_t)((Wire.read() << 8) | Wire.read());
  v = raw * (4.096f / 32768.0f);
  return true;
}

static bool ethVolts(float &v) {                     // average of 4 conversions on A0
  float sum = 0, x;
  for (int i = 0; i < 4; i++) { if (!adsVolts(0, x)) return false; sum += x; }
  v = sum / 4;
  return true;
}

static void ethLoad() {
  if (prefs.begin("saakshi", true)) {
    g_ethZeroV = prefs.getFloat("e_zero", g_ethZeroV);
    g_ethVPerPpm = prefs.getFloat("e_gain", g_ethVPerPpm);
    g_ethMinutes = prefs.getUInt("e_min", 0);
    prefs.end();
  }
  if (g_ethVPerPpm < 0.0001f) g_ethVPerPpm = 0.004f;
}

// Called for every record: looks for the sensor each time, so plugging it in later just works.
static uint32_t ethReading(uint16_t &flags) {
  flags |= F_ETHYLENE;
  float v;
  g_adsOk = ethVolts(v);
  if (!g_adsOk) { flags |= F_ETH_NONE; return 0; }
  unsigned long now = millis();                       // count powered minutes for the 48 h preheat
  if (g_ethTick == 0) g_ethTick = now;
  if (now - g_ethTick >= 60000UL) {
    uint32_t add = (now - g_ethTick) / 60000UL;
    g_ethTick += add * 60000UL;
    bool crossing = g_ethMinutes < ETH_WARM_MIN && g_ethMinutes + add >= ETH_WARM_MIN;
    g_ethMinutes += add;
    if (crossing || g_ethMinutes % 10 < add) {        // save every ~10 min, and when warm-up ends
      if (prefs.begin("saakshi", false)) { prefs.putUInt("e_min", g_ethMinutes); prefs.end(); }
    }
  }
  if (g_ethMinutes < ETH_WARM_MIN) flags |= F_ETH_WARMUP;
  float ppm = (v - g_ethZeroV) / g_ethVPerPpm;
  if (ppm < 0) ppm = 0;
  uint32_t ppb = (uint32_t)lroundf(ppm * 1000.0f);
  return ppb > ETH_MAX_PPB ? ETH_MAX_PPB : ppb;
}

static void ethShow() {
  Serial.println();
  float v;
  for (uint8_t ch = 0; ch < 4; ch++) {
    if (adsVolts(ch, v)) Serial.printf("ADS1115 A%u : %.4f V%s\n", ch, v, ch == 0 ? "   <- ethylene amplifier" : "");
    else { Serial.println("ADS1115 not answering at 0x48 - check VDD 3V3, GND, SDA 8, SCL 9, ADDR to GND"); break; }
  }
  Serial.printf("conversion : %.4f V = 0 ppm, %.2f mV per ppm\n", g_ethZeroV, g_ethVPerPpm * 1000);
  Serial.printf("warm-up    : %lu of %d min powered%s\n", (unsigned long)g_ethMinutes, ETH_WARM_MIN,
                g_ethMinutes >= ETH_WARM_MIN ? " - done" : " - readings are marked WARMUP until 48 h");
  if (ethVolts(v)) {
    float ppm = (v - g_ethZeroV) / g_ethVPerPpm;
    Serial.printf("ethylene   : %.1f ppm now\n", ppm < 0 ? 0 : ppm);
  }
  Serial.println();
}

static void ethZero() {
  float v;
  if (!ethVolts(v)) { Serial.println("ADS1115 not answering - can't set zero\n"); return; }
  g_ethZeroV = v;
  if (prefs.begin("saakshi", false)) { prefs.putFloat("e_zero", v); prefs.end(); }
  Serial.printf("ethylene zero set: %.4f V = 0 ppm (do this in clean outdoor air, after warm-up)\n\n", v);
}

static void ethSpan(float ppm) {
  float v;
  if (ppm <= 0) { Serial.println("give the known concentration:  ethspan 50\n"); return; }
  if (!ethVolts(v)) { Serial.println("ADS1115 not answering - can't set span\n"); return; }
  float g = (v - g_ethZeroV) / ppm;
  if (g < 0.0001f) { Serial.println("the signal is too small for that concentration - check the gas and wiring\n"); return; }
  g_ethVPerPpm = g;
  if (prefs.begin("saakshi", false)) { prefs.putFloat("e_gain", g); prefs.end(); }
  Serial.printf("ethylene span set: %.2f mV per ppm (from %.1f ppm test gas)\n\n", g * 1000, ppm);
}

static void ethReady() {
  g_ethMinutes = ETH_WARM_MIN;
  if (prefs.begin("saakshi", false)) { prefs.putUInt("e_min", g_ethMinutes); prefs.end(); }
  Serial.println("ethylene sensor marked as warmed up (only if it really was powered for 48 h)\n");
}

// ---------------- showing records ----------------

static void showRecord(const Record &r, const char *indent) {
  char when[32], t2[12], t3[12], hs[9];
  fmtTime(when, sizeof when, r.unix_time);
  fmtTemp(t2, sizeof t2, r.rtc_temp_cc);
  fmtTemp(t3, sizeof t3, r.mpu_temp_cc);
  hexN(r.hash, 4, hs);
  char eth[16] = "--";
  if ((r.flags & F_ETHYLENE) && !(r.flags & F_ETH_NONE)) snprintf(eth, sizeof eth, "%.1f", r.uptime_s / 1000.0);
  Serial.printf("%s#%-6lu %s  T %6.2f C  RH %5.2f %%  P %7.2f hPa  Gas %6.1f kOhm  C2H4 %s ppm  | clock %s C  mpu %s C"
                "  | jolt %.2f g  | %s %s",
                indent, (unsigned long)r.seq, when, r.temp_mc / 1000.0, r.rh_mpct / 1000.0,
                r.press_pa / 100.0, r.gas_ohm / 1000.0, eth, t2[0] ? t2 : "--", t3[0] ? t3 : "--",
                r.peak_mg / 1000.0, hs, (r.flags & F_UNSIGNED) ? "UNSIGNED" : "signed");
  static const struct { uint16_t bit; const char *name; } TAGS[] = {
      {F_BOOT, "BOOT"}, {F_CLOCK_SET, "CLOCK SET"}, {F_SHOCK, "SHOCK"}, {F_MOTION, "MOVED"},
      {F_TEMP_MISMATCH, "THERMOMETERS DISAGREE"}, {F_SENSOR_CHANGED, "SENSOR CHANGED"},
      {F_SENSOR_FAIL, "SENSOR FAIL"}, {F_RTC_FAIL, "CLOCK FAIL"}, {F_MPU_FAIL, "MPU FAIL"},
      {F_ETH_WARMUP, "C2H4 WARMING UP"}};
  for (auto &tag : TAGS)
    if (r.flags & tag.bit) Serial.printf("  [%s]", tag.name);
  Serial.println();
}

// ---------------- logging ----------------

static void logReading(bool shockNow) {
  Record r;
  memset(&r, 0, sizeof r);
  uint16_t flags = g_nextFlags;
  g_nextFlags = 0;

  // BME688 reading
  if (!g_bmeOk && (g_bmeOk = bme.begin(BME_ADDR))) configureSensor();
  if (g_bmeOk && bme.performReading()) {
    g_failStreak = 0;
    r.temp_mc  = (int32_t)lroundf(bme.temperature * 1000.0f);
    r.rh_mpct  = (int32_t)lroundf(bme.humidity    * 1000.0f);
    r.press_pa = (int32_t)lroundf((float)bme.pressure);
    r.gas_ohm  = (int32_t)bme.gas_resistance;
  } else {
    flags |= F_SENSOR_FAIL;                  // the gap is recorded, never hidden
    if (g_bmeOk && ++g_failStreak >= 3) {
      Serial.println("re-initialising BME688...");
      g_bmeOk = bme.begin(BME_ADDR);
      if (g_bmeOk) configureSensor();
      g_failStreak = 0;
    }
  }

  // which BME688 this is
  r.sensor_id = sensorId();
  if (r.sensor_id && g_lastSensorId && r.sensor_id != g_lastSensorId) flags |= F_SENSOR_CHANGED;
  if (r.sensor_id) g_lastSensorId = r.sensor_id;

  // time and the two other thermometers
  uint32_t t = 0;
  int clk = rtcRead(t);
  if (clk < 0) flags |= F_RTC_FAIL | F_NO_TIME;
  else if (clk == 0) flags |= F_NO_TIME;
  else r.unix_time = t;
  int16_t cc;
  r.rtc_temp_cc = (clk >= 0 && rtcTemp(cc)) ? cc : NO_TEMP;
  if (!g_mpuOk) mpuInit();
  r.mpu_temp_cc = (g_mpuOk && mpuTemp(cc)) ? cc : NO_TEMP;
  if (r.mpu_temp_cc == NO_TEMP) { flags |= F_MPU_FAIL; g_mpuOk = false; }

  // movement since the last record
  r.peak_mg = g_peakMg;
  r.moves = g_moves;
  if (g_moves >= 3) flags |= F_MOTION;        // at least 60 ms of movement
  if (g_peakMg >= SHOCK_MG || shockNow) flags |= F_SHOCK;
  g_peakMg = 0;
  g_moves = 0;
  g_shockPending = false;

  // three thermometers: the BME688 must agree with at least one of the others
  if (!(flags & F_SENSOR_FAIL)) {
    int32_t bmeCc = r.temp_mc / 10;
    bool haveRtc = r.rtc_temp_cc != NO_TEMP, haveMpu = r.mpu_temp_cc != NO_TEMP;
    bool offRtc = !haveRtc || abs(bmeCc - r.rtc_temp_cc) > TEMP_GAP_CC;
    bool offMpu = !haveMpu || abs(bmeCc - r.mpu_temp_cc) > TEMP_GAP_CC;
    if ((haveRtc || haveMpu) && offRtc && offMpu) flags |= F_TEMP_MISMATCH;
  }

  r.seq      = g_seq;
  r.boot_id  = g_boot_id;
  r.uptime_s = ethReading(flags);            // v8: ethylene in ppb (flag ETHYLENE says so)
  r.flags    = flags;
  memcpy(r.prev_hash, g_lastHash, 32);
  computeHash(r, r.hash);
  if (!signRecord(r)) {                      // logged anyway, marked as unsigned
    r.flags |= F_UNSIGNED;
    memset(r.sig, 0, sizeof r.sig);
    computeHash(r, r.hash);
  }

  if (!appendRecord(r)) { Serial.println("FLASH WRITE FAILED"); return; }
  memcpy(g_lastHash, r.hash, 32);
  g_seq++;
  showRecord(r, "");
  if (!g_chainHex[0]) updateChainId();       // the first record of a new chain names it
}

// ---------------- verifier (same rules as saakshi_pull.py) ----------------

static void problem(uint32_t seq, const char *what, const char *detail) {
  Serial.printf("  seq %-7lu %-18s %s\n", (unsigned long)seq, what, detail);
}

static void verifyChain() {
  uint32_t n = recordCount();
  Serial.printf("\n--- verifying %lu records and their signatures on the device ---\n", (unsigned long)n);
  if (n == 0) { Serial.println("chain is empty\n"); return; }
  if (!g_eccOk) Serial.println("(no key from the ATECC608 - signatures are not checked)");

  File f = FFat.open(CHAIN_PATH, FILE_READ);
  if (!f) { Serial.println("cannot open chain\n"); return; }

  uint8_t  expectPrev[32];
  memset(expectPrev, 0, 32);                 // genesis
  uint32_t expectSeq = 0, problems = 0, checked = 0, shown = 0, covered = 0;
  Record   r;
  char     detail[96];
  // An unsigned record is still protected once a later record is signed: that signature covers a hash
  // which includes the unsigned record's hash. Unsigned records wait here until one comes along.
  uint32_t pending[16], pendingCount = 0;
  auto flushPending = [&](const char *why) {
    for (uint32_t k = 0; k < pendingCount; k++) {
      problems++;
      if (shown++ < 40 && k < 16) problem(pending[k], "UNSIGNED", why);
    }
    pendingCount = 0;
  };

  for (uint32_t i = 0; i < n; i++) {
    if (f.read((uint8_t *)&r, REC_SZ) != REC_SZ) break;
    checked++;
    if (i % 200 == 199) Serial.printf("  ... %lu checked\n", (unsigned long)checked);
    if (i % 50 == 49 && mqtt.connected()) mqtt.loop();   // a long check mustn't drop the broker

    uint8_t calc[32];
    computeHash(r, calc);
    bool advance = true;
    const char *what = nullptr;
    detail[0] = 0;

    if (memcmp(calc, r.hash, 32) != 0) {
      what = "DATA ALTERED";
      snprintf(detail, sizeof detail, "contents changed after the hash was made");
    } else if (memcmp(r.prev_hash, expectPrev, 32) != 0) {
      if (r.seq > expectSeq) {
        what = "RECORDS DELETED";
        if (r.seq - expectSeq == 1)
          snprintf(detail, sizeof detail, "seq %lu missing before this one", (unsigned long)expectSeq);
        else
          snprintf(detail, sizeof detail, "seq %lu..%lu missing before this one",
                   (unsigned long)expectSeq, (unsigned long)(r.seq - 1));
      } else if (r.seq < expectSeq) {
        what = "REPLAYED";
        snprintf(detail, sizeof detail, "sequence went backwards - an old record was re-inserted");
        advance = false;                     // an inserted extra: keep judging against the real chain
      } else if (r.seq == 0) {
        what = "LINK BROKEN";
        snprintf(detail, sizeof detail, "first record does not start from genesis");
      } else {
        what = "LINK BROKEN";
        snprintf(detail, sizeof detail, "seq %lu was edited and re-hashed, or this record is forged",
                 (unsigned long)(r.seq - 1));
      }
    } else if (r.flags & F_UNSIGNED) {
      what = "";                             // decided later: covered by a later signature, or not
    } else if (g_eccOk && !signatureValid(r)) {
      what = "SIGNATURE INVALID";
      snprintf(detail, sizeof detail, "not signed by this node's chip - changed or made elsewhere");
    } else if (r.seq != expectSeq) {
      what = "SEQUENCE ERROR";
      snprintf(detail, sizeof detail, "expected seq %lu", (unsigned long)expectSeq);
    }

    if (what && !what[0]) {                  // unsigned: wait for a later signature to cover it
      if (pendingCount < 16) pending[pendingCount] = r.seq;
      pendingCount++;
    } else if (what) {
      flushPending("not signed, and the record after it failed its check");
      problems++;
      if (shown++ < 40) problem(r.seq, what, detail);
    } else if (g_eccOk && pendingCount) {    // a good signature: everything before it is covered
      covered += pendingCount;
      pendingCount = 0;
    }
    if (advance) {                           // judge the next record against what is stored
      memcpy(expectPrev, r.hash, 32);
      expectSeq = r.seq + 1;
    }
  }
  f.close();
  flushPending("not signed, and no later signature covers it yet");
  if (shown > 40) Serial.printf("  ... and %lu more\n", (unsigned long)(shown - 40));
  if (covered)
    Serial.printf("  (%lu record(s) the chip didn't sign are covered by the next record's signature)\n",
                  (unsigned long)covered);

  char head[65];
  hexN(r.hash, 32, head);
  if (problems == 0)
    Serial.printf("CHAIN INTACT - all %lu records verified%s\n", (unsigned long)checked,
                  g_eccOk ? ", every signature from this node's chip" : "");
  else
    Serial.printf("CHAIN INVALID - %lu problem(s) in %lu records\n", (unsigned long)problems, (unsigned long)checked);
  Serial.printf("head  seq %lu  0x%s\n\n", (unsigned long)r.seq, head);
}

// ---------------- export, identity and status ----------------

// One record as a CSV line - the same line the export prints and the ledger stores.
static void formatRow(const Record &r, char *line, size_t n) {
  char t[16], h[16], p[16], g[16], t2[12], t3[12], pk[12], ph[65], hh[65], sg[129];
  fmtFixed(t, sizeof t, r.temp_mc, 1000, 3);
  fmtFixed(h, sizeof h, r.rh_mpct, 1000, 3);
  fmtFixed(p, sizeof p, r.press_pa, 100, 2);
  fmtFixed(g, sizeof g, r.gas_ohm, 1000, 3);
  fmtTemp(t2, sizeof t2, r.rtc_temp_cc);
  fmtTemp(t3, sizeof t3, r.mpu_temp_cc);
  fmtFixed(pk, sizeof pk, r.peak_mg, 1000, 3);
  hexN(r.prev_hash, 32, ph);
  hexN(r.hash, 32, hh);
  hexN(r.sig, 64, sg);
  snprintf(line, n, "%lu,%lu,%lu,%lu,%s,%s,%s,%s,%s,%s,%s,%u,0x%08lx,%u,0x%s,0x%s,0x%s",
           (unsigned long)r.seq, (unsigned long)r.boot_id, (unsigned long)r.uptime_s,
           (unsigned long)r.unix_time, t, h, p, g, t2, t3, pk, (unsigned)r.moves,
           (unsigned long)r.sensor_id, (unsigned)r.flags, ph, hh, sg);
}

static void exportCSV() {
  uint32_t n = recordCount();
  uint32_t sent = 0;
  char key[131] = "none";
  if (g_eccOk) {
    key[0] = '0';
    key[1] = '4';
    hexN(g_pub, 64, key + 2);
  }
  Serial.printf("#BEGIN_CSV count=%lu node=%s key=%s\n", (unsigned long)n, g_nodeId, key);
  Serial.println("seq,boot,uptime_s,unix_time,temp_c,rh_pct,pressure_hpa,gas_kohm,"
                 "rtc_temp_c,mpu_temp_c,peak_g,moves,sensor_id,flags,prev_hash,hash,sig");

  File f = FFat.open(CHAIN_PATH, FILE_READ);
  if (f) {
    Record r;
    char line[ROW_MAX];
    for (uint32_t i = 0; i < n; i++) {
      if (f.read((uint8_t *)&r, REC_SZ) != REC_SZ) break;
      formatRow(r, line, sizeof line);
      Serial.printf("%s\n", line);
      sent++;
    }
    f.close();
  }
  Serial.printf("#END_CSV count=%lu\n", (unsigned long)sent);
}

static void identity() {
  if (!g_eccOk) { Serial.println("\nno identity - the ATECC608 is missing or not set up\n"); return; }
  char key[129];
  hexN(g_pub, 64, key);
  Serial.printf("\nnode ID     %s\npublic key  04%s\n", g_nodeId, key);
  Serial.println("(compare with the public key you saved at setup - they must be identical)\n");
}

static void showClock() {
  uint32_t t = 0;
  int clk = rtcRead(t);
  char when[32];
  fmtTime(when, sizeof when, clk > 0 ? t : 0);
  Serial.printf("#CLOCK %lu\n", (unsigned long)(clk > 0 ? t : 0));
  if (clk < 0) Serial.println("clock: DS3231 not answering");
  else Serial.printf("clock: %s%s\n", when, clk > 0 ? " (IST)" : " - run saakshi_pull.py to set it");
}

static void setClock(uint32_t t) {
  if (t < 946684800UL || !rtcSet(t)) {       // 946684800 = 1 Jan 2000
    Serial.println("#CLOCK_FAIL");
    Serial.println("could not set the clock (give UTC seconds, e.g. clock 1790000000)");
    return;
  }
  g_nextFlags |= F_CLOCK_SET;                // the next record shows that the clock was set
  char when[32];
  fmtTime(when, sizeof when, t);
  Serial.printf("#CLOCK_SET %lu\n", (unsigned long)t);
  Serial.printf("clock set to %s (IST)\n", when);
}

static void stats() {
  uint32_t n = recordCount();
  Serial.printf("\nrecords     : %lu\n", (unsigned long)n);
  if (n > 0) {
    Record first, last;
    if (readRecord(0, first) && readRecord(n - 1, last))
      Serial.printf("seq range   : %lu..%lu\n", (unsigned long)first.seq, (unsigned long)last.seq);
  }
  Serial.printf("node ID     : %s%s\n", g_nodeId, g_eccOk ? "  (records are signed)" : "  (records are UNSIGNED)");
  uint32_t t = 0;
  int clk = rtcRead(t);
  char when[32];
  fmtTime(when, sizeof when, clk > 0 ? t : 0);
  Serial.printf("clock       : %s\n", clk < 0 ? "DS3231 not answering" : when);
  Serial.printf("BME688      : %s, fingerprint %08lx\n", g_bmeOk ? "ok" : "NOT answering",
                (unsigned long)g_lastSensorId);
  Serial.printf("MPU-6050    : %s\n", g_mpuOk ? "ok" : "NOT answering");
  Serial.printf("ethylene    : %s\n", !g_adsOk ? "not connected (no ADS1115 at 0x48)"
                : g_ethMinutes < ETH_WARM_MIN ? "connected, warming up (type eth)" : "connected (type eth)");
  Serial.printf("signing     : %lu retried, %lu failed since power-on\n",
                (unsigned long)g_signRetries, (unsigned long)g_signFails);
  Serial.printf("record size : %u bytes (%u hashed, 64 signature)\n", (unsigned)REC_SZ, (unsigned)HASH_IN);
  Serial.printf("boot id     : %lu   next seq %lu\n", (unsigned long)g_boot_id, (unsigned long)g_seq);
  Serial.printf("FFat free   : %lu bytes, room for ~%lu more records\n",
                (unsigned long)FFat.freeBytes(), (unsigned long)(FFat.freeBytes() / REC_SZ));
  printNetwork();
  Serial.println();
}

// ---------------- sync: WiFi + MQTT to saakshi_ledger.py ----------------
// Topics (the node ID comes from the ATECC608's key, the chain name from the chain's first record):
//   saakshi/<node>/status        "online chain=<c> next=<n> key=04..." (retained; "offline ..." when gone)
//   saakshi/<node>/rec/<chain>   one record per message, as the CSV line the export prints
//   saakshi/<node>/ack           from the ledger: "next=<n> chain=<c>" - it holds every seq below n
//   saakshi/<node>/cmd           from the ledger: "resend=<n> chain=<c>", "time=<unix seconds>"
// The ledger is the authority on what it holds. Records go out at most SYNC_WINDOW ahead of its last
// reply; if replies stop, the board resends from there. Duplicates are harmless - the ledger drops them.

static bool wifiConfigured() {
  return strlen(WIFI_NAME) > 0 && strcmp(WIFI_NAME, "YOUR_HOTSPOT_NAME") != 0;
}

static bool syncPossible() { return g_eccOk && wifiConfigured(); }

static void onWiFiEvent(arduino_event_id_t event, arduino_event_info_t info) {
  if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) g_wifiReason = info.wifi_sta_disconnected.reason;
  else if (event == ARDUINO_EVENT_WIFI_STA_GOT_IP) g_wifiReason = 0;
}

static const char *wifiReasonText(uint8_t why) {
  switch (why) {
    case WIFI_REASON_NO_AP_FOUND:
    case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY:
    case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD:
    case WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD:
      return "can't see the hotspot - check its name, that it's on, and (iPhone) Maximize Compatibility ON";
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_MIC_FAILURE:
    case WIFI_REASON_AUTH_FAIL:
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
      return "the hotspot refused the password - check WIFI_PASSWORD at the top of the sketch";
    case WIFI_REASON_AUTH_EXPIRE:
    case WIFI_REASON_AUTH_LEAVE:
    case WIFI_REASON_STA_LEAVING:
    case WIFI_REASON_ASSOC_TOOMANY:
      return "the hotspot didn't let the board in - open the Personal Hotspot screen on the phone and keep it open";
    case WIFI_REASON_BEACON_TIMEOUT:
      return "lost the hotspot's signal";
    default:
      return "the hotspot didn't answer";
  }
}

// Why the last TLS connection failed, in the library's words (empty if it didn't get that far).
static const char *tlsError() {
  static char buf[100];
  buf[0] = 0;
  if (g_tls) netTls.lastError(buf, sizeof buf);
  return buf;
}

static const char *mqttStateText(int st) {
  switch (st) {
    case MQTT_CONNECTION_TIMEOUT:    return "no answer";
    case MQTT_CONNECT_FAILED:        return g_tls ? "can't connect - wrong address, broker not running, or its certificate doesn't match broker_ca.h"
                                                  : "can't connect - wrong address, or no internet on the hotspot";
    case MQTT_CONNECT_BAD_PROTOCOL:
    case MQTT_CONNECT_BAD_CLIENT_ID:
    case MQTT_CONNECT_UNAVAILABLE:   return "the broker refused the connection";
    case MQTT_CONNECT_BAD_CREDENTIALS:
    case MQTT_CONNECT_UNAUTHORIZED:  return "the broker refused the login - set it with  mqttpass <password>";
    default:                         return "not connected";
  }
}

static void publishStatus(const char *state) {
  char msg[200], key[129];
  hexN(g_pub, 64, key);
  snprintf(msg, sizeof msg, "%s chain=%s next=%lu key=04%s", state, g_chainHex, (unsigned long)g_seq, key);
  mqtt.publish(t_status, msg, true);
}

// file position of the first record whose seq is >= wanted (records are stored in seq order)
static bool locateFrom(uint32_t wanted, uint32_t &idx, Record &r) {
  File f = FFat.open(CHAIN_PATH, FILE_READ);
  if (!f) return false;
  uint32_t n = f.size() / REC_SZ;
  bool found = false;
  if (n > 0 && f.read((uint8_t *)&r, REC_SZ) == REC_SZ) {
    uint32_t guess = wanted > r.seq ? wanted - r.seq : 0;    // no deletions: position = seq - first seq
    if (guess == 0) {
      idx = 0;
      found = true;
    } else if (guess < n && f.seek(guess * REC_SZ) && f.read((uint8_t *)&r, REC_SZ) == REC_SZ &&
               r.seq == wanted) {
      idx = guess;
      found = true;
    } else if (f.seek(0)) {                                  // after a deletion: search from the start
      for (uint32_t i = 0; i < n && f.read((uint8_t *)&r, REC_SZ) == REC_SZ; i++) {
        if (r.seq >= wanted) { idx = i; found = true; break; }
      }
    }
  }
  f.close();
  return found;
}

static void rewindTo(uint32_t seq) {
  g_sendSeq   = seq;
  g_cursorOk  = false;
  g_lastAckMs = millis();
}

// The ledger says where its copy ends: carry on from there.
static void ledgerPosition(uint32_t next, const char *why) {
  bool first = !g_haveAck;
  bool moved = next != g_sendSeq;
  g_haveAck      = true;
  g_ackNext      = next;
  g_stallNoted   = false;
  g_ackTimeoutMs = ACK_TIMEOUT_MS;
  g_progressSeq  = next;
  rewindTo(next);
  if (first) {
    if (next >= g_seq)
      Serial.printf("[sync] the ledger is up to date (it holds this chain up to seq %ld)\n", (long)next - 1);
    else if (next == 0)
      Serial.printf("[sync] the ledger has nothing from this chain yet - sending seq 0..%lu\n",
                    (unsigned long)(g_seq - 1));
    else
      Serial.printf("[sync] the ledger holds seq 0..%lu - sending seq %lu..%lu\n", (unsigned long)(next - 1),
                    (unsigned long)next, (unsigned long)(g_seq - 1));
    g_catchingUp = g_seq > next + 1;
  } else if (moved) {
    Serial.printf("[sync] %s - resending from seq %lu\n", why, (unsigned long)next);
  }
}

// If the board's clock was never set (or lost its time), take the laptop's time from the ledger.
static void clockFromLedger(uint32_t t) {
  uint32_t now = 0;
  int clk = rtcRead(now);
  if (clk == 0) {
    Serial.println("[sync] the board's clock is not set - taking the time from the ledger");
    setClock(t);
  } else if (clk > 0 && !g_clockNoted && (now > t + 60 || t > now + 60)) {
    g_clockNoted = true;
    Serial.printf("[sync] note: the board's clock is %ld s off the laptop's - saakshi_pull.py corrects it\n",
                  (long)now - (long)t);
  }
}

static void onMqtt(char *topic, byte *payload, unsigned int len) {
  char msg[160];
  if (len >= sizeof msg) len = sizeof msg - 1;
  memcpy(msg, payload, len);
  msg[len] = 0;
  const char *c = strstr(msg, "chain=");
  bool ours = g_chainHex[0] && c && strncmp(c + 6, g_chainHex, 8) == 0;
  const char *p;
  if (strcmp(topic, t_ack) == 0) {
    if (!ours || (p = strstr(msg, "next=")) == nullptr) return;   // about another chain
    uint32_t next = strtoul(p + 5, nullptr, 10);
    g_everSynced = true;
    if (!g_haveAck) {
      ledgerPosition(next, "");                                   // where to start after connecting
    } else if (next > g_ackNext) {                                // normal progress
      g_ackNext      = next;
      g_lastAckMs    = millis();
      g_stallNoted   = false;
      g_ackTimeoutMs = ACK_TIMEOUT_MS;
      if (g_window < SYNC_WINDOW) g_window += 5;                  // replies are coming: send more again
      if (next > g_sendSeq) rewindTo(next);
    }
  } else if (strcmp(topic, t_cmd) == 0) {
    if (ours && (p = strstr(msg, "resend=")) != nullptr)
      ledgerPosition(strtoul(p + 7, nullptr, 10), "the ledger asked for records it missed");
    if ((p = strstr(msg, "time=")) != nullptr) clockFromLedger(strtoul(p + 5, nullptr, 10));
  }
}

static bool mqttConnect() {
  char clientId[40], will[40];
  snprintf(clientId, sizeof clientId, "saakshi-%s", g_nodeId);
  snprintf(will, sizeof will, "offline chain=%s", g_chainHex);
  mqtt.setServer(g_broker, g_port);
  bool ok = g_mqPass[0] ? mqtt.connect(clientId, g_nodeId, g_mqPass, t_status, 1, true, will)
                        : mqtt.connect(clientId, t_status, 1, true, will);
  if (!ok) return false;
  mqtt.subscribe(t_ack, 1);
  mqtt.subscribe(t_cmd, 1);
  g_haveAck = false;
  g_waitNoted = false;
  g_lastAckMs = millis();
  publishStatus("online");
  Serial.printf("[sync] connected to broker %s:%u as %s (%s), chain %s - %lu record(s) on the board\n",
                g_broker, (unsigned)g_port, g_nodeId, g_tls ? "encrypted, TLS" : "NOT encrypted",
                g_chainHex, (unsigned long)recordCount());
  return true;
}

// Room in the connection for a whole batch right now? Never wait: on a slow link the board must keep
// logging. (lwIP reports "writable" only when more than ~2.8 KB is free - one batch always fits.)
static bool roomToSend() {
  int fd = g_tls ? netTls.fd() : netPlain.fd();
  if (fd < 0) return g_tls && netTls.connected();   // a TLS client that doesn't show its socket: just send
  fd_set set;
  FD_ZERO(&set);
  FD_SET(fd, &set);
  struct timeval tv = {0, 0};
  return select(fd + 1, nullptr, &set, nullptr, &tv) > 0 && FD_ISSET(fd, &set);
}

// Records g_sendSeq.. as one message: as many CSV lines as fit in BATCH_BYTES, one per line.
static bool sendBatch() {
  if (g_sendSeq >= g_seq) {                                  // everything written has gone out
    if (g_catchingUp) {
      g_catchingUp = false;
      Serial.println("[sync] backlog sent");
    }
    return false;
  }
  uint32_t limit = g_ackNext + g_window;
  if (g_sendSeq >= limit || !roomToSend()) return false;     // wait for replies, or for room
  static char batch[BATCH_BYTES + 1];
  size_t used = 0;
  uint32_t count = 0, firstSeq = 0, lastSeq = 0, cursor = g_cursor;
  bool located = g_cursorOk;
  Record r;
  char line[ROW_MAX];
  while (used < BATCH_BYTES) {
    if (!located) {
      if (!locateFrom(g_sendSeq, cursor, r)) break;
      located = true;
    } else if (!readRecord(cursor, r) || r.seq < g_sendSeq) {
      g_cursorOk = false;                                    // the file changed under us: look again
      break;
    }
    if (r.seq >= limit || (count > 0 && r.seq != lastSeq + 1)) break;   // window full, or a hole: next time
    formatRow(r, line, sizeof line);
    size_t len = strlen(line);
    if (used + len + (count ? 1 : 0) > BATCH_BYTES) break;
    if (count) batch[used++] = '\n';
    memcpy(batch + used, line, len);
    used += len;
    if (count == 0) firstSeq = r.seq;
    lastSeq = r.seq;
    count++;
    cursor++;
    if (r.seq + 1 >= g_seq) break;                           // that was the newest record
  }
  if (count == 0) return false;
  batch[used] = 0;
  if (!mqtt.publish(t_rec, (const uint8_t *)batch, used, false)) {
    // Only part of the message went out: the connection can't be trusted any more. Drop it; after
    // reconnecting, the ledger says where its copy ends and the board carries on from there.
    g_slowNotes++;
    Serial.printf("[sync] the connection is too slow - reconnecting (nothing is lost; seq %lu..%lu go again)\n",
                  (unsigned long)firstSeq, (unsigned long)lastSeq);
    if (g_tls) netTls.stop(); else netPlain.stop();
    g_cursorOk = false;
    g_haveAck = false;
    g_lastMqttTry = millis();                                // give the link a few seconds first
    g_mqttRetryMs = 5000;
    return false;
  }
  g_sendSeq = lastSeq + 1;
  g_cursor = cursor;
  g_cursorOk = true;
  g_sentCount += count;
  if (g_catchingUp && lastSeq >= g_progressSeq + 200) {     // a long backlog: say how far it got
    g_progressSeq = lastSeq;
    Serial.printf("[sync] ... sent up to seq %lu of %lu\n", (unsigned long)lastSeq, (unsigned long)(g_seq - 1));
  }
  return true;
}

static void syncTask() {
  if (!g_netOn || !syncPossible()) return;
  unsigned long now = millis();

  if (WiFi.status() != WL_CONNECTED) {
    if (g_wifiUp) {
      g_wifiUp = false;
      g_haveAck = false;
      g_joinNoteMs = 0;
      Serial.println("[sync] WiFi lost - records keep chaining on flash and go out when it's back");
    }
    uint8_t why = g_wifiReason;
    if (why && why != WIFI_REASON_ASSOC_LEAVE && (g_joinNoteMs == 0 || now - g_joinNoteMs > 30000)) {
      g_joinNoteMs = now ? now : 1;                          // one message per 30 s, not one per try
      Serial.printf("[sync] can't join \"%s\" yet: %s (reason %u) - still trying\n", WIFI_NAME,
                    wifiReasonText(why), (unsigned)why);
    }
    if (now - g_lastWifiTry > 30000) {                       // nudge the driver now and then
      g_lastWifiTry = now;
      WiFi.disconnect();
      WiFi.begin(WIFI_NAME, WIFI_PASSWORD);
    }
    return;
  }
  if (!g_wifiUp) {
    g_wifiUp = true;
    g_joinNoteMs = 0;
    g_lastMqttTry = 0;
    g_mqttRetryMs = 5000;
    Serial.printf("[sync] WiFi connected to \"%s\", IP %s\n", WIFI_NAME, WiFi.localIP().toString().c_str());
    if (!g_ntpAsked) {                                       // internet time, if the hotspot has internet
      g_ntpAsked = true;
      configTime(0, 0, "pool.ntp.org", "time.google.com");
    }
  }
  if (g_ntpAsked && !g_ntpDone && time(nullptr) > 1700000000) {
    g_ntpDone = true;
    uint32_t ntp = (uint32_t)time(nullptr), rtc = 0;
    int clk = rtcRead(rtc);
    if (clk == 0 || (clk > 0 && (rtc > ntp + 120 || ntp > rtc + 120))) {
      Serial.printf("[sync] internet time received - %s the board's clock\n", clk == 0 ? "setting" : "correcting");
      setClock(ntp);
    }
  }

  if (!mqtt.connected()) {
    if (g_haveAck) {
      g_haveAck = false;
      Serial.println("[sync] lost the broker - reconnecting");
    }
    if (!g_chainHex[0]) return;                              // nothing logged on this chain yet
    if (g_lastMqttTry != 0 && now - g_lastMqttTry < g_mqttRetryMs) return;
    g_lastMqttTry = now ? now : 1;
    if (!mqttConnect()) {
      if (!g_brokerNoted) {
        g_brokerNoted = true;
        const char *te = tlsError();
        Serial.printf("[sync] broker %s:%u: %s%s%s - will keep trying\n", g_broker, (unsigned)g_port,
                      mqttStateText(mqtt.state()), te[0] ? " | TLS: " : "", te);
      }
      if (g_mqttRetryMs < 60000) g_mqttRetryMs *= 2;         // back off: a failed try blocks for a moment
      return;
    }
    g_brokerNoted = false;
    g_mqttRetryMs = 5000;
  }
  mqtt.loop();
  now = millis();                                            // the ledger's replies just moved the timers on

  if (!g_haveAck) {
    if (!g_waitNoted && !g_everSynced && now - g_lastAckMs > 10000) {
      g_waitNoted = true;
      Serial.println("[sync] waiting for the ledger - run  python3 saakshi_ledger.py  on the laptop");
    }
    return;
  }
  if (g_sendSeq > g_ackNext && now - g_lastAckMs > g_ackTimeoutMs && !roomToSend()) {
    g_lastAckMs = now;               // our records are still queued on a slow link: TCP will deliver them
  } else if (g_sendSeq > g_ackNext && now - g_lastAckMs > g_ackTimeoutMs) {
    if (!g_stallNoted) {
      g_stallNoted = true;
      Serial.printf("[sync] no reply from the ledger for %lu s - resending from seq %lu, one batch at a time\n",
                    g_ackTimeoutMs / 1000, (unsigned long)g_ackNext);
    }
    rewindTo(g_ackNext);
    g_window = 5;                                            // a slow link: don't pile on more
    if (g_ackTimeoutMs < 120000) g_ackTimeoutMs *= 2;        // ledger gone? try less and less often
  }
  sendBatch();
}

// Which connection MQTT uses: encrypted (TLS, needs broker_ca.h) or plain.
static void applyTransport() {
  if (g_tls && !CA_PEM) {
    g_tls = false;
    Serial.println("TLS needs broker_ca.h in the sketch folder (python3 saakshi_broker.py setup) - using plain MQTT");
  }
  if (g_tls) {
    netTls.setCACert(CA_PEM);               // only a broker signed by YOUR authority is accepted
    netTls.setConnectionTimeout(4000);      // an unreachable broker must not stall logging for long
    netTls.setHandshakeTimeout(15);
    mqtt.setClient(netTls);
  } else {
    netPlain.setConnectionTimeout(4000);
    mqtt.setClient(netPlain);
  }
}

static void loadNetSettings() {
  g_tls = CA_PEM != nullptr;                // encrypted by default whenever the board has a CA
  if (prefs.begin("saakshi", true)) {
    String b = prefs.getString("broker", "");
    if (b.length() > 0 && b.length() < sizeof g_broker) strcpy(g_broker, b.c_str());
    g_tls = prefs.getBool("tls", g_tls);
    String p = prefs.getString("mqpass", "");
    if (p.length() > 0 && p.length() < sizeof g_mqPass) strcpy(g_mqPass, p.c_str());
    g_port = prefs.getUShort("port", 0);
    prefs.end();
  }
  applyTransport();
  if (g_port == 0) g_port = g_tls ? PORT_TLS : PORT_PLAIN;
}

static void startNetwork() {
  mqtt.setCallback(onMqtt);
  mqtt.setBufferSize(BATCH_BYTES + 200);
  mqtt.setKeepAlive(60);                    // a patchy mobile uplink can stall for a while
  mqtt.setSocketTimeout(5);
  loadNetSettings();
  snprintf(t_status, sizeof t_status, "saakshi/%s/status", g_nodeId);
  snprintf(t_ack, sizeof t_ack, "saakshi/%s/ack", g_nodeId);
  snprintf(t_cmd, sizeof t_cmd, "saakshi/%s/cmd", g_nodeId);
  snprintf(t_rec, sizeof t_rec, "saakshi/%s/rec/%s", g_nodeId, g_chainHex);
  if (!g_eccOk) {
    Serial.println("sync is off - it needs the ATECC608's identity");
    return;
  }
  if (!wifiConfigured()) {
    Serial.println("sync is off - type your hotspot name and password at the top of the sketch and upload again");
    return;
  }
  if (!g_netStarted) {
    WiFi.onEvent(onWiFiEvent);
    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(true);
    WiFi.begin(WIFI_NAME, WIFI_PASSWORD);
    g_lastWifiTry = millis();
    g_netStarted = true;
  }
  Serial.printf("joining WiFi \"%s\", then broker %s:%u (%s%s) ...\n", WIFI_NAME, g_broker, (unsigned)g_port,
                g_tls ? "encrypted" : "NOT encrypted", g_mqPass[0] ? ", with login" : ", no login");
}

static void printNetwork() {
  if (!g_eccOk) { Serial.println("sync        : off - needs the ATECC608's identity"); return; }
  if (!wifiConfigured()) { Serial.println("sync        : off - no hotspot name/password at the top of the sketch"); return; }
  if (!g_netOn)
    Serial.println("WiFi        : OFF (you typed offline) - type online");
  else if (WiFi.status() == WL_CONNECTED)
    Serial.printf("WiFi        : \"%s\", IP %s, signal %d dBm\n", WIFI_NAME, WiFi.localIP().toString().c_str(),
                  (int)WiFi.RSSI());
  else
    Serial.printf("WiFi        : looking for \"%s\"%s%s\n", WIFI_NAME, g_wifiReason ? " - " : "",
                  g_wifiReason ? wifiReasonText(g_wifiReason) : "");
  Serial.printf("broker      : %s:%u, %s\n", g_broker, (unsigned)g_port, mqtt.connected() ? "connected" : "not connected");
  Serial.printf("encryption  : %s\n", g_tls ? "TLS - records are encrypted on the way" :
                CA_PEM ? "OFF (tls off was typed) - type  tls on" : "OFF - no broker_ca.h in the sketch folder");
  Serial.printf("login       : %s\n", g_mqPass[0] ? g_nodeId : "none (set with  mqttpass <password>)");
  Serial.printf("chain       : %s\n", g_chainHex[0] ? g_chainHex : "(empty - the next record starts one)");
  if (!mqtt.connected() || !g_haveAck) {
    Serial.printf("ledger      : no reply yet - %lu record(s) on the board\n", (unsigned long)g_seq);
  } else {
    uint32_t left = g_seq > g_ackNext ? g_seq - g_ackNext : 0;
    if (g_ackNext == 0) Serial.printf("ledger      : holds nothing yet, %lu to send\n", (unsigned long)left);
    else Serial.printf("ledger      : holds seq 0..%lu, %lu still to send\n", (unsigned long)(g_ackNext - 1),
                       (unsigned long)left);
  }
  Serial.printf("sent        : %lu record(s) since power-on%s\n", (unsigned long)g_sentCount,
                g_slowNotes ? " (the link was slow at times - reconnected cleanly)" : "");
}

static void setNetwork(bool on) {
  if (!syncPossible()) { printNetwork(); Serial.println(); return; }
  if (on == g_netOn) { Serial.println(on ? "already online\n" : "already offline\n"); return; }
  g_netOn = on;
  if (!on) {
    if (mqtt.connected()) {
      publishStatus("offline");
      mqtt.disconnect();
    }
    WiFi.disconnect();
    g_wifiUp = false;
    g_haveAck = false;
    Serial.println("\n[sync] OFFLINE, like losing signal. Records keep chaining on flash. Type online to reconnect.\n");
  } else {
    g_lastWifiTry = millis();
    WiFi.begin(WIFI_NAME, WIFI_PASSWORD);
    Serial.println("\n[sync] reconnecting...\n");
  }
}

static void reconnectBroker() {
  if (mqtt.connected()) {
    publishStatus("offline");
    mqtt.disconnect();
  }
  g_haveAck = false;
  g_lastMqttTry = 0;
  g_mqttRetryMs = 5000;
  g_brokerNoted = false;
}

static void setBroker(String host) {
  if (host.length() == 0) {
    Serial.printf("broker: %s:%u   (change it with:  broker <address>[:port]   or  broker default)\n\n", g_broker,
                  (unsigned)g_port);
    return;
  }
  uint16_t port = 0;
  if (host == "default") host = DEFAULT_BROKER;
  int colon = host.lastIndexOf(':');
  if (colon > 0) {
    long p = host.substring(colon + 1).toInt();
    if (p <= 0 || p > 65535) { Serial.println("that port is not a number from 1 to 65535\n"); return; }
    port = (uint16_t)p;
    host = host.substring(0, colon);
  }
  if (host.length() == 0 || host.length() >= sizeof g_broker || host.indexOf(' ') >= 0) {
    Serial.println("that doesn't look like a broker address\n");
    return;
  }
  strcpy(g_broker, host.c_str());
  g_port = port ? port : (g_tls ? PORT_TLS : PORT_PLAIN);
  if (prefs.begin("saakshi", false)) {
    prefs.putString("broker", g_broker);
    prefs.putUShort("port", port);           // 0 = the usual port for TLS / plain
    prefs.end();
  }
  reconnectBroker();
  Serial.printf("broker set to %s:%u (saved)\n\n", g_broker, (unsigned)g_port);
}

static void setMqttPass(String pw) {
  if (pw.length() == 0) {
    Serial.printf("login: %s\n\n", g_mqPass[0] ? "set (user = node ID)" : "none - set with  mqttpass <password>");
    return;
  }
  if (pw == "clear") pw = "";
  if (pw.length() >= sizeof g_mqPass || pw.indexOf(' ') >= 0) {
    Serial.println("the password must be one word, at most 64 characters\n");
    return;
  }
  strcpy(g_mqPass, pw.c_str());
  if (prefs.begin("saakshi", false)) {
    prefs.putString("mqpass", g_mqPass);
    prefs.end();
  }
  reconnectBroker();
  Serial.printf(g_mqPass[0] ? "broker login saved: user %s\n\n" : "broker login cleared\n\n", g_nodeId);
}

static void setTls(String arg) {
  if (arg != "on" && arg != "off") {
    Serial.printf("encryption: %s   (tls on / tls off)\n\n", g_tls ? "TLS on" : "off");
    return;
  }
  bool want = arg == "on";
  if (want && !CA_PEM) {
    Serial.println("can't: no broker_ca.h in the sketch folder - run  python3 saakshi_broker.py setup  and upload again\n");
    return;
  }
  reconnectBroker();
  if (g_tls) netTls.stop(); else netPlain.stop();
  bool portWasDefault = g_port == (g_tls ? PORT_TLS : PORT_PLAIN);
  g_tls = want;
  applyTransport();
  if (portWasDefault) g_port = g_tls ? PORT_TLS : PORT_PLAIN;
  if (prefs.begin("saakshi", false)) {
    prefs.putBool("tls", g_tls);
    prefs.end();
  }
  Serial.printf("encryption %s (saved) - broker %s:%u\n%s\n", g_tls ? "ON (TLS)" : "OFF",
                g_broker, (unsigned)g_port, g_tls ? "" : "records now travel readable - use this only to troubleshoot\n");
}

// ---------------- tamper demo ----------------
// These edit flash directly, the way an attacker with the board in hand would - but without the
// ATECC608's private key, which nobody can take out of the chip. So none of them can make a new signature.

static void attackEdit(uint32_t seq) {
  uint32_t idx;
  Record r;
  if (!findSeq(seq, idx, r)) { Serial.printf("no record with seq %lu\n\n", (unsigned long)seq); return; }
  int32_t before = r.temp_mc;
  r.temp_mc -= 5000;                         // hide an excursion: report 5 C colder
  if (!writeRecordAt(idx, r)) { Serial.println("flash write failed\n"); return; }
  updateChainId();
  Serial.printf("\nATTACK 1 on seq %lu: temperature %.3f C -> %.3f C, hash and signature left alone\n",
                (unsigned long)seq, before / 1000.0, r.temp_mc / 1000.0);
  Serial.println("now run v\n");
}

// The smartest attack without the chip: change a reading, then rebuild every hash after it so the
// chain links up perfectly again. Only the signatures still point to the truth.
static void attackRewrite(uint32_t seq) {
  uint32_t idx;
  Record r;
  if (!findSeq(seq, idx, r)) { Serial.printf("no record with seq %lu\n\n", (unsigned long)seq); return; }
  uint32_t n = recordCount();
  File f = FFat.open(CHAIN_PATH, "r+");
  if (!f) { Serial.println("cannot open chain\n"); return; }
  int32_t before = r.temp_mc, after = r.temp_mc - 5000;
  uint8_t prev[32];
  uint32_t rebuilt = 0;
  for (uint32_t i = idx; i < n; i++) {
    if (!f.seek(i * REC_SZ) || f.read((uint8_t *)&r, REC_SZ) != REC_SZ) break;
    if (i == idx) r.temp_mc = after;
    else memcpy(r.prev_hash, prev, 32);
    computeHash(r, r.hash);                  // signature left as it was: no chip, no new signature
    memcpy(prev, r.hash, 32);
    if (!f.seek(i * REC_SZ) || f.write((const uint8_t *)&r, REC_SZ) != REC_SZ) break;
    rebuilt++;
  }
  f.close();
  loadTail();                                // carry on from the rewritten chain, as after a restart
  updateChainId();
  Serial.printf("\nATTACK 2 on seq %lu: temperature %.3f C -> %.3f C, then %lu hash(es) rebuilt so every link fits\n",
                (unsigned long)seq, before / 1000.0, after / 1000.0, (unsigned long)rebuilt);
  Serial.println("the hash chain alone now looks perfect - run v to see the signatures\n");
}

static void attackDelete(uint32_t seq) {
  uint32_t idx;
  Record r;
  if (!findSeq(seq, idx, r)) { Serial.printf("no record with seq %lu\n\n", (unsigned long)seq); return; }
  uint32_t n = recordCount();
  File src = FFat.open(CHAIN_PATH, FILE_READ);
  File dst = FFat.open(TMP_PATH, FILE_WRITE);
  if (!src || !dst) {
    if (src) src.close();
    if (dst) dst.close();
    Serial.println("cannot rewrite the chain file\n");
    return;
  }
  uint32_t kept = 0;
  for (uint32_t i = 0; i < n; i++) {
    if (src.read((uint8_t *)&r, REC_SZ) != REC_SZ) break;
    if (i == idx) continue;
    dst.write((const uint8_t *)&r, REC_SZ);
    kept++;
  }
  src.close();
  dst.close();
  FFat.remove(CHAIN_PATH);
  if (!FFat.rename(TMP_PATH, CHAIN_PATH)) { Serial.println("rename failed - chain is in /chain4.tmp\n"); return; }
  updateChainId();
  Serial.printf("\nATTACK 3: seq %lu deleted, %lu records left\n", (unsigned long)seq, (unsigned long)kept);
  Serial.println("now run v\n");
}

// A fake "everything was fine" reading added at the end. Its hash and link are right; its signature is
// copied from the previous record, because a new one can't be made without the chip.
static void attackForge() {
  uint32_t n = recordCount();
  Record last;
  if (n == 0 || !readRecord(n - 1, last)) { Serial.println("chain is empty\n"); return; }
  Record r = last;
  r.seq = last.seq + 1;
  r.uptime_s = last.uptime_s;               // v8: the ethylene reading, copied
  if (r.unix_time) r.unix_time += LOG_PERIOD_MS / 1000;
  r.temp_mc = 4000;                          // a perfect cold-chain reading
  r.flags = last.flags & (F_NO_TIME | F_ETHYLENE | F_ETH_NONE | F_ETH_WARMUP);
  r.peak_mg = 0;
  r.moves = 0;
  memcpy(r.prev_hash, last.hash, 32);
  computeHash(r, r.hash);
  memcpy(r.sig, last.sig, 64);
  if (!appendRecord(r)) { Serial.println("flash write failed\n"); return; }
  loadTail();
  updateChainId();
  Serial.printf("\nATTACK 4: forged seq %lu reading 4.000 C, hash and link correct, signature copied\n",
                (unsigned long)r.seq);
  Serial.println("now run v\n");
}

// ---------------- console ----------------

static void clearChain() {
  FFat.remove(CHAIN_PATH);
  if (FFat.exists(TMP_PATH)) FFat.remove(TMP_PATH);
  g_seq = 0;
  memset(g_lastHash, 0, 32);
  updateChainId();
  Serial.println("chain cleared - the next record starts a new chain\n");
}

static void help() {
  Serial.println(
    "\ncommands:\n"
    "  h            this help\n"
    "  s            status: records, identity, clock, sensors, network\n"
    "  w            network and sync status\n"
    "  offline      drop WiFi, like losing signal;  online  reconnects\n"
    "  broker       show the MQTT broker;  broker <address>[:port] changes it\n"
    "  mqttpass     mqttpass <password>: this node's broker login (saved)\n"
    "  tls          show encryption;  tls on / tls off\n"
    "  i            this node's identity (node ID and public key)\n"
    "  d [n]        show the last n records (default 10)\n"
    "  x            export the whole chain as CSV\n"
    "  v            verify the whole chain and every signature\n"
    "  clock        show the clock (saakshi_pull.py sets it)\n"
    "  eth          ethylene: voltages, ppm, warm-up;  ethzero  (clean air = 0 ppm)\n"
    "  ethspan <p>  ethylene: calibrate with a known gas of <p> ppm;  ethready  (already warmed up)\n"
    "  t <seq>      attack 1: edit a temperature, leave hash and signature\n"
    "  r <seq>      attack 2: edit a temperature and rebuild every hash after it\n"
    "  k <seq>      attack 3: delete a record\n"
    "  f            attack 4: forge an 'all fine' record at the end\n"
    "  clear        delete the whole chain\n");
}

// The argument must be a plain number: "t N" or "t abc" is refused instead of being read as 0.
static bool isNumber(const String &s) {
  if (s.length() == 0 || s.length() > 10) return false;
  for (unsigned int i = 0; i < s.length(); i++)
    if (s.charAt(i) < '0' || s.charAt(i) > '9') return false;
  return true;
}

static bool haveSeq(const String &arg) {
  if (isNumber(arg)) return true;
  if (arg.length()) Serial.printf("\"%s\" is not a sequence number - type the number itself, e.g.  t 12\n", arg.c_str());
  else Serial.println("give a sequence number, e.g.  t 12   (d shows the latest ones)");
  Serial.println();
  return false;
}

static void handleCommand(String line) {
  line.trim();
  if (line.length() == 0) return;
  int space = line.indexOf(' ');
  String word = space < 0 ? line : line.substring(0, space);
  String rest = space < 0 ? String("") : line.substring(space + 1);
  word.toLowerCase();
  rest.trim();
  bool hasArg = rest.length() > 0;
  uint32_t arg = (uint32_t)strtoul(rest.c_str(), nullptr, 10);

  if (word == "h" || word == "help") help();
  else if (word == "s") stats();
  else if (word == "w") { Serial.println(); printNetwork(); Serial.println(); }
  else if (word == "offline") setNetwork(false);
  else if (word == "online") setNetwork(true);
  else if (word == "broker") setBroker(rest);
  else if (word == "mqttpass") setMqttPass(rest);
  else if (word == "tls") { rest.toLowerCase(); setTls(rest); }
  else if (word == "i") identity();
  else if (word == "d") {
    uint32_t n = hasArg && arg > 0 ? arg : 10, total = recordCount();
    Serial.printf("\n--- last %lu of %lu records ---\n", (unsigned long)(n < total ? n : total), (unsigned long)total);
    for (uint32_t i = total > n ? total - n : 0; i < total; i++) {
      Record r;
      if (readRecord(i, r)) showRecord(r, "  ");
    }
    Serial.println();
  }
  else if (word == "x") exportCSV();
  else if (word == "v") verifyChain();
  else if (word == "clock") { if (!hasArg) showClock(); else if (isNumber(rest)) setClock(arg); else setClock(0); }
  else if (word == "t") { if (haveSeq(rest)) attackEdit(arg); }
  else if (word == "r") { if (haveSeq(rest)) attackRewrite(arg); }
  else if (word == "k") { if (haveSeq(rest)) attackDelete(arg); }
  else if (word == "f") attackForge();
  else if (word == "clear") clearChain();
  else if (word == "eth") ethShow();
  else if (word == "ethzero") ethZero();
  else if (word == "ethspan") ethSpan(rest.toFloat());
  else if (word == "ethready") ethReady();
  else Serial.println("unknown command - try h");
}

// ---------------- setup / loop ----------------

void setup() {
  Serial.begin(115200);
  delay(3000);
  Serial.println("\n=== SAAKSHI node v8 - signed records + encrypted sync + ethylene ===");

  if (!FFat.begin(true)) {
    Serial.println("FFat mount FAILED");
    Serial.println("Tools > Partition Scheme must be '16M Flash (3MB APP/9.9MB FATFS)'");
    while (1) delay(1000);
  }
  if (FFat.exists(TMP_PATH)) FFat.remove(TMP_PATH);   // left over from an interrupted delete

  prefs.begin("saakshi", false);
  g_boot_id = prefs.getUInt("boot", 0) + 1;
  prefs.putUInt("boot", g_boot_id);
  prefs.end();

#ifdef WIRE_HAS_BUFFER_SIZE
  Wire.setBufferSize(256);
#endif
  Wire.begin(SDA_PIN, SCL_PIN);
  Wire.setClock(BUS_HZ);

  for (int attempt = 0; attempt < 3; attempt++) {    // a chip still waking up gets two more chances
    if (attempt) delay(300);
    initIdentity(attempt < 2);
    if (g_eccOk) break;
  }
  g_lastEccTry = millis();
  g_bmeOk = bme.begin(BME_ADDR);
  if (g_bmeOk) configureSensor();
  else Serial.println("BME688 not found at 0x76 - logging SENSOR FAIL records until it answers");
  if (!mpuInit()) Serial.println("MPU-6050 not found at 0x69 - no movement data");
  ethLoad();
  float ev;
  g_adsOk = ethVolts(ev);
  Serial.println(g_adsOk ? "ethylene sensor (ADS1115 at 0x48) found" : "no ethylene sensor yet (ADS1115 at 0x48) - records say 'not connected' until it answers");
  uint32_t t = 0;
  int clk = rtcRead(t);
  if (clk < 0) Serial.println("DS3231 not answering - records will have no time");
  else if (clk == 0) Serial.println("clock not set yet - run saakshi_pull.py once and it sets it");

  loadTail();
  updateChainId();
  g_nextFlags |= F_BOOT;
  Serial.printf("node %s, boot #%lu, resuming at seq %lu, %lu records on flash, chain %s\n", g_nodeId,
                (unsigned long)g_boot_id, (unsigned long)g_seq, (unsigned long)recordCount(),
                g_chainHex[0] ? g_chainHex : "(new)");
  help();
  startNetwork();
}

void loop() {
  if (Serial.available()) handleCommand(Serial.readStringUntil('\n'));
  sampleMotion();
  unsigned long now = millis();
  bool shockNow = g_shockPending && now - g_lastShockLog >= SHOCK_GAP_MS;
  if (now - g_lastLog >= LOG_PERIOD_MS || shockNow) {
    g_lastLog = now;
    if (shockNow) g_lastShockLog = now;
    logReading(shockNow);
  }
  if (!g_eccOk && now - g_lastEccTry >= 20000) {      // chip missed at boot: keep trying, quietly
    g_lastEccTry = now;
    initIdentity(true);
    if (g_eccOk) {
      Serial.printf("ATECC608 answered - node %s, records are signed again\n", g_nodeId);
      startNetwork();                                  // sync needs the identity: start it now
    }
  }
  syncTask();
}
