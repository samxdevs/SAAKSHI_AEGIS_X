/*
 * SAAKSHI - ATECC608 + MPU-6050 check. READ-ONLY: it writes nothing to any chip, so it is safe on a locked chip.
 * (Unlike the ArduinoECCX08 example sketches, which can change or lock a chip - never run those.)
 *
 * Prints: every I2C device on the bus, whether the ATECC608 answers, whether it is set up (locked),
 * and if so its node ID - so you can tell your original chip (SAAKSHI-25D8016E) from the spare.
 * Same wiring as the node: SDA = GPIO 8, SCL = GPIO 9. Serial Monitor at 115200.
 */
#include <Wire.h>
#include <ArduinoECCX08.h>
#include "mbedtls/sha256.h"

#define SDA_PIN 8
#define SCL_PIN 9
static const char *ORIGINAL_NODE = "SAAKSHI-25D8016E";

static bool readReg(uint8_t addr, uint8_t reg, uint8_t &val) {
  Wire.beginTransmission(addr);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) return false;
  if (Wire.requestFrom(addr, (uint8_t)1) != 1) return false;
  val = Wire.read();
  return true;
}

// Known "who am I" answers: MPU-6050 = 0x68; common clones/relatives: 0x70 (MPU-6500), 0x71/0x73 (MPU-9250/9255),
// 0x98, 0x19, 0x72. The DS3231 clock has no register 0x75, so it gives none of these as a rule.
static bool looksLikeMpu(uint8_t who) {
  return who == 0x68 || who == 0x70 || who == 0x71 || who == 0x72 || who == 0x73 || who == 0x98 || who == 0x19;
}

static void checkMpu() {
  Serial.println("\n--- MPU-6050 (motion sensor) ---");
  uint8_t who;
  if (readReg(0x69, 0x75, who)) {
    Serial.printf("at 0x69: answers, WHO_AM_I = 0x%02X%s\n", who, looksLikeMpu(who) ? "" : " (unusual value - still usable)");
    Serial.println("=> MPU found where the firmware expects it. Movement and jolt data will work.");
    return;
  }
  Serial.println("at 0x69: nothing answers");
  if (readReg(0x68, 0x75, who) && looksLikeMpu(who)) {
    Serial.printf("at 0x68: something answers WHO_AM_I = 0x%02X, like an MPU\n", who);
    Serial.println("=> the MPU is probably sitting at 0x68, on top of the DS3231 clock: AD0 is NOT connected to 3V3.");
    Serial.println("   Connect the MPU's AD0 pin to 3V3, then run this again - it should move to 0x69.");
  } else {
    Serial.println("at 0x68: only the DS3231 clock (no MPU answer)");
    Serial.println("=> the MPU isn't on the bus at all. Check, with the board unplugged:");
    Serial.println("   VCC -> 3V3, GND -> GND, SDA -> GPIO 8, SCL -> GPIO 9 (not swapped), AD0 -> 3V3");
    Serial.println("   and that the module's power LED is on.");
  }
}

static void checkAtecc();

void setup() {
  Serial.begin(115200);
  delay(2500);
  Serial.println("\n=== SAAKSHI ATECC608 + MPU check (read-only - changes nothing) ===");

  Wire.begin(SDA_PIN, SCL_PIN);
  Wire.setClock(100000);
  Serial.print("I2C devices found:");
  int n = 0;
  for (uint8_t a = 1; a < 127; a++) {
    Wire.beginTransmission(a);
    if (Wire.endTransmission() == 0) { Serial.printf(" 0x%02X", a); n++; }
  }
  Serial.println(n ? "" : " none - check SDA/SCL wiring and 3V3/GND");
  Serial.println("expected:          0x60 ATECC608, 0x68 DS3231, 0x69 MPU-6050, 0x76 BME688");
  checkAtecc();
  Wire.setClock(100000);
  checkMpu();
}

static void checkAtecc() {
  Serial.println("\n--- ATECC608 (security chip) ---");
  bool ok = false;
  for (int attempt = 1; attempt <= 3 && !ok; attempt++) {
    ok = ECCX08.begin();
    if (!ok) delay(600);
  }
  Wire.setClock(100000);
  if (!ok) {
    Serial.println("ATECC608: NOT ANSWERING - check its wiring (SDA, SCL, 3V3, GND); if wiring is right, the chip may be damaged");
    return;
  }
  Serial.print("ATECC608 serial number: ");
  Serial.println(ECCX08.serialNumber());

  bool locked = ECCX08.locked();
  Serial.printf("set up (locked):        %s\n", locked ? "YES" : "NO - this chip has never been set up");
  if (!locked) {
    Serial.println("\n=> a fresh chip (probably the spare). Don't set it up yet - tell Claude first.");
    return;
  }

  uint8_t pub[64];
  if (!ECCX08.generatePublicKey(0, pub)) {   // computes the public key from the stored private key; writes nothing
    Serial.println("could not read the key from slot 0");
    return;
  }
  uint8_t point[65], h[32];
  point[0] = 0x04;
  memcpy(point + 1, pub, 64);
  mbedtls_sha256(point, sizeof point, h, 0);
  char node[20];
  snprintf(node, sizeof node, "SAAKSHI-%02X%02X%02X%02X", h[0], h[1], h[2], h[3]);
  Serial.printf("node ID:                %s\n", node);
  Serial.print("public key:             04");
  for (int i = 0; i < 64; i++) Serial.printf("%02X", pub[i]);
  Serial.println();
  if (strcmp(node, ORIGINAL_NODE) == 0)
    Serial.println("\n=> this is your ORIGINAL chip - same identity as before, registered on Polygon. Good.");
  else
    Serial.println("\n=> a set-up chip, but NOT the original SAAKSHI-25D8016E. Send this output to Claude.");
}

void loop() {}
