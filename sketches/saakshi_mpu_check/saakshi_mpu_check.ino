/*
 * SAAKSHI - MPU-6050 check. Finds the motion sensor and shows live readings.
 * Touches only the MPU-6050 (wakes it to read movement). The ATECC608 is never touched.
 *
 * Wiring (YD-ESP32-S3): VCC->3V3  GND->GND  SDA->GPIO 8  SCL->GPIO 9  AD0->3V3  INT->GPIO 7
 * Serial Monitor at 115200. Tilt or tap the board and watch the numbers change.
 */
#include <Wire.h>

#define SDA_PIN 8
#define SCL_PIN 9
#define WHO_AM_I 0x75
#define PWR_MGMT_1 0x6B
#define ACCEL_XOUT_H 0x3B

static uint8_t mpuAddr = 0;

static bool readReg(uint8_t addr, uint8_t reg, uint8_t *buf, uint8_t n) {
  Wire.beginTransmission(addr);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) return false;
  if (Wire.requestFrom(addr, n) != n) return false;
  for (uint8_t i = 0; i < n; i++) buf[i] = Wire.read();
  return true;
}

static const char *whoName(uint8_t v) {
  switch (v) {
    case 0x68: return "MPU-6050 (genuine ID)";
    case 0x70: return "MPU-6500 (works the same for SAAKSHI)";
    case 0x71: case 0x73: return "MPU-9250/9255 (works the same for SAAKSHI)";
    case 0x72: case 0x98: case 0x19: return "MPU-6050 clone (usually works)";
    default: return "not an MPU";
  }
}

void setup() {
  Serial.begin(115200);
  delay(2500);
  Serial.println("\n=== SAAKSHI MPU-6050 check ===");
  Wire.begin(SDA_PIN, SCL_PIN);
  Wire.setClock(100000);

  uint8_t who = 0;
  bool at69 = readReg(0x69, WHO_AM_I, &who, 1);
  if (at69) {
    Serial.printf("0x69: answers, WHO_AM_I = 0x%02X -> %s\n", who, whoName(who));
    if (strcmp(whoName(who), "not an MPU") != 0) mpuAddr = 0x69;
  } else {
    Serial.println("0x69: nothing (this is where SAAKSHI expects the MPU)");
  }

  uint8_t who68 = 0;
  bool at68 = readReg(0x68, WHO_AM_I, &who68, 1);
  if (at68 && strcmp(whoName(who68), "not an MPU") != 0) {
    Serial.printf("0x68: an MPU answers (WHO_AM_I 0x%02X) -> AD0 is NOT on 3V3.\n", who68);
    Serial.println("      It clashes with the DS3231 clock at 0x68. Connect AD0 to 3V3, then run this again.");
  } else {
    Serial.println("0x68: DS3231 clock only (normal)");
  }

  if (!mpuAddr) {
    Serial.println("\nResult: NO MPU at 0x69.");
    if (!(at68 && strcmp(whoName(who68), "not an MPU") != 0))
      Serial.println("Check, in order: VCC to 3V3 and GND (is the module's LED on?), SDA->8 and SCL->9 not swapped,\n"
                     "loose jumpers, then try the module on its own. If nothing helps, the module is likely damaged.");
    return;
  }

  Wire.beginTransmission(mpuAddr);           // wake it up (it starts asleep)
  Wire.write(PWR_MGMT_1);
  Wire.write(0x00);
  Wire.endTransmission();
  delay(100);
  Serial.printf("\nResult: MPU found at 0x%02X. Live readings (at rest: total close to 1.00 g):\n", mpuAddr);
}

void loop() {
  if (!mpuAddr) { delay(1000); return; }
  uint8_t b[6];
  if (!readReg(mpuAddr, ACCEL_XOUT_H, b, 6)) { Serial.println("read failed - loose wire?"); delay(500); return; }
  float x = (int16_t)(b[0] << 8 | b[1]) / 16384.0f;
  float y = (int16_t)(b[2] << 8 | b[3]) / 16384.0f;
  float z = (int16_t)(b[4] << 8 | b[5]) / 16384.0f;
  Serial.printf("x %+5.2f g   y %+5.2f g   z %+5.2f g   total %4.2f g\n", x, y, z, sqrtf(x * x + y * y + z * z));
  delay(300);
}
