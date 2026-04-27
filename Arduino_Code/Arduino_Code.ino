/*
   ____  __  __  ____  _  _  _____       ___  _____  ____  _  _
  (  _ \(  )(  )(_  _)( \( )(  _  )___  / __)(  _  )(_  _)( \( )
   )(_) ))(__)(  _)(_  )  (  )(_)((___)( (__  )(_)(  _)(_  )  (
  (____/(______)(____)(_)\_)(_____)     \___)(_____)(____)(_)\_)
  Official code for Arduino boards (and relatives)   version 4.3
  Duino-Coin Team & Community 2019-2024 © MIT Licensed
  this script was firstly made by Chocoetom, also knowed as BloodFell, and then improved Ruvyzvat.
  this script can reach almost 783/785hs with a Arduino Uno (stable), no errors or instabilitys found while testing this code.
  some comments may look weird, cause Ruvyzvat write it in other language
  i added lots of comments for easier begginer understand
*/

/*
about this code:
> this script was firstly made by Chocoetom, also knowed as BloodFell, and then improved Ruvyzvat.
> this script can reach almost 783/785hs with a Arduino Uno (stable), no errors or instabilitys found while testing this code.
> some comments may look weird, cause Ruvyzvat write it in other language
> i added lots of comments for easier begginer understand (last thing made)
*/

/* For microcontrollers with low memory change that to -Os in all files,
for default settings use -O0. -O may be a good tradeoff between both */
#pragma GCC optimize ("-Ofast")

#include <stdint.h>

/* For microcontrollers with custom LED pins, adjust the line below */
#ifndef LED_BUILTIN
#define LED_BUILTIN 13
#endif

/* Protocol tokens used when sending results back to the DUCO server.
The server expects: nonce,elapsed_us,DUCOID\n */
#define SEP_TOKEN ","
#define END_TOKEN "\n"

typedef uint32_t uintDiff;

#include "uniqueID.h"
#include <string.h>
#include "duco_hash.h"

// Forward declaration
uintDiff ducos1a_mine(const char* prevBlockHash, const uint32_t* targetWords, uintDiff maxNonce);

// Size sufficient for “DUCOID” + 16 hex characters + null
static char ducoid_chars[23];

/* Builds the miner's unique ID string: "DUCOID" + 16 hex chars from the chip's
hardware serial number. This ID is sent with every result so the server knows
which device submitted the share. */
static void generate_ducoid() {
  memcpy(ducoid_chars, "DUCOID", 6);
  char* ptr = ducoid_chars + 6;
  for (uint8_t i = 0; i < 8; i++) {
    uint8_t val = (uint8_t)UniqueID8[i];
    *ptr++ = "0123456789ABCDEF"[val >> 4];
    *ptr++ = "0123456789ABCDEF"[val & 0x0F];
  }
  *ptr = '\0';
}

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  generate_ducoid();

  Serial.begin(115200);
  Serial.setTimeout(10000);
  while (!Serial);
  Serial.flush();  // keep it
}

/* Converts a single lowercase hex character ('0'-'9', 'a'-'f') to its 4-bit value.
  Example: HEX_NIBBLE('b') == 11 */
#define HEX_NIBBLE(c) (((c) - '0' < 10) ? ((c) - '0') : ((c) - 'a' + 10))

static void hex_to_words(const char* hex, uint32_t* words) {
  for (uint8_t w = 0; w < SHA1_HASH_LEN / 4; w++) {
    const char* src = hex + w * 8;
    uint32_t b0 = (HEX_NIBBLE(src[0]) << 4) | HEX_NIBBLE(src[1]);
    uint32_t b1 = (HEX_NIBBLE(src[2]) << 4) | HEX_NIBBLE(src[3]);
    uint32_t b2 = (HEX_NIBBLE(src[4]) << 4) | HEX_NIBBLE(src[5]);
    uint32_t b3 = (HEX_NIBBLE(src[6]) << 4) | HEX_NIBBLE(src[7]);

    words[w] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
  }
}

/* Increments a decimal number stored as an ASCII string in-place.
  Handles carry (e.g. "99" -> "100") and automatically grows the string length.
  This avoids any integer-to-string conversion inside the hot mining loop. */
static void increment_nonce_ascii(char* nonceStr, uint8_t* nonceLen) {
  int8_t i = *nonceLen - 1;
  for (; i >= 0; --i) {
    if (nonceStr[i] != '9') {
      nonceStr[i]++;
      return;
    }
    nonceStr[i] = '0';
  }
  for (uint8_t j = *nonceLen; j > 0; --j)
    nonceStr[j] = nonceStr[j - 1];
  nonceStr[0] = '1';
  (*nonceLen)++;
  nonceStr[*nonceLen] = '\0';
}

/* DUCO-S1 algorithm entry point.
  Converts the target hash from hex to 5 uint32 words, then searches for the
  nonce in range [0, difficulty*100] whose SHA1(prevHash + nonce) == target.
  Returns the winning nonce, or 0 if not found within the limit. */
uintDiff ducos1a(const char* prevBlockHash, const char* targetBlockHash, uintDiff difficulty) {
#if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
  if (difficulty > 655) return 0;
#endif

  uint32_t targetWords[SHA1_HASH_LEN / 4];
  hex_to_words(targetBlockHash, targetWords);

  uintDiff maxNonce = difficulty * 100 + 1;
  return ducos1a_mine(prevBlockHash, targetWords, maxNonce);
}

/* Inner mining loop. Iterates nonce as a decimal ASCII string ("0", "1", ...)
  and calls duco_hash_try_nonce() for each candidate.
  The nonce is kept as ASCII because that is exactly what SHA1 will hash —
  no conversion needed, saving cycles on every iteration. */
uintDiff ducos1a_mine(const char* prevBlockHash, const uint32_t* targetWords, uintDiff maxNonce) {
  static duco_hash_state_t hash;
  duco_hash_init(&hash, prevBlockHash);

  char nonceStr[10 + 1] = "0";
  uint8_t nonceLen = 1;

  for (uintDiff nonce = 0; nonce < maxNonce; nonce++) {
    if (duco_hash_try_nonce(&hash, nonceStr, nonceLen, targetWords)) {
      return nonce;
    }
    increment_nonce_ascii(nonceStr, &nonceLen);
  }
  return 0;
}

void loop() {
  if (Serial.available() <= 0)
    return;

  char lastBlockHash[40 + 1];
  char newBlockHash[40 + 1];

  if (Serial.readBytesUntil(',', lastBlockHash, 41) != 40)
    return;
  lastBlockHash[40] = '\0';

  if (Serial.readBytesUntil(',', newBlockHash, 41) != 40)
    return;
  newBlockHash[40] = '\0';

  char diffBuffer[16];
  int diffLen = Serial.readBytesUntil(',', diffBuffer, sizeof(diffBuffer));
  if (diffLen == 0) return;
  diffBuffer[diffLen] = '\0';
  uintDiff difficulty = strtoul(diffBuffer, NULL, 10);

// Turn LED ON to signal that mining has started (PORTB bit 5 = pin 13 on Uno).
// Direct port write is used instead of digitalWrite() to save ~4 µs per job.
#if defined(ARDUINO_ARCH_AVR)
  PORTB |= B00100000;
#else
  digitalWrite(LED_BUILTIN, HIGH);
#endif

  uint32_t startTime = micros();
  uintDiff result = ducos1a(lastBlockHash, newBlockHash, difficulty);
  uint32_t elapsed = micros() - startTime;

// Turn LED OFF when the result is ready and about to be transmitted.
#if defined(ARDUINO_ARCH_AVR)
  PORTB &= B11011111;
#else
  digitalWrite(LED_BUILTIN, LOW);
#endif

  while (Serial.available()) Serial.read();

  // Submit the results in the **correct format**: nonce (binary), timestamp (binary), DUCOID
  Serial.print(result, BIN);
  Serial.print(SEP_TOKEN);
  Serial.print(elapsed, BIN);
  Serial.print(SEP_TOKEN);
  Serial.print(ducoid_chars);
  Serial.print(END_TOKEN);      // Send only “\n”, not '\r'
}
