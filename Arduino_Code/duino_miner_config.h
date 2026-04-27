#pragma once
#include <Arduino.h>

// Central configuration for the DUCO miner firmware.
// Edit the values below to tune the miner for your board or network setup.

// Baud rate for serial communication with the DUCO server bridge.
// Must match whatever baud rate the host-side script is using.
#ifndef DUINO_MINER_BAUD
#define DUINO_MINER_BAUD 115200u
#endif

// How long (in milliseconds) to wait for each character to arrive from the server.
// If the connection is slow or the server is busy, raise this value.
// Lowering it too much will cause valid jobs to be rejected as timeouts.
#ifndef DUINO_MINER_SERIAL_TIMEOUT_MS
#define DUINO_MINER_SERIAL_TIMEOUT_MS 2000u
#endif

// A SHA1 digest is 20 bytes = 40 lowercase hex characters.
// Both the previous hash and the target hash in each job are this length.
#define DUINO_HASH_HEX_LEN 40u

// Sent back to the server when a job cannot be parsed or is malformed.
// The server will respond by sending a new job.
#define DUINO_ERR_RESPONSE "ERR\n"

#if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
typedef uint32_t duino_uint_diff_t;
/* DUINO_MAX_SAFE_DIFF is the highest difficulty this board can handle and
  still return a result before the server's timeout expires.
  At difficulty D, the miner searches up to D*100 nonces.
  An Arduino Uno does roughly 785 H/s, so anything above ~655 would time out.
  Boards with more RAM or flash can afford a much smaller safe limit because
  they are faster — but the AVR limit is the binding constraint here. */
#define DUINO_MAX_SAFE_DIFF 655u
#else
typedef uint32_t duino_uint_diff_t;
// On faster boards (ESP32, ARM, etc.) the server timeout is rarely a concern,
// so a much higher ceiling is allowed.
#define DUINO_MAX_SAFE_DIFF 100000u
#endif

// Detect whether we can use direct port manipulation to toggle the built-in LED.
// On ATmega328(P)/168(P) boards with LED on pin 13, PORTB bit 5 is faster than
// digitalWrite() — it saves a few microseconds per job which adds up over time.
#if (defined(__AVR_ATmega328P__) || defined(__AVR_ATmega328__) \
     || defined(__AVR_ATmega168__) || defined(__AVR_ATmega168P__)) \
    && (LED_BUILTIN == 13)
#define DUINO_LED_MINING_PORTB
#endif

// Turn the built-in LED on (called when mining starts).
static inline void duino_led_mining_on(void) {
#if defined(DUINO_LED_MINING_PORTB)
  PORTB |= (uint8_t)(1 << 5);   // set bit 5 directly → faster than digitalWrite
#else
  digitalWrite(LED_BUILTIN, HIGH);
#endif
}

// Turn the built-in LED off (called when a result is ready to send).
static inline void duino_led_mining_off(void) {
#if defined(DUINO_LED_MINING_PORTB)
  PORTB &= (uint8_t)~(1 << 5);  // clear bit 5 directly → faster than digitalWrite
#else
  digitalWrite(LED_BUILTIN, LOW);
#endif
}
