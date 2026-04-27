#pragma once
#include <Arduino.h>
#include "duino_miner_config.h"

/* Serial I/O helpers for receiving a mining job and sending back results.

  Job format received from the DUCO server (DUCO-S1 protocol):
  <prevHash(40 hex)>,<targetHash(40 hex)>,<difficulty(decimal)>,0\n

  Result format sent back:
    <nonce(binary)>,<elapsed_µs(binary)>,<DUCOID>\n

  All functions return false on timeout or malformed input so the caller
  can discard the job and wait for the next one cleanly. */

#if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
#include <avr/wdt.h>
// On AVR the hardware watchdog will reset the CPU if not kicked within ~2 seconds.
// DUINO_WDT_RESET() must be called inside any loop that can run longer than that
// (serial reads, the mining loop, etc.). On other platforms this is a safe no-op.
#define DUINO_WDT_RESET() wdt_reset()
#else
#define DUINO_WDT_RESET() ((void)0)
#endif

#pragma GCC optimize ("-Ofast")

// Drains any leftover bytes sitting in the serial receive buffer.
// Called before sending an error response so we don't leave garbage
// that would confuse the next job read.
static inline void duino_serial_flush_read(void) {
  while (Serial.available() > 0) { DUINO_WDT_RESET(); (void)Serial.read(); }
}

// Flushes the receive buffer and sends "ERR\n" back to the server.
// The server will re-send a new job after receiving this.
static inline void duino_send_err_and_flush(void) {
  duino_serial_flush_read();
  Serial.print(DUINO_ERR_RESPONSE);
}

// Blocks until at least one byte arrives on serial, or until timeout_ms elapses.
// Returns true if a byte is ready to read, false if we timed out.
// The watchdog is kicked on every iteration so a long wait doesn't reset the CPU.
static inline bool duino_wait_serial_byte(uint32_t timeout_ms) {
  uint32_t start_ms = millis();
  while (Serial.available() <= 0) {
    DUINO_WDT_RESET();
    if ((uint32_t)(millis() - start_ms) >= timeout_ms) return false;
    delay(1);
  }
  return true;
}

// Reads exactly one character from serial, waiting up to DUINO_MINER_SERIAL_TIMEOUT_MS.
// Writes the result to *out_char. Returns false on timeout or read error.
static inline bool duino_read_char_with_timeout(char* out_char) {
  if (!duino_wait_serial_byte(DUINO_MINER_SERIAL_TIMEOUT_MS)) return false;
  int c = Serial.read();
  if (c < 0) return false;
  *out_char = (char)c;
  return true;
}

// Returns true if c is a valid lowercase hex digit ('0'-'9' or 'a'-'f').
// Uppercase hex is intentionally rejected — the server always sends lowercase.
static inline bool duino_is_lower_hex_char(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* Reads exactly hex_len lowercase hex characters into out_hash, then expects
  a comma separator. Returns false if any character is invalid or the comma
  is missing — this means the job line is malformed and should be discarded. */
static inline bool duino_read_hash_field_until_comma(char* out_hash, uint8_t hex_len) {
  char c = '\0';
  for (uint8_t i = 0; i < hex_len; i++) {
    if (!duino_read_char_with_timeout(&c) || !duino_is_lower_hex_char(c)) return false;
    out_hash[i] = c;
  }
  out_hash[hex_len] = '\0';
  if (!duino_read_char_with_timeout(&c)) return false;
  return c == ',';
}

/* Reads a decimal difficulty value followed by a comma, e.g. "500,".
  Rejects values that would overflow uint32, empty fields, or non-digit characters.
  The difficulty controls how many nonces we search: up to difficulty * 100. */
static inline bool duino_read_difficulty_until_comma(duino_uint_diff_t* out_diff) {
  uint32_t v = 0u; uint8_t digits = 0; char c = '\0';
  for (;;) {
    if (!duino_read_char_with_timeout(&c)) return false;
    if (c == ',') break;
    if ((uint8_t)c >= '0' && (uint8_t)c <= '9') {
      uint8_t d = (uint8_t)c - (uint8_t)'0';
      if (v > (0xFFFFFFFFu - d) / 10u) return false;  // overflow guard
      v = v * 10u + d;
      if (++digits > 9u) return false;
    } else return false;
  }
  if (digits == 0u) return false;
  *out_diff = (duino_uint_diff_t)v;
  return true;
}

/* Reads and validates the trailing "0\n" (or "0\r\n") at the end of each job line.
  The server appends a protocol version field ("0") after the difficulty.
  Returns false if the bytes do not match, which signals a malformed or
  partially-received job — the caller should send ERR and wait for the next one. */
static inline bool duino_discard_job_tail(void) {
  char c = '\0';
  if (!duino_read_char_with_timeout(&c) || c != '0') return false;
  if (!duino_read_char_with_timeout(&c)) return false;
  if (c == '\r') { if (!duino_read_char_with_timeout(&c)) return false; }
  return c == '\n';
}
