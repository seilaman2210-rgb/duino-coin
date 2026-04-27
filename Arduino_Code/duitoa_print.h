#pragma once
#include <Arduino.h>
#pragma GCC optimize ("-Ofast")

/* Fast integer-to-serial helpers used when submitting mining results.

  IMPORTANT: The DUCO-S1 protocol expects the nonce and elapsed time as
  base-2 (binary) strings with no leading zeros — not decimal, not hex.
  For example, the number 6 is sent as "110", and 0 is sent as "0".
  This matches what Arduino's Serial.print(value, BIN) produces. */

/* Prints a uint32 value in binary (base-2) with no leading zeros.
   Scans from the highest bit down, skipping leading zeros, then
   prints '1' or '0' for each remaining bit.
   Example: 6  -> "110"
   1  -> "1"
   0  -> "0" 
*/
static inline void duino_print_u32_bin_minimal(uint32_t n) {
  if (n == 0u) { Serial.write('0'); return; }
  uint32_t mask = 1UL << 31;
  while (mask && ((n & mask) == 0u)) mask >>= 1;  // skip leading zero bits
  for (; mask; mask >>= 1) Serial.write((n & mask) ? '1' : '0');
}

// Sends a complete result line to the server in the format:
//   <nonce_binary>,<elapsed_us_binary>,<DUCOID>\n
//
// result_nonce  — the nonce value that produced the matching hash
// elapsed_us    — how many microseconds the mining took (used by the server
//                 to calculate the reported hashrate)
// duco_id_cstr  — the miner's unique ID string (e.g. "DUCOID1A2B3C...")
static inline void duino_send_result_line(uint32_t result_nonce,
                                          uint32_t elapsed_us,
                                          const char* duco_id_cstr) {
  duino_print_u32_bin_minimal(result_nonce);
  Serial.write(',');
  duino_print_u32_bin_minimal(elapsed_us);
  Serial.write(',');
  Serial.print(duco_id_cstr);
  Serial.write('\n');
}
