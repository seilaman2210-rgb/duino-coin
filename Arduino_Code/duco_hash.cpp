/*
  SHA1-based hashing core for the DUCO-S1 mining algorithm.

  Key optimization: the previous block hash (40 hex chars = 320 bits) always
  fills exactly the first 10 of the 16 SHA1 message words. Those 10 words never
  change within a single job, so duco_hash_init() processes them once and caches
  the intermediate SHA1 state. duco_hash_try_nonce() then picks up from that
  cached state and only processes the remaining words (which contain the nonce),
  cutting roughly 12% of work per nonce tested.
*/
#include "duco_hash.h"

#pragma GCC optimize("-Ofast")

// Generic left-rotation for 32-bit words — used on non-AVR platforms.
// On AVR this is replaced by hand-written assembly (see duco_hash_asm.S)
// because AVR has no barrel shifter and a C loop would be too slow.
#define sha1_rotl(bits, word) \
    (((word) << (bits)) | ((word) >> (32 - (bits))))

#if defined(__AVR__)
extern "C" uint32_t sha1_rotl5(uint32_t value);
extern "C" uint32_t sha1_rotl30(uint32_t value);
#define SHA1_ROTL5(word) sha1_rotl5(word)
#define SHA1_ROTL30(word) sha1_rotl30(word)
#else
#define SHA1_ROTL5(word) sha1_rotl(5, word)
#define SHA1_ROTL30(word) sha1_rotl(30, word)
#endif

// SHA1_EXPAND derives a new message word from the previous four,
// wrapping around a 16-entry circular buffer (hence the & 15 masks).
// This is the standard SHA1 message schedule expansion step.
#define SHA1_EXPAND(i) \
    W[(i) & 15] = sha1_rotl(1,  W[((i)-3)  & 15] \
                              ^ W[((i)-8)  & 15] \
                              ^ W[((i)-14) & 15] \
                              ^ W[(i)      & 15])

// One SHA1 round: mixes the five state words (a-e) using the current
// message word W[i & 15], a round-specific function f_expr, and constant K.
// The result rotates into 'a'; all other words shift down by one position.
#define SHA1_ROUND(f_expr, K) do {          \
    uint32_t _t = SHA1_ROTL5(a) + (f_expr) + e + W[i & 15] + (K); \
    e = d;                                  \
    d = c;                                  \
    c = SHA1_ROTL30(b);                     \
    b = a;                                  \
    a = _t;                                 \
} while (0)

// SHA1 padding requires the last word of the message block to hold the
// total message length in bits. The base message is always 40 bytes (the
// previous hash), so the total is (40 + nonceLen) * 8.
// These values are pre-computed for nonce lengths 0-5 to avoid any
// multiplication inside the hot loop.
// Example: nonceLen=1 -> (40+1)*8 = 328 = 0x148
static uint32_t const kLengthWordByNonceLen[6] = {
    0x00000000UL,
    0x00000148UL,
    0x00000150UL,
    0x00000158UL,
    0x00000160UL,
    0x00000168UL
};

// Fills the 16-word SHA1 message block (W[0..15]) for a given nonce.
//
// W[0..9]  = the fixed previous-hash words (copied from baseWords).
// W[10..15]= the nonce bytes + SHA1 padding.
//
// SHA1 padding works like this: after the message bytes, append a 0x80 byte,
// then zero-fill, then put the message length in bits in the last word.
// The switch handles nonces up to 5 digits with fully unrolled packing,
// avoiding any loop overhead for the most common case.
// Nonces longer than 5 digits fall through to a generic byte-by-byte loop.
static inline __attribute__((always_inline)) void duco_hash_load_block_words(
    uint32_t *W,
    uint32_t const *baseWords,
    char const *nonce,
    uint8_t nonceLen)
{
    W[0] = baseWords[0];
    W[1] = baseWords[1];
    W[2] = baseWords[2];
    W[3] = baseWords[3];
    W[4] = baseWords[4];
    W[5] = baseWords[5];
    W[6] = baseWords[6];
    W[7] = baseWords[7];
    W[8] = baseWords[8];
    W[9] = baseWords[9];

    uint32_t d0 = (uint8_t)nonce[0];
    uint32_t d1 = (uint8_t)nonce[1];
    uint32_t d2 = (uint8_t)nonce[2];
    uint32_t d3 = (uint8_t)nonce[3];
    uint32_t d4 = (uint8_t)nonce[4];

    if (nonceLen <= 5) {
        switch (nonceLen) {
            case 1:
                // 1 byte + 0x80 padding byte packed into W[10], rest is zero
                W[10] = (d0 << 24) | 0x00800000UL;
                W[11] = 0;
                W[12] = 0;
                break;
            case 2:
                W[10] = (d0 << 24) | (d1 << 16) | 0x00008000UL;
                W[11] = 0;
                W[12] = 0;
                break;
            case 3:
                W[10] = (d0 << 24) | (d1 << 16) | (d2 << 8) | 0x00000080UL;
                W[11] = 0;
                W[12] = 0;
                break;
            case 4:
                // 4 bytes fill W[10] completely; padding byte goes at the top of W[11]
                W[10] = (d0 << 24) | (d1 << 16) | (d2 << 8) | d3;
                W[11] = 0x80000000UL;
                W[12] = 0;
                break;
            default: // case 5
                W[10] = (d0 << 24) | (d1 << 16) | (d2 << 8) | d3;
                W[11] = (d4 << 24) | 0x00800000UL;
                W[12] = 0;
                break;
        }

        W[13] = 0;
        W[14] = 0;
        W[15] = kLengthWordByNonceLen[nonceLen];
        return;
    }

    // Generic path for nonces longer than 5 digits.
    // Pack each character into the correct word and bit position,
    // then append the 0x80 padding byte and the length word.
    W[10] = 0;
    W[11] = 0;
    W[12] = 0;
    W[13] = 0;
    W[14] = 0;

    for (uint8_t i = 0; i < nonceLen; i++) {
        uint8_t wordIndex = 10 + (i >> 2);       // which word (4 bytes per word)
        uint8_t shift = 24 - ((i & 3) << 3);     // which byte inside that word (big-endian)
        W[wordIndex] |= (uint32_t)(uint8_t)nonce[i] << shift;
    }

    {
        // Append the mandatory 0x80 padding byte right after the last nonce byte
        uint8_t wordIndex = 10 + (nonceLen >> 2);
        uint8_t shift = 24 - ((nonceLen & 3) << 3);
        W[wordIndex] |= 0x80UL << shift;
    }

    W[15] = (uint32_t)(40 + nonceLen) << 3;  // total message length in bits
}

/* Tests a single nonce candidate against the target hash.
   Picks up from the cached intermediate SHA1 state (rounds 0-9 were already
   done by duco_hash_init), runs rounds 10-79, then adds the SHA1 initial
   constants and compares all five output words against the target.
   Returns true only when the nonce produces an exact hash match —
   meaning we found the answer the server is looking for. */
__attribute__((noinline)) bool duco_hash_try_nonce(duco_hash_state_t *hasher,
                                                   char const *nonce,
                                                   uint8_t nonceLen,
                                                   uint32_t const *targetWords)
{
    static uint32_t W[16];
    duco_hash_load_block_words(W, hasher->initialWords, nonce, nonceLen);

    uint32_t a = hasher->tempState[0];
    uint32_t b = hasher->tempState[1];
    uint32_t c = hasher->tempState[2];
    uint32_t d = hasher->tempState[3];
    uint32_t e = hasher->tempState[4];

    // Rounds 10-19: Ch function (choose), constant 0x5A827999
    for (uint8_t i = 10; i < 16; i++) {
        SHA1_ROUND((b & (c ^ d)) ^ d, 0x5A827999UL);
    }

    for (uint8_t i = 16; i < 20; i++) {
        SHA1_EXPAND(i);
        SHA1_ROUND((b & (c ^ d)) ^ d, 0x5A827999UL);
    }

    // Rounds 20-39: Parity function (XOR), constant 0x6ED9EBA1
    for (uint8_t i = 20; i < 40; i++) {
        SHA1_EXPAND(i);
        SHA1_ROUND(b ^ c ^ d, 0x6ED9EBA1UL);
    }

    // Rounds 40-59: Majority function, constant 0x8F1BBCDC
    for (uint8_t i = 40; i < 60; i++) {
        SHA1_EXPAND(i);
        SHA1_ROUND((b & c) | (b & d) | (c & d), 0x8F1BBCDCUL);
    }

    // Rounds 60-79: Parity again, constant 0xCA62C1D6
    for (uint8_t i = 60; i < 80; i++) {
        SHA1_EXPAND(i);
        SHA1_ROUND(b ^ c ^ d, 0xCA62C1D6UL);
    }

    // Add the SHA1 initial hash values (IV) to produce the final digest
    a += 0x67452301UL;
    b += 0xEFCDAB89UL;
    c += 0x98BADCFEUL;
    d += 0x10325476UL;
    e += 0xC3D2E1F0UL;

    // All five words must match — a partial match is not a valid share
    return a == targetWords[0]
        && b == targetWords[1]
        && c == targetWords[2]
        && d == targetWords[3]
        && e == targetWords[4];
}

/* Pre-processes the fixed part of the SHA1 input (the previous block hash)
   so that work is not repeated for every nonce candidate.
   The previous hash is 40 hex characters, which packs into exactly 10 uint32
   words — filling the first 10 slots of SHA1's 16-word message block.
   We run SHA1 rounds 0-9 on those words here and store the resulting
   intermediate state in hasher->tempState.
   Call this once per job. Then call duco_hash_try_nonce() for every nonce. */
void duco_hash_init(duco_hash_state_t *hasher, char const *prevHash)
{
    // Standard SHA1 initial hash values (defined in the SHA1 specification)
    uint32_t a = 0x67452301UL;
    uint32_t b = 0xEFCDAB89UL;
    uint32_t c = 0x98BADCFEUL;
    uint32_t d = 0x10325476UL;
    uint32_t e = 0xC3D2E1F0UL;

    // Pack the 40 ASCII hex characters into 10 big-endian 32-bit words.
    // Each group of 4 characters becomes one word.
    for (uint8_t i = 0, i4 = 0; i < 10; i++, i4 += 4) {
        hasher->initialWords[i] =
            ((uint32_t)(uint8_t)prevHash[i4    ] << 24) |
            ((uint32_t)(uint8_t)prevHash[i4 + 1] << 16) |
            ((uint32_t)(uint8_t)prevHash[i4 + 2] <<  8) |
            ((uint32_t)(uint8_t)prevHash[i4 + 3]);
    }

    // Run SHA1 rounds 0-9 on the previous hash words.
    // These use the Ch (choose) function and constant 0x5A827999,
    // which is the standard for SHA1 rounds 0-19.
    for (uint8_t i = 0; i < 10; i++) {
        uint32_t temp = SHA1_ROTL5(a) + e
                      + ((b & c) | ((~b) & d))
                      + hasher->initialWords[i]
                      + 0x5A827999UL;
        e = d;
        d = c;
        c = SHA1_ROTL30(b);
        b = a;
        a = temp;
    }

    // Save the state so duco_hash_try_nonce() can resume from here
    hasher->tempState[0] = a;
    hasher->tempState[1] = b;
    hasher->tempState[2] = c;
    hasher->tempState[3] = d;
    hasher->tempState[4] = e;
}