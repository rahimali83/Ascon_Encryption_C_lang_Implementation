//  MIT License
//
//  Copyright (c) 2025 Rahim Ali
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//
//  * Contact: info@virtuousbpo.com
//  * Website: www.virtuousbpo.com
//
//  * Project: Ascon-Hash256
//  * File: main.c
//  * Created: 08/Sept/2025
//  * Author: Rahim Ali

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// --- Constants based on the Ascon specification ---
// The IV is taken from the provided algorithm image
const uint64_t ASCON_HASH_IV = 0x0000080100cc0002ULL;
const int ASCON_RATE = 8; // Rate in bytes (64 bits)
const int ASCON_PA_ROUNDS = 12;

// Round constants for 12 rounds (moved outside function for efficiency)
static const uint64_t ROUND_CONSTANTS[12] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
    0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

// --- Helper macros ---
#define ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

// Compiler optimization hints
#if defined(__GNUC__) || defined(__clang__)
    #define LIKELY(x) __builtin_expect(!!(x), 1)
    #define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
    #define LIKELY(x) (x)
    #define UNLIKELY(x) (x)
#endif

// Endianness conversion helpers (alignment-safe)
static inline uint64_t BYTES_TO_U64(const uint8_t* ptr) {
    uint64_t val;
    memcpy(&val, ptr, sizeof(val));
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap64(val);
#else
    return val;
#endif
}

static inline uint64_t U64_TO_BYTES(uint64_t val) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap64(val);
#else
    return val;
#endif
}

// --- Ascon Permutation State ---
typedef struct {
    uint64_t x[5];
} ascon_state_t;

// --- Function Prototypes ---
void ascon_print_state(const ascon_state_t* state);
static inline void ascon_permutation(ascon_state_t* state, int rounds) __attribute__((always_inline));
void ascon_hash256(const uint8_t* msg, size_t msg_len, uint8_t* digest);

// --- Implementation ---

/**
 * @brief Prints the 320-bit state for debugging purposes.
 * @param state Pointer to the Ascon state.
 */
void ascon_print_state(const ascon_state_t* state) {
    printf("  x0: %016lx\n", state->x[0]);
    printf("  x1: %016lx\n", state->x[1]);
    printf("  x2: %016lx\n", state->x[2]);
    printf("  x3: %016lx\n", state->x[3]);
    printf("  x4: %016lx\n", state->x[4]);
}

/**
 * @brief The core Ascon permutation function.
 * @param state Pointer to the 320-bit state to be permuted.
 * @param rounds The number of rounds to perform (e.g., 12).
 */
static inline void ascon_permutation(ascon_state_t* state, int rounds) {
    uint64_t x0 = state->x[0], x1 = state->x[1], x2 = state->x[2];
    uint64_t x3 = state->x[3], x4 = state->x[4];

    for (int i = 12 - rounds; i < 12; ++i) {
        // --- Add constant ---
        x2 ^= ROUND_CONSTANTS[i];

        // --- S-box layer (optimized) ---
        x0 ^= x4; x4 ^= x3; x2 ^= x1;
        uint64_t t0 = (~x0) & x1;
        uint64_t t1 = (~x1) & x2;
        uint64_t t2 = (~x2) & x3;
        uint64_t t3 = (~x3) & x4;
        uint64_t t4 = (~x4) & x0;
        x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
        x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2;

        // --- Linear diffusion layer ---
        x0 ^= ROTATE_RIGHT(x0, 19) ^ ROTATE_RIGHT(x0, 28);
        x1 ^= ROTATE_RIGHT(x1, 61) ^ ROTATE_RIGHT(x1, 39);
        x2 ^= ROTATE_RIGHT(x2, 1) ^ ROTATE_RIGHT(x2, 6);
        x3 ^= ROTATE_RIGHT(x3, 10) ^ ROTATE_RIGHT(x3, 17);
        x4 ^= ROTATE_RIGHT(x4, 7) ^ ROTATE_RIGHT(x4, 41);
    }

    state->x[0] = x0; state->x[1] = x1; state->x[2] = x2;
    state->x[3] = x3; state->x[4] = x4;
}


/**
 * @brief Computes the Ascon-Hash256 digest of a message.
 * @param msg Pointer to the input message bytes.
 * @param msg_len Length of the input message in bytes.
 * @param digest Pointer to a 32-byte array where the output digest will be stored.
 */
void ascon_hash256(const uint8_t* msg, size_t msg_len, uint8_t* digest) {
    ascon_state_t state = {
        .x = {ASCON_HASH_IV, 0, 0, 0, 0}
    };

    ascon_permutation(&state, ASCON_PA_ROUNDS);

    // 2. Absorbing Phase - optimized for aligned access
    const uint8_t* msg_ptr = msg;
    size_t blocks = msg_len / ASCON_RATE;

    for (size_t i = 0; i < blocks; ++i) {
        state.x[0] ^= BYTES_TO_U64(msg_ptr);
        ascon_permutation(&state, ASCON_PA_ROUNDS);
        msg_ptr += ASCON_RATE;
    }

    // Padding the last block
    // Padding the last block
    uint64_t last_block = 0;
    size_t remaining_len = msg_len % ASCON_RATE;
    if (LIKELY(remaining_len > 0)) {
        memcpy(&last_block, msg_ptr, remaining_len);
    }
    // Append the '1' bit (0x80)
    ((uint8_t*)&last_block)[remaining_len] = 0x80;
   state.x[0] ^= BYTES_TO_U64((const uint8_t*)&last_block);
    ascon_permutation(&state, ASCON_PA_ROUNDS);

    // 3. Squeezing Phase - optimized with endian conversion
    uint64_t out_val = U64_TO_BYTES(state.x[0]);
    memcpy(digest, &out_val, 8);
    ascon_permutation(&state, ASCON_PA_ROUNDS);

    out_val = U64_TO_BYTES(state.x[0]);
    memcpy(digest + 8, &out_val, 8);
    ascon_permutation(&state, ASCON_PA_ROUNDS);

    out_val = U64_TO_BYTES(state.x[0]);
    memcpy(digest + 16, &out_val, 8);
    ascon_permutation(&state, ASCON_PA_ROUNDS);

    out_val = U64_TO_BYTES(state.x[0]);
    memcpy(digest + 24, &out_val, 8);
}


int main() {
    // Example: Hashing the empty string ""
    const uint8_t msg1[] = "";
    size_t len1 = 0;
    uint8_t digest1[32];

    ascon_hash256(msg1, len1, digest1);

    printf("Hashing empty string \"\":\n");
    printf("H = ");
    for(int i = 0; i < 32; ++i) {
        printf("%02x", digest1[i]);
    }
    printf("\n\n");

    // Example: Hashing "abc"
    const uint8_t msg2[] = "abc";
    size_t len2 = 3;
    uint8_t digest2[32];

    ascon_hash256(msg2, len2, digest2);

    printf("Hashing string \"abc\":\n");
    printf("H = ");
    for(int i = 0; i < 32; ++i) {
        printf("%02x", digest2[i]);
    }
    printf("\n");

    return 0;
}
