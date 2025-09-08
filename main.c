// Copyright (c) 2005 Virtuous BPO Software Projects
//
//  All rights reserved.
//
//  This software and associated documentation files (the "Software") are proprietary to Virtuous BPO Software Projects and are protected by copyright law and international treaty provisions. Unauthorized reproduction or distribution of this Software, or any portion of it, may result in severe civil and criminal penalties, and will be prosecuted to the maximum extent possible under the law.
//
// RESTRICTED RIGHTS: Use, duplication, or disclosure by the government is subject to restrictions as set forth in subparagraph (c)(1)(ii) of the Rights in Technical Data and Computer Software clause at DFARS 252.227-7013 or subparagraphs (c)(1) and (2) of the Commercial Computer Software-Restricted Rights clause at FAR 52.227-19, as applicable.
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
const uint64_t ASCON_HASH_IV = 0x0000080100cc0002;
const int ASCON_RATE = 8; // Rate in bytes (64 bits)
const int ASCON_PA_ROUNDS = 12;

// --- Helper macros ---
#define ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

// --- Ascon Permutation State ---
typedef struct {
    uint64_t x[5];
} ascon_state_t;

// --- Function Prototypes ---
void ascon_print_state(const ascon_state_t* state);
void ascon_permutation(ascon_state_t* state, int rounds);
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
void ascon_permutation(ascon_state_t* state, int rounds) {
    // Round constants for 12 rounds

    uint64_t* x = state->x;

    for (int i = 12 - rounds; i < 12; ++i) {
        const uint64_t round_constants[12] = {
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
            0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
        };
        // --- Add constant ---
        x[2] ^= round_constants[i];

        // --- S-box layer ---
        x[0] ^= x[4];
        x[4] ^= x[3];
        x[2] ^= x[1];
        uint64_t t0 = x[0], t1 = x[1], t2 = x[2], t3 = x[3], t4 = x[4];
        t0 = ~t0; t1 = ~t1; t2 = ~t2; t3 = ~t3; t4 = ~t4;
        t0 &= x[1]; t1 &= x[2]; t2 &= x[3]; t3 &= x[4]; t4 &= x[0];
        x[0] ^= t1; x[1] ^= t2; x[2] ^= t3; x[3] ^= t4; x[4] ^= t0;

        // --- Linear diffusion layer ---
        x[0] ^= ROTATE_RIGHT(x[0], 19) ^ ROTATE_RIGHT(x[0], 28);
        x[1] ^= ROTATE_RIGHT(x[1], 61) ^ ROTATE_RIGHT(x[1], 39);
        x[2] ^= ROTATE_RIGHT(x[2], 1) ^ ROTATE_RIGHT(x[2], 6);
        x[3] ^= ROTATE_RIGHT(x[3], 10) ^ ROTATE_RIGHT(x[3], 17);
        x[4] ^= ROTATE_RIGHT(x[4], 7) ^ ROTATE_RIGHT(x[4], 41);
    }
}


/**
 * @brief Computes the Ascon-Hash256 digest of a message.
 * @param msg Pointer to the input message bytes.
 * @param msg_len Length of the input message in bytes.
 * @param digest Pointer to a 32-byte array where the output digest will be stored.
 */
void ascon_hash256(const uint8_t* msg, size_t msg_len, uint8_t* digest) {
    ascon_state_t state;

    // 1. Initialization
    state.x[0] = ASCON_HASH_IV;
    state.x[1] = 0;
    state.x[2] = 0;
    state.x[3] = 0;
    state.x[4] = 0;
    ascon_permutation(&state, ASCON_PA_ROUNDS);

    // 2. Absorbing Phase
    size_t processed_len = 0;
    while (processed_len + ASCON_RATE <= msg_len) {
        uint64_t m_block = 0;
        memcpy(&m_block, msg + processed_len, ASCON_RATE);
        state.x[0] ^= m_block;
        ascon_permutation(&state, ASCON_PA_ROUNDS);
        processed_len += ASCON_RATE;
    }

    // Padding the last block
    uint64_t last_block = 0;
    size_t remaining_len = msg_len - processed_len;
    if (remaining_len > 0) {
        memcpy(&last_block, msg + processed_len, remaining_len);
    }
    // Append the '1' bit (0x80)
    ((uint8_t*)&last_block)[remaining_len] = 0x80;

    state.x[0] ^= last_block;
    ascon_permutation(&state, ASCON_PA_ROUNDS);

    // 3. Squeezing Phase
    for (int i = 0; i < 3; ++i) {
        memcpy(digest + (i * 8), &state.x[0], 8);
        ascon_permutation(&state, ASCON_PA_ROUNDS);
    }
    memcpy(digest + 24, &state.x[0], 8);
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
