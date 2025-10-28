// Copyright (c) ${YEAR} Virtuous BPO Software Projects
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
//  * Project: ${PROJECT_NAME}
//  * File: ${FILE_NAME}
//  * Created: ${DATE}
//  * Author: ${USER}

// Ascon AEAD implementations
// SPDX-License-Identifier: MIT
#include <string.h>
#include "../include/ascon/ascon_aead.h"
#include "../include/ascon/ascon_common.h"

 // Parameters for ASCON-128 (v1.2): rate=8 bytes, pa=12, pb=6
#define ASCON_AEAD_RATE 8
#define ASCON_PA_ROUNDS 12
#define ASCON_PB_ROUNDS 6
// Initialization Vector for ASCON-128 (encodes params r=64,a=12,b=6,k=128)
static const uint64_t ASCON128_IV = 0x80400c0600000000ULL;

static inline uint64_t load64_be(const uint8_t* p) {
    // Use existing endian-safe helper
    return ascon_load64(p);
}
static inline void store64_be(uint8_t* p, uint64_t v) {
    ascon_store64(p, v);
}

static void ascon_init(ascon_state_t* s,
                       const uint8_t key[ASCON_KEY_BYTES],
                       const uint8_t nonce[ASCON_NONCE_BYTES]) {
    uint64_t k0 = load64_be(key);
    uint64_t k1 = load64_be(key + 8);
    uint64_t n0 = load64_be(nonce);
    uint64_t n1 = load64_be(nonce + 8);
    s->x[0] = ASCON128_IV;
    s->x[1] = k0;
    s->x[2] = k1;
    s->x[3] = n0;
    s->x[4] = n1;
    ascon_permute(s, ASCON_PA_ROUNDS);
    s->x[3] ^= k0;
    s->x[4] ^= k1;
}

static void ascon_absorb_ad(ascon_state_t* s, const uint8_t* ad, size_t ad_len) {
    if (!ad || ad_len == 0) {
        // Domain separation still required even if no AD
        s->x[4] ^= 1ULL;
        return;
    }
    // Full-rate blocks
    size_t blocks = ad_len / ASCON_AEAD_RATE;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t lane = load64_be(ad + i * ASCON_AEAD_RATE);
        s->x[0] ^= lane;
        ascon_permute(s, ASCON_PB_ROUNDS);
    }
    // Final partial block with 10* padding in byte domain (only if remainder present)
    size_t rem = ad_len % ASCON_AEAD_RATE;
    if (rem) {
        uint8_t tmp[ASCON_AEAD_RATE] = {0};
        memcpy(tmp, ad + blocks * ASCON_AEAD_RATE, rem);
        tmp[rem] = 0x80;
        uint64_t lane = load64_be(tmp);
        s->x[0] ^= lane;
        ascon_permute(s, ASCON_PB_ROUNDS);
        ascon_secure_wipe(tmp, sizeof(tmp));
    }

    // Domain separation
    s->x[4] ^= 1ULL;
}

static void ascon_encrypt_msg(ascon_state_t* s,
                              const uint8_t* pt, size_t pt_len,
                              uint8_t* ct) {
    size_t blocks = pt_len / ASCON_AEAD_RATE;
    // Full blocks
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t m = load64_be(pt + i * ASCON_AEAD_RATE);
        s->x[0] ^= m;
        store64_be(ct + i * ASCON_AEAD_RATE, s->x[0]);
        ascon_permute(s, ASCON_PB_ROUNDS);
    }
    // Partial block
    size_t rem = pt_len % ASCON_AEAD_RATE;
    if (rem) {
        // Copy state x0 to bytes
        uint8_t lane_bytes[ASCON_AEAD_RATE];
        store64_be(lane_bytes, s->x[0]);
        for (size_t i = 0; i < rem; ++i) {
            lane_bytes[i] ^= pt[blocks * ASCON_AEAD_RATE + i];
            ct[blocks * ASCON_AEAD_RATE + i] = lane_bytes[i];
        }
        lane_bytes[rem] ^= 0x80;
        uint64_t newx0 = load64_be(lane_bytes);
        s->x[0] = newx0;
        ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
    }
}

static int ascon_decrypt_msg(ascon_state_t* s,
                             const uint8_t* ct, size_t ct_len,
                             uint8_t* pt) {
    size_t blocks = ct_len / ASCON_AEAD_RATE;
    // Full blocks
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t c = load64_be(ct + i * ASCON_AEAD_RATE);
        uint64_t m = s->x[0] ^ c;
        store64_be(pt + i * ASCON_AEAD_RATE, m);
        s->x[0] = c;
        ascon_permute(s, ASCON_PB_ROUNDS);
    }
    // Partial block
    size_t rem = ct_len % ASCON_AEAD_RATE;
    if (rem) {
        uint8_t lane_bytes[ASCON_AEAD_RATE];
        store64_be(lane_bytes, s->x[0]);
        for (size_t i = 0; i < rem; ++i) {
            uint8_t cbi = ct[blocks * ASCON_AEAD_RATE + i];
            uint8_t mbi = lane_bytes[i] ^ cbi;
            pt[blocks * ASCON_AEAD_RATE + i] = mbi;
            lane_bytes[i] = cbi; // x0 becomes ciphertext bytes
        }
        lane_bytes[rem] ^= 0x80;
        s->x[0] = load64_be(lane_bytes);
        ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
    }
    return 0;
}

static void ascon_finalize(ascon_state_t* s,
                           const uint8_t key[ASCON_KEY_BYTES],
                           uint8_t tag[ASCON_TAG_BYTES]) {
    uint64_t k0 = load64_be(key);
    uint64_t k1 = load64_be(key + 8);
    s->x[1] ^= k0;
    s->x[2] ^= k1;
    ascon_permute(s, ASCON_PA_ROUNDS);
    s->x[3] ^= k0;
    s->x[4] ^= k1;
    store64_be(tag, s->x[3]);
    store64_be(tag + 8, s->x[4]);
}

int ascon128_encrypt(
    const uint8_t key[ASCON_KEY_BYTES],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext, uint8_t tag[ASCON_TAG_BYTES]) {
    if (!key || !nonce || (!plaintext && pt_len) || (!ciphertext && pt_len) || !tag) return -2;
    ascon_state_t st;
    ascon_init(&st, key, nonce);
    ascon_absorb_ad(&st, ad, ad_len);
    ascon_encrypt_msg(&st, plaintext, pt_len, ciphertext);
    ascon_finalize(&st, key, tag);
    ascon_secure_wipe(&st, sizeof(st));
    return 0;
}

int ascon128_decrypt(
    const uint8_t key[ASCON_KEY_BYTES],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[ASCON_TAG_BYTES],
    uint8_t* plaintext) {
    if (!key || !nonce || (!ciphertext && ct_len) || (!plaintext && ct_len) || !tag) return -2;
    ascon_state_t st;
    ascon_init(&st, key, nonce);
    ascon_absorb_ad(&st, ad, ad_len);
    ascon_decrypt_msg(&st, ciphertext, ct_len, plaintext);
    uint8_t calc_tag[ASCON_TAG_BYTES];
    ascon_finalize(&st, key, calc_tag);
    int neq = ascon_ct_compare(calc_tag, tag, ASCON_TAG_BYTES);
    // Wipe sensitive material regardless of result
    ascon_secure_wipe(calc_tag, sizeof(calc_tag));
    ascon_secure_wipe(&st, sizeof(st));
    if (ASCON_UNLIKELY(neq != 0)) {
        // On failure, wipe plaintext buffer
        if (plaintext && ct_len) ascon_secure_wipe(plaintext, ct_len);
        return -1;
    }
    return 0;
}

// ASCON-128a parameters: rate=16 bytes, pa=12, pb=8
#define ASCON128A_RATE 16
#define ASCON128A_PB_ROUNDS 8
static const uint64_t ASCON128A_IV = 0x80800c0800000000ULL;

static void ascon128a_init(ascon_state_t* s,
                           const uint8_t key[ASCON_KEY_BYTES],
                           const uint8_t nonce[ASCON_NONCE_BYTES]) {
    uint64_t k0 = load64_be(key);
    uint64_t k1 = load64_be(key + 8);
    uint64_t n0 = load64_be(nonce);
    uint64_t n1 = load64_be(nonce + 8);
    s->x[0] = ASCON128A_IV;
    s->x[1] = k0;
    s->x[2] = k1;
    s->x[3] = n0;
    s->x[4] = n1;
    ascon_permute(s, ASCON_PA_ROUNDS);
    s->x[3] ^= k0;
    s->x[4] ^= k1;
}

static void ascon128a_absorb_ad(ascon_state_t* s, const uint8_t* ad, size_t ad_len) {
    if (!ad || ad_len == 0) {
        s->x[4] ^= 1ULL;
        return;
    }
    size_t full = ad_len / ASCON128A_RATE;
    for (size_t i = 0; i < full; ++i) {
        uint64_t a0 = load64_be(ad + i * ASCON128A_RATE);
        uint64_t a1 = load64_be(ad + i * ASCON128A_RATE + 8);
        s->x[0] ^= a0;
        s->x[1] ^= a1;
        ascon_permute(s, ASCON128A_PB_ROUNDS);
    }
    size_t rem = ad_len % ASCON128A_RATE;
    if (rem) {
        uint8_t lane0[8]; uint8_t lane1[8];
        store64_be(lane0, s->x[0]);
        store64_be(lane1, s->x[1]);
        size_t first = rem > 8 ? 8 : rem;
        for (size_t i = 0; i < first; ++i) lane0[i] ^= ad[full * ASCON128A_RATE + i];
        if (rem <= 8) {
            lane0[rem] ^= 0x80;
        } else {
            size_t r2 = rem - 8;
            for (size_t i = 0; i < r2; ++i) lane1[i] ^= ad[full * ASCON128A_RATE + 8 + i];
            lane1[r2] ^= 0x80;
        }
        s->x[0] = load64_be(lane0);
        s->x[1] = load64_be(lane1);
        ascon_secure_wipe(lane0, sizeof(lane0));
        ascon_secure_wipe(lane1, sizeof(lane1));
        ascon_permute(s, ASCON128A_PB_ROUNDS);
    }
    s->x[4] ^= 1ULL;
}

static void ascon128a_encrypt_msg(ascon_state_t* s,
                                  const uint8_t* pt, size_t pt_len,
                                  uint8_t* ct) {
    size_t full = pt_len / ASCON128A_RATE;
    for (size_t i = 0; i < full; ++i) {
        uint64_t m0 = load64_be(pt + i * ASCON128A_RATE);
        uint64_t m1 = load64_be(pt + i * ASCON128A_RATE + 8);
        s->x[0] ^= m0; s->x[1] ^= m1;
        store64_be(ct + i * ASCON128A_RATE, s->x[0]);
        store64_be(ct + i * ASCON128A_RATE + 8, s->x[1]);
        ascon_permute(s, ASCON128A_PB_ROUNDS);
    }
    size_t rem = pt_len % ASCON128A_RATE;
    if (rem) {
        uint8_t lane0[8]; uint8_t lane1[8];
        store64_be(lane0, s->x[0]);
        store64_be(lane1, s->x[1]);
        size_t first = rem > 8 ? 8 : rem;
        // first lane
        for (size_t i = 0; i < first; ++i) {
            lane0[i] ^= pt[full * ASCON128A_RATE + i];
            ct[full * ASCON128A_RATE + i] = lane0[i];
        }
        if (rem <= 8) {
            lane0[rem] ^= 0x80;
        } else {
            size_t r2 = rem - 8;
            for (size_t i = 0; i < r2; ++i) {
                lane1[i] ^= pt[full * ASCON128A_RATE + 8 + i];
                ct[full * ASCON128A_RATE + 8 + i] = lane1[i];
            }
            lane1[r2] ^= 0x80;
        }
        s->x[0] = load64_be(lane0);
        s->x[1] = load64_be(lane1);
        ascon_secure_wipe(lane0, sizeof(lane0));
        ascon_secure_wipe(lane1, sizeof(lane1));
    }
}

static int ascon128a_decrypt_msg(ascon_state_t* s,
                                 const uint8_t* ct, size_t ct_len,
                                 uint8_t* pt) {
    size_t full = ct_len / ASCON128A_RATE;
    for (size_t i = 0; i < full; ++i) {
        uint64_t c0 = load64_be(ct + i * ASCON128A_RATE);
        uint64_t c1 = load64_be(ct + i * ASCON128A_RATE + 8);
        uint64_t m0 = s->x[0] ^ c0;
        uint64_t m1 = s->x[1] ^ c1;
        store64_be(pt + i * ASCON128A_RATE, m0);
        store64_be(pt + i * ASCON128A_RATE + 8, m1);
        s->x[0] = c0; s->x[1] = c1;
        ascon_permute(s, ASCON128A_PB_ROUNDS);
    }
    size_t rem = ct_len % ASCON128A_RATE;
    if (rem) {
        uint8_t lane0[8]; uint8_t lane1[8];
        store64_be(lane0, s->x[0]);
        store64_be(lane1, s->x[1]);
        size_t first = rem > 8 ? 8 : rem;
        for (size_t i = 0; i < first; ++i) {
            uint8_t cbi = ct[full * ASCON128A_RATE + i];
            uint8_t mbi = lane0[i] ^ cbi;
            pt[full * ASCON128A_RATE + i] = mbi;
            lane0[i] = cbi;
        }
        if (rem > 8) {
            size_t r2 = rem - 8;
            for (size_t i = 0; i < r2; ++i) {
                uint8_t cbi = ct[full * ASCON128A_RATE + 8 + i];
                uint8_t mbi = lane1[i] ^ cbi;
                pt[full * ASCON128A_RATE + 8 + i] = mbi;
                lane1[i] = cbi;
            }
            lane1[r2] ^= 0x80;
        } else {
            lane0[rem] ^= 0x80;
        }
        s->x[0] = load64_be(lane0);
        s->x[1] = load64_be(lane1);
        ascon_secure_wipe(lane0, sizeof(lane0));
        ascon_secure_wipe(lane1, sizeof(lane1));
    }
    return 0;
}

int ascon128a_encrypt(
    const uint8_t key[ASCON_KEY_BYTES],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext, uint8_t tag[ASCON_TAG_BYTES]) {
    if (!key || !nonce || (!plaintext && pt_len) || (!ciphertext && pt_len) || !tag) return -2;
    ascon_state_t st;
    ascon128a_init(&st, key, nonce);
    ascon128a_absorb_ad(&st, ad, ad_len);
    ascon128a_encrypt_msg(&st, plaintext, pt_len, ciphertext);
    ascon_finalize(&st, key, tag);
    ascon_secure_wipe(&st, sizeof(st));
    return 0;
}

int ascon128a_decrypt(
    const uint8_t key[ASCON_KEY_BYTES],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[ASCON_TAG_BYTES],
    uint8_t* plaintext) {
    if (!key || !nonce || (!ciphertext && ct_len) || (!plaintext && ct_len) || !tag) return -2;
    ascon_state_t st;
    ascon128a_init(&st, key, nonce);
    ascon128a_absorb_ad(&st, ad, ad_len);
    ascon128a_decrypt_msg(&st, ciphertext, ct_len, plaintext);
    uint8_t calc_tag[ASCON_TAG_BYTES];
    ascon_finalize(&st, key, calc_tag);
    int neq = ascon_ct_compare(calc_tag, tag, ASCON_TAG_BYTES);
    ascon_secure_wipe(calc_tag, sizeof(calc_tag));
    ascon_secure_wipe(&st, sizeof(st));
    if (ASCON_UNLIKELY(neq != 0)) {
        if (plaintext && ct_len) ascon_secure_wipe(plaintext, ct_len);
        return -1;
    }
    return 0;
}

// ASCON-80pq parameters (v1.2): key=20 bytes, rate=8, pa=12, pb=6
#define ASCON80PQ_RATE 8
#define ASCON80PQ_PB_ROUNDS 6
static const uint64_t ASCON80PQ_IV = 0xA0400C0600000000ULL; // top byte differs to encode k=160

static inline uint64_t load32_to64_be(const uint8_t* p) {
    // Load 32-bit big-endian and place in the high 32 bits of a 64-bit lane
    uint32_t v = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return ((uint64_t)v) << 32;
}

static void ascon80pq_init(ascon_state_t* s,
                           const uint8_t key[20],
                           const uint8_t nonce[ASCON_NONCE_BYTES]) {
    uint64_t k0 = load64_be(key);
    uint64_t k1 = load64_be(key + 8);
    uint64_t k2 = load32_to64_be(key + 16);
    uint64_t n0 = load64_be(nonce);
    uint64_t n1 = load64_be(nonce + 8);
    s->x[0] = ASCON80PQ_IV;
    s->x[1] = k0;
    s->x[2] = k1;
    s->x[3] = k2;
    s->x[4] = n0 ^ n1;
    ascon_permute(s, ASCON_PA_ROUNDS);
    s->x[1] ^= k0;
    s->x[2] ^= k1;
    s->x[3] ^= k2;
    s->x[4] ^= n0;
}

static void ascon80pq_absorb_ad(ascon_state_t* s, const uint8_t* ad, size_t ad_len) {
    if (!ad || ad_len == 0) { s->x[4] ^= 1ULL; return; }
    size_t blocks = ad_len / ASCON80PQ_RATE;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t lane = load64_be(ad + i * ASCON80PQ_RATE);
        s->x[0] ^= lane;
        ascon_permute(s, ASCON80PQ_PB_ROUNDS);
    }
    size_t rem = ad_len % ASCON80PQ_RATE;
    uint8_t tmp[ASCON80PQ_RATE] = {0};
    if (rem) memcpy(tmp, ad + blocks * ASCON80PQ_RATE, rem);
    tmp[rem] = 0x80;
    uint64_t lane = load64_be(tmp);
    s->x[0] ^= lane;
    ascon_permute(s, ASCON80PQ_PB_ROUNDS);
    s->x[4] ^= 1ULL;
    ascon_secure_wipe(tmp, sizeof(tmp));
}

static void ascon80pq_encrypt_msg(ascon_state_t* s,
                                  const uint8_t* pt, size_t pt_len,
                                  uint8_t* ct) {
    size_t blocks = pt_len / ASCON80PQ_RATE;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t m = load64_be(pt + i * ASCON80PQ_RATE);
        s->x[0] ^= m;
        store64_be(ct + i * ASCON80PQ_RATE, s->x[0]);
        ascon_permute(s, ASCON80PQ_PB_ROUNDS);
    }
    size_t rem = pt_len % ASCON80PQ_RATE;
    if (rem) {
        uint8_t lane_bytes[ASCON80PQ_RATE];
        store64_be(lane_bytes, s->x[0]);
        for (size_t i = 0; i < rem; ++i) {
            lane_bytes[i] ^= pt[blocks * ASCON80PQ_RATE + i];
            ct[blocks * ASCON80PQ_RATE + i] = lane_bytes[i];
        }
        lane_bytes[rem] ^= 0x80;
        s->x[0] = load64_be(lane_bytes);
        ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
    }
}

static int ascon80pq_decrypt_msg(ascon_state_t* s,
                                 const uint8_t* ct, size_t ct_len,
                                 uint8_t* pt) {
    size_t blocks = ct_len / ASCON80PQ_RATE;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t c = load64_be(ct + i * ASCON80PQ_RATE);
        uint64_t m = s->x[0] ^ c;
        store64_be(pt + i * ASCON80PQ_RATE, m);
        s->x[0] = c;
        ascon_permute(s, ASCON80PQ_PB_ROUNDS);
    }
    size_t rem = ct_len % ASCON80PQ_RATE;
    if (rem) {
        uint8_t lane_bytes[ASCON80PQ_RATE];
        store64_be(lane_bytes, s->x[0]);
        for (size_t i = 0; i < rem; ++i) {
            uint8_t cbi = ct[blocks * ASCON80PQ_RATE + i];
            uint8_t mbi = lane_bytes[i] ^ cbi;
            pt[blocks * ASCON80PQ_RATE + i] = mbi;
            lane_bytes[i] = cbi;
        }
        lane_bytes[rem] ^= 0x80;
        s->x[0] = load64_be(lane_bytes);
        ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
    }
    return 0;
}

static void ascon80pq_finalize(ascon_state_t* s,
                               const uint8_t key[20],
                               uint8_t tag[ASCON_TAG_BYTES]) {
    uint64_t k0 = load64_be(key);
    uint64_t k1 = load64_be(key + 8);
    uint64_t k2 = load32_to64_be(key + 16);
    s->x[1] ^= k0;
    s->x[2] ^= k1;
    s->x[3] ^= k2;
    ascon_permute(s, ASCON_PA_ROUNDS);
    s->x[3] ^= k0;
    s->x[4] ^= k1;
    store64_be(tag, s->x[3]);
    store64_be(tag + 8, s->x[4]);
}

int ascon80pq_encrypt(
    const uint8_t key[20],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext, uint8_t tag[ASCON_TAG_BYTES]) {
    if (!key || !nonce || (!plaintext && pt_len) || (!ciphertext && pt_len) || !tag) return -2;
    ascon_state_t st;
    ascon80pq_init(&st, key, nonce);
    ascon80pq_absorb_ad(&st, ad, ad_len);
    ascon80pq_encrypt_msg(&st, plaintext, pt_len, ciphertext);
    ascon80pq_finalize(&st, key, tag);
    ascon_secure_wipe(&st, sizeof(st));
    return 0;
}

int ascon80pq_decrypt(
    const uint8_t key[20],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[ASCON_TAG_BYTES],
    uint8_t* plaintext) {
    if (!key || !nonce || (!ciphertext && ct_len) || (!plaintext && ct_len) || !tag) return -2;
    ascon_state_t st;
    ascon80pq_init(&st, key, nonce);
    ascon80pq_absorb_ad(&st, ad, ad_len);
    ascon80pq_decrypt_msg(&st, ciphertext, ct_len, plaintext);
    uint8_t calc_tag[ASCON_TAG_BYTES];
    ascon80pq_finalize(&st, key, calc_tag);
    int neq = ascon_ct_compare(calc_tag, tag, ASCON_TAG_BYTES);
    ascon_secure_wipe(calc_tag, sizeof(calc_tag));
    ascon_secure_wipe(&st, sizeof(st));
    if (ASCON_UNLIKELY(neq != 0)) {
        if (plaintext && ct_len) ascon_secure_wipe(plaintext, ct_len);
        return -1;
    }
    return 0;
}


// ================= Incremental AEAD APIs (streaming) =================
// Helpers for 8-byte rate variants (ASCON-128, ASCON-80pq)
static void aead_absorb_ad_update_r8(ascon_state_t* st, uint8_t* ad_buf, size_t* ad_len,
                                     const uint8_t* ad, size_t ad_in_len, int pb_rounds) {
    const size_t RATE = 8;
    const uint8_t* p = ad;
    // Fill partial buffer
    if (*ad_len) {
        size_t need = RATE - *ad_len;
        size_t take = (ad_in_len < need) ? ad_in_len : need;
        if (take) {
            memcpy(ad_buf + *ad_len, p, take);
            *ad_len += take; p += take; ad_in_len -= take;
        }
        if (*ad_len == RATE) {
            uint64_t lane = load64_be(ad_buf);
            st->x[0] ^= lane;
            ascon_permute(st, pb_rounds);
            *ad_len = 0;
        }
    }
    // Full blocks
    while (ad_in_len >= RATE) {
        uint64_t lane = load64_be(p);
        st->x[0] ^= lane;
        ascon_permute(st, pb_rounds);
        p += RATE; ad_in_len -= RATE;
    }
    // Tail
    if (ad_in_len) {
        memcpy(ad_buf + *ad_len, p, ad_in_len);
        *ad_len += ad_in_len;
    }
}

static void aead_absorb_ad_finalize_r8(ascon_state_t* st, uint8_t* ad_buf, size_t* ad_len, int pb_rounds) {
    uint8_t tmp[8]; memset(tmp, 0, 8);
    if (*ad_len) memcpy(tmp, ad_buf, *ad_len);
    tmp[*ad_len] = 0x80;
    uint64_t lane = load64_be(tmp);
    st->x[0] ^= lane;
    ascon_permute(st, pb_rounds);
    st->x[4] ^= 1ULL; // domain separation
    ascon_secure_wipe(tmp, sizeof(tmp));
    *ad_len = 0;
}

static void aead_encrypt_update_r8(ascon_state_t* st, uint8_t* msg_buf, size_t* msg_len,
                                   const uint8_t* pt, size_t pt_len, uint8_t* ct, int pb_rounds) {
    const size_t RATE = 8;
    const uint8_t* p = pt; uint8_t* q = ct;
    // Complete partial buffer if present
    if (*msg_len) {
        uint8_t lane_bytes[RATE];
        store64_be(lane_bytes, st->x[0]);
        size_t need = RATE - *msg_len;
        size_t take = (pt_len < need) ? pt_len : need;
        for (size_t i = 0; i < take; ++i) {
            lane_bytes[*msg_len + i] ^= p[i];
            q[i] = lane_bytes[*msg_len + i];
        }
        *msg_len += take; p += take; q += take; pt_len -= take;
        if (*msg_len == RATE) {
            st->x[0] = load64_be(lane_bytes);
            ascon_permute(st, pb_rounds);
            *msg_len = 0;
        } else {
            // still partial, save lane_bytes back into msg_buf
            memcpy(msg_buf, lane_bytes, *msg_len);
            ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
            return;
        }
        ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
    }
    // Full blocks
    while (pt_len >= RATE) {
        uint64_t m = load64_be(p);
        st->x[0] ^= m;
        store64_be(q, st->x[0]);
        ascon_permute(st, pb_rounds);
        p += RATE; q += RATE; pt_len -= RATE;
    }
    // Tail: buffer
    if (pt_len) {
        uint8_t lane_bytes[RATE];
        store64_be(lane_bytes, st->x[0]);
        for (size_t i = 0; i < pt_len; ++i) {
            lane_bytes[i] ^= p[i];
            q[i] = lane_bytes[i];
        }
        memcpy(msg_buf, lane_bytes, pt_len);
        *msg_len = pt_len;
        ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
    }
}

static void aead_encrypt_final_r8(ascon_state_t* st, const uint8_t* key, uint8_t* msg_buf, size_t* msg_len,
                                   uint8_t tag[ASCON_TAG_BYTES]) {
    if (*msg_len) {
        uint8_t lane_bytes[8]; memset(lane_bytes, 0, 8);
        memcpy(lane_bytes, msg_buf, *msg_len);
        lane_bytes[*msg_len] ^= 0x80;
        st->x[0] = load64_be(lane_bytes);
        ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
        *msg_len = 0;
    }
    ascon_finalize(st, key, tag);
}

static void aead_decrypt_update_r8(ascon_state_t* st, uint8_t* msg_buf, size_t* msg_len,
                                   const uint8_t* ct, size_t ct_len, uint8_t* pt, int pb_rounds) {
    const size_t RATE = 8;
    const uint8_t* p = ct; uint8_t* q = pt;

    if (*msg_len) {
        uint8_t lane_bytes[RATE];
        store64_be(lane_bytes, st->x[0]);
        size_t need = RATE - *msg_len;
        size_t take = (ct_len < need) ? ct_len : need;
        for (size_t i = 0; i < take; ++i) {
            uint8_t cbi = p[i];
            uint8_t mbi = lane_bytes[*msg_len + i] ^ cbi;
            q[i] = mbi;
            lane_bytes[*msg_len + i] = cbi; // state becomes ciphertext bytes
        }
        *msg_len += take; p += take; q += take; ct_len -= take;
        if (*msg_len == RATE) {
            st->x[0] = load64_be(lane_bytes);
            ascon_permute(st, pb_rounds);
            *msg_len = 0;
        } else {
            memcpy(msg_buf, lane_bytes, *msg_len);
            ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
            return;
        }
        ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
    }

    while (ct_len >= RATE) {
        uint64_t c = load64_be(p);
        uint64_t m = st->x[0] ^ c;
        store64_be(q, m);
        st->x[0] = c;
        ascon_permute(st, pb_rounds);
        p += RATE; q += RATE; ct_len -= RATE;
    }

    if (ct_len) {
        uint8_t lane_bytes[RATE];
        store64_be(lane_bytes, st->x[0]);
        for (size_t i = 0; i < ct_len; ++i) {
            uint8_t cbi = p[i];
            uint8_t mbi = lane_bytes[i] ^ cbi;
            q[i] = mbi;
            lane_bytes[i] = cbi;
        }
        memcpy(msg_buf, lane_bytes, ct_len);
        *msg_len = ct_len;
        ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
    }
}

static void aead_decrypt_final_r8(ascon_state_t* st, const uint8_t* key, uint8_t* msg_buf, size_t* msg_len) {
    if (*msg_len) {
        uint8_t lane_bytes[8]; memset(lane_bytes, 0, 8);
        memcpy(lane_bytes, msg_buf, *msg_len);
        lane_bytes[*msg_len] ^= 0x80;
        st->x[0] = load64_be(lane_bytes);
        ascon_secure_wipe(lane_bytes, sizeof(lane_bytes));
        *msg_len = 0;
    }
    (void)key; // key used in finalize step by caller
}

// Helpers for 16-byte rate variant (ASCON-128a)
static void aead_absorb_ad_update_r16(ascon_state_t* st, uint8_t* ad_buf, size_t* ad_len,
                                      const uint8_t* ad, size_t ad_in_len, int pb_rounds) {
    const size_t RATE = 16;
    const uint8_t* p = ad;
    if (*ad_len) {
        size_t need = RATE - *ad_len;
        size_t take = (ad_in_len < need) ? ad_in_len : need;
        if (take) { memcpy(ad_buf + *ad_len, p, take); *ad_len += take; p += take; ad_in_len -= take; }
        if (*ad_len == RATE) {
            uint64_t a0 = load64_be(ad_buf);
            uint64_t a1 = load64_be(ad_buf + 8);
            st->x[0] ^= a0; st->x[1] ^= a1;
            ascon_permute(st, pb_rounds);
            *ad_len = 0;
        }
    }
    while (ad_in_len >= RATE) {
        uint64_t a0 = load64_be(p);
        uint64_t a1 = load64_be(p + 8);
        st->x[0] ^= a0; st->x[1] ^= a1;
        ascon_permute(st, pb_rounds);
        p += RATE; ad_in_len -= RATE;
    }
    if (ad_in_len) { memcpy(ad_buf + *ad_len, p, ad_in_len); *ad_len += ad_in_len; }
}

static void aead_absorb_ad_finalize_r16(ascon_state_t* st, uint8_t* ad_buf, size_t* ad_len, int pb_rounds) {
    uint8_t lane0[8]; uint8_t lane1[8];
    store64_be(lane0, st->x[0]);
    store64_be(lane1, st->x[1]);
    if (*ad_len <= 8) {
        for (size_t i = 0; i < *ad_len; ++i) lane0[i] ^= ad_buf[i];
        lane0[*ad_len] ^= 0x80;
    } else {
        size_t r2 = *ad_len - 8;
        for (size_t i = 0; i < 8; ++i) lane0[i] ^= ad_buf[i];
        for (size_t i = 0; i < r2; ++i) lane1[i] ^= ad_buf[8 + i];
        lane1[r2] ^= 0x80;
    }
    st->x[0] = load64_be(lane0);
    st->x[1] = load64_be(lane1);
    ascon_permute(st, pb_rounds);
    st->x[4] ^= 1ULL;
    ascon_secure_wipe(lane0, sizeof(lane0));
    ascon_secure_wipe(lane1, sizeof(lane1));
    *ad_len = 0;
}

static void aead_encrypt_update_r16(ascon_state_t* st, uint8_t* msg_buf, size_t* msg_len,
                                    const uint8_t* pt, size_t pt_len, uint8_t* ct, int pb_rounds) {
    const size_t RATE = 16;
    const uint8_t* p = pt; uint8_t* q = ct;

    if (*msg_len) {
        uint8_t lane0[8]; uint8_t lane1[8];
        store64_be(lane0, st->x[0]);
        store64_be(lane1, st->x[1]);
        size_t first = (*msg_len < 8) ? (8 - *msg_len) : 0; // bytes remaining in first lane before padding region
        size_t avail0 = 8 - (*msg_len > 8 ? 8 : *msg_len);
        size_t need = RATE - *msg_len;
        size_t take = (pt_len < need) ? pt_len : need;
        for (size_t i = 0; i < take && (*msg_len + i) < 8; ++i) {
            lane0[*msg_len + i] ^= p[i];
            q[i] = lane0[*msg_len + i];
        }
        for (size_t i = (8 > *msg_len ? (8 - *msg_len) : 0); i < take; ++i) {
            size_t idx = *msg_len + i;
            if (idx >= 8) {
                size_t j = idx - 8;
                lane1[j] ^= p[i];
                q[i] = lane1[j];
            }
        }
        *msg_len += take; p += take; q += take; pt_len -= take;
        if (*msg_len == RATE) {
            st->x[0] = load64_be(lane0);
            st->x[1] = load64_be(lane1);
            ascon_permute(st, pb_rounds);
            *msg_len = 0;
        } else {
            // save partial
            memcpy(msg_buf, lane0, (*msg_len > 8 ? 8 : *msg_len));
            if (*msg_len > 8) memcpy(msg_buf + 8, lane1, *msg_len - 8);
            ascon_secure_wipe(lane0, sizeof(lane0));
            ascon_secure_wipe(lane1, sizeof(lane1));
            return;
        }
        ascon_secure_wipe(lane0, sizeof(lane0));
        ascon_secure_wipe(lane1, sizeof(lane1));
    }

    while (pt_len >= RATE) {
        uint64_t m0 = load64_be(p);
        uint64_t m1 = load64_be(p + 8);
        st->x[0] ^= m0; st->x[1] ^= m1;
        store64_be(q, st->x[0]);
        store64_be(q + 8, st->x[1]);
        ascon_permute(st, pb_rounds);
        p += RATE; q += RATE; pt_len -= RATE;
    }

    if (pt_len) {
        uint8_t lane0[8]; uint8_t lane1[8];
        store64_be(lane0, st->x[0]);
        store64_be(lane1, st->x[1]);
        size_t first = pt_len > 8 ? 8 : pt_len;
        for (size_t i = 0; i < first; ++i) { lane0[i] ^= p[i]; q[i] = lane0[i]; }
        if (pt_len > 8) {
            size_t r2 = pt_len - 8;
            for (size_t i = 0; i < r2; ++i) { lane1[i] ^= p[8 + i]; q[8 + i] = lane1[i]; }
        }
        memcpy(msg_buf, lane0, (pt_len > 8 ? 8 : pt_len));
        if (pt_len > 8) memcpy(msg_buf + 8, lane1, pt_len - 8);
        *msg_len = pt_len;
        ascon_secure_wipe(lane0, sizeof(lane0));
        ascon_secure_wipe(lane1, sizeof(lane1));
    }
}

static void aead_encrypt_final_r16(ascon_state_t* st, const uint8_t* key, uint8_t* msg_buf, size_t* msg_len,
                                   uint8_t tag[ASCON_TAG_BYTES]) {
    if (*msg_len) {
        uint8_t lane0[8] = {0}; uint8_t lane1[8] = {0};
        if (*msg_len <= 8) {
            memcpy(lane0, msg_buf, *msg_len);
            lane0[*msg_len] ^= 0x80;
        } else {
            memcpy(lane0, msg_buf, 8);
            size_t r2 = *msg_len - 8;
            memcpy(lane1, msg_buf + 8, r2);
            lane1[r2] ^= 0x80;
        }
        st->x[0] = load64_be(lane0);
        st->x[1] = load64_be(lane1);
        ascon_secure_wipe(lane0, sizeof(lane0));
        ascon_secure_wipe(lane1, sizeof(lane1));
        *msg_len = 0;
    }
    ascon_finalize(st, key, tag);
}

static void aead_decrypt_update_r16(ascon_state_t* st, uint8_t* msg_buf, size_t* msg_len,
                                    const uint8_t* ct, size_t ct_len, uint8_t* pt, int pb_rounds) {
    const size_t RATE = 16; const uint8_t* p = ct; uint8_t* q = pt;

    if (*msg_len) {
        uint8_t lane0[8]; uint8_t lane1[8];
        store64_be(lane0, st->x[0]);
        store64_be(lane1, st->x[1]);
        size_t need = RATE - *msg_len;
        size_t take = (ct_len < need) ? ct_len : need;
        for (size_t i = 0; i < take && (*msg_len + i) < 8; ++i) {
            uint8_t cbi = p[i];
            uint8_t mbi = lane0[*msg_len + i] ^ cbi;
            q[i] = mbi;
            lane0[*msg_len + i] = cbi;
        }
        for (size_t i = (8 > *msg_len ? (8 - *msg_len) : 0); i < take; ++i) {
            size_t idx = *msg_len + i;
            if (idx >= 8) {
                size_t j = idx - 8;
                uint8_t cbi = p[i];
                uint8_t mbi = lane1[j] ^ cbi;
                q[i] = mbi;
                lane1[j] = cbi;
            }
        }
        *msg_len += take; p += take; q += take; ct_len -= take;
        if (*msg_len == RATE) {
            st->x[0] = load64_be(lane0);
            st->x[1] = load64_be(lane1);
            ascon_permute(st, pb_rounds);
            *msg_len = 0;
        } else {
            memcpy(msg_buf, lane0, (*msg_len > 8 ? 8 : *msg_len));
            if (*msg_len > 8) memcpy(msg_buf + 8, lane1, *msg_len - 8);
            ascon_secure_wipe(lane0, sizeof(lane0));
            ascon_secure_wipe(lane1, sizeof(lane1));
            return;
        }
        ascon_secure_wipe(lane0, sizeof(lane0));
        ascon_secure_wipe(lane1, sizeof(lane1));
    }

    while (ct_len >= RATE) {
        uint64_t c0 = load64_be(p);
        uint64_t c1 = load64_be(p + 8);
        uint64_t m0 = st->x[0] ^ c0;
        uint64_t m1 = st->x[1] ^ c1;
        store64_be(q, m0); store64_be(q + 8, m1);
        st->x[0] = c0; st->x[1] = c1;
        ascon_permute(st, pb_rounds);
        p += RATE; q += RATE; ct_len -= RATE;
    }

    if (ct_len) {
        uint8_t lane0[8]; uint8_t lane1[8];
        store64_be(lane0, st->x[0]);
        store64_be(lane1, st->x[1]);
        size_t first = ct_len > 8 ? 8 : ct_len;
        for (size_t i = 0; i < first; ++i) { uint8_t cbi = p[i]; q[i] = lane0[i] ^ cbi; lane0[i] = cbi; }
        if (ct_len > 8) {
            size_t r2 = ct_len - 8;
            for (size_t i = 0; i < r2; ++i) { uint8_t cbi = p[8 + i]; q[8 + i] = lane1[i] ^ cbi; lane1[i] = cbi; }
        }
        memcpy(msg_buf, lane0, (ct_len > 8 ? 8 : ct_len));
        if (ct_len > 8) memcpy(msg_buf + 8, lane1, ct_len - 8);
        *msg_len = ct_len;
        ascon_secure_wipe(lane0, sizeof(lane0));
        ascon_secure_wipe(lane1, sizeof(lane1));
    }
}

static void aead_decrypt_final_r16(ascon_state_t* st, const uint8_t* key, uint8_t* msg_buf, size_t* msg_len) {
    if (*msg_len) {
        uint8_t lane0[8] = {0}; uint8_t lane1[8] = {0};
        if (*msg_len <= 8) {
            memcpy(lane0, msg_buf, *msg_len); lane0[*msg_len] ^= 0x80;
        } else {
            memcpy(lane0, msg_buf, 8);
            size_t r2 = *msg_len - 8; memcpy(lane1, msg_buf + 8, r2); lane1[r2] ^= 0x80;
        }
        st->x[0] = load64_be(lane0); st->x[1] = load64_be(lane1);
        ascon_secure_wipe(lane0, sizeof(lane0)); ascon_secure_wipe(lane1, sizeof(lane1));
        *msg_len = 0;
    }
    (void)key;
}

// -------- ASCON-128 (rate=8) streaming API --------
void ascon128_ctx_init(ascon128_ctx* ctx, const uint8_t key[ASCON_KEY_BYTES], const uint8_t nonce[ASCON_NONCE_BYTES]) {
    if (!ctx || !key || !nonce) return;
    memcpy(ctx->key, key, ASCON_KEY_BYTES);
    ascon_init(&ctx->st, key, nonce);
    ctx->ad_len = 0; ctx->msg_len = 0; ctx->ad_finalized = 0;
}

void ascon128_absorb_ad_update(ascon128_ctx* ctx, const uint8_t* ad, size_t ad_len) {
    if (!ctx || (!ad && ad_len)) return;
    aead_absorb_ad_update_r8(&ctx->st, ctx->ad_buf, &ctx->ad_len, ad, ad_len, ASCON_PB_ROUNDS);
}

void ascon128_absorb_ad_finalize(ascon128_ctx* ctx) {
    if (!ctx || ctx->ad_finalized) return;
    aead_absorb_ad_finalize_r8(&ctx->st, ctx->ad_buf, &ctx->ad_len, ASCON_PB_ROUNDS);
    ctx->ad_finalized = 1;
}

void ascon128_encrypt_update(ascon128_ctx* ctx, const uint8_t* pt, size_t pt_len, uint8_t* ct) {
    if (!ctx || (!pt && pt_len) || (!ct && pt_len)) return;
    if (!ctx->ad_finalized) ascon128_absorb_ad_finalize(ctx);
    aead_encrypt_update_r8(&ctx->st, ctx->msg_buf, &ctx->msg_len, pt, pt_len, ct, ASCON_PB_ROUNDS);
}

void ascon128_encrypt_final(ascon128_ctx* ctx, uint8_t tag[ASCON_TAG_BYTES]) {
    if (!ctx || !tag) return;
    if (!ctx->ad_finalized) ascon128_absorb_ad_finalize(ctx);
    aead_encrypt_final_r8(&ctx->st, ctx->key, ctx->msg_buf, &ctx->msg_len, tag);
    ascon_secure_wipe(ctx, sizeof(*ctx));
}

void ascon128_decrypt_update(ascon128_ctx* ctx, const uint8_t* ct, size_t ct_len, uint8_t* pt) {
    if (!ctx || (!ct && ct_len) || (!pt && ct_len)) return;
    if (!ctx->ad_finalized) ascon128_absorb_ad_finalize(ctx);
    aead_decrypt_update_r8(&ctx->st, ctx->msg_buf, &ctx->msg_len, ct, ct_len, pt, ASCON_PB_ROUNDS);
}

int ascon128_decrypt_final(ascon128_ctx* ctx, const uint8_t tag[ASCON_TAG_BYTES]) {
    if (!ctx || !tag) return -2;
    if (!ctx->ad_finalized) ascon128_absorb_ad_finalize(ctx);
    aead_decrypt_final_r8(&ctx->st, ctx->key, ctx->msg_buf, &ctx->msg_len);
    uint8_t calc[ASCON_TAG_BYTES];
    ascon_finalize(&ctx->st, ctx->key, calc);
    int neq = ascon_ct_compare(calc, tag, ASCON_TAG_BYTES);
    ascon_secure_wipe(calc, sizeof(calc));
    int rc = (neq == 0) ? 0 : -1;
    ascon_secure_wipe(ctx, sizeof(*ctx));
    return rc;
}

// -------- ASCON-128a (rate=16) streaming API --------
void ascon128a_ctx_init(ascon128a_ctx* ctx, const uint8_t key[ASCON_KEY_BYTES], const uint8_t nonce[ASCON_NONCE_BYTES]) {
    if (!ctx || !key || !nonce) return;
    memcpy(ctx->key, key, ASCON_KEY_BYTES);
    ascon128a_init(&ctx->st, key, nonce);
    ctx->ad_len = 0; ctx->msg_len = 0; ctx->ad_finalized = 0;
}

void ascon128a_absorb_ad_update(ascon128a_ctx* ctx, const uint8_t* ad, size_t ad_len) {
    if (!ctx || (!ad && ad_len)) return;
    aead_absorb_ad_update_r16(&ctx->st, ctx->ad_buf, &ctx->ad_len, ad, ad_len, ASCON128A_PB_ROUNDS);
}

void ascon128a_absorb_ad_finalize(ascon128a_ctx* ctx) {
    if (!ctx || ctx->ad_finalized) return;
    aead_absorb_ad_finalize_r16(&ctx->st, ctx->ad_buf, &ctx->ad_len, ASCON128A_PB_ROUNDS);
    ctx->ad_finalized = 1;
}

void ascon128a_encrypt_update(ascon128a_ctx* ctx, const uint8_t* pt, size_t pt_len, uint8_t* ct) {
    if (!ctx || (!pt && pt_len) || (!ct && pt_len)) return;
    if (!ctx->ad_finalized) ascon128a_absorb_ad_finalize(ctx);
    aead_encrypt_update_r16(&ctx->st, ctx->msg_buf, &ctx->msg_len, pt, pt_len, ct, ASCON128A_PB_ROUNDS);
}

void ascon128a_encrypt_final(ascon128a_ctx* ctx, uint8_t tag[ASCON_TAG_BYTES]) {
    if (!ctx || !tag) return;
    if (!ctx->ad_finalized) ascon128a_absorb_ad_finalize(ctx);
    aead_encrypt_final_r16(&ctx->st, ctx->key, ctx->msg_buf, &ctx->msg_len, tag);
    ascon_secure_wipe(ctx, sizeof(*ctx));
}

void ascon128a_decrypt_update(ascon128a_ctx* ctx, const uint8_t* ct, size_t ct_len, uint8_t* pt) {
    if (!ctx || (!ct && ct_len) || (!pt && ct_len)) return;
    if (!ctx->ad_finalized) ascon128a_absorb_ad_finalize(ctx);
    aead_decrypt_update_r16(&ctx->st, ctx->msg_buf, &ctx->msg_len, ct, ct_len, pt, ASCON128A_PB_ROUNDS);
}

int ascon128a_decrypt_final(ascon128a_ctx* ctx, const uint8_t tag[ASCON_TAG_BYTES]) {
    if (!ctx || !tag) return -2;
    if (!ctx->ad_finalized) ascon128a_absorb_ad_finalize(ctx);
    aead_decrypt_final_r16(&ctx->st, ctx->key, ctx->msg_buf, &ctx->msg_len);
    uint8_t calc[ASCON_TAG_BYTES];
    ascon_finalize(&ctx->st, ctx->key, calc);
    int neq = ascon_ct_compare(calc, tag, ASCON_TAG_BYTES);
    ascon_secure_wipe(calc, sizeof(calc));
    int rc = (neq == 0) ? 0 : -1;
    ascon_secure_wipe(ctx, sizeof(*ctx));
    return rc;
}

// -------- ASCON-80pq (rate=8) streaming API --------
void ascon80pq_ctx_init(ascon80pq_ctx* ctx, const uint8_t key[20], const uint8_t nonce[ASCON_NONCE_BYTES]) {
    if (!ctx || !key || !nonce) return;
    memcpy(ctx->key, key, 20);
    ascon80pq_init(&ctx->st, key, nonce);
    ctx->ad_len = 0; ctx->msg_len = 0; ctx->ad_finalized = 0;
}

void ascon80pq_absorb_ad_update(ascon80pq_ctx* ctx, const uint8_t* ad, size_t ad_len) {
    if (!ctx || (!ad && ad_len)) return;
    aead_absorb_ad_update_r8(&ctx->st, ctx->ad_buf, &ctx->ad_len, ad, ad_len, ASCON80PQ_PB_ROUNDS);
}

void ascon80pq_absorb_ad_finalize(ascon80pq_ctx* ctx) {
    if (!ctx || ctx->ad_finalized) return;
    aead_absorb_ad_finalize_r8(&ctx->st, ctx->ad_buf, &ctx->ad_len, ASCON80PQ_PB_ROUNDS);
    ctx->ad_finalized = 1;
}

void ascon80pq_encrypt_update(ascon80pq_ctx* ctx, const uint8_t* pt, size_t pt_len, uint8_t* ct) {
    if (!ctx || (!pt && pt_len) || (!ct && pt_len)) return;
    if (!ctx->ad_finalized) ascon80pq_absorb_ad_finalize(ctx);
    aead_encrypt_update_r8(&ctx->st, ctx->msg_buf, &ctx->msg_len, pt, pt_len, ct, ASCON80PQ_PB_ROUNDS);
}

void ascon80pq_encrypt_final(ascon80pq_ctx* ctx, uint8_t tag[ASCON_TAG_BYTES]) {
    if (!ctx || !tag) return;
    if (!ctx->ad_finalized) ascon80pq_absorb_ad_finalize(ctx);
    aead_encrypt_final_r8(&ctx->st, ctx->key, ctx->msg_buf, &ctx->msg_len, tag);
    ascon_secure_wipe(ctx, sizeof(*ctx));
}

void ascon80pq_decrypt_update(ascon80pq_ctx* ctx, const uint8_t* ct, size_t ct_len, uint8_t* pt) {
    if (!ctx || (!ct && ct_len) || (!pt && ct_len)) return;
    if (!ctx->ad_finalized) ascon80pq_absorb_ad_finalize(ctx);
    aead_decrypt_update_r8(&ctx->st, ctx->msg_buf, &ctx->msg_len, ct, ct_len, pt, ASCON80PQ_PB_ROUNDS);
}

int ascon80pq_decrypt_final(ascon80pq_ctx* ctx, const uint8_t tag[ASCON_TAG_BYTES]) {
    if (!ctx || !tag) return -2;
    if (!ctx->ad_finalized) ascon80pq_absorb_ad_finalize(ctx);
    aead_decrypt_final_r8(&ctx->st, ctx->key, ctx->msg_buf, &ctx->msg_len);
    uint8_t calc[ASCON_TAG_BYTES];
    ascon80pq_finalize(&ctx->st, ctx->key, calc);
    int neq = ascon_ct_compare(calc, tag, ASCON_TAG_BYTES);
    ascon_secure_wipe(calc, sizeof(calc));
    int rc = (neq == 0) ? 0 : -1;
    ascon_secure_wipe(ctx, sizeof(*ctx));
    return rc;
}
