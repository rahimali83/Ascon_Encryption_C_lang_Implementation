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
    // Final partial block with 10* padding in byte domain
    size_t rem = ad_len % ASCON_AEAD_RATE;
    uint8_t tmp[ASCON_AEAD_RATE] = {0};
    if (rem) memcpy(tmp, ad + blocks * ASCON_AEAD_RATE, rem);
    tmp[rem] = 0x80;
    uint64_t lane = load64_be(tmp);
    s->x[0] ^= lane;
    ascon_permute(s, ASCON_PB_ROUNDS);

    // Domain separation
    s->x[4] ^= 1ULL;
    ascon_secure_wipe(tmp, sizeof(tmp));
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
