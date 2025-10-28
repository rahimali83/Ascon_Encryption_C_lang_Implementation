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

// Ascon-Hash implementations
// SPDX-License-Identifier: MIT
#include <string.h>
#include "../include/ascon/ascon_hash.h"
#include "../include/ascon/ascon_common.h"

// Generic sponge-based hash helper (32-byte digest)
static const int ASCON_HASH_RATE = 8; // bytes
static const int ASCON_HASH_PA_ROUNDS = 12;

static void ascon_hash_core(uint64_t iv, const uint8_t* msg, size_t msg_len, uint8_t* digest) {
    ascon_state_t st = {{ iv, 0, 0, 0, 0 }};

    ascon_permute(&st, ASCON_HASH_PA_ROUNDS);

    // Absorb full rate-size blocks
    const uint8_t* p = msg;
    size_t blocks = msg_len / ASCON_HASH_RATE;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t lane = ascon_load64(p);
        st.x[0] ^= lane;
        ascon_permute(&st, ASCON_HASH_PA_ROUNDS);
        p += ASCON_HASH_RATE;
    }

    // Pad and absorb final block (10* padding)
    uint64_t last = 0;
    size_t rem = msg_len % ASCON_HASH_RATE;
    if (rem > 0) {
        memcpy(&last, p, rem);
    }
    ((uint8_t*)&last)[rem] = 0x80; // append single 1 bit then zeros in byte terms
    st.x[0] ^= ascon_load64(&last);
    ascon_permute(&st, ASCON_HASH_PA_ROUNDS);

    // Squeeze 32 bytes (4 lanes of 8 bytes)
    uint8_t* out = digest;
    for (int i = 0; i < 4; ++i) {
        ascon_store64(out + 8*i, st.x[0]);
        if (i != 3) ascon_permute(&st, ASCON_HASH_PA_ROUNDS);
    }
}

// Provisional IVs (distinct values for domain separation). Replace with official IVs when KATs are added.
static const uint64_t ASCON_HASH256_IV = 0x0000080100cc0002ULL; // existing IV used in project
static const uint64_t ASCON_HASH_IV    = 0x0000080100cc0010ULL; // provisional distinct IV
static const uint64_t ASCON_HASHA_IV   = 0x0000080100cc0011ULL; // provisional distinct IV

void ascon_hash256(const uint8_t* msg, size_t msg_len, uint8_t* digest) {
    ascon_hash_core(ASCON_HASH256_IV, msg, msg_len, digest);
}

void ascon_hash(const uint8_t* msg, size_t msg_len, uint8_t* digest) {
    ascon_hash_core(ASCON_HASH_IV, msg, msg_len, digest);
}

void ascon_hasha(const uint8_t* msg, size_t msg_len, uint8_t* digest) {
    ascon_hash_core(ASCON_HASHA_IV, msg, msg_len, digest);
}

// Streaming Hash-256 implementation
void ascon_hash256_init(ascon_hash256_ctx* ctx) {
    if (!ctx) return;
    ctx->st.x[0] = ASCON_HASH256_IV;
    ctx->st.x[1] = 0; ctx->st.x[2] = 0; ctx->st.x[3] = 0; ctx->st.x[4] = 0;
    ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
    ctx->buf_len = 0;
    ctx->finalized = 0;
}

void ascon_hash256_update(ascon_hash256_ctx* ctx, const uint8_t* data, size_t len) {
    if (!ctx || ctx->finalized) return;
    if (!data && len) return;
    const uint8_t* p = data;
    // Fill partial buffer first
    if (ctx->buf_len) {
        size_t need = (size_t)ASCON_HASH_RATE - ctx->buf_len;
        size_t take = (len < need) ? len : need;
        if (take) {
            memcpy(ctx->buf + ctx->buf_len, p, take);
            ctx->buf_len += take;
            p += take; len -= take;
        }
        if (ctx->buf_len == (size_t)ASCON_HASH_RATE) {
            uint64_t lane = ascon_load64(ctx->buf);
            ctx->st.x[0] ^= lane;
            ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
            ctx->buf_len = 0;
        }
    }
    // Process full blocks directly
    while (len >= (size_t)ASCON_HASH_RATE) {
        uint64_t lane = ascon_load64(p);
        ctx->st.x[0] ^= lane;
        ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
        p += ASCON_HASH_RATE;
        len -= ASCON_HASH_RATE;
    }
    // Buffer tail
    if (len) {
        memcpy(ctx->buf + ctx->buf_len, p, len);
        ctx->buf_len += len;
    }
}

void ascon_hash256_final(ascon_hash256_ctx* ctx, uint8_t out[32]) {
    if (!ctx || ctx->finalized) {
        if (ctx && out && ctx->finalized) {
            // Do nothing if already finalized; out would be undefined.
        }
        return;
    }
    // Apply padding to remaining bytes in buffer and absorb
    uint8_t lastb[8]; memset(lastb, 0, 8);
    if (ctx->buf_len) memcpy(lastb, ctx->buf, ctx->buf_len);
    lastb[ctx->buf_len] = 0x80;
    uint64_t lane = ascon_load64(lastb);
    ctx->st.x[0] ^= lane;
    ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);

    // Squeeze 32 bytes
    for (int i = 0; i < 4; ++i) {
        ascon_store64(out + 8*i, ctx->st.x[0]);
        if (i != 3) ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
    }

    // Wipe
    ascon_secure_wipe(ctx, sizeof(*ctx));
    ctx->finalized = 1;
}


// ===== Streaming HASH (Ascon-Hash) implementation =====
void ascon_hash_init(ascon_hash_ctx* ctx) {
    if (!ctx) return;
    ctx->st.x[0] = ASCON_HASH_IV;
    ctx->st.x[1] = 0; ctx->st.x[2] = 0; ctx->st.x[3] = 0; ctx->st.x[4] = 0;
    ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
    ctx->buf_len = 0;
    ctx->finalized = 0;
}

void ascon_hash_update(ascon_hash_ctx* ctx, const uint8_t* data, size_t len) {
    if (!ctx || ctx->finalized) return;
    if (!data && len) return;
    const uint8_t* p = data;
    if (ctx->buf_len) {
        size_t need = (size_t)ASCON_HASH_RATE - ctx->buf_len;
        size_t take = (len < need) ? len : need;
        if (take) {
            memcpy(ctx->buf + ctx->buf_len, p, take);
            ctx->buf_len += take;
            p += take; len -= take;
        }
        if (ctx->buf_len == (size_t)ASCON_HASH_RATE) {
            uint64_t lane = ascon_load64(ctx->buf);
            ctx->st.x[0] ^= lane;
            ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
            ctx->buf_len = 0;
        }
    }
    while (len >= (size_t)ASCON_HASH_RATE) {
        uint64_t lane = ascon_load64(p);
        ctx->st.x[0] ^= lane;
        ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
        p += ASCON_HASH_RATE;
        len -= ASCON_HASH_RATE;
    }
    if (len) {
        memcpy(ctx->buf + ctx->buf_len, p, len);
        ctx->buf_len += len;
    }
}

void ascon_hash_final(ascon_hash_ctx* ctx, uint8_t out[32]) {
    if (!ctx || ctx->finalized) {
        if (ctx && out && ctx->finalized) { /* already finalized */ }
        return;
    }
    uint8_t lastb[8]; memset(lastb, 0, 8);
    if (ctx->buf_len) memcpy(lastb, ctx->buf, ctx->buf_len);
    lastb[ctx->buf_len] = 0x80;
    uint64_t lane = ascon_load64(lastb);
    ctx->st.x[0] ^= lane;
    ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
    for (int i = 0; i < 4; ++i) {
        ascon_store64(out + 8*i, ctx->st.x[0]);
        if (i != 3) ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
    }
    ascon_secure_wipe(ctx, sizeof(*ctx));
    ctx->finalized = 1;
}

// ===== Streaming HASHa (Ascon-Hasha) implementation =====
void ascon_hasha_init(ascon_hasha_ctx* ctx) {
    if (!ctx) return;
    ctx->st.x[0] = ASCON_HASHA_IV;
    ctx->st.x[1] = 0; ctx->st.x[2] = 0; ctx->st.x[3] = 0; ctx->st.x[4] = 0;
    ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
    ctx->buf_len = 0;
    ctx->finalized = 0;
}

void ascon_hasha_update(ascon_hasha_ctx* ctx, const uint8_t* data, size_t len) {
    if (!ctx || ctx->finalized) return;
    if (!data && len) return;
    const uint8_t* p = data;
    if (ctx->buf_len) {
        size_t need = (size_t)ASCON_HASH_RATE - ctx->buf_len;
        size_t take = (len < need) ? len : need;
        if (take) {
            memcpy(ctx->buf + ctx->buf_len, p, take);
            ctx->buf_len += take;
            p += take; len -= take;
        }
        if (ctx->buf_len == (size_t)ASCON_HASH_RATE) {
            uint64_t lane = ascon_load64(ctx->buf);
            ctx->st.x[0] ^= lane;
            ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
            ctx->buf_len = 0;
        }
    }
    while (len >= (size_t)ASCON_HASH_RATE) {
        uint64_t lane = ascon_load64(p);
        ctx->st.x[0] ^= lane;
        ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
        p += ASCON_HASH_RATE;
        len -= ASCON_HASH_RATE;
    }
    if (len) {
        memcpy(ctx->buf + ctx->buf_len, p, len);
        ctx->buf_len += len;
    }
}

void ascon_hasha_final(ascon_hasha_ctx* ctx, uint8_t out[32]) {
    if (!ctx || ctx->finalized) {
        if (ctx && out && ctx->finalized) { /* already finalized */ }
        return;
    }
    uint8_t lastb[8]; memset(lastb, 0, 8);
    if (ctx->buf_len) memcpy(lastb, ctx->buf, ctx->buf_len);
    lastb[ctx->buf_len] = 0x80;
    uint64_t lane = ascon_load64(lastb);
    ctx->st.x[0] ^= lane;
    ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
    for (int i = 0; i < 4; ++i) {
        ascon_store64(out + 8*i, ctx->st.x[0]);
        if (i != 3) ascon_permute(&ctx->st, ASCON_HASH_PA_ROUNDS);
    }
    ascon_secure_wipe(ctx, sizeof(*ctx));
    ctx->finalized = 1;
}
