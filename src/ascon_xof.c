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

// Ascon XOF implementations
// SPDX-License-Identifier: MIT
#include <string.h>
#include "../include/ascon/ascon_xof.h"
#include "../include/ascon/ascon_common.h"

// Temporary parameterization to enable functionality pending official IVs/KATs.
// We reuse HASH256-like parameters: rate=8, rounds=12.
#define ASCON_XOF_RATE 8
#define ASCON_XOF_ROUNDS 12
static const uint64_t ASCON_XOF_IV  = 0x0000080100cc0002ULL; // placeholder (same as hash256 impl)
static const uint64_t ASCON_XOFA_IV = 0x0000080100cc0003ULL; // distinct placeholder for XOFa

static int ascon_xof_core(uint64_t iv,
                          const uint8_t* in, size_t in_len,
                          uint8_t* out, size_t out_len) {
    if ((!in && in_len) || (!out && out_len)) return -2;
    ascon_state_t st = {{ iv, 0, 0, 0, 0 }};
    ascon_permute(&st, ASCON_XOF_ROUNDS);

    // Absorb input in rate-sized blocks
    const uint8_t* p = in;
    size_t blocks = in_len / ASCON_XOF_RATE;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t lane = ascon_load64(p);
        st.x[0] ^= lane;
        ascon_permute(&st, ASCON_XOF_ROUNDS);
        p += ASCON_XOF_RATE;
    }
    // Final partial with 10* padding
    uint64_t last = 0;
    size_t rem = in_len % ASCON_XOF_RATE;
    if (rem > 0) memcpy(&last, p, rem);
    ((uint8_t*)&last)[rem] = 0x80;
    st.x[0] ^= ascon_load64(&last);
    ascon_permute(&st, ASCON_XOF_ROUNDS);

    // Squeeze out_len bytes
    uint8_t* q = out;
    size_t out_blocks = out_len / ASCON_XOF_RATE;
    for (size_t i = 0; i < out_blocks; ++i) {
        ascon_store64(q, st.x[0]);
        ascon_permute(&st, ASCON_XOF_ROUNDS);
        q += ASCON_XOF_RATE;
    }
    size_t out_rem = out_len % ASCON_XOF_RATE;
    if (out_rem) {
        uint8_t tmp[ASCON_XOF_RATE];
        ascon_store64(tmp, st.x[0]);
        memcpy(q, tmp, out_rem);
        ascon_secure_wipe(tmp, sizeof(tmp));
    }

    // Wipe sensitive state
    ascon_secure_wipe(&st, sizeof(st));
    return 0;
}

int ascon_xof(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len) {
    return ascon_xof_core(ASCON_XOF_IV, in, in_len, out, out_len);
}

int ascon_xofa(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len) {
    return ascon_xof_core(ASCON_XOFA_IV, in, in_len, out, out_len);
}


// Streaming XOF implementation
static void ascon_xof_init_common(ascon_xof_ctx* ctx, int variant_a) {
    if (!ctx) return;
    ctx->variant_a = variant_a ? 1 : 0;
    ctx->st.x[0] = variant_a ? ASCON_XOFA_IV : ASCON_XOF_IV;
    ctx->st.x[1] = 0; ctx->st.x[2] = 0; ctx->st.x[3] = 0; ctx->st.x[4] = 0;
    ascon_permute(&ctx->st, ASCON_XOF_ROUNDS);
    ctx->buf_len = 0;
    ctx->absorbed_final = 0;
}

void ascon_xof_init(ascon_xof_ctx* ctx) {
    ascon_xof_init_common(ctx, 0);
}

void ascon_xofa_init(ascon_xof_ctx* ctx) {
    ascon_xof_init_common(ctx, 1);
}

void ascon_xof_absorb(ascon_xof_ctx* ctx, const uint8_t* in, size_t in_len) {
    if (!ctx || ctx->absorbed_final) return;
    if (!in && in_len) return;
    const size_t RATE = (size_t)ASCON_XOF_RATE;
    const uint8_t* p = in;

    // Fill any partial buffer first
    if (ctx->buf_len) {
        size_t need = RATE - ctx->buf_len;
        size_t take = (in_len < need) ? in_len : need;
        if (take) {
            memcpy(ctx->buf + ctx->buf_len, p, take);
            ctx->buf_len += take;
            p += take; in_len -= take;
        }
        if (ctx->buf_len == RATE) {
            uint64_t lane = ascon_load64(ctx->buf);
            ctx->st.x[0] ^= lane;
            ascon_permute(&ctx->st, ASCON_XOF_ROUNDS);
            ctx->buf_len = 0;
        }
    }

    // Absorb full blocks
    while (in_len >= RATE) {
        uint64_t lane = ascon_load64(p);
        ctx->st.x[0] ^= lane;
        ascon_permute(&ctx->st, ASCON_XOF_ROUNDS);
        p += RATE; in_len -= RATE;
    }

    // Buffer the tail
    if (in_len) {
        memcpy(ctx->buf + ctx->buf_len, p, in_len);
        ctx->buf_len += in_len;
    }
}

void ascon_xof_finalize(ascon_xof_ctx* ctx) {
    if (!ctx || ctx->absorbed_final) return;
    const size_t RATE = (size_t)ASCON_XOF_RATE;
    uint8_t last[ASCON_XOF_RATE] = {0};
    if (ctx->buf_len) memcpy(last, ctx->buf, ctx->buf_len);
    last[ctx->buf_len] = 0x80;
    uint64_t lane = ascon_load64(last);
    ctx->st.x[0] ^= lane;
    ascon_permute(&ctx->st, ASCON_XOF_ROUNDS);
    ctx->buf_len = 0;
    ctx->absorbed_final = 1;
}

void ascon_xof_squeeze(ascon_xof_ctx* ctx, uint8_t* out, size_t out_len) {
    if (!ctx || (!out && out_len)) return;
    if (!ctx->absorbed_final) ascon_xof_finalize(ctx);
    const size_t RATE = (size_t)ASCON_XOF_RATE;
    uint8_t* q = out;

    // Full blocks
    while (out_len >= RATE) {
        ascon_store64(q, ctx->st.x[0]);
        ascon_permute(&ctx->st, ASCON_XOF_ROUNDS);
        q += RATE; out_len -= RATE;
    }

    // Remainder
    if (out_len) {
        uint8_t tmp[ASCON_XOF_RATE];
        ascon_store64(tmp, ctx->st.x[0]);
        memcpy(q, tmp, out_len);
        ascon_secure_wipe(tmp, sizeof(tmp));
        // Do not permute after partial squeeze; next squeeze continues from same state
    }
}
