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
