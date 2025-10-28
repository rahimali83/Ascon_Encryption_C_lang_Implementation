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

// Ascon XOF API: ASCON-XOF, ASCON-XOFa
// SPDX-License-Identifier: MIT
#ifndef ASCON_XOF_H
#define ASCON_XOF_H

#include <stdint.h>
#include <stddef.h>
#include "ascon_common.h"
#include "ascon_permutation.h"

#ifdef __cplusplus
extern "C" {
#endif

// One-shot XOFs: absorb input and squeeze out_len bytes
int ascon_xof(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len);
int ascon_xofa(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len);

// Streaming XOF API (incremental absorb + multi-call squeeze)
typedef struct {
    ascon_state_t st;      // internal permutation state
    uint8_t buf[8];        // absorb buffer (rate = 8 bytes)
    size_t buf_len;        // bytes currently in buf
    int absorbed_final;    // whether padding/finalization has been applied
    int variant_a;         // 0 = XOF, 1 = XOFA (chooses IV)
} ascon_xof_ctx;

// Initialize context for ASCON-XOF (variant_a = 0) or ASCON-XOFa (variant_a = 1)
void ascon_xof_init(ascon_xof_ctx* ctx);
void ascon_xofa_init(ascon_xof_ctx* ctx);

// Absorb more input (only valid before finalization)
void ascon_xof_absorb(ascon_xof_ctx* ctx, const uint8_t* in, size_t in_len);

// Finalize absorption (apply padding). Implicitly done on first squeeze if not called.
void ascon_xof_finalize(ascon_xof_ctx* ctx);

// Squeeze arbitrary number of bytes. Can be called multiple times after finalize.
void ascon_xof_squeeze(ascon_xof_ctx* ctx, uint8_t* out, size_t out_len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // ASCON_XOF_H
