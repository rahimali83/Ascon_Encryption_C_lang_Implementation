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
// Parameters:
//   - in: pointer to input bytes (may be NULL only if in_len == 0)
//   - in_len: length of input in bytes
//   - out: pointer to output buffer (must be non-NULL if out_len > 0)
//   - out_len: number of bytes to produce
// Returns:
//   - 0 on success
//   - -2 if arguments are invalid (e.g., out is NULL but out_len > 0)
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
