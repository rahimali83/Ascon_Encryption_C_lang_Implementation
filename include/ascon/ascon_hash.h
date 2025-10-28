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

// Ascon hash API (HASH, HASHa, HASH256)
// SPDX-License-Identifier: MIT
#ifndef ASCON_HASH_H
#define ASCON_HASH_H

#include <stdint.h>
#include <stddef.h>
#include "ascon_permutation.h"

#ifdef __cplusplus
extern "C" {
#endif

// One-shot APIs produce 32-byte digest for HASH/HASHa/HASH256
// Parameters:
//   - msg: pointer to input message bytes (may be NULL only if msg_len == 0)
//   - msg_len: length in bytes of the input message
//   - digest: pointer to a 32-byte buffer to receive the digest (must be non-NULL)
// Return value: none. The digest is written to the provided buffer.
void ascon_hash256(const uint8_t* msg, size_t msg_len, uint8_t* digest);
void ascon_hash(const uint8_t* msg, size_t msg_len, uint8_t* digest);
void ascon_hasha(const uint8_t* msg, size_t msg_len, uint8_t* digest);

// Streaming Hash-256 API (incremental hashing)
typedef struct {
    ascon_state_t st;      // internal permutation state
    uint8_t buf[8];        // absorb buffer (rate = 8 bytes)
    size_t buf_len;        // number of bytes currently in buf
    int finalized;         // set after final() is called
} ascon_hash256_ctx;

// Initialize context
void ascon_hash256_init(ascon_hash256_ctx* ctx);
// Absorb more message bytes (can be called many times)
void ascon_hash256_update(ascon_hash256_ctx* ctx, const uint8_t* data, size_t len);
// Finalize and write 32-byte digest; context is wiped
void ascon_hash256_final(ascon_hash256_ctx* ctx, uint8_t out[32]);

// Streaming HASH (Ascon-Hash) API
typedef struct {
    ascon_state_t st;
    uint8_t buf[8];
    size_t buf_len;
    int finalized;
} ascon_hash_ctx;

void ascon_hash_init(ascon_hash_ctx* ctx);
void ascon_hash_update(ascon_hash_ctx* ctx, const uint8_t* data, size_t len);
void ascon_hash_final(ascon_hash_ctx* ctx, uint8_t out[32]);

// Streaming HASHa (Ascon-Hasha) API
typedef struct {
    ascon_state_t st;
    uint8_t buf[8];
    size_t buf_len;
    int finalized;
} ascon_hasha_ctx;

void ascon_hasha_init(ascon_hasha_ctx* ctx);
void ascon_hasha_update(ascon_hasha_ctx* ctx, const uint8_t* data, size_t len);
void ascon_hasha_final(ascon_hasha_ctx* ctx, uint8_t out[32]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // ASCON_HASH_H

// -----------------------------------------------------------------------------
// Streaming API notes (Hash/Hasha/Hash256)
//
// All streaming hash functions in this header follow the same pattern:
//   - init(ctx)
//   - update(ctx, data, len) [can be called many times; accepts len=0]
//   - final(ctx, out32)
// Behavior:
//   - Rate is 8 bytes; 10* padding is applied once in final().
//   - After final(), the context is securely wiped and must not be reused.
//   - update(ctx, NULL, len>0) is ignored (treated as invalid args, no-op).
// Return codes:
//   - Hash functions are void and write the 32-byte digest to the provided buffer.
// -----------------------------------------------------------------------------
