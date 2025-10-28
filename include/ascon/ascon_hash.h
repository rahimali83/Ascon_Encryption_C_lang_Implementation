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
