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

// Ascon AEAD API: ASCON-128, ASCON-128a, ASCON-80pq
// SPDX-License-Identifier: MIT
#ifndef ASCON_AEAD_H
#define ASCON_AEAD_H

#include <stdint.h>
#include <stddef.h>
#include "ascon_common.h"
#include "ascon_permutation.h"

#ifdef __cplusplus
extern "C" {
#endif

// Sizes per Ascon spec
#define ASCON_KEY_BYTES   16
#define ASCON_NONCE_BYTES 16
#define ASCON_TAG_BYTES   16

// Return 0 on success; non-zero on error.
int ascon128_encrypt(
    const uint8_t key[ASCON_KEY_BYTES],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext, uint8_t tag[ASCON_TAG_BYTES]);

int ascon128_decrypt(
    const uint8_t key[ASCON_KEY_BYTES],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[ASCON_TAG_BYTES],
    uint8_t* plaintext);

int ascon128a_encrypt(
    const uint8_t key[ASCON_KEY_BYTES],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext, uint8_t tag[ASCON_TAG_BYTES]);

int ascon128a_decrypt(
    const uint8_t key[ASCON_KEY_BYTES],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[ASCON_TAG_BYTES],
    uint8_t* plaintext);

int ascon80pq_encrypt(
    const uint8_t key[20],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext, uint8_t tag[ASCON_TAG_BYTES]);

int ascon80pq_decrypt(
    const uint8_t key[20],
    const uint8_t nonce[ASCON_NONCE_BYTES],
    const uint8_t* ad, size_t ad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[ASCON_TAG_BYTES],
    uint8_t* plaintext);

// Incremental AEAD API (streaming)
// Common pattern per variant:
//  - init(ctx, key, nonce)
//  - absorb_ad_update(ctx, ad, ad_len) [repeat]
//  - absorb_ad_finalize(ctx)           [once]
//  - encrypt_update(ctx, pt, pt_len, ct) [repeat]
//  - encrypt_final(ctx, tag)
// Or for decryption:
//  - decrypt_update(ctx, ct, ct_len, pt) [repeat]
//  - decrypt_final(ctx, tag) -> 0 on success, -1 on tag mismatch

typedef struct {
    ascon_state_t st;
    uint8_t key[ASCON_KEY_BYTES];
    uint8_t ad_buf[8]; size_t ad_len;
    uint8_t msg_buf[8]; size_t msg_len;
    int ad_finalized; // domain separation applied
} ascon128_ctx;

void ascon128_ctx_init(ascon128_ctx* ctx, const uint8_t key[ASCON_KEY_BYTES], const uint8_t nonce[ASCON_NONCE_BYTES]);
void ascon128_absorb_ad_update(ascon128_ctx* ctx, const uint8_t* ad, size_t ad_len);
void ascon128_absorb_ad_finalize(ascon128_ctx* ctx);
void ascon128_encrypt_update(ascon128_ctx* ctx, const uint8_t* pt, size_t pt_len, uint8_t* ct);
void ascon128_encrypt_final(ascon128_ctx* ctx, uint8_t tag[ASCON_TAG_BYTES]);
void ascon128_decrypt_update(ascon128_ctx* ctx, const uint8_t* ct, size_t ct_len, uint8_t* pt);
int  ascon128_decrypt_final(ascon128_ctx* ctx, const uint8_t tag[ASCON_TAG_BYTES]);

// ASCON-128a (rate=16)
typedef struct {
    ascon_state_t st;
    uint8_t key[ASCON_KEY_BYTES];
    uint8_t ad_buf[16]; size_t ad_len;
    uint8_t msg_buf[16]; size_t msg_len;
    int ad_finalized;
} ascon128a_ctx;

void ascon128a_ctx_init(ascon128a_ctx* ctx, const uint8_t key[ASCON_KEY_BYTES], const uint8_t nonce[ASCON_NONCE_BYTES]);
void ascon128a_absorb_ad_update(ascon128a_ctx* ctx, const uint8_t* ad, size_t ad_len);
void ascon128a_absorb_ad_finalize(ascon128a_ctx* ctx);
void ascon128a_encrypt_update(ascon128a_ctx* ctx, const uint8_t* pt, size_t pt_len, uint8_t* ct);
void ascon128a_encrypt_final(ascon128a_ctx* ctx, uint8_t tag[ASCON_TAG_BYTES]);
void ascon128a_decrypt_update(ascon128a_ctx* ctx, const uint8_t* ct, size_t ct_len, uint8_t* pt);
int  ascon128a_decrypt_final(ascon128a_ctx* ctx, const uint8_t tag[ASCON_TAG_BYTES]);

// ASCON-80pq (rate=8)
typedef struct {
    ascon_state_t st;
    uint8_t key[20];
    uint8_t ad_buf[8]; size_t ad_len;
    uint8_t msg_buf[8]; size_t msg_len;
    int ad_finalized;
} ascon80pq_ctx;

void ascon80pq_ctx_init(ascon80pq_ctx* ctx, const uint8_t key[20], const uint8_t nonce[ASCON_NONCE_BYTES]);
void ascon80pq_absorb_ad_update(ascon80pq_ctx* ctx, const uint8_t* ad, size_t ad_len);
void ascon80pq_absorb_ad_finalize(ascon80pq_ctx* ctx);
void ascon80pq_encrypt_update(ascon80pq_ctx* ctx, const uint8_t* pt, size_t pt_len, uint8_t* ct);
void ascon80pq_encrypt_final(ascon80pq_ctx* ctx, uint8_t tag[ASCON_TAG_BYTES]);
void ascon80pq_decrypt_update(ascon80pq_ctx* ctx, const uint8_t* ct, size_t ct_len, uint8_t* pt);
int  ascon80pq_decrypt_final(ascon80pq_ctx* ctx, const uint8_t tag[ASCON_TAG_BYTES]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // ASCON_AEAD_H

// -----------------------------------------------------------------------------
// Return codes and API notes
//
// Unless otherwise stated, AEAD functions in this header use the following
// convention for return values:
//   - 0  : success
//   - -1 : authentication/tag verification failed (for decrypt operations)
//   - -2 : invalid arguments (e.g., NULL pointer where non-NULL required)
//
// One-shot APIs:
//   - Encrypt variants write ciphertext and a 16-byte tag on success.
//   - Decrypt variants write plaintext on success; on tag mismatch (-1), the
//     plaintext buffer (if provided) is wiped.
//
// Streaming APIs:
//   - Call order (per variant):
//       init → [absorb_ad_update]* → absorb_ad_finalize →
//         {encrypt_update* → encrypt_final | decrypt_update* → decrypt_final}
//   - decrypt_final returns 0 on success, -1 on tag mismatch, -2 on invalid args.
//   - All contexts are securely wiped in final() functions.
// -----------------------------------------------------------------------------
