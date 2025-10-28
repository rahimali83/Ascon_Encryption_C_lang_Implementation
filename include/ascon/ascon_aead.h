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

#ifdef __cplusplus
} // extern "C"
#endif

#endif // ASCON_AEAD_H
