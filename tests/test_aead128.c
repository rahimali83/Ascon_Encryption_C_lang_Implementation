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

// MIT License
// Simple unit tests for ASCON-128 AEAD: round-trip and negative tamper cases
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../include/ascon/ascon_aead.h"
#include "../include/ascon/ascon_common.h"
#include <stdlib.h>

static int roundtrip_case(const uint8_t* key,
                          const uint8_t* nonce,
                          const uint8_t* ad, size_t ad_len,
                          const uint8_t* pt, size_t pt_len) {
    uint8_t* ct = (uint8_t*)malloc(pt_len);
    if (!ct) { fprintf(stderr, "OOM ct\n"); return 1; }
    uint8_t* dec = (uint8_t*)malloc(pt_len);
    if (!dec) { fprintf(stderr, "OOM dec\n"); free(ct); return 1; }
    uint8_t tag[ASCON_TAG_BYTES];

    int rc = ascon128_encrypt(key, nonce, ad, ad_len, pt, pt_len, ct, tag);
    if (rc != 0) {
        fprintf(stderr, "encrypt rc=%d\n", rc);
        free(ct); free(dec);
        return 1;
    }
    rc = ascon128_decrypt(key, nonce, ad, ad_len, ct, pt_len, tag, dec);
    if (rc != 0) {
        fprintf(stderr, "decrypt rc=%d (should succeed)\n", rc);
        free(ct); free(dec);
        return 1;
    }
    int ok = (pt_len == 0) || (memcmp(pt, dec, pt_len) == 0);
    if (!ok) {
        fprintf(stderr, "round-trip mismatch for len=%zu\n", pt_len);
        free(ct); free(dec);
        return 1;
    }
    ascon_secure_wipe(ct, pt_len);
    ascon_secure_wipe(dec, pt_len);
    free(ct); free(dec);
    return 0;
}

static int negative_cases(const uint8_t* key, const uint8_t* nonce) {
    const uint8_t ad[] = {0x01,0x02,0x03};
    const uint8_t pt[] = {0x10,0x11,0x12,0x13,0x14};
    uint8_t ct[sizeof(pt)];
    uint8_t tag[ASCON_TAG_BYTES];

    if (ascon128_encrypt(key, nonce, ad, sizeof(ad), pt, sizeof(pt), ct, tag) != 0) {
        fprintf(stderr, "encrypt failed in negative_cases\n");
        return 1;
    }

    // Tamper with tag
    uint8_t bad_tag[ASCON_TAG_BYTES];
    memcpy(bad_tag, tag, ASCON_TAG_BYTES);
    bad_tag[0] ^= 0x01;
    uint8_t dec[sizeof(pt)];
    int rc = ascon128_decrypt(key, nonce, ad, sizeof(ad), ct, sizeof(ct), bad_tag, dec);
    if (rc == 0) {
        fprintf(stderr, "tampered tag accepted (should fail)\n");
        return 1;
    }

    // Tamper with AD
    uint8_t bad_ad[sizeof(ad)];
    memcpy(bad_ad, ad, sizeof(ad));
    bad_ad[1] ^= 0x80;
    rc = ascon128_decrypt(key, nonce, bad_ad, sizeof(bad_ad), ct, sizeof(ct), tag, (uint8_t*)dec);
    if (rc == 0) {
        fprintf(stderr, "tampered AD accepted (should fail)\n");
        return 1;
    }

    // Tamper with nonce
    uint8_t bad_nonce[ASCON_NONCE_BYTES];
    memcpy(bad_nonce, nonce, ASCON_NONCE_BYTES);
    bad_nonce[ASCON_NONCE_BYTES-1] ^= 0x55;
    rc = ascon128_decrypt(key, bad_nonce, ad, sizeof(ad), ct, sizeof(ct), tag, (uint8_t*)dec);
    if (rc == 0) {
        fprintf(stderr, "tampered nonce accepted (should fail)\n");
        return 1;
    }

    return 0;
}

int main(void) {
    // Fixed key/nonce for repeatability
    uint8_t key[ASCON_KEY_BYTES]   = {0};
    uint8_t nonce[ASCON_NONCE_BYTES] = {0};
    for (int i = 0; i < ASCON_KEY_BYTES; ++i) key[i] = (uint8_t)i;
    for (int i = 0; i < ASCON_NONCE_BYTES; ++i) nonce[i] = (uint8_t)(0xA0 + i);

    // No AD, empty PT
    if (roundtrip_case(key, nonce, NULL, 0, NULL, 0) != 0) return 1;

    // No AD, small PTs
    const uint8_t pt1[] = {0x00};
    if (roundtrip_case(key, nonce, NULL, 0, pt1, sizeof(pt1)) != 0) return 1;
    const uint8_t pt2[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06};
    if (roundtrip_case(key, nonce, NULL, 0, pt2, sizeof(pt2)) != 0) return 1;
    const uint8_t pt3[] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17}; // one full block
    if (roundtrip_case(key, nonce, NULL, 0, pt3, sizeof(pt3)) != 0) return 1;
    const uint8_t pt4[] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28}; // block + 1
    if (roundtrip_case(key, nonce, NULL, 0, pt4, sizeof(pt4)) != 0) return 1;

    // With AD
    const uint8_t ad1[] = {0xAA};
    const uint8_t pt5[] = {0x33,0x34,0x35,0x36};
    if (roundtrip_case(key, nonce, ad1, sizeof(ad1), pt5, sizeof(pt5)) != 0) return 1;

    if (negative_cases(key, nonce) != 0) return 1;

    return 0;
}
