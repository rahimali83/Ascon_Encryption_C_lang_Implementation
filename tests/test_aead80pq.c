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

// MIT License
// Simple unit tests for ASCON-80pq AEAD: round-trip and negative tamper cases
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "../include/ascon/ascon_aead.h"
#include "../include/ascon/ascon_common.h"

static int roundtrip_case(const uint8_t key[20],
                          const uint8_t* nonce,
                          const uint8_t* ad, size_t ad_len,
                          const uint8_t* pt, size_t pt_len) {
    uint8_t* ct = (uint8_t*)malloc(pt_len);
    if (!ct) { fprintf(stderr, "OOM ct\n"); return 1; }
    uint8_t* dec = (uint8_t*)malloc(pt_len);
    if (!dec) { fprintf(stderr, "OOM dec\n"); free(ct); return 1; }
    uint8_t tag[ASCON_TAG_BYTES];

    int rc = ascon80pq_encrypt(key, nonce, ad, ad_len, pt, pt_len, ct, tag);
    if (rc != 0) {
        fprintf(stderr, "encrypt rc=%d\n", rc);
        free(ct); free(dec);
        return 1;
    }
    rc = ascon80pq_decrypt(key, nonce, ad, ad_len, ct, pt_len, tag, dec);
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

static int negative_cases(const uint8_t key[20], const uint8_t* nonce) {
    const uint8_t ad[] = {0x01,0x02,0x03};
    const uint8_t pt[] = {0x10,0x11,0x12,0x13,0x14};
    uint8_t ct[sizeof(pt)];
    uint8_t tag[ASCON_TAG_BYTES];

    if (ascon80pq_encrypt(key, nonce, ad, sizeof(ad), pt, sizeof(pt), ct, tag) != 0) {
        fprintf(stderr, "encrypt failed in negative_cases\n");
        return 1;
    }

    // Tamper with tag
    uint8_t bad_tag[ASCON_TAG_BYTES];
    memcpy(bad_tag, tag, ASCON_TAG_BYTES);
    bad_tag[0] ^= 0x01;
    uint8_t dec[sizeof(pt)];
    int rc = ascon80pq_decrypt(key, nonce, ad, sizeof(ad), ct, sizeof(ct), bad_tag, dec);
    if (rc == 0) {
        fprintf(stderr, "tampered tag accepted (should fail)\n");
        return 1;
    }

    // Tamper with AD
    uint8_t bad_ad[sizeof(ad)];
    memcpy(bad_ad, ad, sizeof(ad));
    bad_ad[1] ^= 0x80;
    rc = ascon80pq_decrypt(key, nonce, bad_ad, sizeof(bad_ad), ct, sizeof(ct), tag, (uint8_t*)dec);
    if (rc == 0) {
        fprintf(stderr, "tampered AD accepted (should fail)\n");
        return 1;
    }

    // Tamper with nonce
    uint8_t bad_nonce[ASCON_NONCE_BYTES];
    memcpy(bad_nonce, nonce, ASCON_NONCE_BYTES);
    bad_nonce[ASCON_NONCE_BYTES-1] ^= 0x55;
    rc = ascon80pq_decrypt(key, bad_nonce, ad, sizeof(ad), ct, sizeof(ct), tag, (uint8_t*)dec);
    if (rc == 0) {
        fprintf(stderr, "tampered nonce accepted (should fail)\n");
        return 1;
    }

    return 0;
}

int main(void) {
    // 20-byte key
    uint8_t key[20] = {0};
    for (int i = 0; i < 20; ++i) key[i] = (uint8_t)(0x55 + i);

    uint8_t nonce[ASCON_NONCE_BYTES] = {0};
    for (int i = 0; i < ASCON_NONCE_BYTES; ++i) nonce[i] = (uint8_t)(0xC0 + i);

    if (roundtrip_case(key, nonce, NULL, 0, NULL, 0) != 0) return 1;

    const uint8_t pt1[] = {0x00};
    if (roundtrip_case(key, nonce, NULL, 0, pt1, sizeof(pt1)) != 0) return 1;
    const uint8_t pt2[] = {0,1,2,3,4,5,6};
    if (roundtrip_case(key, nonce, NULL, 0, pt2, sizeof(pt2)) != 0) return 1;
    const uint8_t pt3[] = {0,1,2,3,4,5,6,7};
    if (roundtrip_case(key, nonce, NULL, 0, pt3, sizeof(pt3)) != 0) return 1;
    const uint8_t pt4[] = {0,1,2,3,4,5,6,7,8};
    if (roundtrip_case(key, nonce, NULL, 0, pt4, sizeof(pt4)) != 0) return 1;

    const uint8_t ad1[] = {0xAA};
    const uint8_t pt5[] = {0x33,0x34,0x35,0x36};
    if (roundtrip_case(key, nonce, ad1, sizeof(ad1), pt5, sizeof(pt5)) != 0) return 1;

    if (negative_cases(key, nonce) != 0) return 1;
    return 0;
}
