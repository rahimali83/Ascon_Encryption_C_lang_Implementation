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
// Tests for ASCON-HASH and ASCON-HASHa provisional implementations
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../include/ascon/ascon_hash.h"

static void hash_to_hex(void (*hf)(const uint8_t*, size_t, uint8_t*),
                        const uint8_t* msg, size_t len, char out[65]) {
    uint8_t d[32];
    hf(msg, len, d);
    static const char* hexd = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[2*i]   = hexd[d[i] >> 4];
        out[2*i+1] = hexd[d[i] & 0xF];
    }
    out[64] = '\0';
}

static int test_determinism(void) {
    const char* m = "abc";
    uint8_t digest1[32], digest2[32];
    ascon_hash((const uint8_t*)m, strlen(m), digest1);
    ascon_hash((const uint8_t*)m, strlen(m), digest2);
    if (memcmp(digest1, digest2, 32) != 0) {
        fprintf(stderr, "HASH determinism failed\n");
        return 1;
    }
    ascon_hasha((const uint8_t*)m, strlen(m), digest1);
    ascon_hasha((const uint8_t*)m, strlen(m), digest2);
    if (memcmp(digest1, digest2, 32) != 0) {
        fprintf(stderr, "HASHa determinism failed\n");
        return 1;
    }
    return 0;
}

static int test_input_diff(void) {
    const char* a = "a";
    const char* b = "b";
    uint8_t da[32], db[32];
    ascon_hash((const uint8_t*)a, strlen(a), da);
    ascon_hash((const uint8_t*)b, strlen(b), db);
    if (memcmp(da, db, 32) == 0) {
        fprintf(stderr, "HASH different inputs produced same digest\n");
        return 1;
    }
    ascon_hasha((const uint8_t*)a, strlen(a), da);
    ascon_hasha((const uint8_t*)b, strlen(b), db);
    if (memcmp(da, db, 32) == 0) {
        fprintf(stderr, "HASHa different inputs produced same digest\n");
        return 1;
    }
    return 0;
}

static int test_variant_diff(void) {
    const char* m = "variant";
    uint8_t d1[32], d2[32];
    ascon_hash((const uint8_t*)m, strlen(m), d1);
    ascon_hasha((const uint8_t*)m, strlen(m), d2);
    if (memcmp(d1, d2, 32) == 0) {
        fprintf(stderr, "HASH and HASHa produced same digest for input\n");
        return 1;
    }
    return 0;
}

int main(void) {
    if (test_determinism() != 0) return 1;
    if (test_input_diff() != 0) return 1;
    if (test_variant_diff() != 0) return 1;
    return 0;
}
