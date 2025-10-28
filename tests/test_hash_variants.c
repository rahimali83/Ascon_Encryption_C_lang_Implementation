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
