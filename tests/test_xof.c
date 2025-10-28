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
// Tests for ASCON-XOF and ASCON-XOFa provisional implementations
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "../include/ascon/ascon_xof.h"

static int eq(const uint8_t* a, const uint8_t* b, size_t n) {
    return memcmp(a, b, n) == 0;
}

static int test_lengths_and_determinism(int use_a) {
    const uint8_t msg1[] = {0x00,0x01,0x02,0x03,0x04};
    const uint8_t* in = msg1;
    size_t in_len = sizeof(msg1);

    const size_t lens[] = {0,1,8,9,64,257};
    for (size_t i = 0; i < sizeof(lens)/sizeof(lens[0]); ++i) {
        size_t L = lens[i];
        uint8_t* out1 = (uint8_t*)malloc(L);
        uint8_t* out2 = (uint8_t*)malloc(L);
        if ((L && (!out1 || !out2)) || (!out1 && !out2 && L)) { fprintf(stderr, "OOM L=%zu\n", L); free(out1); free(out2); return 1; }
        int rc1 = use_a ? ascon_xofa(in, in_len, out1, L) : ascon_xof(in, in_len, out1, L);
        int rc2 = use_a ? ascon_xofa(in, in_len, out2, L) : ascon_xof(in, in_len, out2, L);
        if (rc1 != 0 || rc2 != 0) { fprintf(stderr, "XOF rc error L=%zu rc1=%d rc2=%d\n", L, rc1, rc2); free(out1); free(out2); return 1; }
        if (!eq(out1, out2, L)) { fprintf(stderr, "Determinism failed for L=%zu\n", L); free(out1); free(out2); return 1; }
        free(out1); free(out2);
    }

    return 0;
}

static int test_prefix_property(int use_a) {
    const uint8_t msg[] = {0xAA,0xBB,0xCC,0xDD};
    const size_t L1 = 17, L2 = 64;
    uint8_t out1[L1];
    uint8_t out2[L2];
    int rc1 = use_a ? ascon_xofa(msg, sizeof(msg), out1, L1) : ascon_xof(msg, sizeof(msg), out1, L1);
    int rc2 = use_a ? ascon_xofa(msg, sizeof(msg), out2, L2) : ascon_xof(msg, sizeof(msg), out2, L2);
    if (rc1 != 0 || rc2 != 0) { fprintf(stderr, "XOF rc error prefix rc1=%d rc2=%d\n", rc1, rc2); return 1; }
    if (!eq(out1, out2, L1)) { fprintf(stderr, "Prefix property failed\n"); return 1; }
    return 0;
}

int main(void) {
    if (test_lengths_and_determinism(0) != 0) return 1;
    if (test_lengths_and_determinism(1) != 0) return 1;
    if (test_prefix_property(0) != 0) return 1;
    if (test_prefix_property(1) != 0) return 1;
    return 0;
}
