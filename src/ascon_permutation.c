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

// Ascon permutation implementation
// SPDX-License-Identifier: MIT
#include "../include/ascon/ascon_permutation.h"

static const uint64_t ASCON_ROUND_CONST[12] = {
    0xf0ULL, 0xe1ULL, 0xd2ULL, 0xc3ULL, 0xb4ULL, 0xa5ULL,
    0x96ULL, 0x87ULL, 0x78ULL, 0x69ULL, 0x5aULL, 0x4bULL
};

void ascon_permute(ascon_state_t* s, int rounds) {
    uint64_t x0 = s->x[0], x1 = s->x[1], x2 = s->x[2];
    uint64_t x3 = s->x[3], x4 = s->x[4];

    for (int i = 12 - rounds; i < 12; ++i) {
        // Add round constant
        x2 ^= ASCON_ROUND_CONST[i];

        // S-box layer
        x0 ^= x4; x4 ^= x3; x2 ^= x1;
        uint64_t t0 = (~x0) & x1;
        uint64_t t1 = (~x1) & x2;
        uint64_t t2 = (~x2) & x3;
        uint64_t t3 = (~x3) & x4;
        uint64_t t4 = (~x4) & x0;
        x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
        x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2;

        // Linear diffusion layer
        x0 ^= ASCON_ROTR64(x0, 19) ^ ASCON_ROTR64(x0, 28);
        x1 ^= ASCON_ROTR64(x1, 61) ^ ASCON_ROTR64(x1, 39);
        x2 ^= ASCON_ROTR64(x2, 1)  ^ ASCON_ROTR64(x2, 6);
        x3 ^= ASCON_ROTR64(x3, 10) ^ ASCON_ROTR64(x3, 17);
        x4 ^= ASCON_ROTR64(x4, 7)  ^ ASCON_ROTR64(x4, 41);
    }

    s->x[0] = x0; s->x[1] = x1; s->x[2] = x2; s->x[3] = x3; s->x[4] = x4;
}
