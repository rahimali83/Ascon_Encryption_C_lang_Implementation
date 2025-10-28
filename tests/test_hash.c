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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../include/ascon/ascon_hash.h"

static void to_hex(const uint8_t* in, size_t n, char* out) {
    static const char* hexd = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[2*i]   = hexd[in[i] >> 4];
        out[2*i+1] = hexd[in[i] & 0xF];
    }
    out[2*n] = '\0';
}

int main(void) {
    // Known answers produced by current implementation for regression
    // Note: replace with official KATs once available.
    const char* kat_empty = "4c972ed816c04ef69e230616f11c3ba94f2c76d6512207383f5f83f0c08ed05a";
    const char* kat_abc   = "44d0ad554e55e46756e91ba5f6d6252b450be1319f312291014d1cdb6f15459d";

    uint8_t digest[32];
    char hex[65];

    // Empty string
    ascon_hash256((const uint8_t*)"", 0, digest);
    to_hex(digest, 32, hex);
    if (strcmp(hex, kat_empty) != 0) {
        fprintf(stderr, "hash256(\"\"):\n  got  %s\n  want %s\n", hex, kat_empty);
        return 1;
    }

    // "abc"
    const char* abc = "abc";
    ascon_hash256((const uint8_t*)abc, strlen(abc), digest);
    to_hex(digest, 32, hex);
    if (strcmp(hex, kat_abc) != 0) {
        fprintf(stderr, "hash256(\"abc\"):\n  got  %s\n  want %s\n", hex, kat_abc);
        return 1;
    }

    return 0;
}
