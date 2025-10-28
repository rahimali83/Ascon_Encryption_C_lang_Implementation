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

// Common Ascon definitions, types, helpers
// SPDX-License-Identifier: MIT
#ifndef ASCON_COMMON_H
#define ASCON_COMMON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Rotation
#define ASCON_ROTR64(x, n) (((uint64_t)(x) >> (n)) | ((uint64_t)(x) << (64 - (n))))

// Branch prediction hints
#if defined(__GNUC__) || defined(__clang__)
#  define ASCON_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define ASCON_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#  define ASCON_LIKELY(x)   (x)
#  define ASCON_UNLIKELY(x) (x)
#endif

// Endianness-safe load/store
static inline uint64_t ascon_load64(const void* src) {
    uint64_t v;
    __builtin_memcpy(&v, src, sizeof(v));
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return __builtin_bswap64(v);
#else
    return v;
#endif
}

static inline void ascon_store64(void* dst, uint64_t v) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    v = __builtin_bswap64(v);
#endif
    __builtin_memcpy(dst, &v, sizeof(v));
}

// Constant-time comparison for authentication tags
static inline int ascon_ct_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; ++i) acc |= (uint8_t)(a[i] ^ b[i]);
    return acc; // 0 if equal
}

// Wipe sensitive memory
static inline void ascon_secure_wipe(void* p, size_t n) {
#if defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    volatile uint8_t* vp = (volatile uint8_t*)p;
    while (n--) *vp++ = 0;
#endif
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // ASCON_COMMON_H
