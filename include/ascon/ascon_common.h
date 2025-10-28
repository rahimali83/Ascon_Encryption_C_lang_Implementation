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
