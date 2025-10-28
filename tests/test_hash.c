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
