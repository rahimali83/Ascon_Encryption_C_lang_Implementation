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
