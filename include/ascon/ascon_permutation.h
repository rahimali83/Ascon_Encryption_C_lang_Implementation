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

// Ascon permutation (p^a with variable rounds)
// SPDX-License-Identifier: MIT
#ifndef ASCON_PERMUTATION_H
#define ASCON_PERMUTATION_H

#include <stdint.h>
#include "ascon_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t x[5];
} ascon_state_t;

void ascon_permute(ascon_state_t* s, int rounds);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // ASCON_PERMUTATION_H
