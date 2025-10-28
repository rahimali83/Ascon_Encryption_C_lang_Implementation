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
#include <stdlib.h>
#include <string.h>
#include "kat_parser.h"
#include "../include/ascon/ascon_hash.h"

static int check_file_exists(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

typedef enum { HV_HASH256 } hash_variant_t;

typedef struct {
    hash_variant_t var;
    size_t cases_total;
    size_t cases_ok;
    size_t cases_fail;
} hash_ctx_t;

static int handle_record(const kat_record_t* rec, void* user) {
    hash_ctx_t* ctx = (hash_ctx_t*)user;
    ctx->cases_total++;

    const kat_field_t* fmsg = kat_get_field(rec, "pt"); // canonicalized from Msg/PT
    const kat_field_t* fdig = kat_get_field(rec, "digest");

    if (!fmsg || !fdig) {
        fprintf(stderr, "HASH KAT missing required fields\n");
        ctx->cases_fail++;
        return 0;
    }

    uint8_t out[32];
    if (ctx->var == HV_HASH256) {
        ascon_hash256(fmsg->data, fmsg->len, out);
    }

    if (fdig->len != 32 || memcmp(out, fdig->data, 32) != 0) {
        fprintf(stderr, "HASH digest mismatch (%d)\n", (int)ctx->var);
        ctx->cases_fail++;
        return 0;
    }

    ctx->cases_ok++;
    return 0;
}

static int run_variant(const char* path, hash_variant_t var) {
    if (!check_file_exists(path)) {
        printf("[KAT] HASH: %s not found: SKIP\n", path);
        return 0; // treat as pass/skip
    }
    hash_ctx_t ctx = { .var = var, .cases_total = 0, .cases_ok = 0, .cases_fail = 0 };
    int rc = kat_parse_file(path, handle_record, &ctx);
    if (rc != 0) {
        fprintf(stderr, "Failed to parse %s (rc=%d)\n", path, rc);
        return 1;
    }
    if (ctx.cases_fail != 0) {
        fprintf(stderr, "HASH KAT failures in %s: %zu/%zu failed\n", path, ctx.cases_fail, ctx.cases_total);
        return 1;
    }
    printf("[KAT] HASH: %s passed (%zu cases)\n", path, ctx.cases_ok);
    return 0;
}

int main(void) {
    int fail = 0;
    fail |= run_variant("tests/vectors/ascon-v1.2/hash256.txt", HV_HASH256);
    return fail ? 1 : 0;
}
