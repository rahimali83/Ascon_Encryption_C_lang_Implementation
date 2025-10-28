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
#include "../include/ascon/ascon_aead.h"

static int check_file_exists(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

typedef enum { VAR_128, VAR_128A, VAR_80PQ } aead_variant_t;

typedef struct {
    aead_variant_t var;
    size_t cases_total;
    size_t cases_ok;
    size_t cases_fail;
} aead_ctx_t;

static int handle_record(const kat_record_t* rec, void* user) {
    aead_ctx_t* ctx = (aead_ctx_t*)user;
    ctx->cases_total++;

    const kat_field_t* fkey = kat_get_field(rec, "key");
    const kat_field_t* fnonce = kat_get_field(rec, "nonce");
    const kat_field_t* fad = kat_get_field(rec, "ad");
    const kat_field_t* fpt = kat_get_field(rec, "pt");
    const kat_field_t* fct = kat_get_field(rec, "ct");
    const kat_field_t* ftag = kat_get_field(rec, "tag");

    if (!fkey || !fnonce || !fad || !fpt || !fct || !ftag) {
        fprintf(stderr, "KAT missing required fields\n");
        ctx->cases_fail++;
        return 0;
    }

    uint8_t* ct = (uint8_t*)malloc(fpt->len);
    uint8_t tag[ASCON_TAG_BYTES];
    uint8_t* pt = (uint8_t*)malloc(fct->len);
    if (!ct || !pt) { free(ct); free(pt); return -1; }

    int rc = 0;
    if (ctx->var == VAR_128) {
        rc = ascon128_encrypt(fkey->data, fnonce->data,
                              fad->data, fad->len,
                              fpt->data, fpt->len,
                              ct, tag);
    } else if (ctx->var == VAR_128A) {
        rc = ascon128a_encrypt(fkey->data, fnonce->data,
                               fad->data, fad->len,
                               fpt->data, fpt->len,
                               ct, tag);
    } else {
        // 80pq uses 20-byte key
        rc = ascon80pq_encrypt(fkey->data, fnonce->data,
                               fad->data, fad->len,
                               fpt->data, fpt->len,
                               ct, tag);
    }
    if (rc != 0 || memcmp(ct, fct->data, fct->len) != 0 || memcmp(tag, ftag->data, ASCON_TAG_BYTES) != 0) {
        fprintf(stderr, "Encrypt mismatch (variant %d)\n", (int)ctx->var);
        ctx->cases_fail++;
        free(ct); free(pt);
        return 0;
    }

    if (ctx->var == VAR_128) {
        rc = ascon128_decrypt(fkey->data, fnonce->data,
                              fad->data, fad->len,
                              fct->data, fct->len,
                              ftag->data, pt);
    } else if (ctx->var == VAR_128A) {
        rc = ascon128a_decrypt(fkey->data, fnonce->data,
                               fad->data, fad->len,
                               fct->data, fct->len,
                               ftag->data, pt);
    } else {
        rc = ascon80pq_decrypt(fkey->data, fnonce->data,
                               fad->data, fad->len,
                               fct->data, fct->len,
                               ftag->data, pt);
    }
    if (rc != 0 || memcmp(pt, fpt->data, fpt->len) != 0) {
        fprintf(stderr, "Decrypt mismatch (variant %d)\n", (int)ctx->var);
        ctx->cases_fail++;
        free(ct); free(pt);
        return 0;
    }

    ctx->cases_ok++;
    free(ct); free(pt);
    return 0;
}

static int run_variant(const char* path, aead_variant_t var) {
    if (!check_file_exists(path)) {
        printf("[KAT] AEAD: %s not found: SKIP\n", path);
        return 0; // treat as pass/skip
    }
    aead_ctx_t ctx = { .var = var, .cases_total = 0, .cases_ok = 0, .cases_fail = 0 };
    int rc = kat_parse_file(path, handle_record, &ctx);
    if (rc != 0) {
        fprintf(stderr, "Failed to parse %s (rc=%d)\n", path, rc);
        return 1;
    }
    if (ctx.cases_fail != 0) {
        fprintf(stderr, "AEAD KAT failures in %s: %zu/%zu failed\n", path, ctx.cases_fail, ctx.cases_total);
        return 1;
    }
    printf("[KAT] AEAD: %s passed (%zu cases)\n", path, ctx.cases_ok);
    return 0;
}

int main(void) {
    int fail = 0;
    fail |= run_variant("tests/vectors/ascon-v1.2/aead128.txt", VAR_128);
    fail |= run_variant("tests/vectors/ascon-v1.2/aead128a.txt", VAR_128A);
    fail |= run_variant("tests/vectors/ascon-v1.2/aead80pq.txt", VAR_80PQ);
    return fail ? 1 : 0;
}
