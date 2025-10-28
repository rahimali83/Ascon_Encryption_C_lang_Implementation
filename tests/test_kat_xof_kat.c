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
#include <stdlib.h>
#include <string.h>
#include "kat_parser.h"
#include "../include/ascon/ascon_xof.h"

static int check_file_exists(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

typedef enum { XV_XOF, XV_XOFA } xof_variant_t;

typedef struct {
    xof_variant_t var;
    size_t cases_total;
    size_t cases_ok;
    size_t cases_fail;
} xof_ctx_t;

static int handle_record(const kat_record_t* rec, void* user) {
    xof_ctx_t* ctx = (xof_ctx_t*)user;
    ctx->cases_total++;

    const kat_field_t* fmsg = kat_get_field(rec, "pt"); // canonicalized from Msg/PT
    const kat_field_t* fout = kat_get_field(rec, "output");
    const kat_field_t* flen = kat_get_field(rec, "outlen");

    if (!fmsg || !fout) {
        fprintf(stderr, "XOF KAT missing required fields\n");
        ctx->cases_fail++;
        return 0;
    }

    size_t out_len = fout->len;
    // If OutLen is present, prefer it (bytes). Some KATs may include an explicit length.
    if (flen && flen->len > 0) {
        // Interpret flen->data as big-endian integer encoded in bytes; commonly they may write decimal in text though.
        // Our parser converts hex only, so treat it as an integer in hex bytes.
        size_t acc = 0;
        for (size_t i = 0; i < flen->len; ++i) acc = (acc << 8) | flen->data[i];
        if (acc != 0) out_len = acc;
    }

    uint8_t* out = (uint8_t*)malloc(out_len);
    if (!out) return -1;
    int rc = 0;
    if (ctx->var == XV_XOF) rc = ascon_xof(fmsg->data, fmsg->len, out, out_len);
    else rc = ascon_xofa(fmsg->data, fmsg->len, out, out_len);

    if (rc != 0 || out_len != fout->len || memcmp(out, fout->data, out_len) != 0) {
        fprintf(stderr, "XOF mismatch (variant %d)\n", (int)ctx->var);
        ctx->cases_fail++;
        free(out);
        return 0;
    }

    ctx->cases_ok++;
    free(out);
    return 0;
}

static int run_variant(const char* path, xof_variant_t var) {
    if (!check_file_exists(path)) {
        printf("[KAT] XOF: %s not found: SKIP\n", path);
        return 0; // treat as pass/skip
    }
    xof_ctx_t ctx = { .var = var, .cases_total = 0, .cases_ok = 0, .cases_fail = 0 };
    int rc = kat_parse_file(path, handle_record, &ctx);
    if (rc != 0) {
        fprintf(stderr, "Failed to parse %s (rc=%d)\n", path, rc);
        return 1;
    }
    if (ctx.cases_fail != 0) {
        fprintf(stderr, "XOF KAT failures in %s: %zu/%zu failed\n", path, ctx.cases_fail, ctx.cases_total);
        return 1;
    }
    printf("[KAT] XOF: %s passed (%zu cases)\n", path, ctx.cases_ok);
    return 0;
}

int main(void) {
    int fail = 0;
    fail |= run_variant("tests/vectors/ascon-v1.2/xof.txt", XV_XOF);
    fail |= run_variant("tests/vectors/ascon-v1.2/xofa.txt", XV_XOFA);
    return fail ? 1 : 0;
}
