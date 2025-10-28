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

#include "kat_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t* parse_hex(const char* s, size_t* out_len) {
    // skip leading spaces
    while (*s == ' ' || *s == '\t') ++s;
    size_t n = strlen(s);
    // trim trailing spaces/newlines
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r' || s[n-1] == ' ' || s[n-1] == '\t')) --n;
    if (n == 0) {
        *out_len = 0;
        return NULL;
    }
    if (n % 2 != 0) {
        return NULL; // invalid hex length
    }
    size_t bytes = n / 2;
    uint8_t* buf = (uint8_t*)malloc(bytes);
    if (!buf) return NULL;
    for (size_t i = 0; i < bytes; ++i) {
        int hi = hex_nibble(s[2*i]);
        int lo = hex_nibble(s[2*i+1]);
        if (hi < 0 || lo < 0) { free(buf); return NULL; }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = bytes;
    return buf;
}

static void str_tolower(char* s) {
    for (; *s; ++s) *s = (char)tolower((unsigned char)*s);
}

void kat_canonicalize_name(char* name) {
    str_tolower(name);
    if (strcmp(name, "npub") == 0) strcpy(name, "nonce");
    else if (strcmp(name, "nonce") == 0) strcpy(name, "nonce");
    else if (strcmp(name, "digest") == 0 || strcmp(name, "md") == 0) strcpy(name, "digest");
    else if (strcmp(name, "msg") == 0 || strcmp(name, "pt") == 0 || strcmp(name, "plaintext") == 0) strcpy(name, "pt");
    else if (strcmp(name, "ct") == 0 || strcmp(name, "ciphertext") == 0) strcpy(name, "ct");
    else if (strcmp(name, "ad") == 0 || strcmp(name, "aad") == 0) strcpy(name, "ad");
    else if (strcmp(name, "tag") == 0 || strcmp(name, "mac") == 0) strcpy(name, "tag");
    else if (strcmp(name, "outlen") == 0 || strcmp(name, "outputlen") == 0) strcpy(name, "outlen");
    else if (strcmp(name, "out") == 0 || strcmp(name, "output") == 0) strcpy(name, "output");
    else if (strcmp(name, "key") == 0) strcpy(name, "key");
    else if (strcmp(name, "count") == 0) strcpy(name, "count");
}

static void free_record(kat_record_t* rec) {
    if (!rec) return;
    for (size_t i = 0; i < rec->count; ++i) free(rec->fields[i].data);
    free(rec->fields);
    rec->fields = NULL;
    rec->count = 0;
}

const kat_field_t* kat_get_field(const kat_record_t* rec, const char* name) {
    if (!rec || !name) return NULL;
    char key[32];
    strncpy(key, name, sizeof(key)-1); key[sizeof(key)-1] = '\0';
    kat_canonicalize_name(key);
    for (size_t i = 0; i < rec->count; ++i) {
        if (strcmp(rec->fields[i].name, key) == 0) return &rec->fields[i];
    }
    return NULL;
}

static int add_field(kat_record_t* rec, const char* name, uint8_t* data, size_t len) {
    size_t n = rec->count + 1;
    kat_field_t* nf = (kat_field_t*)realloc(rec->fields, n * sizeof(kat_field_t));
    if (!nf) { free(data); return -1; }
    rec->fields = nf;
    kat_field_t* f = &rec->fields[rec->count];
    memset(f, 0, sizeof(*f));
    strncpy(f->name, name, sizeof(f->name)-1);
    f->name[sizeof(f->name)-1] = '\0';
    kat_canonicalize_name(f->name);
    f->data = data;
    f->len = len;
    rec->count = n;
    return 0;
}

static int process_record(kat_record_t* rec, kat_record_cb cb, void* user) {
    if (rec->count == 0) return 0; // skip empty records
    int rc = cb(rec, user);
    return rc;
}

int kat_parse_file(const char* path, kat_record_cb cb, void* user) {
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    char line[4096];
    kat_record_t rec = (kat_record_t){0};
    int rc = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        // Trim leading spaces
        char* p = line;
        while (*p == ' ' || *p == '\t') ++p;
        // Skip comments
        if (*p == '#' || *p == ';') continue;
        // Blank line -> end of record
        if (*p == '\n' || *p == '\r' || *p == '\0') {
            rc = process_record(&rec, cb, user);
            free_record(&rec);
            if (rc != 0) break;
            continue;
        }
        // Find '='
        char* eq = strchr(p, '=');
        if (!eq) continue; // ignore malformed lines
        // Extract name
        char namebuf[64];
        size_t name_len = 0;
        char* q = p;
        while (q < eq && name_len + 1 < sizeof(namebuf)) {
            if (*q != ' ' && *q != '\t') namebuf[name_len++] = *q;
            ++q;
        }
        namebuf[name_len] = '\0';
        // Extract value start
        q = eq + 1;
        while (*q == ' ' || *q == '\t') ++q;
        // Parse hex (empty allowed)
        size_t vlen = 0;
        uint8_t* v = parse_hex(q, &vlen);
        if (q[0] != '\0' && v == NULL && vlen == 0) {
            // invalid hex non-empty
            rc = -2;
            break;
        }
        if (add_field(&rec, namebuf, v, vlen) != 0) { rc = -3; break; }
    }
    if (rc == 0) {
        // flush last record if file didn't end with blank line
        rc = process_record(&rec, cb, user);
    }
    free_record(&rec);
    fclose(f);
    return rc;
}
