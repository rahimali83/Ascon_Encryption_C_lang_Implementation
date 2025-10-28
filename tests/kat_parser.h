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

// Simple KAT file parser for Ascon v1.2 public KATs (LWC/NIST-style fields)
// This is intended for testing only.
//
// Format assumptions:
// - Text file consisting of records separated by blank lines.
// - Each non-empty line is of the form: <FieldName> = <hex-or-empty>
// - Field names are case-insensitive. Common aliases are supported (e.g., Nonce/Npub, Digest/MD).
// - Hex strings may be empty, meaning zero-length.
// - Lines beginning with '#' are comments and ignored.
//
// This parser collects key-value pairs per record and invokes a callback.
// Unknown fields are kept as-is in a generic list.

#ifndef ASCON_TESTS_KAT_PARSER_H
#define ASCON_TESTS_KAT_PARSER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// A parsed field with name (lower-cased) and value as bytes.
typedef struct {
    char name[32];     // lower-cased canonical name, e.g., "key", "nonce", "pt"
    uint8_t* data;     // malloc'ed byte buffer (may be NULL if len==0)
    size_t len;        // length in bytes
} kat_field_t;

// A single KAT record (list of fields)
typedef struct {
    kat_field_t* fields;
    size_t count;      // number of fields
} kat_record_t;

// Callback called for each record. Return 0 to continue, non-zero to stop parsing with that code.
typedef int (*kat_record_cb)(const kat_record_t* rec, void* user);

// Parse the KAT file at path and invoke cb for each record.
// Returns 0 on complete success; otherwise non-zero error code.
int kat_parse_file(const char* path, kat_record_cb cb, void* user);

// Utility: get field by name (case-insensitive). Returns pointer or NULL if missing.
const kat_field_t* kat_get_field(const kat_record_t* rec, const char* name);

// Utility: canonicalize field name into our preferred set (lower-case).
// Supported aliases (case-insensitive):
//   npub -> nonce, nonce -> nonce
//   digest, md -> digest
//   msg, pt -> pt
//   ct, ciphertext -> ct
//   ad, aad -> ad
//   tag, mac -> tag
//   outlen, outputlen -> outlen
//   out, output -> output
void kat_canonicalize_name(char* name);

#ifdef __cplusplus
}
#endif

#endif // ASCON_TESTS_KAT_PARSER_H
