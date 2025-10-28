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
//
//  * Contact: info@virtuousbpo.com
//  * Website: www.virtuousbpo.com
//
//  * Project: Ascon-Hash256
//  * File: main.c
//  * Created: 08/Sept/2025
//  * Author: Rahim Ali

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "include/ascon/ascon_hash.h"
#include "include/ascon/ascon_xof.h"
#include "include/ascon/ascon_aead.h"
#include "include/ascon/ascon_common.h"

static void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) printf("%02x", data[i]);
}

static void usage(const char* prog) {
    fprintf(stderr,
            "Ascon CLI\n\n"
            "Usage:\n"
            "  Hashing (32-byte digest):\n"
            "    %s hash256 --text <string>\n"
            "    %s hash256 --file <path>\n"
            "    %s hash --text <string>\n"
            "    %s hash --file <path>\n"
            "    %s hasha --text <string>\n"
            "    %s hasha --file <path>\n"
            "    %s hash256-stream --text <string> [--chunksize <n>]\n"
            "    %s hash256-stream --file <path>   [--chunksize <n>]\n\n"
            "  XOF (arbitrary output length):\n"
            "    %s xof  --text <string> --outlen <bytes>\n"
            "    %s xof  --file <path>   --outlen <bytes>\n"
            "    %s xofa --text <string> --outlen <bytes>\n"
            "    %s xofa --file <path>   --outlen <bytes>\n"
            "    %s xof-stream  --text <string> --outlen <bytes> [--chunksize <n>]\n"
            "    %s xof-stream  --file <path>   --outlen <bytes> [--chunksize <n>]\n"
            "    %s xofa-stream --text <string> --outlen <bytes> [--chunksize <n>]\n"
            "    %s xofa-stream --file <path>   --outlen <bytes> [--chunksize <n>]\n\n"
            "  AEAD (ASCON-128):\n"
            "    %s aead-128 encrypt --key <hex16B> --nonce <hex16B> --ad <hex|@file|empty> --in <hex|@file>\n"
            "    %s aead-128 decrypt --key <hex16B> --nonce <hex16B> --ad <hex|@file|empty> --in <hex|@file> --tag <hex16B>\n\n"
            "Notes:\n"
            "  - Hex arguments may be given as @path to use raw file bytes instead of hex.\n"
            "  - Streaming demos show chunked absorb and multi-call squeeze.\n"
            "  - AEAD prints hex on stdout: for encrypt -> ciphertext + newline + tag; for decrypt -> plaintext.\n",
            prog, prog, prog, prog, prog, prog,
            prog, prog,
            prog, prog, prog, prog,
            prog, prog, prog, prog,
            prog, prog);
}

static int read_file(const char* path, uint8_t** out_buf, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    uint8_t* buf = (uint8_t*)malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return -1; }
    *out_buf = buf; *out_len = (size_t)sz; return 0;
}

static int from_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parse hex string into a newly malloc'ed buffer. Returns 0 on success.
// If arg starts with '@', read file bytes instead of parsing hex.
static int parse_hex_or_file(const char* arg, uint8_t** out, size_t* out_len) {
    if (!arg || !out || !out_len) return -1;
    if (arg[0] == '@') {
        return read_file(arg + 1, out, out_len);
    }
    size_t n = strlen(arg);
    if (n % 2 != 0) return -1;
    uint8_t* buf = (uint8_t*)malloc(n / 2);
    if (!buf) return -1;
    for (size_t i = 0; i < n; i += 2) {
        int hi = from_hex_nibble(arg[i]);
        int lo = from_hex_nibble(arg[i+1]);
        if (hi < 0 || lo < 0) { free(buf); return -1; }
        buf[i/2] = (uint8_t)((hi << 4) | lo);
    }
    *out = buf; *out_len = n / 2; return 0;
}

static int parse_size_t(const char* s, size_t* out) {
    if (!s || !out) return -1;
    char* end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (!end || *end != '\0') return -1;
    *out = (size_t)v;
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(argv[0]); return 1; }

    const char* op = argv[1];

    // Hash256 streaming demo
    if (strcmp(op, "hash256-stream") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        const uint8_t* msg = NULL; size_t len = 0; uint8_t* heap = NULL;
        size_t chunksz = 8; // default chunk size
        // Parse args
        if (strcmp(argv[2], "--text") == 0 && argc >= 4) {
            msg = (const uint8_t*)argv[3]; len = strlen(argv[3]);
        } else if (strcmp(argv[2], "--file") == 0 && argc >= 4) {
            if (read_file(argv[3], &heap, &len) != 0) { fprintf(stderr, "Failed to read file: %s\n", argv[3]); return 2; }
            msg = heap;
        } else { usage(argv[0]); return 1; }
        for (int i = 4; i < argc; ++i) {
            if (strcmp(argv[i], "--chunksize") == 0 && i + 1 < argc) {
                size_t v = 0; if (parse_size_t(argv[++i], &v) != 0 || v == 0) { fprintf(stderr, "Invalid chunksize\n"); if (heap) { ascon_secure_wipe(heap, len); free(heap);} return 1; }
                chunksz = v;
            }
        }
        ascon_hash256_ctx ctx; uint8_t out[32];
        ascon_hash256_init(&ctx);
        size_t off = 0;
        while (off < len) {
            size_t take = (len - off < chunksz) ? (len - off) : chunksz;
            ascon_hash256_update(&ctx, msg + off, take);
            off += take;
        }
        ascon_hash256_final(&ctx, out);
        print_hex(out, sizeof(out)); printf("\n");
        if (heap) { ascon_secure_wipe(heap, len); free(heap);} 
        return 0;
    }

    // Hash256
    if (strcmp(op, "hash256") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        const uint8_t* msg = NULL;
        size_t len = 0;
        uint8_t* heap = NULL;
        if (strcmp(argv[2], "--text") == 0 && argc >= 4) {
            msg = (const uint8_t*)argv[3];
            len = strlen(argv[3]);
        } else if (strcmp(argv[2], "--file") == 0 && argc >= 4) {
            if (read_file(argv[3], &heap, &len) != 0) {
                fprintf(stderr, "Failed to read file: %s\n", argv[3]);
                return 2;
            }
            msg = heap;
        } else {
            usage(argv[0]);
            return 1;
        }
        uint8_t digest[32];
        ascon_hash256(msg, len, digest);
        print_hex(digest, sizeof(digest));
        printf("\n");
        if (heap) { ascon_secure_wipe(heap, len); free(heap); }
        return 0;
    }

    // Hash
    if (strcmp(op, "hash") == 0 || strcmp(op, "hasha") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        const uint8_t* msg = NULL; size_t len = 0; uint8_t* heap = NULL;
        if (strcmp(argv[2], "--text") == 0 && argc >= 4) {
            msg = (const uint8_t*)argv[3]; len = strlen(argv[3]);
        } else if (strcmp(argv[2], "--file") == 0 && argc >= 4) {
            if (read_file(argv[3], &heap, &len) != 0) { fprintf(stderr, "Failed to read file: %s\n", argv[3]); return 2; }
            msg = heap;
        } else { usage(argv[0]); return 1; }
        uint8_t digest[32];
        if (strcmp(op, "hash") == 0) ascon_hash(msg, len, digest);
        else ascon_hasha(msg, len, digest);
        print_hex(digest, sizeof(digest)); printf("\n");
        if (heap) { ascon_secure_wipe(heap, len); free(heap); }
        return 0;
    }

    // XOF streaming demos
    if (strcmp(op, "xof-stream") == 0 || strcmp(op, "xofa-stream") == 0) {
        if (argc < 6) { usage(argv[0]); return 1; }
        const uint8_t* in = NULL; size_t in_len = 0; uint8_t* heap = NULL;
        size_t outlen = 0; size_t chunksz = 8; int have_in = 0; int have_outlen = 0;
        for (int i = 2; i < argc; ++i) {
            if (strcmp(argv[i], "--text") == 0 && i + 1 < argc) {
                in = (const uint8_t*)argv[++i]; in_len = strlen((const char*)in); have_in = 1;
            } else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
                if (read_file(argv[++i], &heap, &in_len) != 0) { fprintf(stderr, "Failed to read file\n"); return 2; }
                in = heap; have_in = 1;
            } else if (strcmp(argv[i], "--outlen") == 0 && i + 1 < argc) {
                if (parse_size_t(argv[++i], &outlen) != 0) { fprintf(stderr, "Invalid outlen\n"); if (heap) { ascon_secure_wipe(heap, in_len); free(heap);} return 1; }
                have_outlen = 1;
            } else if (strcmp(argv[i], "--chunksize") == 0 && i + 1 < argc) {
                if (parse_size_t(argv[++i], &chunksz) != 0 || chunksz == 0) { fprintf(stderr, "Invalid chunksize\n"); if (heap) { ascon_secure_wipe(heap, in_len); free(heap);} return 1; }
            }
        }
        if (!have_in || !have_outlen) { usage(argv[0]); if (heap) { ascon_secure_wipe(heap, in_len); free(heap);} return 1; }
        ascon_xof_ctx ctx;
        if (strcmp(op, "xof-stream") == 0) ascon_xof_init(&ctx); else ascon_xofa_init(&ctx);
        // absorb in chunks
        size_t off = 0;
        while (off < in_len) {
            size_t take = (in_len - off < chunksz) ? (in_len - off) : chunksz;
            ascon_xof_absorb(&ctx, in + off, take);
            off += take;
        }
        // finalize and squeeze in chunks
        ascon_xof_finalize(&ctx);
        uint8_t* out = (uint8_t*)malloc(outlen);
        if (!out) { fprintf(stderr, "OOM\n"); if (heap) { ascon_secure_wipe(heap, in_len); free(heap);} return 3; }
        size_t remaining = outlen; size_t out_off = 0;
        while (remaining) {
            size_t take = (remaining < chunksz) ? remaining : chunksz;
            ascon_xof_squeeze(&ctx, out + out_off, take);
            out_off += take; remaining -= take;
        }
        print_hex(out, outlen); printf("\n");
        ascon_secure_wipe(out, outlen); free(out);
        if (heap) { ascon_secure_wipe(heap, in_len); free(heap);} 
        return 0;
    }

    // XOF
    if (strcmp(op, "xof") == 0 || strcmp(op, "xofa") == 0) {
        if (argc < 6) { usage(argv[0]); return 1; }
        const uint8_t* in = NULL; size_t in_len = 0; uint8_t* heap = NULL;
        size_t outlen = 0; int have_in = 0; int have_outlen = 0;
        for (int i = 2; i < argc; ++i) {
            if (strcmp(argv[i], "--text") == 0 && i + 1 < argc) {
                in = (const uint8_t*)argv[++i]; in_len = strlen((const char*)in); have_in = 1;
            } else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
                if (read_file(argv[++i], &heap, &in_len) != 0) { fprintf(stderr, "Failed to read file\n"); return 2; }
                in = heap; have_in = 1;
            } else if (strcmp(argv[i], "--outlen") == 0 && i + 1 < argc) {
                if (parse_size_t(argv[++i], &outlen) != 0) { fprintf(stderr, "Invalid outlen\n"); return 1; }
                have_outlen = 1;
            }
        }
        if (!have_in || !have_outlen) { usage(argv[0]); if (heap) { ascon_secure_wipe(heap, in_len); free(heap);} return 1; }
        uint8_t* out = (uint8_t*)malloc(outlen);
        if (!out) { fprintf(stderr, "OOM\n"); if (heap) { ascon_secure_wipe(heap, in_len); free(heap);} return 3; }
        int rc = (strcmp(op, "xof") == 0) ? ascon_xof(in, in_len, out, outlen)
                                           : ascon_xofa(in, in_len, out, outlen);
        if (rc != 0) { fprintf(stderr, "XOF not implemented or error (rc=%d)\n", rc); free(out); if (heap) { ascon_secure_wipe(heap, in_len); free(heap);} return 4; }
        print_hex(out, outlen); printf("\n");
        ascon_secure_wipe(out, outlen); free(out);
        if (heap) { ascon_secure_wipe(heap, in_len); free(heap);} 
        return 0;
    }

    // AEAD-128
    if (strcmp(op, "aead-128") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        if (argc >= 3 && strcmp(argv[2], "encrypt") == 0) {
            const char* key_hex = NULL; const char* nonce_hex = NULL; const char* ad_arg = "empty"; const char* in_arg = NULL;
            for (int i = 3; i < argc; ++i) {
                if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_hex = argv[++i];
                else if (strcmp(argv[i], "--nonce") == 0 && i + 1 < argc) nonce_hex = argv[++i];
                else if (strcmp(argv[i], "--ad") == 0 && i + 1 < argc) ad_arg = argv[++i];
                else if (strcmp(argv[i], "--in") == 0 && i + 1 < argc) in_arg = argv[++i];
            }
            if (!key_hex || !nonce_hex || !in_arg) { usage(argv[0]); return 1; }
            uint8_t *key=NULL,*nonce=NULL,*ad=NULL,*pt=NULL,*ct=NULL, tag[ASCON_TAG_BYTES];
            size_t key_len=0, nonce_len=0, ad_len=0, pt_len=0;
            if (parse_hex_or_file(key_hex, &key, &key_len) != 0 || key_len != ASCON_KEY_BYTES) { fprintf(stderr, "Invalid key\n"); goto aead128_encrypt_fail; }
            if (parse_hex_or_file(nonce_hex, &nonce, &nonce_len) != 0 || nonce_len != ASCON_NONCE_BYTES) { fprintf(stderr, "Invalid nonce\n"); goto aead128_encrypt_fail; }
            if (strcmp(ad_arg, "empty") == 0) { ad = NULL; ad_len = 0; }
            else if (parse_hex_or_file(ad_arg, &ad, &ad_len) != 0) { fprintf(stderr, "Invalid AD\n"); goto aead128_encrypt_fail; }
            if (parse_hex_or_file(in_arg, &pt, &pt_len) != 0) { fprintf(stderr, "Invalid input\n"); goto aead128_encrypt_fail; }
            ct = (uint8_t*)malloc(pt_len);
            if (!ct) { fprintf(stderr, "OOM\n"); goto aead128_encrypt_fail; }
            {
                int rc = ascon128_encrypt(key, nonce, ad, ad_len, pt, pt_len, ct, tag);
                if (rc != 0) { fprintf(stderr, "AEAD-128 encrypt not implemented or error (rc=%d)\n", rc); goto aead128_encrypt_fail; }
                print_hex(ct, pt_len); printf("\n");
                print_hex(tag, ASCON_TAG_BYTES); printf("\n");
            }
            ascon_secure_wipe(key, key_len); free(key);
            ascon_secure_wipe(nonce, nonce_len); free(nonce);
            if (ad) { ascon_secure_wipe(ad, ad_len); free(ad); }
            ascon_secure_wipe(pt, pt_len); free(pt);
            ascon_secure_wipe(ct, pt_len); free(ct);
            return 0;
        aead128_encrypt_fail:
            if (key) { ascon_secure_wipe(key, key_len); free(key);} 
            if (nonce) { ascon_secure_wipe(nonce, nonce_len); free(nonce);} 
            if (ad) { ascon_secure_wipe(ad, ad_len); free(ad);} 
            if (pt) { ascon_secure_wipe(pt, pt_len); free(pt);} 
            if (ct) { ascon_secure_wipe(ct, pt_len); free(ct);} 
            return 5;
        } else if (argc >= 3 && strcmp(argv[2], "decrypt") == 0) {
            const char* key_hex = NULL; const char* nonce_hex = NULL; const char* ad_arg = "empty"; const char* in_arg = NULL; const char* tag_hex = NULL;
            for (int i = 3; i < argc; ++i) {
                if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_hex = argv[++i];
                else if (strcmp(argv[i], "--nonce") == 0 && i + 1 < argc) nonce_hex = argv[++i];
                else if (strcmp(argv[i], "--ad") == 0 && i + 1 < argc) ad_arg = argv[++i];
                else if (strcmp(argv[i], "--in") == 0 && i + 1 < argc) in_arg = argv[++i];
                else if (strcmp(argv[i], "--tag") == 0 && i + 1 < argc) tag_hex = argv[++i];
            }
            if (!key_hex || !nonce_hex || !in_arg || !tag_hex) { usage(argv[0]); return 1; }
            uint8_t *key=NULL,*nonce=NULL,*ad=NULL,*ct=NULL,*pt=NULL,*tag=NULL; size_t key_len=0, nonce_len=0, ad_len=0, ct_len=0, tag_len=0;
            if (parse_hex_or_file(key_hex, &key, &key_len) != 0 || key_len != ASCON_KEY_BYTES) { fprintf(stderr, "Invalid key\n"); goto aead128_decrypt_fail; }
            if (parse_hex_or_file(nonce_hex, &nonce, &nonce_len) != 0 || nonce_len != ASCON_NONCE_BYTES) { fprintf(stderr, "Invalid nonce\n"); goto aead128_decrypt_fail; }
            if (strcmp(ad_arg, "empty") == 0) { ad = NULL; ad_len = 0; }
            else if (parse_hex_or_file(ad_arg, &ad, &ad_len) != 0) { fprintf(stderr, "Invalid AD\n"); goto aead128_decrypt_fail; }
            if (parse_hex_or_file(in_arg, &ct, &ct_len) != 0) { fprintf(stderr, "Invalid input\n"); goto aead128_decrypt_fail; }
            if (parse_hex_or_file(tag_hex, &tag, &tag_len) != 0 || tag_len != ASCON_TAG_BYTES) { fprintf(stderr, "Invalid tag\n"); goto aead128_decrypt_fail; }
            pt = (uint8_t*)malloc(ct_len);
            if (!pt) { fprintf(stderr, "OOM\n"); goto aead128_decrypt_fail; }
            {
                int rc = ascon128_decrypt(key, nonce, ad, ad_len, ct, ct_len, tag, pt);
                if (rc != 0) { fprintf(stderr, "AEAD-128 decrypt not implemented or error (rc=%d)\n", rc); goto aead128_decrypt_fail; }
                print_hex(pt, ct_len); printf("\n");
            }
            ascon_secure_wipe(key, key_len); free(key);
            ascon_secure_wipe(nonce, nonce_len); free(nonce);
            if (ad) { ascon_secure_wipe(ad, ad_len); free(ad); }
            ascon_secure_wipe(ct, ct_len); free(ct);
            ascon_secure_wipe(tag, tag_len); free(tag);
            ascon_secure_wipe(pt, ct_len); free(pt);
            return 0;
        aead128_decrypt_fail:
            if (key) { ascon_secure_wipe(key, key_len); free(key);} 
            if (nonce) { ascon_secure_wipe(nonce, nonce_len); free(nonce);} 
            if (ad) { ascon_secure_wipe(ad, ad_len); free(ad);} 
            if (ct) { ascon_secure_wipe(ct, ct_len); free(ct);} 
            if (tag) { ascon_secure_wipe(tag, tag_len); free(tag);} 
            if (pt) { ascon_secure_wipe(pt, ct_len); free(pt);} 
            return 5;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    usage(argv[0]);
    return 1;
}
