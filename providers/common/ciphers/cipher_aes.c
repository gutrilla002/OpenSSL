/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for AES cipher modes ecb, cbc, ofb, cfb, ctr */

#include "cipher_aes.h"
#include "internal/provider_algs.h"

static OSSL_OP_cipher_freectx_fn aes_freectx;
static OSSL_OP_cipher_dupctx_fn aes_dupctx;

static void aes_freectx(void *vctx)
{
    PROV_AES_CTX *ctx = (PROV_AES_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *aes_dupctx(void *ctx)
{
    PROV_AES_CTX *in = (PROV_AES_CTX *)ctx;
    PROV_AES_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

/* aes256ecb_functions */
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 256, 128, 0, block)
= { "AES-256-ECB", NULL };
/* aes192ecb_functions */
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 192, 128, 0, block)
= { "AES-192-ECB", NULL };
/* aes128ecb_functions */
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 128, 128, 0, block)
= { "AES-128-ECB", NULL };
/* aes256cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 256, 128, 128, block)
= { "AES-256-CBC", NULL };
/* aes192cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 192, 128, 128, block)
= { "AES-192-CBC", NULL };
/* aes128cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 128, 128, 128, block)
= { "AES-128-CBC", NULL };
/* aes256ofb_functions */
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 256, 8, 128, stream)
= { "AES-256-OFB", NULL };
/* aes192ofb_functions */
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 192, 8, 128, stream)
= { "AES-192-OFB", NULL };
/* aes128ofb_functions */
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 128, 8, 128, stream)
= { "AES-128-OFB", NULL };
/* aes256cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 256, 8, 128, stream)
= { "AES-256-CFB", NULL };
/* aes192cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 192, 8, 128, stream)
= { "AES-192-CFB", NULL };
/* aes128cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 128, 8, 128, stream)
= { "AES-128-CFB", NULL };
/* aes256cfb1_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 256, 8, 128, stream)
= { "AES-256-CFB1", NULL };
/* aes192cfb1_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 192, 8, 128, stream)
= { "AES-192-CFB1", NULL };
/* aes128cfb1_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 128, 8, 128, stream)
= { "AES-128-CFB1", NULL };
/* aes256cfb8_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 256, 8, 128, stream)
= { "AES-256-CFB8", NULL };
/* aes192cfb8_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 192, 8, 128, stream)
= { "AES-192-CFB8", NULL };
/* aes128cfb8_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 128, 8, 128, stream)
= { "AES-128-CFB8", NULL };
/* aes256ctr_functions */
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 256, 8, 128, stream)
= { "AES-256-CTR", NULL };
/* aes192ctr_functions */
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 192, 8, 128, stream)
= { "AES-192-CTR", NULL };
/* aes128ctr_functions */
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 128, 8, 128, stream)
= { "AES-128-CTR", NULL };
