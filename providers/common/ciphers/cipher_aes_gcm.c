/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for AES GCM mode */

#include "cipher_local.h"
#include "internal/ciphers/cipher_gcm.h"
#include "internal/provider_algs.h"

static void *aes_gcm_newctx(void *provctx, size_t keybits)
{
    PROV_AES_GCM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        gcm_initctx(provctx, &ctx->base, keybits, PROV_AES_HW_gcm(keybits), 8);
    return ctx;
}

static OSSL_OP_cipher_freectx_fn aes_gcm_freectx;
static void aes_gcm_freectx(void *vctx)
{
    PROV_AES_GCM_CTX *ctx = (PROV_AES_GCM_CTX *)vctx;

    gcm_deinitctx((PROV_GCM_CTX *)ctx);
    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

/* aes128gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 128, 8, 96)
= { "id-aes128-GCM", "AES-128-GCM", NULL };
/* aes192gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 192, 8, 96)
= { "id-aes192-GCM", "AES-192-GCM", NULL };
/* aes256gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 256, 8, 96)
= { "id-aes256-GCM", "AES-256-GCM", NULL };
