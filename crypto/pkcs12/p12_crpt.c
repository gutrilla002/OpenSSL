/*
 * Copyright 1999-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/pkcs12.h>

/* PKCS#12 PBE algorithms now in static table */

void PKCS12_PBE_add(void)
{
}

int PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                        ASN1_TYPE *param, const EVP_CIPHER *cipher,
                        const EVP_MD *md, int en_de)
{
    PBEPARAM *pbe;
    int saltlen, iter, ret;
    unsigned char *salt;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    int (*pkcs12_key_gen)(const char *pass, int passlen,
                          unsigned char *salt, int slen,
                          int id, int iter, int n,
                          unsigned char *out,
                          const EVP_MD *md_type);

    pkcs12_key_gen = PKCS12_key_gen_utf8;

    if (cipher == NULL)
        return 0;

    /* Extract useful info from parameter */

    pbe = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM), param);
    if (pbe == NULL) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR);
        return 0;
    }

    if (pbe->iter == NULL)
        iter = 1;
    else
        iter = ASN1_INTEGER_get(pbe->iter);
    salt = pbe->salt->data;
    saltlen = pbe->salt->length;
    if (!(*pkcs12_key_gen)(pass, passlen, salt, saltlen, PKCS12_KEY_ID,
                           iter, EVP_CIPHER_key_length(cipher), key, md)) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_KEY_GEN_ERROR);
        PBEPARAM_free(pbe);
        return 0;
    }
    if (!(*pkcs12_key_gen)(pass, passlen, salt, saltlen, PKCS12_IV_ID,
                           iter, EVP_CIPHER_iv_length(cipher), iv, md)) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_IV_GEN_ERROR);
        PBEPARAM_free(pbe);
        return 0;
    }
    PBEPARAM_free(pbe);
    ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, en_de);
    OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(iv, EVP_MAX_IV_LENGTH);
    return ret;
}

int PKCS12_PBE_params_decode(ASN1_TYPE *param, OSSL_PARAM **params, int params_len)
{
    PBEPARAM *pbe;
    OSSL_PARAM *p = params;
    unsigned int iter = 0;

    while (p != NULL)
        p++;

    /* Extract useful info from parameter */
    pbe = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM), param);
    if (pbe == NULL) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR);
        return 0;
    }

    if (pbe->iter != NULL) {
        iter = ASN1_INTEGER_get(pbe->iter);
        *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter);
    }
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, pbe->salt->data,
                                             pbe->salt->length);
    PBEPARAM_free(pbe);
    return 1;
}

