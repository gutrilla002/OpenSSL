/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include <openssl/aes.h>
#include <openssl/sha.h>
#include "crypto/evp.h"

#if defined(__aarch64__)
typedef struct {
    AES_KEY ks;
    SHA512_CTX head, tail, md;
} EVP_AES_HMAC_SHA512;

extern unsigned int OPENSSL_armcap_P;

# define ARMV8_AES       (1<<2)
# define ARMV8_SHA512    (1<<6)

# define HWAES_CBC_HMAC_SHA512_CAPABLE \
         ((OPENSSL_armcap_P & ARMV8_AES) && \
         (OPENSSL_armcap_P & ARMV8_SHA512))

# define AES_CBC_SHA512_CIPHER_FLAG  EVP_CIPH_CBC_MODE | \
                                     EVP_CIPH_FLAG_DEFAULT_ASN1 | \
                                     EVP_CIPH_FLAG_ENC_THEN_MAC

static EVP_CIPHER hwaes_128_cbc_hmac_sha512_cipher = {
# ifdef NID_aes_128_cbc_hmac_sha512
    NID_aes_128_cbc_hmac_sha512,
# else
    NID_undef,
# endif
    AES_BLOCK_SIZE, 16, AES_BLOCK_SIZE,
    AES_CBC_SHA512_CIPHER_FLAG,
    EVP_ORIG_GLOBAL,
    NULL,
    NULL,
    NULL,
    sizeof(EVP_AES_HMAC_SHA512),
    EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv,
    EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

static EVP_CIPHER hwaes_256_cbc_hmac_sha512_cipher = {
# ifdef NID_aes_256_cbc_hmac_sha512
    NID_aes_256_cbc_hmac_sha512,
# else
    NID_undef,
# endif
    AES_BLOCK_SIZE, 32, AES_BLOCK_SIZE,
    AES_CBC_SHA512_CIPHER_FLAG,
    EVP_ORIG_GLOBAL,
    NULL,
    NULL,
    NULL,
    sizeof(EVP_AES_HMAC_SHA512),
    EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv,
    EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv,
    NULL,
    NULL
};

const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha512(void)
{
    return (HWAES_CBC_HMAC_SHA512_CAPABLE ?
            &hwaes_128_cbc_hmac_sha512_cipher : NULL);
}

const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha512(void)
{
    return (HWAES_CBC_HMAC_SHA512_CAPABLE ?
            &hwaes_256_cbc_hmac_sha512_cipher : NULL);
}
#else
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha512(void)
{
    return NULL;
}

const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha512(void)
{
    return NULL;
}
#endif
