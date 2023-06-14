/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * All low level APIs are deprecated for public use, but still ok for internal
 * use where we're using them to implement the higher level EVP interface, as is
 * the case here.
 */
#include "internal/deprecated.h"

#include "cipher_aes_cbc_hmac_sha.h"

#if !defined(AES_CBC_HMAC_SHA_CAPABLE) || !defined(AES_CBC_HMAC_SHA_ENC_THEN_MAC)
int ossl_cipher_capable_aes_cbc_hmac_sha512(void)
{
    return 0;
}

const PROV_CIPHER_HW_AES_HMAC_SHA *ossl_prov_cipher_hw_aes_cbc_hmac_sha512(void)
{
    return NULL;
}
#else
#if defined(__aarch64__)
void asm_aescbc_sha512_hmac(const uint8_t *csrc, uint8_t *cdst, uint64_t clen,
                            uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
                            CIPH_DIGEST *arg);
void asm_sha512_hmac_aescbc_dec(const uint8_t *csrc, uint8_t *cdst, uint64_t clen,
                                uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
                                CIPH_DIGEST *arg);
#    define HWAES_SET_ENCRYPT_KEY aes_v8_set_encrypt_key
#    define HWAES_SET_DECRYPT_KEY aes_v8_set_decrypt_key
#    define HWAES_ENC_CBC_SHA512_ENC_THEN_MAC asm_aescbc_sha512_hmac
#    define HWAES_DEC_CBC_SHA512_ENC_THEN_MAC asm_sha512_hmac_aescbc_dec
#endif

int ossl_cipher_capable_aes_cbc_hmac_sha512(void)
{
    return HWAES_CBC_HMAC_SHA512_CAPABLE;
}

static int hwaes_cbc_hmac_sha512_init_key(PROV_CIPHER_CTX *vctx,
                                          const unsigned char *key,
                                          size_t keylen)
{
    int ret;
    PROV_AES_HMAC_SHA_CTX *ctx = (PROV_AES_HMAC_SHA_CTX *)vctx;
    PROV_AES_HMAC_SHA512_CTX *sctx = (PROV_AES_HMAC_SHA512_CTX *)vctx;

    if (ctx->base.enc)
        ret = HWAES_SET_ENCRYPT_KEY(key, ctx->base.keylen * 8, &ctx->ks);
    else
        ret = HWAES_SET_DECRYPT_KEY(key, ctx->base.keylen * 8, &ctx->ks);

    SHA512_Init(&sctx->head);    /* handy when benchmarking */
    sctx->tail = sctx->head;
    sctx->md = sctx->head;

    ctx->payload_length = NO_PAYLOAD_LENGTH;

    return ret < 0 ? 0 : 1;
}

void sha512_block_data_order(void *c, const void *p, size_t len);

static void sha512_update(SHA512_CTX *c, const void *data, size_t len)
{
    const unsigned char *ptr = data;
    size_t res;

    if ((res = c->num)) {
        res = SHA512_CBLOCK - res;
        if (len < res)
            res = len;
        SHA512_Update(c, ptr, res);
        ptr += res;
        len -= res;
    }

    res = len % SHA512_CBLOCK;
    len -= res;

    if (len) {
        sha512_block_data_order(c, ptr, len / SHA512_CBLOCK);

        ptr += len;
        c->Nh += len >> 61;
        c->Nl += len <<= 3;
        if (c->Nl < (unsigned int)len)
            c->Nh++;
    }

    if (res)
        SHA512_Update(c, ptr, res);
}

# if defined(AES_CBC_HMAC_SHA_ENC_THEN_MAC)
static void ciph_digest_arg_init(CIPH_DIGEST *arg, PROV_CIPHER_CTX *vctx)
{
    PROV_AES_HMAC_SHA_CTX *ctx = (PROV_AES_HMAC_SHA_CTX *)vctx;
    PROV_AES_HMAC_SHA512_CTX *sctx = (PROV_AES_HMAC_SHA512_CTX *)vctx;

    arg->cipher.key = (uint8_t *)&(ctx->ks);
    arg->cipher.key_rounds = ctx->ks.rounds;
    arg->cipher.iv = (uint8_t *)&(ctx->base.iv);
    arg->digest.hmac.i_key_pad = (uint8_t *)&(sctx->head);
    arg->digest.hmac.o_key_pad = (uint8_t *)&(sctx->tail);
}

static int hwaes_cbc_hmac_sha512_enc_then_mac_chain(PROV_CIPHER_CTX *vctx,
                                                    unsigned char *out,
                                                    const unsigned char *in, size_t len)
{
    PROV_AES_HMAC_SHA_CTX *ctx = (PROV_AES_HMAC_SHA_CTX *)vctx;

    CIPH_DIGEST arg= {0};

    ciph_digest_arg_init(&arg, vctx);

    if (len % AES_BLOCK_SIZE)
        return 0;

    if (ctx->base.enc) {
        HWAES_ENC_CBC_SHA512_ENC_THEN_MAC(in, out, len, out, ctx->tag, len, &arg);
    } else {
        HWAES_DEC_CBC_SHA512_ENC_THEN_MAC(in, out, len, out, ctx->tag, len, &arg);
    }
    return 1;
}
# endif

static int hwaes_cbc_hmac_sha512_cipher(PROV_CIPHER_CTX *vctx,
                                        unsigned char *out,
                                        const unsigned char *in, size_t len)
{
# if defined(AES_CBC_HMAC_SHA_ENC_THEN_MAC)
    PROV_AES_HMAC_SHA_CTX *ctx = (PROV_AES_HMAC_SHA_CTX *)vctx;
    if (ctx->enc_then_mac == 1)
        return hwaes_cbc_hmac_sha512_enc_then_mac_chain(vctx, out, in, len);
# endif
    return 0;
}

static void hwaes_cbc_hmac_sha512_set_mac_key(void *vctx,
                                              const unsigned char *mackey,
                                              size_t len)
{
    PROV_AES_HMAC_SHA512_CTX *ctx = (PROV_AES_HMAC_SHA512_CTX *)vctx;
    unsigned int i;
    unsigned char hmac_key[128];

    memset(hmac_key, 0, sizeof(hmac_key));

    if (len > sizeof(hmac_key)) {
        SHA512_Init(&ctx->head);
        sha512_update(&ctx->head, mackey, len);
        SHA512_Final(hmac_key, &ctx->head);
    } else {
        memcpy(hmac_key, mackey, len);
    }

    for (i = 0; i < sizeof(hmac_key); i++)
        hmac_key[i] ^= 0x36; /* ipad */
    SHA512_Init(&ctx->head);
    sha512_update(&ctx->head, hmac_key, sizeof(hmac_key));

    for (i = 0; i < sizeof(hmac_key); i++)
        hmac_key[i] ^= 0x36 ^ 0x5c; /* opad */
    SHA512_Init(&ctx->tail);
    sha512_update(&ctx->tail, hmac_key, sizeof(hmac_key));

    OPENSSL_cleanse(hmac_key, sizeof(hmac_key));
}

static const PROV_CIPHER_HW_AES_HMAC_SHA cipher_hw_aes_hmac_sha512 = {
    {
      hwaes_cbc_hmac_sha512_init_key,
      hwaes_cbc_hmac_sha512_cipher
    },
    hwaes_cbc_hmac_sha512_set_mac_key,
    NULL,
# if !defined(OPENSSL_NO_MULTIBLOCK)
    NULL,
    NULL,
    NULL
# endif
};

const PROV_CIPHER_HW_AES_HMAC_SHA *ossl_prov_cipher_hw_aes_cbc_hmac_sha512(void)
{
    return &cipher_hw_aes_hmac_sha512;
}

#endif /* !defined(AES_CBC_HMAC_SHA_CAPABLE) || (!defined(AESNI_CAPABLE) && !defined(HWAES_CAPABLE)) */
