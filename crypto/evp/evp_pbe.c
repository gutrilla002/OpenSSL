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
#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include "crypto/evp.h"
#include "evp_local.h"

/* Password based encryption (PBE) functions */

/* Setup a cipher context from a PBE algorithm */

struct evp_pbe_st {
    int pbe_type;
    int pbe_nid;
    int cipher_nid;
    int md_nid;
    EVP_PBE_KEYGEN *keygen;
//    const char * pbe_name;
    EVP_PBE_ENCODE *encode;
    EVP_PBE_DECODE *decode;
};

static STACK_OF(EVP_PBE_CTL) *pbe_algs;

static const EVP_PBE_CTL builtin_pbe[] = {
    {EVP_PBE_TYPE_OUTER, NID_pbeWithMD2AndDES_CBC,
     NID_des_cbc, NID_md2, PKCS5_PBE_keyivgen, OSSL_PBE_NAME_PKCS5},
    {EVP_PBE_TYPE_OUTER, NID_pbeWithMD5AndDES_CBC,
     NID_des_cbc, NID_md5, PKCS5_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbeWithSHA1AndRC2_CBC,
     NID_rc2_64_cbc, NID_sha1, PKCS5_PBE_keyivgen},

    {EVP_PBE_TYPE_OUTER, NID_id_pbkdf2, -1, -1, PKCS5_v2_PBKDF2_keyivgen},

    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And128BitRC4,
     NID_rc4, NID_sha1, PKCS12_PBE_keyivgen, OSSL_PBE_NAME_PKCS12},
    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And40BitRC4,
     NID_rc4_40, NID_sha1, PKCS12_PBE_keyivgen, OSSL_PBE_NAME_PKCS12},
    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
     NID_des_ede3_cbc, NID_sha1, PKCS12_PBE_keyivgen, OSSL_PBE_NAME_PKCS12},
    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And2_Key_TripleDES_CBC,
     NID_des_ede_cbc, NID_sha1, PKCS12_PBE_keyivgen, OSSL_PBE_NAME_PKCS12},
    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And128BitRC2_CBC,
     NID_rc2_cbc, NID_sha1, PKCS12_PBE_keyivgen, OSSL_PBE_NAME_PKCS12},
    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And40BitRC2_CBC,
     NID_rc2_40_cbc, NID_sha1, PKCS12_PBE_keyivgen, OSSL_PBE_NAME_PKCS12},

    {EVP_PBE_TYPE_OUTER, NID_pbes2, -1, -1, PKCS5_v2_PBE_keyivgen, OSSL_PBE_NAME_PBES2},

    {EVP_PBE_TYPE_OUTER, NID_pbeWithMD2AndRC2_CBC,
     NID_rc2_64_cbc, NID_md2, PKCS5_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbeWithMD5AndRC2_CBC,
     NID_rc2_64_cbc, NID_md5, PKCS5_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbeWithSHA1AndDES_CBC,
     NID_des_cbc, NID_sha1, PKCS5_PBE_keyivgen},

    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA1, -1, NID_sha1, 0},
    {EVP_PBE_TYPE_PRF, NID_hmac_md5, -1, NID_md5, 0},
    {EVP_PBE_TYPE_PRF, NID_hmac_sha1, -1, NID_sha1, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithMD5, -1, NID_md5, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA224, -1, NID_sha224, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA256, -1, NID_sha256, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA384, -1, NID_sha384, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA512, -1, NID_sha512, 0},
    {EVP_PBE_TYPE_PRF, NID_id_HMACGostR3411_94, -1, NID_id_GostR3411_94, 0},
    {EVP_PBE_TYPE_PRF, NID_id_tc26_hmac_gost_3411_2012_256, -1,
     NID_id_GostR3411_2012_256, 0},
    {EVP_PBE_TYPE_PRF, NID_id_tc26_hmac_gost_3411_2012_512, -1,
     NID_id_GostR3411_2012_512, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA512_224, -1, NID_sha512_224, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA512_256, -1, NID_sha512_256, 0},
    {EVP_PBE_TYPE_KDF, NID_id_pbkdf2, -1, -1, PKCS5_v2_PBKDF2_keyivgen},
#ifndef OPENSSL_NO_SCRYPT
    {EVP_PBE_TYPE_KDF, NID_id_scrypt, -1, -1, PKCS5_v2_scrypt_keyivgen}
#endif
};

int EVP_PBE_params_decode(ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
                          ASN1_TYPE *param, OSSL_PARAM **params, int *params_len)
{
    int p_index = 0;
    int pbe_nid, cipher_nid, md_nid;
    const char *pbe_name, *cipher_name, *md_name;
    EVP_PBE_KEYGEN *keygen;

    pbe_nid = OBJ_obj2nid(pbe_obj);
    if (!EVP_PBE_find_ex(EVP_PBE_TYPE_OUTER, pbe_nid, &cipher_nid, &md_nid,
                         &keygen, &pbe_name)) {
        char obj_tmp[80];
        if (pbe_obj == NULL)
            OPENSSL_strlcpy(obj_tmp, "NULL", sizeof(obj_tmp));
        else
            i2t_ASN1_OBJECT(obj_tmp, sizeof(obj_tmp), pbe_obj);
        ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_PBE_ALGORITHM,
                       "TYPE=%s", obj_tmp);
        return 0;
    }

    if (pbe_name == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNKNOWN_PBE_ALGORITHM);
        return 0;
    }

    *params[p_index++] = OSSL_PARAM_construct_utf8_string(OSSL_PBE_PARAM_ALG, pbe_name, 0);

    if (pass == NULL)
        passlen = 0;
    else if (passlen == -1)
        passlen = strlen(pass);
    *params[p_index++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, pass,
                                             passlen);

    /* If cipher/digest can be determined from PBE OID, set them here */
    if (cipher_nid != -1) {
        cipher_name = OBJ_nid2sn(cipher_nid);
        if (!cipher_name) {
            ERR_raise(ERR_LIB_EVP, EVP_R_UNKNOWN_CIPHER);
            return 0;
        }
        *params[p_index++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER, cipher_name, 0);
    }

    if (md_nid != -1) {
        md_name = OBJ_nid2sn(md_nid);
        if (!md_name) {
            ERR_raise(ERR_LIB_EVP, EVP_R_UNKNOWN_DIGEST);
            return 0;
        }
        *params[p_index++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name, 0);
    }

  if (strcmp(pbe_name, "PBES2") == 0)
  {
    /* Decode PBES2 */
    PBE2PARAM *pbe2 = NULL;
    const EVP_CIPHER *cipher;
    EVP_PBE_KEYGEN *kdf;

    int rv = 0;

    pbe2 = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBE2PARAM), param);
    if (pbe2 == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        return 0;
    }

    /* See if we recognise the key derivation function */
    if (!EVP_PBE_find(EVP_PBE_TYPE_KDF, OBJ_obj2nid(pbe2->keyfunc->algorithm),
                        NULL, NULL, &kdf)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION);
        return 0;
    }

    /*
     * lets see if we recognise the encryption algorithm.
     */

    cipher_name = OBJ_obj2sn(pbe2->encryption->algorithm);

    if (!cipher) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER);
        return 0;
    }

  } else {
    /* Decode PBES1 */
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
  }

    return decode(param, params, params_len);
}

int EVP_PBE_from_params(OSSL_PARAM *params,
                        EVP_CIPHER_CTX *ctx, int en_de)
{
/* TODO: Implement
    const EVP_CIPHER *cipher;
    const EVP_MD *md;
    int cipher_nid, md_nid;
    EVP_PBE_KEYGEN *keygen;

    if (!EVP_PBE_find_ex(EVP_PBE_TYPE_OUTER, OBJ_obj2nid(pbe_obj),
                         &cipher_nid, &md_nid, &keygen, NULL)) {
        char obj_tmp[80];

        if (pbe_obj == NULL)
            OPENSSL_strlcpy(obj_tmp, "NULL", sizeof(obj_tmp));
        else
            i2t_ASN1_OBJECT(obj_tmp, sizeof(obj_tmp), pbe_obj);
        ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_PBE_ALGORITHM,
                       "TYPE=%s", obj_tmp);
        return 0;
    }

    if (pass == NULL)
        passlen = 0;
    else if (passlen == -1)
        passlen = strlen(pass);

    if (cipher_nid == -1)
        cipher = NULL;
    else {
        cipher = EVP_get_cipherbynid(cipher_nid);
        if (!cipher) {
            ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_CIPHER,
                           OBJ_nid2sn(cipher_nid));
            return 0;
        }
    }

    if (md_nid == -1)
        md = NULL;
    else {
        md = EVP_get_digestbynid(md_nid);
        if (!md) {
            ERR_raise(ERR_LIB_EVP, EVP_R_UNKNOWN_DIGEST);
            return 0;
        }
    }

    return keygen(ctx, pass, passlen, param, cipher, md, en_de);
*/
    return 0;
}

int EVP_PBE_CipherInit(ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
                       ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de)
{
    const EVP_CIPHER *cipher;
    const EVP_MD *md;
    int cipher_nid, md_nid;
    EVP_PBE_KEYGEN *keygen;

    if (!EVP_PBE_find(EVP_PBE_TYPE_OUTER, OBJ_obj2nid(pbe_obj),
                      &cipher_nid, &md_nid, &keygen)) {
        char obj_tmp[80];

        if (pbe_obj == NULL)
            OPENSSL_strlcpy(obj_tmp, "NULL", sizeof(obj_tmp));
        else
            i2t_ASN1_OBJECT(obj_tmp, sizeof(obj_tmp), pbe_obj);
        ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_PBE_ALGORITHM,
                       "TYPE=%s", obj_tmp);
        return 0;
    }

    if (pass == NULL)
        passlen = 0;
    else if (passlen == -1)
        passlen = strlen(pass);

    if (cipher_nid == -1)
        cipher = NULL;
    else {
        cipher = EVP_get_cipherbynid(cipher_nid);
        if (!cipher) {
            ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_CIPHER,
                           OBJ_nid2sn(cipher_nid));
            return 0;
        }
    }

    if (md_nid == -1)
        md = NULL;
    else {
        md = EVP_get_digestbynid(md_nid);
        if (!md) {
            ERR_raise(ERR_LIB_EVP, EVP_R_UNKNOWN_DIGEST);
            return 0;
        }
    }

    return keygen(ctx, pass, passlen, param, cipher, md, en_de);
}

DECLARE_OBJ_BSEARCH_CMP_FN(EVP_PBE_CTL, EVP_PBE_CTL, pbe2);

static int pbe2_cmp(const EVP_PBE_CTL *pbe1, const EVP_PBE_CTL *pbe2)
{
    int ret = pbe1->pbe_type - pbe2->pbe_type;
    if (ret)
        return ret;
    else
        return pbe1->pbe_nid - pbe2->pbe_nid;
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(EVP_PBE_CTL, EVP_PBE_CTL, pbe2);

static int pbe_cmp(const EVP_PBE_CTL *const *a, const EVP_PBE_CTL *const *b)
{
    int ret = (*a)->pbe_type - (*b)->pbe_type;
    if (ret)
        return ret;
    else
        return (*a)->pbe_nid - (*b)->pbe_nid;
}

/* Add a PBE algorithm */

int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid,
                         int md_nid, EVP_PBE_KEYGEN *keygen)
{
    EVP_PBE_CTL *pbe_tmp;

    if (pbe_algs == NULL) {
        pbe_algs = sk_EVP_PBE_CTL_new(pbe_cmp);
        if (pbe_algs == NULL)
            goto err;
    }

    if ((pbe_tmp = OPENSSL_malloc(sizeof(*pbe_tmp))) == NULL)
        goto err;

    pbe_tmp->pbe_type = pbe_type;
    pbe_tmp->pbe_nid = pbe_nid;
    pbe_tmp->cipher_nid = cipher_nid;
    pbe_tmp->md_nid = md_nid;
    pbe_tmp->keygen = keygen;

    if (!sk_EVP_PBE_CTL_push(pbe_algs, pbe_tmp)) {
        OPENSSL_free(pbe_tmp);
        goto err;
    }
    return 1;

 err:
    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
    return 0;
}

int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md,
                    EVP_PBE_KEYGEN *keygen)
{
    int cipher_nid, md_nid;

    if (cipher)
        cipher_nid = EVP_CIPHER_nid(cipher);
    else
        cipher_nid = -1;
    if (md)
        md_nid = EVP_MD_type(md);
    else
        md_nid = -1;

    return EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, nid,
                                cipher_nid, md_nid, keygen);
}

int EVP_PBE_find_ex(int type, int pbe_nid,
                    int *pcnid, int *pmnid, EVP_PBE_KEYGEN **pkeygen,
                    const char **pbe_name)
{
    EVP_PBE_CTL *pbetmp = NULL, pbelu;
    int i;
    if (pbe_nid == NID_undef)
        return 0;

    pbelu.pbe_type = type;
    pbelu.pbe_nid = pbe_nid;

    if (pbe_algs != NULL) {
        i = sk_EVP_PBE_CTL_find(pbe_algs, &pbelu);
        pbetmp = sk_EVP_PBE_CTL_value(pbe_algs, i);
    }
    if (pbetmp == NULL) {
        pbetmp = OBJ_bsearch_pbe2(&pbelu, builtin_pbe, OSSL_NELEM(builtin_pbe));
    }
    if (pbetmp == NULL)
        return 0;
    if (pcnid)
        *pcnid = pbetmp->cipher_nid;
    if (pmnid)
        *pmnid = pbetmp->md_nid;
    if (pkeygen)
        *pkeygen = pbetmp->keygen;
    if (pbe_name)
        *pbe_name = pbetmp->pbe_name;
    return 1;
}

int EVP_PBE_find(int type, int pbe_nid,
                 int *pcnid, int *pmnid, EVP_PBE_KEYGEN **pkeygen)
{
    return EVP_PBE_find_ex(type, pbe_nid, pcnid, pmnid, pkeygen, NULL);
}

static void free_evp_pbe_ctl(EVP_PBE_CTL *pbe)
{
    OPENSSL_free(pbe);
}

void EVP_PBE_cleanup(void)
{
    sk_EVP_PBE_CTL_pop_free(pbe_algs, free_evp_pbe_ctl);
    pbe_algs = NULL;
}

int EVP_PBE_get(int *ptype, int *ppbe_nid, size_t num)
{
    const EVP_PBE_CTL *tpbe;

    if (num >= OSSL_NELEM(builtin_pbe))
        return 0;

    tpbe = builtin_pbe + num;
    if (ptype)
        *ptype = tpbe->pbe_type;
    if (ppbe_nid)
        *ppbe_nid = tpbe->pbe_nid;
    return 1;
}
