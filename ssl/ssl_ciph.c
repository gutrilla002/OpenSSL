/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <stdio.h>
#include <openssl/objects.h>
#ifndef OPENSSL_NO_COMP
# include <openssl/comp.h>
#endif
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include "ssl_locl.h"

#define SSL_ENC_DES_IDX         0
#define SSL_ENC_3DES_IDX        1
#define SSL_ENC_RC4_IDX         2
#define SSL_ENC_RC2_IDX         3
#define SSL_ENC_IDEA_IDX        4
#define SSL_ENC_NULL_IDX        5
#define SSL_ENC_AES128_IDX      6
#define SSL_ENC_AES256_IDX      7
#define SSL_ENC_CAMELLIA128_IDX 8
#define SSL_ENC_CAMELLIA256_IDX 9
#define SSL_ENC_GOST89_IDX      10
#define SSL_ENC_SEED_IDX        11
#define SSL_ENC_AES128GCM_IDX   12
#define SSL_ENC_AES256GCM_IDX   13
#define SSL_ENC_AES128CCM_IDX   14
#define SSL_ENC_AES256CCM_IDX   15
#define SSL_ENC_AES128CCM8_IDX  16
#define SSL_ENC_AES256CCM8_IDX  17
#define SSL_ENC_GOST8912_IDX    18
#define SSL_ENC_CHACHA_IDX      19
#define SSL_ENC_NUM_IDX         20

/* NB: make sure indices in these tables match values above */

typedef struct {
    uint32_t mask;
    int nid;
} ssl_cipher_table;

/* Table of NIDs for each cipher */
static const ssl_cipher_table ssl_cipher_table_cipher[SSL_ENC_NUM_IDX] = {
    {SSL_DES, NID_des_cbc},     /* SSL_ENC_DES_IDX 0 */
    {SSL_3DES, NID_des_ede3_cbc}, /* SSL_ENC_3DES_IDX 1 */
    {SSL_RC4, NID_rc4},         /* SSL_ENC_RC4_IDX 2 */
    {SSL_RC2, NID_rc2_cbc},     /* SSL_ENC_RC2_IDX 3 */
    {SSL_IDEA, NID_idea_cbc},   /* SSL_ENC_IDEA_IDX 4 */
    {SSL_eNULL, NID_undef},     /* SSL_ENC_NULL_IDX 5 */
    {SSL_AES128, NID_aes_128_cbc}, /* SSL_ENC_AES128_IDX 6 */
    {SSL_AES256, NID_aes_256_cbc}, /* SSL_ENC_AES256_IDX 7 */
    {SSL_CAMELLIA128, NID_camellia_128_cbc}, /* SSL_ENC_CAMELLIA128_IDX 8 */
    {SSL_CAMELLIA256, NID_camellia_256_cbc}, /* SSL_ENC_CAMELLIA256_IDX 9 */
    {SSL_eGOST2814789CNT, NID_gost89_cnt}, /* SSL_ENC_GOST89_IDX 10 */
    {SSL_SEED, NID_seed_cbc},   /* SSL_ENC_SEED_IDX 11 */
    {SSL_AES128GCM, NID_aes_128_gcm}, /* SSL_ENC_AES128GCM_IDX 12 */
    {SSL_AES256GCM, NID_aes_256_gcm}, /* SSL_ENC_AES256GCM_IDX 13 */
    {SSL_AES128CCM, NID_aes_128_ccm}, /* SSL_ENC_AES128CCM_IDX 14 */
    {SSL_AES256CCM, NID_aes_256_ccm}, /* SSL_ENC_AES256CCM_IDX 15 */
    {SSL_AES128CCM8, NID_aes_128_ccm}, /* SSL_ENC_AES128CCM8_IDX 16 */
    {SSL_AES256CCM8, NID_aes_256_ccm}, /* SSL_ENC_AES256CCM8_IDX 17 */
    {SSL_eGOST2814789CNT12, NID_gost89_cnt_12}, /* SSL_ENC_GOST8912_IDX */
    {SSL_CHACHA20POLY1305, NID_chacha20_poly1305},
};

static const EVP_CIPHER *ssl_cipher_methods[SSL_ENC_NUM_IDX] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL
};

#define SSL_COMP_NULL_IDX       0
#define SSL_COMP_ZLIB_IDX       1
#define SSL_COMP_NUM_IDX        2

static STACK_OF(SSL_COMP) *ssl_comp_methods = NULL;

/*
 * Constant SSL_MAX_DIGEST equal to size of digests array should be defined
 * in the ssl_locl.h
 */

#define SSL_MD_NUM_IDX  SSL_MAX_DIGEST

/* NB: make sure indices in this table matches values above */
static const ssl_cipher_table ssl_cipher_table_mac[SSL_MD_NUM_IDX] = {
    {SSL_MD5, NID_md5},         /* SSL_MD_MD5_IDX 0 */
    {SSL_SHA1, NID_sha1},       /* SSL_MD_SHA1_IDX 1 */
    {SSL_GOST94, NID_id_GostR3411_94}, /* SSL_MD_GOST94_IDX 2 */
    {SSL_GOST89MAC, NID_id_Gost28147_89_MAC}, /* SSL_MD_GOST89MAC_IDX 3 */
    {SSL_SHA256, NID_sha256},   /* SSL_MD_SHA256_IDX 4 */
    {SSL_SHA384, NID_sha384},   /* SSL_MD_SHA384_IDX 5 */
    {SSL_GOST12_256, NID_id_GostR3411_2012_256},  /* SSL_MD_GOST12_256_IDX 6 */
    {SSL_GOST89MAC12, NID_gost_mac_12},           /* SSL_MD_GOST89MAC12_IDX 7 */
    {SSL_GOST12_512, NID_id_GostR3411_2012_512},  /* SSL_MD_GOST12_512_IDX 8 */
    {0, NID_md5_sha1},          /* SSL_MD_MD5_SHA1_IDX 9 */
    {0, NID_sha224},            /* SSL_MD_SHA224_IDX 10 */
    {0, NID_sha512}             /* SSL_MD_SHA512_IDX 11 */
};

static const EVP_MD *ssl_digest_methods[SSL_MD_NUM_IDX] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/* Utility function for table lookup */
static int ssl_cipher_info_find(const ssl_cipher_table * table,
                                size_t table_cnt, uint32_t mask)
{
    size_t i;
    for (i = 0; i < table_cnt; i++, table++) {
        if (table->mask == mask)
            return i;
    }
    return -1;
}

#define ssl_cipher_info_lookup(table, x) \
    ssl_cipher_info_find(table, OSSL_NELEM(table), x)

/*
 * PKEY_TYPE for GOST89MAC is known in advance, but, because implementation
 * is engine-provided, we'll fill it only if corresponding EVP_PKEY_METHOD is
 * found
 */
static int ssl_mac_pkey_id[SSL_MD_NUM_IDX] = {
    /* MD5, SHA, GOST94, MAC89 */
    EVP_PKEY_HMAC, EVP_PKEY_HMAC, EVP_PKEY_HMAC, NID_undef,
    /* SHA256, SHA384, GOST2012_256, MAC89-12 */
    EVP_PKEY_HMAC, EVP_PKEY_HMAC, EVP_PKEY_HMAC, NID_undef,
    /* GOST2012_512 */
    EVP_PKEY_HMAC,
};

static int ssl_mac_secret_size[SSL_MD_NUM_IDX] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define CIPHER_ADD      1
#define CIPHER_KILL     2
#define CIPHER_DEL      3
#define CIPHER_ORD      4
#define CIPHER_SPECIAL  5

typedef struct cipher_order_st {
    const SSL_CIPHER *cipher;
    int active;
    int dead;
    struct cipher_order_st *next, *prev;
} CIPHER_ORDER;

static const SSL_CIPHER cipher_aliases[] = {
    /* "ALL" doesn't include eNULL (must be specifically enabled) */
    {0, SSL_TXT_ALL, 0, 0, 0, ~SSL_eNULL, 0, 0, 0, 0, 0, 0},
    /* "COMPLEMENTOFALL" */
    {0, SSL_TXT_CMPALL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0},

    /*
     * "COMPLEMENTOFDEFAULT" (does *not* include ciphersuites not found in
     * ALL!)
     */
    {0, SSL_TXT_CMPDEF, 0, 0, 0, ~SSL_eNULL, 0, 0, SSL_NOT_DEFAULT, 0, 0, 0},

    /*
     * key exchange aliases (some of those using only a single bit here
     * combine multiple key exchange algs according to the RFCs, e.g. kDHE
     * combines DHE_DSS and DHE_RSA)
     */
    {0, SSL_TXT_kRSA, 0, SSL_kRSA, 0, 0, 0, 0, 0, 0, 0, 0},

    {0, SSL_TXT_kEDH, 0, SSL_kDHE, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDHE, 0, SSL_kDHE, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DH, 0, SSL_kDHE, 0, 0, 0, 0, 0, 0, 0,
     0},

    {0, SSL_TXT_kEECDH, 0, SSL_kECDHE, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDHE, 0, SSL_kECDHE, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDH, 0, SSL_kECDHE, 0, 0, 0, 0, 0,
     0, 0, 0},

    {0, SSL_TXT_kPSK, 0, SSL_kPSK, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kRSAPSK, 0, SSL_kRSAPSK, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kECDHEPSK, 0, SSL_kECDHEPSK, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kDHEPSK, 0, SSL_kDHEPSK, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kSRP, 0, SSL_kSRP, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_kGOST, 0, SSL_kGOST, 0, 0, 0, 0, 0, 0, 0, 0},

    /* server authentication aliases */
    {0, SSL_TXT_aRSA, 0, 0, SSL_aRSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aDSS, 0, 0, SSL_aDSS, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DSS, 0, 0, SSL_aDSS, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aNULL, 0, 0, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aECDSA, 0, 0, SSL_aECDSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDSA, 0, 0, SSL_aECDSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aPSK, 0, 0, SSL_aPSK, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST01, 0, 0, SSL_aGOST01, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST12, 0, 0, SSL_aGOST12, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_aGOST, 0, 0, SSL_aGOST01 | SSL_aGOST12, 0, 0, 0,
     0, 0, 0, 0},
    {0, SSL_TXT_aSRP, 0, 0, SSL_aSRP, 0, 0, 0, 0, 0, 0, 0},

    /* aliases combining key exchange and server authentication */
    {0, SSL_TXT_EDH, 0, SSL_kDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_DHE, 0, SSL_kDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_EECDH, 0, SSL_kECDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ECDHE, 0, SSL_kECDHE, ~SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_NULL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RSA, 0, SSL_kRSA, SSL_aRSA, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_ADH, 0, SSL_kDHE, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AECDH, 0, SSL_kECDHE, SSL_aNULL, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_PSK, 0, SSL_PSK, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SRP, 0, SSL_kSRP, 0, 0, 0, 0, 0, 0, 0, 0},

    /* symmetric encryption aliases */
    {0, SSL_TXT_DES, 0, 0, 0, SSL_DES, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_3DES, 0, 0, 0, SSL_3DES, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RC4, 0, 0, 0, SSL_RC4, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_RC2, 0, 0, 0, SSL_RC2, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_IDEA, 0, 0, 0, SSL_IDEA, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SEED, 0, 0, 0, SSL_SEED, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_eNULL, 0, 0, 0, SSL_eNULL, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST, 0, 0, 0, SSL_eGOST2814789CNT | SSL_eGOST2814789CNT12, 0,
     0, 0, 0, 0, 0},
    {0, SSL_TXT_AES128, 0, 0, 0, SSL_AES128 | SSL_AES128GCM | SSL_AES128CCM | SSL_AES128CCM8, 0,
     0, 0, 0, 0, 0},
    {0, SSL_TXT_AES256, 0, 0, 0, SSL_AES256 | SSL_AES256GCM | SSL_AES256CCM | SSL_AES256CCM8, 0,
     0, 0, 0, 0, 0},
    {0, SSL_TXT_AES, 0, 0, 0, SSL_AES, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_AES_GCM, 0, 0, 0, SSL_AES128GCM | SSL_AES256GCM, 0, 0, 0, 0,
     0, 0},
    {0, SSL_TXT_AES_CCM, 0, 0, 0, SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8, 0, 0, 0, 0,
     0, 0},
    {0, SSL_TXT_AES_CCM_8, 0, 0, 0, SSL_AES128CCM8 | SSL_AES256CCM8, 0, 0, 0, 0,
     0, 0},
    {0, SSL_TXT_CAMELLIA128, 0, 0, 0, SSL_CAMELLIA128, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA256, 0, 0, 0, SSL_CAMELLIA256, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CAMELLIA, 0, 0, 0, SSL_CAMELLIA, 0, 0, 0, 0, 0, 0},
    {0, SSL_TXT_CHACHA20, 0, 0, 0, SSL_CHACHA20, 0, 0, 0, 0, 0, 0 },

    /* MAC aliases */
    {0, SSL_TXT_MD5, 0, 0, 0, 0, SSL_MD5, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA1, 0, 0, 0, 0, SSL_SHA1, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA, 0, 0, 0, 0, SSL_SHA1, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST94, 0, 0, 0, 0, SSL_GOST94, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST89MAC, 0, 0, 0, 0, SSL_GOST89MAC | SSL_GOST89MAC12, 0, 0,
     0, 0, 0},
    {0, SSL_TXT_SHA256, 0, 0, 0, 0, SSL_SHA256, 0, 0, 0, 0, 0},
    {0, SSL_TXT_SHA384, 0, 0, 0, 0, SSL_SHA384, 0, 0, 0, 0, 0},
    {0, SSL_TXT_GOST12, 0, 0, 0, 0, SSL_GOST12_256, 0, 0, 0, 0, 0},

    /* protocol version aliases */
    {0, SSL_TXT_SSLV3, 0, 0, 0, 0, 0, SSL_SSLV3, 0, 0, 0, 0},
    {0, SSL_TXT_TLSV1, 0, 0, 0, 0, 0, SSL_SSLV3, 0, 0, 0, 0},
    {0, "TLSv1.0", 0, 0, 0, 0, 0, SSL_TLSV1, 0, 0, 0, 0},
    {0, SSL_TXT_TLSV1_2, 0, 0, 0, 0, 0, SSL_TLSV1_2, 0, 0, 0, 0},

    /* strength classes */
    {0, SSL_TXT_LOW, 0, 0, 0, 0, 0, 0, SSL_LOW, 0, 0, 0},
    {0, SSL_TXT_MEDIUM, 0, 0, 0, 0, 0, 0, SSL_MEDIUM, 0, 0, 0},
    {0, SSL_TXT_HIGH, 0, 0, 0, 0, 0, 0, SSL_HIGH, 0, 0, 0},
    /* FIPS 140-2 approved ciphersuite */
    {0, SSL_TXT_FIPS, 0, 0, 0, ~SSL_eNULL, 0, 0, SSL_FIPS, 0, 0, 0},

    /* "EDH-" aliases to "DHE-" labels (for backward compatibility) */
    {0, SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA, 0,
     SSL_kDHE, SSL_aDSS, SSL_3DES, SSL_SHA1, SSL_SSLV3,
     SSL_HIGH | SSL_FIPS, 0, 0, 0,},
    {0, SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA, 0,
     SSL_kDHE, SSL_aRSA, SSL_3DES, SSL_SHA1, SSL_SSLV3,
     SSL_HIGH | SSL_FIPS, 0, 0, 0,},

};

/*
 * Search for public key algorithm with given name and return its pkey_id if
 * it is available. Otherwise return 0
 */
#ifdef OPENSSL_NO_ENGINE

static int get_optional_pkey_id(const char *pkey_name)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    int pkey_id = 0;
    ameth = EVP_PKEY_asn1_find_str(NULL, pkey_name, -1);
    if (ameth && EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL,
                                         ameth) > 0) {
        return pkey_id;
    }
    return 0;
}

#else

static int get_optional_pkey_id(const char *pkey_name)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *tmpeng = NULL;
    int pkey_id = 0;
    ameth = EVP_PKEY_asn1_find_str(&tmpeng, pkey_name, -1);
    if (ameth) {
        if (EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL,
                                    ameth) <= 0)
            pkey_id = 0;
    }
    ENGINE_finish(tmpeng);
    return pkey_id;
}

#endif

/* masks of disabled algorithms */
static uint32_t disabled_enc_mask;
static uint32_t disabled_mac_mask;
static uint32_t disabled_mkey_mask;
static uint32_t disabled_auth_mask;

void ssl_load_ciphers(void)
{
    size_t i;
    const ssl_cipher_table *t;
    disabled_enc_mask = 0;
    for (i = 0, t = ssl_cipher_table_cipher; i < SSL_ENC_NUM_IDX; i++, t++) {
        if (t->nid == NID_undef) {
            ssl_cipher_methods[i] = NULL;
        } else {
            const EVP_CIPHER *cipher = EVP_get_cipherbynid(t->nid);
            ssl_cipher_methods[i] = cipher;
            if (cipher == NULL)
                disabled_enc_mask |= t->mask;
        }
    }
#ifdef SSL_FORBID_ENULL
    disabled_enc_mask |= SSL_eNULL;
#endif
    disabled_mac_mask = 0;
    for (i = 0, t = ssl_cipher_table_mac; i < SSL_MD_NUM_IDX; i++, t++) {
        const EVP_MD *md = EVP_get_digestbynid(t->nid);
        ssl_digest_methods[i] = md;
        if (md == NULL) {
            disabled_mac_mask |= t->mask;
        } else {
            ssl_mac_secret_size[i] = EVP_MD_size(md);
            OPENSSL_assert(ssl_mac_secret_size[i] >= 0);
        }
    }
    /* Make sure we can access MD5 and SHA1 */
    OPENSSL_assert(ssl_digest_methods[SSL_MD_MD5_IDX] != NULL);
    OPENSSL_assert(ssl_digest_methods[SSL_MD_SHA1_IDX] != NULL);

    disabled_mkey_mask = 0;
    disabled_auth_mask = 0;

#ifdef OPENSSL_NO_RSA
    disabled_mkey_mask |= SSL_kRSA | SSL_kRSAPSK;
    disabled_auth_mask |= SSL_aRSA;
#endif
#ifdef OPENSSL_NO_DSA
    disabled_auth_mask |= SSL_aDSS;
#endif
#ifdef OPENSSL_NO_DH
    disabled_mkey_mask |= SSL_kDHE | SSL_kDHEPSK;
#endif
#ifdef OPENSSL_NO_EC
    disabled_mkey_mask |= SSL_kECDHEPSK;
    disabled_auth_mask |= SSL_aECDSA;
#endif
#ifdef OPENSSL_NO_PSK
    disabled_mkey_mask |= SSL_PSK;
    disabled_auth_mask |= SSL_aPSK;
#endif
#ifdef OPENSSL_NO_SRP
    disabled_mkey_mask |= SSL_kSRP;
#endif

    /*
     * Check for presence of GOST 34.10 algorithms, and if they are not
     * present, disable appropriate auth and key exchange
     */
    ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX] = get_optional_pkey_id("gost-mac");
    if (ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX]) {
        ssl_mac_secret_size[SSL_MD_GOST89MAC_IDX] = 32;
    } else {
        disabled_mac_mask |= SSL_GOST89MAC;
    }

    ssl_mac_pkey_id[SSL_MD_GOST89MAC12_IDX] = get_optional_pkey_id("gost-mac-12");
    if (ssl_mac_pkey_id[SSL_MD_GOST89MAC12_IDX]) {
        ssl_mac_secret_size[SSL_MD_GOST89MAC12_IDX] = 32;
    } else {
        disabled_mac_mask |= SSL_GOST89MAC12;
    }

    if (!get_optional_pkey_id("gost2001"))
        disabled_auth_mask |= SSL_aGOST01 | SSL_aGOST12;
    if (!get_optional_pkey_id("gost2012_256"))
        disabled_auth_mask |= SSL_aGOST12;
    if (!get_optional_pkey_id("gost2012_512"))
        disabled_auth_mask |= SSL_aGOST12;
    /*
     * Disable GOST key exchange if no GOST signature algs are available *
     */
    if ((disabled_auth_mask & (SSL_aGOST01 | SSL_aGOST12)) == (SSL_aGOST01 | SSL_aGOST12))
        disabled_mkey_mask |= SSL_kGOST;
}

#ifndef OPENSSL_NO_COMP

static int sk_comp_cmp(const SSL_COMP *const *a, const SSL_COMP *const *b)
{
    return ((*a)->id - (*b)->id);
}

static void load_builtin_compressions(void)
{
    int got_write_lock = 0;

    CRYPTO_r_lock(CRYPTO_LOCK_SSL);
    if (ssl_comp_methods == NULL) {
        CRYPTO_r_unlock(CRYPTO_LOCK_SSL);
        CRYPTO_w_lock(CRYPTO_LOCK_SSL);
        got_write_lock = 1;

        if (ssl_comp_methods == NULL) {
            SSL_COMP *comp = NULL;
            COMP_METHOD *method = COMP_zlib();

            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
            ssl_comp_methods = sk_SSL_COMP_new(sk_comp_cmp);
            if (COMP_get_type(method) != NID_undef
                && ssl_comp_methods != NULL) {
                comp = OPENSSL_malloc(sizeof(*comp));
                if (comp != NULL) {
                    comp->method = method;
                    comp->id = SSL_COMP_ZLIB_IDX;
                    comp->name = COMP_get_name(method);
                    sk_SSL_COMP_push(ssl_comp_methods, comp);
                    sk_SSL_COMP_sort(ssl_comp_methods);
                }
            }
            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
        }
    }

    if (got_write_lock)
        CRYPTO_w_unlock(CRYPTO_LOCK_SSL);
    else
        CRYPTO_r_unlock(CRYPTO_LOCK_SSL);
}
#endif

int ssl_cipher_get_evp(const SSL_SESSION *s, const EVP_CIPHER **enc,
                       const EVP_MD **md, int *mac_pkey_type,
                       int *mac_secret_size, SSL_COMP **comp, int use_etm)
{
    int i;
    const SSL_CIPHER *c;

    c = s->cipher;
    if (c == NULL)
        return (0);
    if (comp != NULL) {
        SSL_COMP ctmp;
#ifndef OPENSSL_NO_COMP
        load_builtin_compressions();
#endif

        *comp = NULL;
        ctmp.id = s->compress_meth;
        if (ssl_comp_methods != NULL) {
            i = sk_SSL_COMP_find(ssl_comp_methods, &ctmp);
            if (i >= 0)
                *comp = sk_SSL_COMP_value(ssl_comp_methods, i);
            else
                *comp = NULL;
        }
        /* If were only interested in comp then return success */
        if ((enc == NULL) && (md == NULL))
            return 1;
    }

    if ((enc == NULL) || (md == NULL))
        return 0;

    i = ssl_cipher_info_lookup(ssl_cipher_table_cipher, c->algorithm_enc);

    if (i == -1)
        *enc = NULL;
    else {
        if (i == SSL_ENC_NULL_IDX)
            *enc = EVP_enc_null();
        else
            *enc = ssl_cipher_methods[i];
    }

    i = ssl_cipher_info_lookup(ssl_cipher_table_mac, c->algorithm_mac);
    if (i == -1) {
        *md = NULL;
        if (mac_pkey_type != NULL)
            *mac_pkey_type = NID_undef;
        if (mac_secret_size != NULL)
            *mac_secret_size = 0;
        if (c->algorithm_mac == SSL_AEAD)
            mac_pkey_type = NULL;
    } else {
        *md = ssl_digest_methods[i];
        if (mac_pkey_type != NULL)
            *mac_pkey_type = ssl_mac_pkey_id[i];
        if (mac_secret_size != NULL)
            *mac_secret_size = ssl_mac_secret_size[i];
    }

    if ((*enc != NULL) &&
        (*md != NULL || (EVP_CIPHER_flags(*enc) & EVP_CIPH_FLAG_AEAD_CIPHER))
        && (!mac_pkey_type || *mac_pkey_type != NID_undef)) {
        const EVP_CIPHER *evp;

        if (use_etm)
            return 1;

        if (s->ssl_version >> 8 != TLS1_VERSION_MAJOR ||
            s->ssl_version < TLS1_VERSION)
            return 1;

        if (FIPS_mode())
            return 1;

        if (c->algorithm_enc == SSL_RC4 &&
            c->algorithm_mac == SSL_MD5 &&
            (evp = EVP_get_cipherbyname("RC4-HMAC-MD5")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == SSL_AES128 &&
                 c->algorithm_mac == SSL_SHA1 &&
                 (evp = EVP_get_cipherbyname("AES-128-CBC-HMAC-SHA1")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == SSL_AES256 &&
                 c->algorithm_mac == SSL_SHA1 &&
                 (evp = EVP_get_cipherbyname("AES-256-CBC-HMAC-SHA1")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == SSL_AES128 &&
                 c->algorithm_mac == SSL_SHA256 &&
                 (evp = EVP_get_cipherbyname("AES-128-CBC-HMAC-SHA256")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == SSL_AES256 &&
                 c->algorithm_mac == SSL_SHA256 &&
                 (evp = EVP_get_cipherbyname("AES-256-CBC-HMAC-SHA256")))
            *enc = evp, *md = NULL;
        return (1);
    } else
        return (0);
}

const EVP_MD *ssl_md(int idx)
{
    idx &= SSL_HANDSHAKE_MAC_MASK;
    if (idx < 0 || idx >= SSL_MD_NUM_IDX)
        return NULL;
    return ssl_digest_methods[idx];
}

const EVP_MD *ssl_handshake_md(SSL *s)
{
    return ssl_md(ssl_get_algorithm2(s));
}

const EVP_MD *ssl_prf_md(SSL *s)
{
    return ssl_md(ssl_get_algorithm2(s) >> TLS1_PRF_DGST_SHIFT);
}

#define ITEM_SEP(a) \
        (((a) == ':') || ((a) == ' ') || ((a) == ';') || ((a) == ','))

static void ll_append_tail(CIPHER_ORDER **head, CIPHER_ORDER *curr,
                           CIPHER_ORDER **tail)
{
    if (curr == *tail)
        return;
    if (curr == *head)
        *head = curr->next;
    if (curr->prev != NULL)
        curr->prev->next = curr->next;
    if (curr->next != NULL)
        curr->next->prev = curr->prev;
    (*tail)->next = curr;
    curr->prev = *tail;
    curr->next = NULL;
    *tail = curr;
}

static void ll_append_head(CIPHER_ORDER **head, CIPHER_ORDER *curr,
                           CIPHER_ORDER **tail)
{
    if (curr == *head)
        return;
    if (curr == *tail)
        *tail = curr->prev;
    if (curr->next != NULL)
        curr->next->prev = curr->prev;
    if (curr->prev != NULL)
        curr->prev->next = curr->next;
    (*head)->prev = curr;
    curr->next = *head;
    curr->prev = NULL;
    *head = curr;
}

static void ssl_cipher_collect_ciphers(const SSL_METHOD *ssl_method,
                                       int num_of_ciphers,
                                       uint32_t disabled_mkey,
                                       uint32_t disabled_auth,
                                       uint32_t disabled_enc,
                                       uint32_t disabled_mac,
                                       uint32_t disabled_ssl,
                                       CIPHER_ORDER *co_list,
                                       CIPHER_ORDER **head_p,
                                       CIPHER_ORDER **tail_p)
{
    int i, co_list_num;
    const SSL_CIPHER *c;

    /*
     * We have num_of_ciphers descriptions compiled in, depending on the
     * method selected (SSLv3, TLSv1 etc).
     * These will later be sorted in a linked list with at most num
     * entries.
     */

    /* Get the initial list of ciphers */
    co_list_num = 0;            /* actual count of ciphers */
    for (i = 0; i < num_of_ciphers; i++) {
        c = ssl_method->get_cipher(i);
        /* drop those that use any of that is not available */
        if ((c != NULL) && c->valid &&
            (!FIPS_mode() || (c->algo_strength & SSL_FIPS)) &&
            !(c->algorithm_mkey & disabled_mkey) &&
            !(c->algorithm_auth & disabled_auth) &&
            !(c->algorithm_enc & disabled_enc) &&
            !(c->algorithm_mac & disabled_mac) &&
            !(c->algorithm_ssl & disabled_ssl)) {
            co_list[co_list_num].cipher = c;
            co_list[co_list_num].next = NULL;
            co_list[co_list_num].prev = NULL;
            co_list[co_list_num].active = 0;
            co_list_num++;
            /*
             * if (!sk_push(ca_list,(char *)c)) goto err;
             */
        }
    }

    /*
     * Prepare linked list from list entries
     */
    if (co_list_num > 0) {
        co_list[0].prev = NULL;

        if (co_list_num > 1) {
            co_list[0].next = &co_list[1];

            for (i = 1; i < co_list_num - 1; i++) {
                co_list[i].prev = &co_list[i - 1];
                co_list[i].next = &co_list[i + 1];
            }

            co_list[co_list_num - 1].prev = &co_list[co_list_num - 2];
        }

        co_list[co_list_num - 1].next = NULL;

        *head_p = &co_list[0];
        *tail_p = &co_list[co_list_num - 1];
    }
}

static void ssl_cipher_collect_aliases(const SSL_CIPHER **ca_list,
                                       int num_of_group_aliases,
                                       uint32_t disabled_mkey,
                                       uint32_t disabled_auth,
                                       uint32_t disabled_enc,
                                       uint32_t disabled_mac,
                                       uint32_t disabled_ssl,
                                       CIPHER_ORDER *head)
{
    CIPHER_ORDER *ciph_curr;
    const SSL_CIPHER **ca_curr;
    int i;
    uint32_t mask_mkey = ~disabled_mkey;
    uint32_t mask_auth = ~disabled_auth;
    uint32_t mask_enc = ~disabled_enc;
    uint32_t mask_mac = ~disabled_mac;
    uint32_t mask_ssl = ~disabled_ssl;

    /*
     * First, add the real ciphers as already collected
     */
    ciph_curr = head;
    ca_curr = ca_list;
    while (ciph_curr != NULL) {
        *ca_curr = ciph_curr->cipher;
        ca_curr++;
        ciph_curr = ciph_curr->next;
    }

    /*
     * Now we add the available ones from the cipher_aliases[] table.
     * They represent either one or more algorithms, some of which
     * in any affected category must be supported (set in enabled_mask),
     * or represent a cipher strength value (will be added in any case because algorithms=0).
     */
    for (i = 0; i < num_of_group_aliases; i++) {
        uint32_t algorithm_mkey = cipher_aliases[i].algorithm_mkey;
        uint32_t algorithm_auth = cipher_aliases[i].algorithm_auth;
        uint32_t algorithm_enc = cipher_aliases[i].algorithm_enc;
        uint32_t algorithm_mac = cipher_aliases[i].algorithm_mac;
        uint32_t algorithm_ssl = cipher_aliases[i].algorithm_ssl;

        if (algorithm_mkey)
            if ((algorithm_mkey & mask_mkey) == 0)
                continue;

        if (algorithm_auth)
            if ((algorithm_auth & mask_auth) == 0)
                continue;

        if (algorithm_enc)
            if ((algorithm_enc & mask_enc) == 0)
                continue;

        if (algorithm_mac)
            if ((algorithm_mac & mask_mac) == 0)
                continue;

        if (algorithm_ssl)
            if ((algorithm_ssl & mask_ssl) == 0)
                continue;

        *ca_curr = (SSL_CIPHER *)(cipher_aliases + i);
        ca_curr++;
    }

    *ca_curr = NULL;            /* end of list */
}

static void ssl_cipher_apply_rule(uint32_t cipher_id, uint32_t alg_mkey,
                                  uint32_t alg_auth, uint32_t alg_enc,
                                  uint32_t alg_mac, uint32_t alg_ssl,
                                  uint32_t algo_strength, int rule,
                                  int32_t strength_bits, CIPHER_ORDER **head_p,
                                  CIPHER_ORDER **tail_p)
{
    CIPHER_ORDER *head, *tail, *curr, *next, *last;
    const SSL_CIPHER *cp;
    int reverse = 0;

#ifdef CIPHER_DEBUG
    fprintf(stderr,
            "Applying rule %d with %08x/%08x/%08x/%08x/%08x %08x (%d)\n",
            rule, alg_mkey, alg_auth, alg_enc, alg_mac, alg_ssl,
            algo_strength, strength_bits);
#endif

    if (rule == CIPHER_DEL)
        reverse = 1;            /* needed to maintain sorting between
                                 * currently deleted ciphers */

    head = *head_p;
    tail = *tail_p;

    if (reverse) {
        next = tail;
        last = head;
    } else {
        next = head;
        last = tail;
    }

    curr = NULL;
    for (;;) {
        if (curr == last)
            break;

        curr = next;

        if (curr == NULL)
            break;

        next = reverse ? curr->prev : curr->next;

        cp = curr->cipher;

        /*
         * Selection criteria is either the value of strength_bits
         * or the algorithms used.
         */
        if (strength_bits >= 0) {
            if (strength_bits != cp->strength_bits)
                continue;
        } else {
#ifdef CIPHER_DEBUG
            fprintf(stderr,
                    "\nName: %s:\nAlgo = %08x/%08x/%08x/%08x/%08x Algo_strength = %08x\n",
                    cp->name, cp->algorithm_mkey, cp->algorithm_auth,
                    cp->algorithm_enc, cp->algorithm_mac, cp->algorithm_ssl,
                    cp->algo_strength);
#endif
            if (alg_mkey && !(alg_mkey & cp->algorithm_mkey))
                continue;
            if (alg_auth && !(alg_auth & cp->algorithm_auth))
                continue;
            if (alg_enc && !(alg_enc & cp->algorithm_enc))
                continue;
            if (alg_mac && !(alg_mac & cp->algorithm_mac))
                continue;
            if (alg_ssl && !(alg_ssl & cp->algorithm_ssl))
                continue;
            if (algo_strength && !(algo_strength & cp->algo_strength))
                continue;
            if ((algo_strength & SSL_DEFAULT_MASK)
                && !(algo_strength & SSL_DEFAULT_MASK & cp->algo_strength))
                continue;
        }

#ifdef CIPHER_DEBUG
        fprintf(stderr, "Action = %d\n", rule);
#endif

        /* add the cipher if it has not been added yet. */
        if (rule == CIPHER_ADD) {
            /* reverse == 0 */
            if (!curr->active) {
                ll_append_tail(&head, curr, &tail);
                curr->active = 1;
            }
        }
        /* Move the added cipher to this location */
        else if (rule == CIPHER_ORD) {
            /* reverse == 0 */
            if (curr->active) {
                ll_append_tail(&head, curr, &tail);
            }
        } else if (rule == CIPHER_DEL) {
            /* reverse == 1 */
            if (curr->active) {
                /*
                 * most recently deleted ciphersuites get best positions for
                 * any future CIPHER_ADD (note that the CIPHER_DEL loop works
                 * in reverse to maintain the order)
                 */
                ll_append_head(&head, curr, &tail);
                curr->active = 0;
            }
        } else if (rule == CIPHER_KILL) {
            /* reverse == 0 */
            if (head == curr)
                head = curr->next;
            else
                curr->prev->next = curr->next;
            if (tail == curr)
                tail = curr->prev;
            curr->active = 0;
            if (curr->next != NULL)
                curr->next->prev = curr->prev;
            if (curr->prev != NULL)
                curr->prev->next = curr->next;
            curr->next = NULL;
            curr->prev = NULL;
        }
    }

    *head_p = head;
    *tail_p = tail;
}

static int ssl_cipher_strength_sort(CIPHER_ORDER **head_p,
                                    CIPHER_ORDER **tail_p)
{
    int32_t max_strength_bits;
    int i, *number_uses;
    CIPHER_ORDER *curr;

    /*
     * This routine sorts the ciphers with descending strength. The sorting
     * must keep the pre-sorted sequence, so we apply the normal sorting
     * routine as '+' movement to the end of the list.
     */
    max_strength_bits = 0;
    curr = *head_p;
    while (curr != NULL) {
        if (curr->active && (curr->cipher->strength_bits > max_strength_bits))
            max_strength_bits = curr->cipher->strength_bits;
        curr = curr->next;
    }

    number_uses = OPENSSL_zalloc(sizeof(int) * (max_strength_bits + 1));
    if (number_uses == NULL) {
        SSLerr(SSL_F_SSL_CIPHER_STRENGTH_SORT, ERR_R_MALLOC_FAILURE);
        return (0);
    }

    /*
     * Now find the strength_bits values actually used
     */
    curr = *head_p;
    while (curr != NULL) {
        if (curr->active)
            number_uses[curr->cipher->strength_bits]++;
        curr = curr->next;
    }
    /*
     * Go through the list of used strength_bits values in descending
     * order.
     */
    for (i = max_strength_bits; i >= 0; i--)
        if (number_uses[i] > 0)
            ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ORD, i, head_p,
                                  tail_p);

    OPENSSL_free(number_uses);
    return (1);
}

static int ssl_cipher_process_rulestr(const char *rule_str,
                                      CIPHER_ORDER **head_p,
                                      CIPHER_ORDER **tail_p,
                                      const SSL_CIPHER **ca_list, CERT *c)
{
    uint32_t alg_mkey, alg_auth, alg_enc, alg_mac, alg_ssl, algo_strength;
    const char *l, *buf;
    int j, multi, found, rule, retval, ok, buflen;
    uint32_t cipher_id = 0;
    char ch;

    retval = 1;
    l = rule_str;
    for (;;) {
        ch = *l;

        if (ch == '\0')
            break;              /* done */
        if (ch == '-') {
            rule = CIPHER_DEL;
            l++;
        } else if (ch == '+') {
            rule = CIPHER_ORD;
            l++;
        } else if (ch == '!') {
            rule = CIPHER_KILL;
            l++;
        } else if (ch == '@') {
            rule = CIPHER_SPECIAL;
            l++;
        } else {
            rule = CIPHER_ADD;
        }

        if (ITEM_SEP(ch)) {
            l++;
            continue;
        }

        alg_mkey = 0;
        alg_auth = 0;
        alg_enc = 0;
        alg_mac = 0;
        alg_ssl = 0;
        algo_strength = 0;

        for (;;) {
            ch = *l;
            buf = l;
            buflen = 0;
#ifndef CHARSET_EBCDIC
            while (((ch >= 'A') && (ch <= 'Z')) ||
                   ((ch >= '0') && (ch <= '9')) ||
                   ((ch >= 'a') && (ch <= 'z')) ||
                   (ch == '-') || (ch == '.') || (ch == '='))
#else
            while (isalnum(ch) || (ch == '-') || (ch == '.') || (ch == '='))
#endif
            {
                ch = *(++l);
                buflen++;
            }

            if (buflen == 0) {
                /*
                 * We hit something we cannot deal with,
                 * it is no command or separator nor
                 * alphanumeric, so we call this an error.
                 */
                SSLerr(SSL_F_SSL_CIPHER_PROCESS_RULESTR,
                       SSL_R_INVALID_COMMAND);
                retval = found = 0;
                l++;
                break;
            }

            if (rule == CIPHER_SPECIAL) {
                found = 0;      /* unused -- avoid compiler warning */
                break;          /* special treatment */
            }

            /* check for multi-part specification */
            if (ch == '+') {
                multi = 1;
                l++;
            } else
                multi = 0;

            /*
             * Now search for the cipher alias in the ca_list. Be careful
             * with the strncmp, because the "buflen" limitation
             * will make the rule "ADH:SOME" and the cipher
             * "ADH-MY-CIPHER" look like a match for buflen=3.
             * So additionally check whether the cipher name found
             * has the correct length. We can save a strlen() call:
             * just checking for the '\0' at the right place is
             * sufficient, we have to strncmp() anyway. (We cannot
             * use strcmp(), because buf is not '\0' terminated.)
             */
            j = found = 0;
            cipher_id = 0;
            while (ca_list[j]) {
                if (strncmp(buf, ca_list[j]->name, buflen) == 0
                    && (ca_list[j]->name[buflen] == '\0')) {
                    found = 1;
                    break;
                } else
                    j++;
            }

            if (!found)
                break;          /* ignore this entry */

            if (ca_list[j]->algorithm_mkey) {
                if (alg_mkey) {
                    alg_mkey &= ca_list[j]->algorithm_mkey;
                    if (!alg_mkey) {
                        found = 0;
                        break;
                    }
                } else
                    alg_mkey = ca_list[j]->algorithm_mkey;
            }

            if (ca_list[j]->algorithm_auth) {
                if (alg_auth) {
                    alg_auth &= ca_list[j]->algorithm_auth;
                    if (!alg_auth) {
                        found = 0;
                        break;
                    }
                } else
                    alg_auth = ca_list[j]->algorithm_auth;
            }

            if (ca_list[j]->algorithm_enc) {
                if (alg_enc) {
                    alg_enc &= ca_list[j]->algorithm_enc;
                    if (!alg_enc) {
                        found = 0;
                        break;
                    }
                } else
                    alg_enc = ca_list[j]->algorithm_enc;
            }

            if (ca_list[j]->algorithm_mac) {
                if (alg_mac) {
                    alg_mac &= ca_list[j]->algorithm_mac;
                    if (!alg_mac) {
                        found = 0;
                        break;
                    }
                } else
                    alg_mac = ca_list[j]->algorithm_mac;
            }

            if (ca_list[j]->algo_strength) {
                if (algo_strength) {
                    algo_strength &= ca_list[j]->algo_strength;
                    if (!algo_strength) {
                        found = 0;
                        break;
                    }
                } else
                    algo_strength = ca_list[j]->algo_strength;
            }

            if (ca_list[j]->algo_strength & SSL_DEFAULT_MASK) {
                if (algo_strength & SSL_DEFAULT_MASK) {
                    algo_strength &=
                        (ca_list[j]->algo_strength & SSL_DEFAULT_MASK) |
                        ~SSL_DEFAULT_MASK;
                    if (!(algo_strength & SSL_DEFAULT_MASK)) {
                        found = 0;
                        break;
                    }
                } else
                    algo_strength |=
                        ca_list[j]->algo_strength & SSL_DEFAULT_MASK;
            }

            if (ca_list[j]->valid) {
                /*
                 * explicit ciphersuite found; its protocol version does not
                 * become part of the search pattern!
                 */

                cipher_id = ca_list[j]->id;
            } else {
                /*
                 * not an explicit ciphersuite; only in this case, the
                 * protocol version is considered part of the search pattern
                 */

                if (ca_list[j]->algorithm_ssl) {
                    if (alg_ssl) {
                        alg_ssl &= ca_list[j]->algorithm_ssl;
                        if (!alg_ssl) {
                            found = 0;
                            break;
                        }
                    } else
                        alg_ssl = ca_list[j]->algorithm_ssl;
                }
            }

            if (!multi)
                break;
        }

        /*
         * Ok, we have the rule, now apply it
         */
        if (rule == CIPHER_SPECIAL) { /* special command */
            ok = 0;
            if ((buflen == 8) && strncmp(buf, "STRENGTH", 8) == 0)
                ok = ssl_cipher_strength_sort(head_p, tail_p);
            else if (buflen == 10 && strncmp(buf, "SECLEVEL=", 9) == 0) {
                int level = buf[9] - '0';
                if (level < 0 || level > 5) {
                    SSLerr(SSL_F_SSL_CIPHER_PROCESS_RULESTR,
                           SSL_R_INVALID_COMMAND);
                } else {
                    c->sec_level = level;
                    ok = 1;
                }
            } else
                SSLerr(SSL_F_SSL_CIPHER_PROCESS_RULESTR,
                       SSL_R_INVALID_COMMAND);
            if (ok == 0)
                retval = 0;
            /*
             * We do not support any "multi" options
             * together with "@", so throw away the
             * rest of the command, if any left, until
             * end or ':' is found.
             */
            while ((*l != '\0') && !ITEM_SEP(*l))
                l++;
        } else if (found) {
            ssl_cipher_apply_rule(cipher_id,
                                  alg_mkey, alg_auth, alg_enc, alg_mac,
                                  alg_ssl, algo_strength, rule, -1, head_p,
                                  tail_p);
        } else {
            while ((*l != '\0') && !ITEM_SEP(*l))
                l++;
        }
        if (*l == '\0')
            break;              /* done */
    }

    return (retval);
}

#ifndef OPENSSL_NO_EC
static int check_suiteb_cipher_list(const SSL_METHOD *meth, CERT *c,
                                    const char **prule_str)
{
    unsigned int suiteb_flags = 0, suiteb_comb2 = 0;
    if (strncmp(*prule_str, "SUITEB128ONLY", 13) == 0) {
        suiteb_flags = SSL_CERT_FLAG_SUITEB_128_LOS_ONLY;
    } else if (strncmp(*prule_str, "SUITEB128C2", 11) == 0) {
        suiteb_comb2 = 1;
        suiteb_flags = SSL_CERT_FLAG_SUITEB_128_LOS;
    } else if (strncmp(*prule_str, "SUITEB128", 9) == 0) {
        suiteb_flags = SSL_CERT_FLAG_SUITEB_128_LOS;
    } else if (strncmp(*prule_str, "SUITEB192", 9) == 0) {
        suiteb_flags = SSL_CERT_FLAG_SUITEB_192_LOS;
    }

    if (suiteb_flags) {
        c->cert_flags &= ~SSL_CERT_FLAG_SUITEB_128_LOS;
        c->cert_flags |= suiteb_flags;
    } else
        suiteb_flags = c->cert_flags & SSL_CERT_FLAG_SUITEB_128_LOS;

    if (!suiteb_flags)
        return 1;
    /* Check version: if TLS 1.2 ciphers allowed we can use Suite B */

    if (!(meth->ssl3_enc->enc_flags & SSL_ENC_FLAG_TLS1_2_CIPHERS)) {
        SSLerr(SSL_F_CHECK_SUITEB_CIPHER_LIST,
               SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE);
        return 0;
    }
# ifndef OPENSSL_NO_EC
    switch (suiteb_flags) {
    case SSL_CERT_FLAG_SUITEB_128_LOS:
        if (suiteb_comb2)
            *prule_str = "ECDHE-ECDSA-AES256-GCM-SHA384";
        else
            *prule_str =
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384";
        break;
    case SSL_CERT_FLAG_SUITEB_128_LOS_ONLY:
        *prule_str = "ECDHE-ECDSA-AES128-GCM-SHA256";
        break;
    case SSL_CERT_FLAG_SUITEB_192_LOS:
        *prule_str = "ECDHE-ECDSA-AES256-GCM-SHA384";
        break;
    }
    return 1;
# else
    SSLerr(SSL_F_CHECK_SUITEB_CIPHER_LIST,
           SSL_R_ECDH_REQUIRED_FOR_SUITEB_MODE);
    return 0;
# endif
}
#endif

STACK_OF(SSL_CIPHER) *ssl_create_cipher_list(const SSL_METHOD *ssl_method, STACK_OF(SSL_CIPHER)
                                             **cipher_list, STACK_OF(SSL_CIPHER)
                                             **cipher_list_by_id,
                                             const char *rule_str, CERT *c)
{
    int ok, num_of_ciphers, num_of_alias_max, num_of_group_aliases;
    uint32_t disabled_mkey, disabled_auth, disabled_enc, disabled_mac,
        disabled_ssl;
    STACK_OF(SSL_CIPHER) *cipherstack, *tmp_cipher_list;
    const char *rule_p;
    CIPHER_ORDER *co_list = NULL, *head = NULL, *tail = NULL, *curr;
    const SSL_CIPHER **ca_list = NULL;

    /*
     * Return with error if nothing to do.
     */
    if (rule_str == NULL || cipher_list == NULL || cipher_list_by_id == NULL)
        return NULL;
#ifndef OPENSSL_NO_EC
    if (!check_suiteb_cipher_list(ssl_method, c, &rule_str))
        return NULL;
#endif

    /*
     * To reduce the work to do we only want to process the compiled
     * in algorithms, so we first get the mask of disabled ciphers.
     */

    disabled_mkey = disabled_mkey_mask;
    disabled_auth = disabled_auth_mask;
    disabled_enc = disabled_enc_mask;
    disabled_mac = disabled_mac_mask;
    disabled_ssl = 0;

    /*
     * Now we have to collect the available ciphers from the compiled
     * in ciphers. We cannot get more than the number compiled in, so
     * it is used for allocation.
     */
    num_of_ciphers = ssl_method->num_ciphers();

    co_list = OPENSSL_malloc(sizeof(*co_list) * num_of_ciphers);
    if (co_list == NULL) {
        SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
        return (NULL);          /* Failure */
    }

    ssl_cipher_collect_ciphers(ssl_method, num_of_ciphers,
                               disabled_mkey, disabled_auth, disabled_enc,
                               disabled_mac, disabled_ssl, co_list, &head,
                               &tail);

    /* Now arrange all ciphers by preference: */

    /*
     * Everything else being equal, prefer ephemeral ECDH over other key
     * exchange mechanisms
     */
    ssl_cipher_apply_rule(0, SSL_kECDHE, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head,
                          &tail);
    ssl_cipher_apply_rule(0, SSL_kECDHE, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head,
                          &tail);

    /* AES is our preferred symmetric cipher */
    ssl_cipher_apply_rule(0, 0, 0, SSL_AES, 0, 0, 0, CIPHER_ADD, -1, &head,
                          &tail);

    /* Temporarily enable everything else for sorting */
    ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head, &tail);

    /* Low priority for MD5 */
    ssl_cipher_apply_rule(0, 0, 0, 0, SSL_MD5, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /*
     * Move anonymous ciphers to the end.  Usually, these will remain
     * disabled. (For applications that allow them, they aren't too bad, but
     * we prefer authenticated ciphers.)
     */
    ssl_cipher_apply_rule(0, 0, SSL_aNULL, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /*
     * ssl_cipher_apply_rule(0, 0, SSL_aDH, 0, 0, 0, 0, CIPHER_ORD, -1,
     * &head, &tail);
     */
    ssl_cipher_apply_rule(0, SSL_kRSA, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);
    ssl_cipher_apply_rule(0, SSL_kPSK, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /* RC4 is sort-of broken -- move the the end */
    ssl_cipher_apply_rule(0, 0, 0, SSL_RC4, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /*
     * Now sort by symmetric encryption strength.  The above ordering remains
     * in force within each class
     */
    if (!ssl_cipher_strength_sort(&head, &tail)) {
        OPENSSL_free(co_list);
        return NULL;
    }

    /* Now disable everything (maintaining the ordering!) */
    ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head, &tail);

    /*
     * We also need cipher aliases for selecting based on the rule_str.
     * There might be two types of entries in the rule_str: 1) names
     * of ciphers themselves 2) aliases for groups of ciphers.
     * For 1) we need the available ciphers and for 2) the cipher
     * groups of cipher_aliases added together in one list (otherwise
     * we would be happy with just the cipher_aliases table).
     */
    num_of_group_aliases = OSSL_NELEM(cipher_aliases);
    num_of_alias_max = num_of_ciphers + num_of_group_aliases + 1;
    ca_list = OPENSSL_malloc(sizeof(*ca_list) * num_of_alias_max);
    if (ca_list == NULL) {
        OPENSSL_free(co_list);
        SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
        return (NULL);          /* Failure */
    }
    ssl_cipher_collect_aliases(ca_list, num_of_group_aliases,
                               disabled_mkey, disabled_auth, disabled_enc,
                               disabled_mac, disabled_ssl, head);

    /*
     * If the rule_string begins with DEFAULT, apply the default rule
     * before using the (possibly available) additional rules.
     */
    ok = 1;
    rule_p = rule_str;
    if (strncmp(rule_str, "DEFAULT", 7) == 0) {
        ok = ssl_cipher_process_rulestr(SSL_DEFAULT_CIPHER_LIST,
                                        &head, &tail, ca_list, c);
        rule_p += 7;
        if (*rule_p == ':')
            rule_p++;
    }

    if (ok && (strlen(rule_p) > 0))
        ok = ssl_cipher_process_rulestr(rule_p, &head, &tail, ca_list, c);

    OPENSSL_free(ca_list); /* Not needed anymore */

    if (!ok) {                  /* Rule processing failure */
        OPENSSL_free(co_list);
        return (NULL);
    }

    /*
     * Allocate new "cipherstack" for the result, return with error
     * if we cannot get one.
     */
    if ((cipherstack = sk_SSL_CIPHER_new_null()) == NULL) {
        OPENSSL_free(co_list);
        return (NULL);
    }

    /*
     * The cipher selection for the list is done. The ciphers are added
     * to the resulting precedence to the STACK_OF(SSL_CIPHER).
     */
    for (curr = head; curr != NULL; curr = curr->next) {
        if (curr->active
            && (!FIPS_mode() || curr->cipher->algo_strength & SSL_FIPS)) {
            if (!sk_SSL_CIPHER_push(cipherstack, curr->cipher)) {
                OPENSSL_free(co_list);
                sk_SSL_CIPHER_free(cipherstack);
                return NULL;
            }
#ifdef CIPHER_DEBUG
            fprintf(stderr, "<%s>\n", curr->cipher->name);
#endif
        }
    }
    OPENSSL_free(co_list);      /* Not needed any longer */

    tmp_cipher_list = sk_SSL_CIPHER_dup(cipherstack);
    if (tmp_cipher_list == NULL) {
        sk_SSL_CIPHER_free(cipherstack);
        return NULL;
    }
    sk_SSL_CIPHER_free(*cipher_list);
    *cipher_list = cipherstack;
    if (*cipher_list_by_id != NULL)
        sk_SSL_CIPHER_free(*cipher_list_by_id);
    *cipher_list_by_id = tmp_cipher_list;
    (void)sk_SSL_CIPHER_set_cmp_func(*cipher_list_by_id,
                                     ssl_cipher_ptr_id_cmp);

    sk_SSL_CIPHER_sort(*cipher_list_by_id);
    return (cipherstack);
}

char *SSL_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int len)
{
    const char *ver;
    const char *kx, *au, *enc, *mac;
    uint32_t alg_mkey, alg_auth, alg_enc, alg_mac;
    static const char *format =
        "%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s\n";

    if (buf == NULL) {
        len = 128;
        buf = OPENSSL_malloc(len);
        if (buf == NULL)
            return NULL;
    } else if (len < 128)
        return NULL;

    alg_mkey = cipher->algorithm_mkey;
    alg_auth = cipher->algorithm_auth;
    alg_enc = cipher->algorithm_enc;
    alg_mac = cipher->algorithm_mac;

    ver = SSL_CIPHER_get_version(cipher);

    switch (alg_mkey) {
    case SSL_kRSA:
        kx = "RSA";
        break;
    case SSL_kDHE:
        kx = "DH";
        break;
    case SSL_kECDHE:
        kx = "ECDH";
        break;
    case SSL_kPSK:
        kx = "PSK";
        break;
    case SSL_kRSAPSK:
        kx = "RSAPSK";
        break;
    case SSL_kECDHEPSK:
        kx = "ECDHEPSK";
        break;
    case SSL_kDHEPSK:
        kx = "DHEPSK";
        break;
    case SSL_kSRP:
        kx = "SRP";
        break;
    case SSL_kGOST:
        kx = "GOST";
        break;
    default:
        kx = "unknown";
    }

    switch (alg_auth) {
    case SSL_aRSA:
        au = "RSA";
        break;
    case SSL_aDSS:
        au = "DSS";
        break;
    case SSL_aNULL:
        au = "None";
        break;
    case SSL_aECDSA:
        au = "ECDSA";
        break;
    case SSL_aPSK:
        au = "PSK";
        break;
    case SSL_aSRP:
        au = "SRP";
        break;
    case SSL_aGOST01:
        au = "GOST01";
        break;
        /* New GOST ciphersuites have both SSL_aGOST12 and SSL_aGOST01 bits */
    case (SSL_aGOST12 | SSL_aGOST01):
        au = "GOST12";
        break;
    default:
        au = "unknown";
        break;
    }

    switch (alg_enc) {
    case SSL_DES:
        enc = "DES(56)";
        break;
    case SSL_3DES:
        enc = "3DES(168)";
        break;
    case SSL_RC4:
        enc = "RC4(128)";
        break;
    case SSL_RC2:
        enc = "RC2(128)";
        break;
    case SSL_IDEA:
        enc = "IDEA(128)";
        break;
    case SSL_eNULL:
        enc = "None";
        break;
    case SSL_AES128:
        enc = "AES(128)";
        break;
    case SSL_AES256:
        enc = "AES(256)";
        break;
    case SSL_AES128GCM:
        enc = "AESGCM(128)";
        break;
    case SSL_AES256GCM:
        enc = "AESGCM(256)";
        break;
    case SSL_AES128CCM:
        enc = "AESCCM(128)";
        break;
    case SSL_AES256CCM:
        enc = "AESCCM(256)";
        break;
    case SSL_AES128CCM8:
        enc = "AESCCM8(128)";
        break;
    case SSL_AES256CCM8:
        enc = "AESCCM8(256)";
        break;
    case SSL_CAMELLIA128:
        enc = "Camellia(128)";
        break;
    case SSL_CAMELLIA256:
        enc = "Camellia(256)";
        break;
    case SSL_SEED:
        enc = "SEED(128)";
        break;
    case SSL_eGOST2814789CNT:
    case SSL_eGOST2814789CNT12:
        enc = "GOST89(256)";
        break;
    case SSL_CHACHA20POLY1305:
        enc = "CHACHA20/POLY1305(256)";
        break;
    default:
        enc = "unknown";
        break;
    }

    switch (alg_mac) {
    case SSL_MD5:
        mac = "MD5";
        break;
    case SSL_SHA1:
        mac = "SHA1";
        break;
    case SSL_SHA256:
        mac = "SHA256";
        break;
    case SSL_SHA384:
        mac = "SHA384";
        break;
    case SSL_AEAD:
        mac = "AEAD";
        break;
    case SSL_GOST89MAC:
    case SSL_GOST89MAC12:
        mac = "GOST89";
        break;
    case SSL_GOST94:
        mac = "GOST94";
        break;
    case SSL_GOST12_256:
    case SSL_GOST12_512:
        mac = "GOST2012";
        break;
    default:
        mac = "unknown";
        break;
    }

    BIO_snprintf(buf, len, format, cipher->name, ver, kx, au, enc, mac);

    return (buf);
}

char *SSL_CIPHER_get_version(const SSL_CIPHER *c)
{
    uint32_t alg_ssl;

    if (c == NULL)
        return "(NONE)";
    alg_ssl = c->algorithm_ssl;

    if (alg_ssl & SSL_SSLV3)
        return "SSLv3";
    if (alg_ssl & SSL_TLSV1)
        return "TLSv1.0";
    if (alg_ssl & SSL_TLSV1_2)
        return "TLSv1.2";
    return "unknown";
}

/* return the actual cipher being used */
const char *SSL_CIPHER_get_name(const SSL_CIPHER *c)
{
    if (c != NULL)
        return (c->name);
    return ("(NONE)");
}

/* number of bits for symmetric cipher */
int SSL_CIPHER_get_bits(const SSL_CIPHER *c, int *alg_bits)
{
    int ret = 0;

    if (c != NULL) {
        if (alg_bits != NULL)
            *alg_bits = (int) c->alg_bits;
        ret = (int) c->strength_bits;
    }
    return ret;
}

uint32_t SSL_CIPHER_get_id(const SSL_CIPHER *c)
{
    return c->id;
}

SSL_COMP *ssl3_comp_find(STACK_OF(SSL_COMP) *sk, int n)
{
    SSL_COMP *ctmp;
    int i, nn;

    if ((n == 0) || (sk == NULL))
        return (NULL);
    nn = sk_SSL_COMP_num(sk);
    for (i = 0; i < nn; i++) {
        ctmp = sk_SSL_COMP_value(sk, i);
        if (ctmp->id == n)
            return (ctmp);
    }
    return (NULL);
}

#ifdef OPENSSL_NO_COMP
STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void)
{
    return NULL;
}
STACK_OF(SSL_COMP) *SSL_COMP_set0_compression_methods(STACK_OF(SSL_COMP)
                                                      *meths)
{
    return meths;
}
void SSL_COMP_free_compression_methods(void)
{
}
int SSL_COMP_add_compression_method(int id, COMP_METHOD *cm)
{
    return 1;
}

#else
STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void)
{
    load_builtin_compressions();
    return (ssl_comp_methods);
}

STACK_OF(SSL_COMP) *SSL_COMP_set0_compression_methods(STACK_OF(SSL_COMP)
                                                      *meths)
{
    STACK_OF(SSL_COMP) *old_meths = ssl_comp_methods;
    ssl_comp_methods = meths;
    return old_meths;
}

static void cmeth_free(SSL_COMP *cm)
{
    OPENSSL_free(cm);
}

void SSL_COMP_free_compression_methods(void)
{
    STACK_OF(SSL_COMP) *old_meths = ssl_comp_methods;
    ssl_comp_methods = NULL;
    sk_SSL_COMP_pop_free(old_meths, cmeth_free);
}

int SSL_COMP_add_compression_method(int id, COMP_METHOD *cm)
{
    SSL_COMP *comp;

    if (cm == NULL || COMP_get_type(cm) == NID_undef)
        return 1;

    /*-
     * According to draft-ietf-tls-compression-04.txt, the
     * compression number ranges should be the following:
     *
     *   0 to  63:  methods defined by the IETF
     *  64 to 192:  external party methods assigned by IANA
     * 193 to 255:  reserved for private use
     */
    if (id < 193 || id > 255) {
        SSLerr(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD,
               SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE);
        return 0;
    }

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
    comp = OPENSSL_malloc(sizeof(*comp));
    if (comp == NULL) {
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
        SSLerr(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD, ERR_R_MALLOC_FAILURE);
        return (1);
    }

    comp->id = id;
    comp->method = cm;
    load_builtin_compressions();
    if (ssl_comp_methods && sk_SSL_COMP_find(ssl_comp_methods, comp) >= 0) {
        OPENSSL_free(comp);
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
        SSLerr(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD,
               SSL_R_DUPLICATE_COMPRESSION_ID);
        return (1);
    }
    if ((ssl_comp_methods == NULL)
               || !sk_SSL_COMP_push(ssl_comp_methods, comp)) {
        OPENSSL_free(comp);
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
        SSLerr(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD, ERR_R_MALLOC_FAILURE);
        return (1);
    }
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
    return (0);
}
#endif

const char *SSL_COMP_get_name(const COMP_METHOD *comp)
{
#ifndef OPENSSL_NO_COMP
    return comp ? COMP_get_name(comp) : NULL;
#else
    return NULL;
#endif
}

/* For a cipher return the index corresponding to the certificate type */
int ssl_cipher_get_cert_index(const SSL_CIPHER *c)
{
    uint32_t alg_a;

    alg_a = c->algorithm_auth;

    if (alg_a & SSL_aECDSA)
        return SSL_PKEY_ECC;
    else if (alg_a & SSL_aDSS)
        return SSL_PKEY_DSA_SIGN;
    else if (alg_a & SSL_aRSA)
        return SSL_PKEY_RSA_ENC;
    else if (alg_a & SSL_aGOST12)
        return SSL_PKEY_GOST_EC;
    else if (alg_a & SSL_aGOST01)
        return SSL_PKEY_GOST01;

    return -1;
}

const SSL_CIPHER *ssl_get_cipher_by_char(SSL *ssl, const unsigned char *ptr)
{
    const SSL_CIPHER *c;
    c = ssl->method->get_cipher_by_char(ptr);
    if (c == NULL || c->valid == 0)
        return NULL;
    return c;
}

const SSL_CIPHER *SSL_CIPHER_find(SSL *ssl, const unsigned char *ptr)
{
    return ssl->method->get_cipher_by_char(ptr);
}

int SSL_CIPHER_get_cipher_nid(const SSL_CIPHER *c)
{
    int i;
    if (c == NULL)
        return -1;
    i = ssl_cipher_info_lookup(ssl_cipher_table_cipher, c->algorithm_enc);
    if (i == -1)
        return -1;
    return ssl_cipher_table_cipher[i].nid;
}

int SSL_CIPHER_get_digest_nid(const SSL_CIPHER *c)
{
    int i;
    if (c == NULL)
        return -1;
    i = ssl_cipher_info_lookup(ssl_cipher_table_mac, c->algorithm_mac);
    if (i == -1)
        return -1;
    return ssl_cipher_table_mac[i].nid;
}
