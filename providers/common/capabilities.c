/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <string.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
/* For TLS1_VERSION etc */
#include <openssl/ssl.h>
#include <openssl/params.h>
#include "internal/nelem.h"
#include "prov/providercommon.h"

typedef struct tls_group_constants_st {
    unsigned int group_id;   /* Group ID */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
    int mindtls;             /* Minimum DTLS version, -1 unsupported */
    int maxdtls;             /* Maximum DTLS version (or 0 for undefined) */
} TLS_GROUP_CONSTANTS;

static const TLS_GROUP_CONSTANTS group_list[] = {
    { /* sect163k1 */ 0x0001, 80, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect163r1 */ 0x0002, 80, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect163r2 */ 0x0003, 80, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect193r1 */ 0x0004, 80, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect193r2 */ 0x0005, 80, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect233k1 */ 0x0006, 112, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect233r1 */ 0x0007, 112, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect239k1 */ 0x0008, 112, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect283k1 */ 0x0009, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect283r1 */ 0x000A, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect409k1 */ 0x000B, 192, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect409r1 */ 0x000C, 192, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect571k1 */ 0x000D, 256, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* sect571r1 */ 0x000E, 256, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* secp160k1 */ 0x000F, 80, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* secp160r1 */ 0x0010, 80, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* secp160r2 */ 0x0011, 80, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* secp192k1 */ 0x0012, 80, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* secp192r1 */ 0x0013, 80, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* secp224k1 */ 0x0014, 112, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* secp224r1 */ 0x0015, 112, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* secp256k1 */ 0x0016, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* secp256r1 */ 0x0017, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* secp384r1 */ 0x0018, 192, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* secp521r1 */ 0x0019, 256, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* brainpoolP256r1 */ 0x001A, 128, TLS1_VERSION, TLS1_2_VERSION, DTLS1_VERSION, DTLS1_2_VERSION },
    { /* brainpoolP384r1 */ 0x001B, 192, TLS1_VERSION, TLS1_2_VERSION, DTLS1_VERSION, DTLS1_2_VERSION },
    { /* brainpoolP512r1 */ 0x001C, 256, TLS1_VERSION, TLS1_2_VERSION, DTLS1_VERSION, DTLS1_2_VERSION },
    { /* x25519 */ 0x001D, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { /* x448 */ 0x001E, 224, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    /* Security bit values for FFDHE groups are as per RFC 7919 */
    { /* ffdhe2048 */ 0x0100, 103, TLS1_3_VERSION, 0, -1, -1 },
    { /* ffdhe3072 */ 0x0101, 125, TLS1_3_VERSION, 0, -1, -1 },
    { /* ffdhe4096 */ 0x0102, 150, TLS1_3_VERSION, 0, -1, -1 },
    { /* ffdhe6144 */ 0x0103, 175, TLS1_3_VERSION, 0, -1, -1 },
    { /* ffdhe8192 */ 0x0104, 192, TLS1_3_VERSION, 0, -1, -1 },
};

#define TLS_GROUP_ENTRY(tlsname, realname, algorithm, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, \
                               tlsname, \
                               sizeof(tlsname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               realname, \
                               sizeof(realname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                               algorithm, \
                               sizeof(algorithm)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, \
                        (unsigned int *)&group_list[idx].group_id), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, \
                        (unsigned int *)&group_list[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, \
                        (unsigned int *)&group_list[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, \
                        (unsigned int *)&group_list[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, \
                        (unsigned int *)&group_list[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, \
                        (unsigned int *)&group_list[idx].maxdtls), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM param_group_list[][10] = {
#ifndef OPENSSL_NO_EC
    TLS_GROUP_ENTRY("sect163k1", "sect163k1", "EC", 0),
    TLS_GROUP_ENTRY("sect163r1", "sect163r1", "EC", 1),
    TLS_GROUP_ENTRY("sect163r2", "sect163r2", "EC", 2),
    TLS_GROUP_ENTRY("sect193r1", "sect193r1", "EC", 3),
    TLS_GROUP_ENTRY("sect193r2", "sect193r2", "EC", 4),
    TLS_GROUP_ENTRY("sect233k1", "sect233k1", "EC", 5),
    TLS_GROUP_ENTRY("sect233r1", "sect233r1", "EC", 6),
    TLS_GROUP_ENTRY("sect239k1", "sect239k1", "EC", 7),
    TLS_GROUP_ENTRY("sect283k1", "sect283k1", "EC", 8),
    TLS_GROUP_ENTRY("sect283r1", "sect283r1", "EC", 9),
    TLS_GROUP_ENTRY("sect409k1", "sect409k1", "EC", 10),
    TLS_GROUP_ENTRY("sect409r1", "sect409r1", "EC", 11),
    TLS_GROUP_ENTRY("sect571k1", "sect571k1", "EC", 12),
    TLS_GROUP_ENTRY("sect571r1", "sect571r1", "EC", 13),
    TLS_GROUP_ENTRY("secp160k1", "secp160k1", "EC", 14),
    TLS_GROUP_ENTRY("secp160r1", "secp160r1", "EC", 15),
    TLS_GROUP_ENTRY("secp160r2", "secp160r2", "EC", 16),
    TLS_GROUP_ENTRY("secp192k1", "secp192k1", "EC", 17),
    TLS_GROUP_ENTRY("secp192r1", "prime192v1", "EC", 18),
    TLS_GROUP_ENTRY("secp224k1", "secp224k1", "EC", 19),
    TLS_GROUP_ENTRY("secp224r1", "secp224r1", "EC", 20),
    TLS_GROUP_ENTRY("secp256k1", "secp256k1", "EC", 21),
    TLS_GROUP_ENTRY("secp256r1", "prime256v1", "EC", 22),
    TLS_GROUP_ENTRY("secp384r1", "secp384r1", "EC", 23),
    TLS_GROUP_ENTRY("secp521r1", "secp521r1", "EC", 24),
# ifndef FIPS_MODULE
    TLS_GROUP_ENTRY("brainpoolP256r1", "brainpoolP256r1", "EC", 25),
    TLS_GROUP_ENTRY("brainpoolP384r1", "brainpoolP384r1", "EC", 26),
    TLS_GROUP_ENTRY("brainpoolP512r1", "brainpoolP512r1", "EC", 27),
# endif
    TLS_GROUP_ENTRY("x25519", "x25519", "X25519", 28),
    TLS_GROUP_ENTRY("x448", "x448", "X448", 29),
#endif /* OPENSSL_NO_EC */
#ifndef OPENSSL_NO_DH
    /* Security bit values for FFDHE groups are as per RFC 7919 */
    TLS_GROUP_ENTRY("ffdhe2048", "ffdhe2048", "DH", 30),
    TLS_GROUP_ENTRY("ffdhe3072", "ffdhe3072", "DH", 31),
    TLS_GROUP_ENTRY("ffdhe4096", "ffdhe4096", "DH", 32),
    TLS_GROUP_ENTRY("ffdhe6144", "ffdhe6144", "DH", 33),
    TLS_GROUP_ENTRY("ffdhe8192", "ffdhe8192", "DH", 34),
#endif
};

static int tls_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_DH) && !defined(FIPS_MODULE)
    assert(OSSL_NELEM(param_group_list) == OSSL_NELEM(group_list));
#endif
    for (i = 0; i < OSSL_NELEM(param_group_list); i++)
        if (!cb(param_group_list[i], arg))
            return 0;

    return 1;
}


int provider_get_capabilities(void *provctx, const char *capability,
                              OSSL_CALLBACK *cb, void *arg)
{
    if (strcmp(capability, "TLS-GROUP") == 0)
        return tls_group_capability(cb, arg);

    /* We don't support this capability */
    return 0;
}
