/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/bn.h>
#include "internal/bn_int.h"
#include "rsa_locl.h"

/*
 * RSA keypair test.
 * Check the Chinese Remainder Theorem components.
 *
 * 6.4.1.2.3: rsakpv1-crt Step 7
 * 6.4.1.3.3: rsakpv2-crt Step 7
 */
int rsa_check_crt_components(const RSA *rsa, BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *r = NULL, *p1 = NULL, *q1 = NULL;

    /* check if only some of the crt components are set */
    if (rsa->dmp1 == NULL || rsa->dmq1 == NULL || rsa->iqmp == NULL) {
        if (rsa->dmp1 != NULL || rsa->dmq1 != NULL || rsa->iqmp != NULL)
            return 0;
        return 1; /* return ok if all components are NULL */
    }

    BN_CTX_start(ctx);
    r = BN_CTX_get(ctx);
    p1 = BN_CTX_get(ctx);
    q1 = BN_CTX_get(ctx);
    ret = (q1 != NULL)
          /* p1 = p -1 */
          && (BN_copy(p1, rsa->p) != NULL)
          && BN_sub_word(p1, 1)
          /* q1 = q - 1 */
          && (BN_copy(q1, rsa->q) != NULL)
          && BN_sub_word(q1, 1)
          /* (a) 1 < dP < (p – 1). */
          && (BN_cmp(rsa->dmp1, BN_value_one()) > 0)
          && (BN_cmp(rsa->dmp1, p1) < 0)
          /* (b) 1 < dQ < (q - 1). */
          && (BN_cmp(rsa->dmq1, BN_value_one()) > 0)
          && (BN_cmp(rsa->dmq1, q1) < 0)
          /* (c) 1 < qInv < p */
          && (BN_cmp(rsa->iqmp, BN_value_one()) > 0)
          && (BN_cmp(rsa->iqmp, rsa->p) < 0)
          /* (d) 1 = (dP . e) mod (p - 1)*/
          && BN_mod_mul(r, rsa->dmp1, rsa->e, p1, ctx)
          && BN_is_one(r)
          /* (e) 1 = (dQ . e) mod (q - 1) */
          && BN_mod_mul(r, rsa->dmq1, rsa->e, q1, ctx)
          && BN_is_one(r)
          /* (f) 1 = (qInv . q) mod p */
          && BN_mod_mul(r, rsa->iqmp, rsa->q, rsa->p, ctx)
          && BN_is_one(r);
    BN_clear(p1);
    BN_clear(q1);
    BN_CTX_end(ctx);
    return ret;
}

/*
 * SP800-5bBr1 6.4.1.2.1 Part 5 (c) & (g) - used for both p and q.
 * Check that (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
 *
 * (√2)(2^(nbits/2 - 1) = (√2/2)(2^(nbits/2))
 * √2/2 = 0.707106781186547524400 = 0.B504F333F9DE6484597D8
 * 0.B504F334 gives an approximation to 11 decimal places.
 * The range is then from
 *   0xB504F334_0000.......................000 to
 *   0xFFFFFFFF_FFFF.......................FFF
 */
int rsa_check_prime_factor_range(const BIGNUM *p, int nbits, BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *tmp, *low;

    nbits >>= 1;

    /* Upper bound check */
    if (BN_num_bits(p) != nbits)
        return 0;

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    low = BN_CTX_get(ctx);

    /* set low = (√2)(2^(nbits/2 - 1) */
    if (low == NULL || !BN_set_word(tmp, 0xB504F334))
        goto err;

    if (nbits >= 32) {
        if (!BN_lshift(low, tmp, nbits - 32))
            goto err;
    }
    else if (!BN_rshift(low, tmp, 32 - nbits)) {
        goto err;
    }
    if (BN_cmp(p, low) < 0)
        goto err;
    ret = 1;
err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Check the prime factor (for either p or q)
 *
 * SP800-5bBr1 6.4.1.2.3 Step 5 (a to d) & (e to h).
 */
int rsa_check_prime_factor(BIGNUM *p, BIGNUM *e, int nbits, BN_CTX *ctx)
{
    int checks = bn_rsa_fips186_4_prime_MR_min_checks(nbits);
    int ret = 0;
    BIGNUM *p1 = NULL, *gcd = NULL;

    /* (Steps 5 a-b) prime test */
    if (BN_is_prime_fasttest_ex(p, checks, ctx, 1, NULL) != 1
            /* (Step 5c) (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2 - 1) */
            || rsa_check_prime_factor_range(p, nbits, ctx) != 1)
        return 0;

    BN_CTX_start(ctx);
    p1 = BN_CTX_get(ctx);
    gcd = BN_CTX_get(ctx);
    ret = (gcd != NULL)
          /* (Step 5d) GCD(p-1, e) = 1 */
          && (BN_copy(p1, p) != NULL)
          && BN_sub_word(p1, 1)
          && BN_gcd(gcd, p1, e, ctx)
          && BN_is_one(gcd);

    BN_clear(p1);
    BN_CTX_end(ctx);
    return ret;
}

/*
 * See SP 800-56Br1 6.4.1.2.3 Part 6(a-b) Check the private exponent d
 * satifies:
 *     (Step 6a) 2^(nBit/2) < d < LCM(p–1, q–1).
 *     (Step 6b) 1 = (d*e) mod LCM(p–1, q–1)
 */
int rsa_check_private_exponent(const RSA *rsa, int nbits, BN_CTX *ctx)
{
    int ret;
    BIGNUM *r, *p1, *q1, *lcm, *p1q1, *gcd;

    /* (Step 6a) 2^(nbits/2) < d */
    if (BN_num_bits(rsa->d) <= (nbits >> 1))
        return 0;

    BN_CTX_start(ctx);
    r = BN_CTX_get(ctx);
    p1 = BN_CTX_get(ctx);
    q1 = BN_CTX_get(ctx);
    lcm = BN_CTX_get(ctx);
    p1q1 = BN_CTX_get(ctx);
    gcd = BN_CTX_get(ctx);
    ret = (gcd != NULL
          /* LCM(p - 1, q - 1) */
          && (rsa_get_lcm(ctx, rsa->p, rsa->q, lcm, gcd, p1, q1, p1q1) == 1)
          /* (Step 6a) d < LCM(p - 1, q - 1) */
          && (BN_cmp(rsa->d, lcm) < 0)
          /* (Step 6b) 1 = (e . d) mod LCM(p - 1, q - 1) */
          && BN_mod_mul(r, rsa->e, rsa->d, lcm, ctx)
          && BN_is_one(r));

    BN_clear(p1);
    BN_clear(q1);
    BN_clear(lcm);
    BN_clear(gcd);
    BN_CTX_end(ctx);
    return ret;
}

int rsa_check_public_exponent(const BIGNUM *e)
{
    int bitlen = BN_num_bits(e);
    return (BN_is_odd(e) &&  bitlen > 16 && bitlen < 257);
}

/* SP800-56Br1 6.4.1.2.1 (Step 5i): |p - q| > 2^(nbits/2 - 100)
 * i.e- numbits(p-q-1) > (nbits/2 -100)
 */
int rsa_check_pminusq_diff(BIGNUM *diff, const BIGNUM *p, const BIGNUM *q,
                           int nbits)
{
    int bitlen = (nbits >> 1) - 100;
    if (!BN_sub(diff, p, q))
        return -1;
    BN_set_negative(diff, 0);

    if (BN_is_zero(diff))
        return 0;

    if (!BN_sub_word(diff, 1))
        return -1;
    return (BN_num_bits(diff) > bitlen);
}

/* return LCM(p-1, q-1) */
int rsa_get_lcm(BN_CTX *ctx, const BIGNUM *p, const BIGNUM *q,
                BIGNUM *lcm, BIGNUM *gcd, BIGNUM *p1, BIGNUM *q1,
                BIGNUM *p1q1)
{
    return (BN_sub(p1, p, BN_value_one())    /* p-1 */
            && BN_sub(q1, q, BN_value_one()) /* q-1 */
            && BN_mul(p1q1, p1, q1, ctx)     /* (p-1)(q-1) */
            && BN_gcd(gcd, p1, q1, ctx)
            && BN_div(lcm, NULL, p1q1, gcd, ctx)); /* LCM((p-1, q-1)) */
}

/*
 * SP800-56Br1 6.4.2.2 Partial Public Key Validation for RSA refers to
 * SP800-89 5.3.3 (Explicit) Partial Public Key Validation for RSA
 * caveat is that the modulus must be as specified in SP800-56Br1
 */
int rsa_sp800_56b_check_public(const RSA *rsa)
{
    int ret, nbits, iterations, status;
    BN_CTX *ctx = NULL;
    BIGNUM *gcd = NULL;

    if (rsa->n == NULL || rsa->e == NULL)
        return 0;

    /* (Step a): modulus must be 2048 or 3072 (caveat from SP800-56Br1) */
    nbits = BN_num_bits(rsa->n);
    if (nbits != 2048 && nbits != 3072) {
        RSAerr(RSA_F_RSA_SP800_56B_CHECK_PUBLIC, RSA_R_INVALID_KEY_LENGTH);
        return 0;
    }
    if (!BN_is_odd(rsa->n)) {
        RSAerr(RSA_F_RSA_SP800_56B_CHECK_PUBLIC, RSA_R_INVALID_MODULUS);
        return 0;
    }

    /* (Steps b-c): 2^16 < e < 2^256, n and e must be odd */
    if (!rsa_check_public_exponent(rsa->e)) {
        RSAerr(RSA_F_RSA_SP800_56B_CHECK_PUBLIC,
               RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        return 0;
    }

    ctx = BN_CTX_new();
    gcd = BN_new();
    if (ctx == NULL || gcd == NULL)
        goto err;

    iterations = bn_rsa_fips186_4_prime_MR_min_checks(nbits);
    /* (Steps d-f):
     * The modulus is composite, but not a power of a prime.
     * The modulus has no factors smaller than 752.
     */
    if (!BN_gcd(gcd, rsa->n, bn_get0_small_factors(), ctx) || !BN_is_one(gcd)) {
        RSAerr(RSA_F_RSA_SP800_56B_CHECK_PUBLIC, RSA_R_INVALID_MODULUS);
        ret = 0;
        goto err;
    }

    ret = bn_miller_rabin_is_prime(rsa->n, iterations, ctx, NULL, 1, &status);
    if (ret != 1 || status != BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME) {
        RSAerr(RSA_F_RSA_SP800_56B_CHECK_PUBLIC, RSA_R_INVALID_MODULUS);
        ret = 0;
        goto err;
    }

    ret = 1;
err:
    BN_free(gcd);
    BN_CTX_free(ctx);
    return ret;
}

/*
 * Perform validation of the RSA private key to check that 0 < D < N.
 */
int rsa_sp800_56b_check_private(const RSA *rsa)
{
    if (rsa->d == NULL || rsa->n == NULL)
        return 0;
    return (BN_cmp(rsa->d, BN_value_one()) >= 0 && BN_cmp(rsa->d, rsa->n) < 0);
}

/*
 * RSA key pair validation.
 *
 * SP800-56Br1.
 *    6.4.1.2 "RSAKPV1 Family: RSA Key - Pair Validation with a Fixed Exponent"
 *    6.4.1.3 "RSAKPV2 Family: RSA Key - Pair Validation with a Random Exponent"
 *
 * It uses:
 *     6.4.1.2.3 "rsakpv1 - crt"
 *     6.4.1.3.3 "rsakpv2 - crt"
 */
int rsa_sp800_56b_check_keypair(const RSA *rsa, const BIGNUM *efixed,
                                int strength, int nbits)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *r = NULL;

    if (rsa->p == NULL
            || rsa->q == NULL
            || rsa->e == NULL
            || rsa->d == NULL
            || rsa->n == NULL) {
        RSAerr(RSA_F_RSA_SP800_56B_CHECK_KEYPAIR, RSA_R_INVALID_REQUEST);
        return 0;
    }
    /* (Step 1): Check Ranges */
    if (!rsa_sp800_56b_validate_strength(nbits, strength))
        return 0;

    /* If the exponent is known */
    if (efixed != NULL) {
        /* (2): Check fixed exponent matches public exponent. */
        if (BN_cmp(efixed, rsa->e) != 0) {
            RSAerr(RSA_F_RSA_SP800_56B_CHECK_KEYPAIR, RSA_R_INVALID_REQUEST);
            return 0;
        }
    }
    /* (Step 1.c): e is odd integer 65537 <= e < 2^256 */
    if (!rsa_check_public_exponent(rsa->e)) {
        /* exponent out of range */
        RSAerr(RSA_F_RSA_SP800_56B_CHECK_KEYPAIR,
               RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        return 0;
    }
    /* (Step 3.b): check the modulus */
    if (nbits != BN_num_bits(rsa->n)) {
        RSAerr(RSA_F_RSA_SP800_56B_CHECK_KEYPAIR, RSA_R_INVALID_KEYPAIR);
        return 0;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
        return 0;

    BN_CTX_start(ctx);
    r = BN_CTX_get(ctx);
    if (r == NULL || !BN_mul(r, rsa->p, rsa->q, ctx))
        goto err;
    /* (Step 4.c): Check n = pq */
    if (BN_cmp(rsa->n, r) != 0) {
        RSAerr(RSA_F_RSA_SP800_56B_CHECK_KEYPAIR, RSA_R_INVALID_REQUEST);
        goto err;
    }

    /* (Step 5): check prime factors p & q */
    ret = rsa_check_prime_factor(rsa->p, rsa->e, nbits, ctx)
          && rsa_check_prime_factor(rsa->q, rsa->e, nbits, ctx)
          && (rsa_check_pminusq_diff(r, rsa->p, rsa->q, nbits) > 0)
          /* (Step 6): Check the private exponent d */
          && rsa_check_private_exponent(rsa, nbits, ctx)
          /* 6.4.1.2.3 (Step 7): Check the CRT components */
          && rsa_check_crt_components(rsa, ctx);
    if (ret != 1)
        RSAerr(RSA_F_RSA_SP800_56B_CHECK_KEYPAIR, RSA_R_INVALID_KEYPAIR);

err:
    BN_clear(r);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}
