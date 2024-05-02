/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "prov/fipsindicator.h"

void ossl_FIPS_INDICATOR_init(ossl_FIPS_INDICATOR *ind)
{
    ind->strict_checks = -1;
    ind->approved = -1;
}

void ossl_FIPS_INDICATOR_set_approved(ossl_FIPS_INDICATOR *ind, int approved)
{
    ind->approved = approved;
}

int ossl_FIPS_INDICATOR_get_approved(const ossl_FIPS_INDICATOR *ind)
{
    return ind->approved;
}

void ossl_FIPS_INDICATOR_set_strict(ossl_FIPS_INDICATOR *ind, int strict)
{
    ind->strict_checks = strict;
}

int ossl_FIPS_INDICATOR_get_strict(const ossl_FIPS_INDICATOR *ind)
{
    return ind->strict_checks;
}
