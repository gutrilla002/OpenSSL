/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_INDICATOR_H
# define OPENSSL_INDICATOR_H
# pragma once

# include <openssl/core.h> /* OSSL_CALLBACK */

# ifdef __cplusplus
extern "C" {
# endif

void OSSL_INDICATOR_set_callback(OSSL_LIB_CTX *libctx, OSSL_CALLBACK *cb,
                                 void *cbarg);
void OSSL_INDICATOR_get_callback(OSSL_LIB_CTX *libctx, OSSL_CALLBACK **cb,
                                 void **cbarg);

int OSSL_INDICATOR_callback(OSSL_LIB_CTX *libctx, const char *type,
                            const char *desc);

# ifdef __cplusplus
}
# endif
#endif /* OPENSSL_INDICATOR_H */
