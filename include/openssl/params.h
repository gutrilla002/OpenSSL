/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PARAMS_H
# define HEADER_PARAMS_H

# include <openssl/core.h>
# include <openssl/bn.h>

# ifdef  __cplusplus
extern "C" {
# endif

# define OSSL_PARAM_END \
    { NULL, 0, NULL, 0, NULL }

# define OSSL_PARAM_DEFN(key, type, addr, sz, rsz)    \
    { (key), (type), (addr), (sz), (rsz) }

/* Basic parameter types without return sizes */
# define OSSL_PARAM_int(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int), NULL)
# define OSSL_PARAM_uint(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned int), NULL)
# define OSSL_PARAM_long(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(long int), \
                    NULL)
# define OSSL_PARAM_ulong(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned long int), NULL)
# define OSSL_PARAM_int32(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int32_t), NULL)
# define OSSL_PARAM_uint32(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint32_t), NULL)
# define OSSL_PARAM_int64(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int64_t), NULL)
# define OSSL_PARAM_uint64(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint64_t), NULL)
# define OSSL_PARAM_size_t(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(size_t), \
               NULL)
# define OSSL_PARAM_double(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_REAL, (addr), sizeof(double), NULL)

# define OSSL_PARAM_utf8_string(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_STRING, (addr), sz, NULL)
# define OSSL_PARAM_octet_string(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_STRING, (addr), sz, NULL)

# define OSSL_PARAM_utf8_ptr(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_PTR, &(addr), sz, NULL)
# define OSSL_PARAM_octet_ptr(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_PTR, &(addr), sz, NULL)

/* Basic parameter types including return sizes */
# define OSSL_PARAM_SIZED_int(key, addr, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int), &(r_sz))
# define OSSL_PARAM_SIZED_uint(key, addr, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned int), &(r_sz))
# define OSSL_PARAM_SIZED_long(key, addr, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(long int), \
                    &(r_sz))
# define OSSL_PARAM_SIZED_ulong(key, addr, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned long int), &(r_sz))
# define OSSL_PARAM_SIZED_int32(key, addr, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int32_t), &(r_sz))
# define OSSL_PARAM_SIZED_uint32(key, addr, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint32_t), &(r_sz))
# define OSSL_PARAM_SIZED_int64(key, addr, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int64_t), &(r_sz))
# define OSSL_PARAM_SIZED_uint64(key, addr, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint64_t), &(r_sz))
# define OSSL_PARAM_SIZED_size_t(key, addr, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(size_t), &(r_sz))
# define OSSL_PARAM_SIZED_double(key, addr, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_REAL, (addr), sizeof(double), &(r_sz))

# define OSSL_PARAM_SIZED_BN(key, addr, sz, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sz, \
                    &(r_sz))

# define OSSL_PARAM_SIZED_utf8_string(key, addr, sz, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_STRING, (addr), sz, &(r_sz))
# define OSSL_PARAM_SIZED_octet_string(key, addr, sz, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_STRING, (addr), sz, &(r_sz))

# define OSSL_PARAM_SIZED_utf8_ptr(key, addr, sz, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_PTR, &(addr), sz, &(r_sz))
# define OSSL_PARAM_SIZED_octet_ptr(key, addr, sz, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_PTR, &(addr), sz, &(r_sz))

/* Search an OSSL_PARAM array for a matching name */
const OSSL_PARAM *OSSL_PARAM_locate(const OSSL_PARAM *p, const char *key);

/* Basic parameter type run-time construction */
OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf, size_t *ret);
OSSL_PARAM OSSL_PARAM_construct_uint(const char *key, unsigned int *buf,
                                     size_t *ret);
OSSL_PARAM OSSL_PARAM_construct_long(const char *key, long int *buf,
                                     size_t *ret);
OSSL_PARAM OSSL_PARAM_construct_ulong(const char *key, unsigned long int *buf,
                                     size_t *ret);
OSSL_PARAM OSSL_PARAM_construct_int32(const char *key, int32_t *buf,
                                      size_t *ret);
OSSL_PARAM OSSL_PARAM_construct_uint32(const char *key, uint32_t *buf,
                                      size_t *ret);
OSSL_PARAM OSSL_PARAM_construct_int64(const char *key, int64_t *buf,
                                      size_t *ret);
OSSL_PARAM OSSL_PARAM_construct_uint64(const char *key, uint64_t *buf,
                                       size_t *ret);
OSSL_PARAM OSSL_PARAM_construct_size_t(const char *key, size_t *buf,
                                       size_t *ret);
OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
                                   size_t bsize, size_t *rsize);
OSSL_PARAM OSSL_PARAM_construct_double(const char *key, double *buf,
                                       size_t *rsize);
OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
                                            size_t bsize, size_t *rsize);
OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf,
                                         size_t *rsize);
OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf,
                                             size_t bsize, size_t *rsize);
OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf,
                                          size_t *rsize);

int OSSL_PARAM_get_int(const OSSL_PARAM *p, int *val);
int OSSL_PARAM_get_uint(const OSSL_PARAM *p, unsigned int *val);
int OSSL_PARAM_get_long(const OSSL_PARAM *p, long int *val);
int OSSL_PARAM_get_ulong(const OSSL_PARAM *p, unsigned long int *val);
int OSSL_PARAM_get_int32(const OSSL_PARAM *p, int32_t *val);
int OSSL_PARAM_get_uint32(const OSSL_PARAM *p, uint32_t *val);
int OSSL_PARAM_get_int64(const OSSL_PARAM *p, int64_t *val);
int OSSL_PARAM_get_uint64(const OSSL_PARAM *p, uint64_t *val);
int OSSL_PARAM_get_size_t(const OSSL_PARAM *p, size_t *val);

int OSSL_PARAM_set_int(const OSSL_PARAM *p, int val);
int OSSL_PARAM_set_uint(const OSSL_PARAM *p, unsigned int val);
int OSSL_PARAM_set_long(const OSSL_PARAM *p, long int val);
int OSSL_PARAM_set_ulong(const OSSL_PARAM *p, unsigned long int val);
int OSSL_PARAM_set_int32(const OSSL_PARAM *p, int32_t val);
int OSSL_PARAM_set_uint32(const OSSL_PARAM *p, uint32_t val);
int OSSL_PARAM_set_int64(const OSSL_PARAM *p, int64_t val);
int OSSL_PARAM_set_uint64(const OSSL_PARAM *p, uint64_t val);
int OSSL_PARAM_set_size_t(const OSSL_PARAM *p, size_t val);

int OSSL_PARAM_get_double(const OSSL_PARAM *p, double *val);
int OSSL_PARAM_set_double(const OSSL_PARAM *p, double val);

int OSSL_PARAM_get_BN(const OSSL_PARAM *p, BIGNUM **val);
int OSSL_PARAM_set_BN(const OSSL_PARAM *p, const BIGNUM *val);

int OSSL_PARAM_get_utf8_string(const OSSL_PARAM *p, char **val, size_t max_len);
int OSSL_PARAM_set_utf8_string(const OSSL_PARAM *p, const char *val);

int OSSL_PARAM_get_octet_string(const OSSL_PARAM *p, void **val, size_t max_len,
                                size_t *used_len);
int OSSL_PARAM_set_octet_string(const OSSL_PARAM *p, const void *val,
                                size_t len);

int OSSL_PARAM_get_utf8_ptr(const OSSL_PARAM *p, const char **val);
int OSSL_PARAM_set_utf8_ptr(const OSSL_PARAM *p, const char *val);

int OSSL_PARAM_get_octet_ptr(const OSSL_PARAM *p, const void **val,
                             size_t *used_len);
int OSSL_PARAM_set_octet_ptr(const OSSL_PARAM *p, const void *val,
                             size_t used_len);

int OSSL_PARAM_locate_get_int(const OSSL_PARAM *p, const char *key, int *val);
int OSSL_PARAM_locate_get_uint(const OSSL_PARAM *p, const char *key,
                               unsigned int *val);
int OSSL_PARAM_locate_get_long(const OSSL_PARAM *p, const char *key,
                               long int *val);
int OSSL_PARAM_locate_get_ulong(const OSSL_PARAM *p, const char *key,
                                unsigned long int *val);
int OSSL_PARAM_locate_get_int32(const OSSL_PARAM *p, const char *key,
                                int32_t *val);
int OSSL_PARAM_locate_get_uint32(const OSSL_PARAM *p, const char *key,
                                 uint32_t *val);
int OSSL_PARAM_locate_get_int64(const OSSL_PARAM *p, const char *key,
                                int64_t *val);
int OSSL_PARAM_locate_get_uint64(const OSSL_PARAM *p, const char *key,
                                 uint64_t *val);
int OSSL_PARAM_locate_get_size_t(const OSSL_PARAM *p, const char *key,
                                 size_t *val);

int OSSL_PARAM_locate_set_int(const OSSL_PARAM *p, const char *key, int val);
int OSSL_PARAM_locate_set_uint(const OSSL_PARAM *p, const char *key,
                               unsigned int val);
int OSSL_PARAM_locate_set_long(const OSSL_PARAM *p, const char *key,
                               long int val);
int OSSL_PARAM_locate_set_ulong(const OSSL_PARAM *p, const char *key,
                                unsigned long int val);
int OSSL_PARAM_locate_set_int32(const OSSL_PARAM *p, const char *key,
                                int32_t val);
int OSSL_PARAM_locate_set_uint32(const OSSL_PARAM *p, const char *key,
                                 uint32_t val);
int OSSL_PARAM_locate_set_int64(const OSSL_PARAM *p, const char *key,
                                int64_t val);
int OSSL_PARAM_locate_set_uint64(const OSSL_PARAM *p, const char *key,
                                 uint64_t val);
int OSSL_PARAM_locate_set_size_t(const OSSL_PARAM *p, const char *key,
                                 size_t val);

int OSSL_PARAM_locate_get_double(const OSSL_PARAM *p, const char *key,
                                 double *val);
int OSSL_PARAM_locate_set_double(const OSSL_PARAM *p, const char *key,
                                 double val);

int OSSL_PARAM_locate_get_BN(const OSSL_PARAM *p, const char *key,
                             BIGNUM **val);
int OSSL_PARAM_locate_set_BN(const OSSL_PARAM *p, const char *key,
                             const BIGNUM *val);

int OSSL_PARAM_locate_get_utf8_string(const OSSL_PARAM *p, const char *key,
                                      char **val, size_t max_len);
int OSSL_PARAM_locate_set_utf8_string(const OSSL_PARAM *p, const char *key,
                                      const char *val);

int OSSL_PARAM_locate_get_octet_string(const OSSL_PARAM *p, const char *key,
                                       void **val, size_t max_len,
                                       size_t *used_len);
int OSSL_PARAM_locate_set_octet_string(const OSSL_PARAM *p, const char *key,
                                       const void *val, size_t len);

int OSSL_PARAM_locate_get_utf8_ptr(const OSSL_PARAM *p, const char *key,
                                   const char **val);
int OSSL_PARAM_locate_set_utf8_ptr(const OSSL_PARAM *p, const char *key,
                                   const char *val);

int OSSL_PARAM_locate_get_octet_ptr(const OSSL_PARAM *p, const char *key,
                                    const void **val, size_t *used_len);
int OSSL_PARAM_locate_set_octet_ptr(const OSSL_PARAM *p, const char *key,
                                    const void *val, size_t used_len);

# ifdef  __cplusplus
}
# endif
#endif
