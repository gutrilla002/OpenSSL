/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

int subtest_level(void);
int test_printf_stdout(const char *fmt, ...);
int test_printf_stderr(const char *fmt, ...);
int openssl_error_cb(const char *str, size_t len, void *u);
