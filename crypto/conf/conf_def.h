/*
 * WARNING: do not edit!
 * Generated by crypto/conf/keysets.pl
 *
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define CONF_NUMBER       1
#define CONF_UPPER        2
#define CONF_LOWER        4
#define CONF_UNDER        256
#define CONF_PUNCT        512
#define CONF_WS           16
#define CONF_ESC          32
#define CONF_QUOTE        64
#define CONF_DQUOTE       1024
#define CONF_COMMENT      128
#define CONF_FCOMMENT     2048
#define CONF_EOF          8
#define CONF_ALPHA        (CONF_UPPER|CONF_LOWER)
#define CONF_ALNUM        (CONF_ALPHA|CONF_NUMBER|CONF_UNDER)
#define CONF_ALNUM_PUNCT  (CONF_ALPHA|CONF_NUMBER|CONF_UNDER|CONF_PUNCT)

#define KEYTYPES(c)       ((const unsigned short *)((c)->meth_data))

#ifndef CHARSET_EBCDIC
# define CVT(a) ((unsigned char)(a) <= 127 ? (unsigned char)(a) : 127)
#else
# define CVT(a) os_toascii[(unsigned char)(a)]
#endif

/*
 * Attention: because the macro argument 'a' is evaluated twice in CVT(a),
 * it is not allowed pass 'a' arguments with side effects to IS_*(c,a)
 * like for example IS_*(c, *p++).
 */
#define IS_COMMENT(c,a)     ((KEYTYPES(c)[CVT(a)] & CONF_COMMENT) ? 1 : 0)
#define IS_FCOMMENT(c,a)    ((KEYTYPES(c)[CVT(a)] & CONF_FCOMMENT) ? 1 : 0)
#define IS_EOF(c,a)         ((KEYTYPES(c)[CVT(a)] & CONF_EOF) ? 1 : 0)
#define IS_ESC(c,a)         ((KEYTYPES(c)[CVT(a)] & CONF_ESC) ? 1 : 0)
#define IS_NUMBER(c,a)      ((KEYTYPES(c)[CVT(a)] & CONF_NUMBER) ? 1 : 0)
#define IS_WS(c,a)          ((KEYTYPES(c)[CVT(a)] & CONF_WS) ? 1 : 0)
#define IS_ALNUM(c,a)       ((KEYTYPES(c)[CVT(a)] & CONF_ALNUM) ? 1 : 0)
#define IS_ALNUM_PUNCT(c,a) ((KEYTYPES(c)[CVT(a)] & CONF_ALNUM_PUNCT) ? 1 : 0)
#define IS_QUOTE(c,a)       ((KEYTYPES(c)[CVT(a)] & CONF_QUOTE) ? 1 : 0)
#define IS_DQUOTE(c,a)      ((KEYTYPES(c)[CVT(a)] & CONF_DQUOTE) ? 1 : 0)

static const unsigned short CONF_type_default[128] = {
    0x0008, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0010, 0x0010, 0x0000, 0x0000, 0x0010, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0010, 0x0200, 0x0040, 0x0080, 0x0000, 0x0200, 0x0200, 0x0040,
    0x0000, 0x0000, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0000, 0x0200, 0x0000, 0x0000, 0x0000, 0x0200,
    0x0200, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0000, 0x0020, 0x0000, 0x0200, 0x0100,
    0x0040, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0000, 0x0200, 0x0000, 0x0200, 0x0000,
};

static const unsigned short CONF_type_win32[128] = {
    0x0008, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0010, 0x0010, 0x0000, 0x0000, 0x0010, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0010, 0x0200, 0x0400, 0x0000, 0x0000, 0x0200, 0x0200, 0x0000,
    0x0000, 0x0000, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0000, 0x0A00, 0x0000, 0x0000, 0x0000, 0x0200,
    0x0200, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0000, 0x0000, 0x0000, 0x0200, 0x0100,
    0x0000, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0000, 0x0200, 0x0000, 0x0200, 0x0000,
};
