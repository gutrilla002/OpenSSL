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
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/e_os2.h>

/*
 * With IPv6, it looks like Digital has mixed up the proper order of
 * recursive header file inclusion, resulting in the compiler complaining
 * that u_int isn't defined, but only if _POSIX_C_SOURCE is defined, which is
 * needed to have fileno() declared correctly...  So let's define u_int
 */
#if defined(OPENSSL_SYS_VMS_DECC) && !defined(__U_INT)
# define __U_INT
typedef unsigned int u_int;
#endif

#define USE_SOCKETS
#include "apps.h"
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include <openssl/bn.h>
#include <openssl/async.h>
#ifndef OPENSSL_NO_SRP
# include <openssl/srp.h>
#endif
#include "s_apps.h"
#include "timeouts.h"

#if (defined(OPENSSL_SYS_VMS) && __VMS_VER < 70000000)
/* FIONBIO used as a switch to enable ioctl, and that isn't in VMS < 7.0 */
# undef FIONBIO
#endif

#define SSL_HOST_NAME   "localhost"

#undef BUFSIZZ
#define BUFSIZZ 1024*8
#define S_CLIENT_IRC_READ_TIMEOUT 8

extern int verify_depth;
extern int verify_error;
extern int verify_return_error;
extern int verify_quiet;

static int async = 0;
static int c_nbio = 0;
static int c_tlsextdebug = 0;
static int c_status_req = 0;
static int c_Pause = 0;
static int c_debug = 0;
static int c_msg = 0;
static int c_showcerts = 0;
static char *keymatexportlabel = NULL;
static int keymatexportlen = 20;
static BIO *bio_c_out = NULL;
static BIO *bio_c_msg = NULL;
static int c_quiet = 0;
static int c_ign_eof = 0;
static int c_brief = 0;

static void print_stuff(BIO *berr, SSL *con, int full);
static int ocsp_resp_cb(SSL *s, void *arg);

#ifndef OPENSSL_NO_PSK
/* Default PSK identity and key */
static char *psk_identity = "Client_identity";
/*
 * char *psk_key=NULL; by default PSK is not used
 */

static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
                                  unsigned int max_identity_len,
                                  unsigned char *psk,
                                  unsigned int max_psk_len)
{
    unsigned int psk_len = 0;
    int ret;
    BIGNUM *bn = NULL;

    if (c_debug)
        BIO_printf(bio_c_out, "psk_client_cb\n");
    if (!hint) {
        /* no ServerKeyExchange message */
        if (c_debug)
            BIO_printf(bio_c_out,
                       "NULL received PSK identity hint, continuing anyway\n");
    } else if (c_debug)
        BIO_printf(bio_c_out, "Received PSK identity hint '%s'\n", hint);

    /*
     * lookup PSK identity and PSK key based on the given identity hint here
     */
    ret = BIO_snprintf(identity, max_identity_len, "%s", psk_identity);
    if (ret < 0 || (unsigned int)ret > max_identity_len)
        goto out_err;
    if (c_debug)
        BIO_printf(bio_c_out, "created identity '%s' len=%d\n", identity,
                   ret);
    ret = BN_hex2bn(&bn, psk_key);
    if (!ret) {
        BIO_printf(bio_err, "Could not convert PSK key '%s' to BIGNUM\n",
                   psk_key);
        BN_free(bn);
        return 0;
    }

    if ((unsigned int)BN_num_bytes(bn) > max_psk_len) {
        BIO_printf(bio_err,
                   "psk buffer of callback is too small (%d) for key (%d)\n",
                   max_psk_len, BN_num_bytes(bn));
        BN_free(bn);
        return 0;
    }

    psk_len = BN_bn2bin(bn, psk);
    BN_free(bn);
    if (psk_len == 0)
        goto out_err;

    if (c_debug)
        BIO_printf(bio_c_out, "created PSK len=%d\n", psk_len);

    return psk_len;
 out_err:
    if (c_debug)
        BIO_printf(bio_err, "Error in PSK client callback\n");
    return 0;
}
#endif

/* This is a context that we pass to callbacks */
typedef struct tlsextctx_st {
    BIO *biodebug;
    int ack;
} tlsextctx;

static int ssl_servername_cb(SSL *s, int *ad, void *arg)
{
    tlsextctx *p = (tlsextctx *) arg;
    const char *hn = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    if (SSL_get_servername_type(s) != -1)
        p->ack = !SSL_session_reused(s) && hn != NULL;
    else
        BIO_printf(bio_err, "Can't use SSL_get_servername\n");

    return SSL_TLSEXT_ERR_OK;
}

#ifndef OPENSSL_NO_SRP

/* This is a context that we pass to all callbacks */
typedef struct srp_arg_st {
    char *srppassin;
    char *srplogin;
    int msg;                    /* copy from c_msg */
    int debug;                  /* copy from c_debug */
    int amp;                    /* allow more groups */
    int strength /* minimal size for N */ ;
} SRP_ARG;

# define SRP_NUMBER_ITERATIONS_FOR_PRIME 64

static int srp_Verify_N_and_g(const BIGNUM *N, const BIGNUM *g)
{
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *r = BN_new();
    int ret =
        g != NULL && N != NULL && bn_ctx != NULL && BN_is_odd(N) &&
        BN_is_prime_ex(N, SRP_NUMBER_ITERATIONS_FOR_PRIME, bn_ctx, NULL) &&
        p != NULL && BN_rshift1(p, N) &&
        /* p = (N-1)/2 */
        BN_is_prime_ex(p, SRP_NUMBER_ITERATIONS_FOR_PRIME, bn_ctx, NULL) &&
        r != NULL &&
        /* verify g^((N-1)/2) == -1 (mod N) */
        BN_mod_exp(r, g, p, N, bn_ctx) &&
        BN_add_word(r, 1) && BN_cmp(r, N) == 0;

    BN_free(r);
    BN_free(p);
    BN_CTX_free(bn_ctx);
    return ret;
}

/*-
 * This callback is used here for two purposes:
 * - extended debugging
 * - making some primality tests for unknown groups
 * The callback is only called for a non default group.
 *
 * An application does not need the call back at all if
 * only the stanard groups are used.  In real life situations,
 * client and server already share well known groups,
 * thus there is no need to verify them.
 * Furthermore, in case that a server actually proposes a group that
 * is not one of those defined in RFC 5054, it is more appropriate
 * to add the group to a static list and then compare since
 * primality tests are rather cpu consuming.
 */

static int ssl_srp_verify_param_cb(SSL *s, void *arg)
{
    SRP_ARG *srp_arg = (SRP_ARG *)arg;
    BIGNUM *N = NULL, *g = NULL;

    if (((N = SSL_get_srp_N(s)) == NULL) || ((g = SSL_get_srp_g(s)) == NULL))
        return 0;
    if (srp_arg->debug || srp_arg->msg || srp_arg->amp == 1) {
        BIO_printf(bio_err, "SRP parameters:\n");
        BIO_printf(bio_err, "\tN=");
        BN_print(bio_err, N);
        BIO_printf(bio_err, "\n\tg=");
        BN_print(bio_err, g);
        BIO_printf(bio_err, "\n");
    }

    if (SRP_check_known_gN_param(g, N))
        return 1;

    if (srp_arg->amp == 1) {
        if (srp_arg->debug)
            BIO_printf(bio_err,
                       "SRP param N and g are not known params, going to check deeper.\n");

        /*
         * The srp_moregroups is a real debugging feature. Implementors
         * should rather add the value to the known ones. The minimal size
         * has already been tested.
         */
        if (BN_num_bits(g) <= BN_BITS && srp_Verify_N_and_g(N, g))
            return 1;
    }
    BIO_printf(bio_err, "SRP param N and g rejected.\n");
    return 0;
}

# define PWD_STRLEN 1024

static char *ssl_give_srp_client_pwd_cb(SSL *s, void *arg)
{
    SRP_ARG *srp_arg = (SRP_ARG *)arg;
    char *pass = app_malloc(PWD_STRLEN + 1, "SRP password buffer");
    PW_CB_DATA cb_tmp;
    int l;

    cb_tmp.password = (char *)srp_arg->srppassin;
    cb_tmp.prompt_info = "SRP user";
    if ((l = password_callback(pass, PWD_STRLEN, 0, &cb_tmp)) < 0) {
        BIO_printf(bio_err, "Can't read Password\n");
        OPENSSL_free(pass);
        return NULL;
    }
    *(pass + l) = '\0';

    return pass;
}

#endif

static char *srtp_profiles = NULL;

#ifndef OPENSSL_NO_NEXTPROTONEG
/* This the context that we pass to next_proto_cb */
typedef struct tlsextnextprotoctx_st {
    unsigned char *data;
    unsigned short len;
    int status;
} tlsextnextprotoctx;

static tlsextnextprotoctx next_proto;

static int next_proto_cb(SSL *s, unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
    tlsextnextprotoctx *ctx = arg;

    if (!c_quiet) {
        /* We can assume that |in| is syntactically valid. */
        unsigned i;
        BIO_printf(bio_c_out, "Protocols advertised by server: ");
        for (i = 0; i < inlen;) {
            if (i)
                BIO_write(bio_c_out, ", ", 2);
            BIO_write(bio_c_out, &in[i + 1], in[i]);
            i += in[i] + 1;
        }
        BIO_write(bio_c_out, "\n", 1);
    }

    ctx->status =
        SSL_select_next_proto(out, outlen, in, inlen, ctx->data, ctx->len);
    return SSL_TLSEXT_ERR_OK;
}
#endif                         /* ndef OPENSSL_NO_NEXTPROTONEG */

static int serverinfo_cli_parse_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char *in, size_t inlen,
                                   int *al, void *arg)
{
    char pem_name[100];
    unsigned char ext_buf[4 + 65536];

    /* Reconstruct the type/len fields prior to extension data */
    ext_buf[0] = ext_type >> 8;
    ext_buf[1] = ext_type & 0xFF;
    ext_buf[2] = inlen >> 8;
    ext_buf[3] = inlen & 0xFF;
    memcpy(ext_buf + 4, in, inlen);

    BIO_snprintf(pem_name, sizeof(pem_name), "SERVERINFO FOR EXTENSION %d",
                 ext_type);
    PEM_write_bio(bio_c_out, pem_name, "", ext_buf, 4 + inlen);
    return 1;
}

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_HOST, OPT_PORT, OPT_CONNECT, OPT_UNIX, OPT_XMPPHOST, OPT_VERIFY,
    OPT_CERT, OPT_CRL, OPT_CRL_DOWNLOAD, OPT_SESS_OUT, OPT_SESS_IN,
    OPT_CERTFORM, OPT_CRLFORM, OPT_VERIFY_RET_ERROR, OPT_VERIFY_QUIET,
    OPT_BRIEF, OPT_PREXIT, OPT_CRLF, OPT_QUIET, OPT_NBIO,
    OPT_SSL_CLIENT_ENGINE, OPT_RAND, OPT_IGN_EOF, OPT_NO_IGN_EOF,
    OPT_PAUSE, OPT_DEBUG, OPT_TLSEXTDEBUG, OPT_STATUS, OPT_WDEBUG,
    OPT_MSG, OPT_MSGFILE, OPT_ENGINE, OPT_TRACE, OPT_SECURITY_DEBUG,
    OPT_SECURITY_DEBUG_VERBOSE, OPT_SHOWCERTS, OPT_NBIO_TEST, OPT_STATE,
    OPT_PSK_IDENTITY, OPT_PSK, OPT_SRPUSER, OPT_SRPPASS, OPT_SRP_STRENGTH,
    OPT_SRP_LATEUSER, OPT_SRP_MOREGROUPS, OPT_SSL3,
    OPT_TLS1_2, OPT_TLS1_1, OPT_TLS1, OPT_DTLS, OPT_DTLS1,
    OPT_DTLS1_2, OPT_TIMEOUT, OPT_MTU, OPT_KEYFORM, OPT_PASS,
    OPT_CERT_CHAIN, OPT_CAPATH, OPT_NOCAPATH, OPT_CHAINCAPATH, OPT_VERIFYCAPATH,
    OPT_KEY, OPT_RECONNECT, OPT_BUILD_CHAIN, OPT_CAFILE, OPT_NOCAFILE,
    OPT_CHAINCAFILE, OPT_VERIFYCAFILE, OPT_NEXTPROTONEG, OPT_ALPN,
    OPT_SERVERINFO, OPT_STARTTLS, OPT_SERVERNAME, OPT_JPAKE,
    OPT_USE_SRTP, OPT_KEYMATEXPORT, OPT_KEYMATEXPORTLEN, OPT_SMTPHOST,
    OPT_ASYNC,
    OPT_V_ENUM,
    OPT_X_ENUM,
    OPT_S_ENUM,
    OPT_FALLBACKSCSV, OPT_NOCMDS, OPT_PROXY
} OPTION_CHOICE;

OPTIONS s_client_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"host", OPT_HOST, 's', "Use -connect instead"},
    {"port", OPT_PORT, 'p', "Use -connect instead"},
    {"connect", OPT_CONNECT, 's',
     "TCP/IP where to connect (default is " SSL_HOST_NAME ":" PORT_STR ")"},
    {"proxy", OPT_PROXY, 's',
     "Connect to via specified proxy to the real server"},
    {"unix", OPT_UNIX, 's', "Connect over unix domain sockets"},
    {"verify", OPT_VERIFY, 'p', "Turn on peer certificate verification"},
    {"cert", OPT_CERT, '<', "Certificate file to use, PEM format assumed"},
    {"certform", OPT_CERTFORM, 'F',
     "Certificate format (PEM or DER) PEM default"},
    {"key", OPT_KEY, '<', "Private key file to use, if not in -cert file"},
    {"keyform", OPT_KEYFORM, 'F', "Key format (PEM or DER) PEM default"},
    {"pass", OPT_PASS, 's', "Private key file pass phrase source"},
    {"CApath", OPT_CAPATH, '/', "PEM format directory of CA's"},
    {"CAfile", OPT_CAFILE, '<', "PEM format file of CA's"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"reconnect", OPT_RECONNECT, '-',
     "Drop and re-make the connection with the same Session-ID"},
    {"pause", OPT_PAUSE, '-', "Sleep  after each read and write system call"},
    {"showcerts", OPT_SHOWCERTS, '-', "Show all certificates in the chain"},
    {"debug", OPT_DEBUG, '-', "Extra output"},
    {"msg", OPT_MSG, '-', "Show protocol messages"},
    {"msgfile", OPT_MSGFILE, '>'},
    {"nbio_test", OPT_NBIO_TEST, '-', "More ssl protocol testing"},
    {"state", OPT_STATE, '-', "Print the ssl states"},
    {"crlf", OPT_CRLF, '-', "Convert LF from terminal into CRLF"},
    {"quiet", OPT_QUIET, '-', "No s_client output"},
    {"ign_eof", OPT_IGN_EOF, '-', "Ignore input eof (default when -quiet)"},
    {"no_ign_eof", OPT_NO_IGN_EOF, '-', "Don't ignore input eof"},
    {"tls1_2", OPT_TLS1_2, '-', "Just use TLSv1.2"},
    {"tls1_1", OPT_TLS1_1, '-', "Just use TLSv1.1"},
    {"tls1", OPT_TLS1, '-', "Just use TLSv1"},
    {"starttls", OPT_STARTTLS, 's',
     "Use the appropriate STARTTLS command before starting TLS"},
    {"xmpphost", OPT_XMPPHOST, 's',
     "Host to use with \"-starttls xmpp[-server]\""},
    {"rand", OPT_RAND, 's',
     "Load the file(s) into the random number generator"},
    {"sess_out", OPT_SESS_OUT, '>', "File to write SSL session to"},
    {"sess_in", OPT_SESS_IN, '<', "File to read SSL session from"},
    {"use_srtp", OPT_USE_SRTP, 's',
     "Offer SRTP key management with a colon-separated profile list"},
    {"keymatexport", OPT_KEYMATEXPORT, 's',
     "Export keying material using label"},
    {"keymatexportlen", OPT_KEYMATEXPORTLEN, 'p',
     "Export len bytes of keying material (default 20)"},
    {"fallback_scsv", OPT_FALLBACKSCSV, '-', "Send the fallback SCSV"},
    {"name", OPT_SMTPHOST, 's', "Hostname to use for \"-starttls smtp\""},
    {"CRL", OPT_CRL, '<'},
    {"crl_download", OPT_CRL_DOWNLOAD, '-'},
    {"CRLform", OPT_CRLFORM, 'F'},
    {"verify_return_error", OPT_VERIFY_RET_ERROR, '-'},
    {"verify_quiet", OPT_VERIFY_QUIET, '-'},
    {"brief", OPT_BRIEF, '-'},
    {"prexit", OPT_PREXIT, '-'},
    {"security_debug", OPT_SECURITY_DEBUG, '-'},
    {"security_debug_verbose", OPT_SECURITY_DEBUG_VERBOSE, '-'},
    {"cert_chain", OPT_CERT_CHAIN, '<'},
    {"chainCApath", OPT_CHAINCAPATH, '/'},
    {"verifyCApath", OPT_VERIFYCAPATH, '/'},
    {"build_chain", OPT_BUILD_CHAIN, '-'},
    {"chainCAfile", OPT_CHAINCAFILE, '<'},
    {"verifyCAfile", OPT_VERIFYCAFILE, '<'},
    {"nocommands", OPT_NOCMDS, '-', "Do not use interactive command letters"},
    {"servername", OPT_SERVERNAME, 's',
     "Set TLS extension servername in ClientHello"},
    {"tlsextdebug", OPT_TLSEXTDEBUG, '-',
     "Hex dump of all TLS extensions received"},
    {"status", OPT_STATUS, '-', "Request certificate status from server"},
    {"serverinfo", OPT_SERVERINFO, 's',
     "types  Send empty ClientHello extensions (comma-separated numbers)"},
    {"alpn", OPT_ALPN, 's',
     "Enable ALPN extension, considering named protocols supported (comma-separated list)"},
    {"async", OPT_ASYNC, '-', "Support asynchronous operation"},
    OPT_S_OPTIONS,
    OPT_V_OPTIONS,
    OPT_X_OPTIONS,
#ifndef OPENSSL_NO_SSL3
    {"ssl3", OPT_SSL3, '-', "Just use SSLv3"},
#endif
#ifndef OPENSSL_NO_DTLS
    {"dtls", OPT_DTLS, '-'},
    {"dtls1", OPT_DTLS1, '-', "Just use DTLSv1"},
    {"dtls1_2", OPT_DTLS1_2, '-'},
    {"timeout", OPT_TIMEOUT, '-'},
    {"mtu", OPT_MTU, 'p', "Set the link layer MTU"},
#endif
#ifndef OPENSSL_NO_SSL_TRACE
    {"trace", OPT_TRACE, '-'},
#endif
#ifdef WATT32
    {"wdebug", OPT_WDEBUG, '-', "WATT-32 tcp debugging"},
#endif
#ifdef FIONBIO
    {"nbio", OPT_NBIO, '-', "Use non-blocking IO"},
#endif
#ifndef OPENSSL_NO_PSK
    {"psk_identity", OPT_PSK_IDENTITY, 's', "PSK identity"},
    {"psk", OPT_PSK, 's', "PSK in hex (without 0x)"},
# ifndef OPENSSL_NO_JPAKE
    {"jpake", OPT_JPAKE, 's', "JPAKE secret to use"},
# endif
#endif
#ifndef OPENSSL_NO_SRP
    {"srpuser", OPT_SRPUSER, 's', "SRP authentification for 'user'"},
    {"srppass", OPT_SRPPASS, 's', "Password for 'user'"},
    {"srp_lateuser", OPT_SRP_LATEUSER, '-',
     "SRP username into second ClientHello message"},
    {"srp_moregroups", OPT_SRP_MOREGROUPS, '-',
     "Tolerate other than the known g N values."},
    {"srp_strength", OPT_SRP_STRENGTH, 'p', "Minimal length in bits for N"},
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
    {"nextprotoneg", OPT_NEXTPROTONEG, 's',
     "Enable NPN extension, considering named protocols supported (comma-separated list)"},
#endif
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
    {"ssl_client_engine", OPT_SSL_CLIENT_ENGINE, 's'},
#endif
    {NULL}
};

typedef enum PROTOCOL_choice {
    PROTO_OFF,
    PROTO_SMTP,
    PROTO_POP3,
    PROTO_IMAP,
    PROTO_FTP,
    PROTO_TELNET,
    PROTO_XMPP,
    PROTO_XMPP_SERVER,
    PROTO_CONNECT,
    PROTO_IRC
} PROTOCOL_CHOICE;

static OPT_PAIR services[] = {
    {"smtp", PROTO_SMTP},
    {"pop3", PROTO_POP3},
    {"imap", PROTO_IMAP},
    {"ftp", PROTO_FTP},
    {"xmpp", PROTO_XMPP},
    {"xmpp-server", PROTO_XMPP_SERVER},
    {"telnet", PROTO_TELNET},
    {"irc", PROTO_IRC},
    {NULL}
};

int s_client_main(int argc, char **argv)
{
    BIO *sbio;
    EVP_PKEY *key = NULL;
    SSL *con = NULL;
    SSL_CTX *ctx = NULL;
    STACK_OF(X509) *chain = NULL;
    X509 *cert = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    SSL_EXCERT *exc = NULL;
    SSL_CONF_CTX *cctx = NULL;
    STACK_OF(OPENSSL_STRING) *ssl_args = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    const SSL_METHOD *meth = TLS_client_method();
    char *CApath = NULL, *CAfile = NULL, *cbuf = NULL, *sbuf = NULL;
    char *mbuf = NULL, *proxystr = NULL, *connectstr = NULL;
    char *cert_file = NULL, *key_file = NULL, *chain_file = NULL, *prog;
    char *chCApath = NULL, *chCAfile = NULL, *host = SSL_HOST_NAME;
    char *inrand = NULL;
    char *passarg = NULL, *pass = NULL, *vfyCApath = NULL, *vfyCAfile = NULL;
    char *sess_in = NULL, *sess_out = NULL, *crl_file = NULL, *p;
    char *jpake_secret = NULL, *xmpphost = NULL;
    const char *unix_path = NULL;
    const char *ehlo = "mail.example.com";
    struct sockaddr peer;
    struct timeval timeout, *timeoutp;
    fd_set readfds, writefds;
    int noCApath = 0, noCAfile = 0;
    int build_chain = 0, cbuf_len, cbuf_off, cert_format = FORMAT_PEM;
    int key_format = FORMAT_PEM, crlf = 0, full_log = 1, mbuf_len = 0;
    int prexit = 0;
    int enable_timeouts = 0, sdebug = 0, peerlen = sizeof peer;
    int reconnect = 0, verify = SSL_VERIFY_NONE, vpmtouched = 0;
    int ret = 1, in_init = 1, i, nbio_test = 0, s = -1, k, width, state = 0;
    int sbuf_len, sbuf_off, socket_type = SOCK_STREAM, cmdletters = 1;
    int starttls_proto = PROTO_OFF, crl_format = FORMAT_PEM, crl_download = 0;
    int write_tty, read_tty, write_ssl, read_ssl, tty_on, ssl_pending;
    int fallback_scsv = 0;
    long socket_mtu = 0, randamt = 0;
    unsigned short port = PORT;
    OPTION_CHOICE o;
#ifndef OPENSSL_NO_ENGINE
    ENGINE *ssl_client_engine = NULL;
#endif
    ENGINE *e = NULL;
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_NETWARE)
    struct timeval tv;
#endif
    char *servername = NULL;
    const char *alpn_in = NULL;
    tlsextctx tlsextcbp = { NULL, 0 };
#define MAX_SI_TYPES 100
    unsigned short serverinfo_types[MAX_SI_TYPES];
    int serverinfo_count = 0, start = 0, len;
#ifndef OPENSSL_NO_NEXTPROTONEG
    const char *next_proto_neg_in = NULL;
#endif
#ifndef OPENSSL_NO_SRP
    char *srppass = NULL;
    int srp_lateuser = 0;
    SRP_ARG srp_arg = { NULL, NULL, 0, 0, 0, 1024 };
#endif

    prog = opt_progname(argv[0]);
    c_Pause = 0;
    c_quiet = 0;
    c_ign_eof = 0;
    c_debug = 0;
    c_msg = 0;
    c_showcerts = 0;
    c_nbio = 0;
    verify_depth = 0;
    verify_error = X509_V_OK;
    vpm = X509_VERIFY_PARAM_new();
    cbuf = app_malloc(BUFSIZZ, "cbuf");
    sbuf = app_malloc(BUFSIZZ, "sbuf");
    mbuf = app_malloc(BUFSIZZ, "mbuf");
    cctx = SSL_CONF_CTX_new();

    if (vpm == NULL || cctx == NULL) {
        BIO_printf(bio_err, "%s: out of memory\n", prog);
        goto end;
    }

    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT | SSL_CONF_FLAG_CMDLINE);

    prog = opt_init(argc, argv, s_client_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(s_client_options);
            ret = 0;
            goto end;
        case OPT_HOST:
            host = opt_arg();
            break;
        case OPT_PORT:
            port = atoi(opt_arg());
            break;
        case OPT_CONNECT:
            connectstr = opt_arg();
            break;
        case OPT_PROXY:
            proxystr = opt_arg();
            starttls_proto = PROTO_CONNECT;
            break;
        case OPT_UNIX:
            unix_path = opt_arg();
            break;
        case OPT_XMPPHOST:
            xmpphost = opt_arg();
            break;
        case OPT_SMTPHOST:
            ehlo = opt_arg();
            break;
        case OPT_VERIFY:
            verify = SSL_VERIFY_PEER;
            verify_depth = atoi(opt_arg());
            if (!c_quiet)
                BIO_printf(bio_err, "verify depth is %d\n", verify_depth);
            break;
        case OPT_CERT:
            cert_file = opt_arg();
            break;
        case OPT_CRL:
            crl_file = opt_arg();
            break;
        case OPT_CRL_DOWNLOAD:
            crl_download = 1;
            break;
        case OPT_SESS_OUT:
            sess_out = opt_arg();
            break;
        case OPT_SESS_IN:
            sess_in = opt_arg();
            break;
        case OPT_CERTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &cert_format))
                goto opthelp;
            break;
        case OPT_CRLFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &crl_format))
                goto opthelp;
            break;
        case OPT_VERIFY_RET_ERROR:
            verify_return_error = 1;
            break;
        case OPT_VERIFY_QUIET:
            verify_quiet = 1;
            break;
        case OPT_BRIEF:
            c_brief = verify_quiet = c_quiet = 1;
            break;
        case OPT_S_CASES:
            if (ssl_args == NULL)
                ssl_args = sk_OPENSSL_STRING_new_null();
            if (ssl_args == NULL
                || !sk_OPENSSL_STRING_push(ssl_args, opt_flag())
                || !sk_OPENSSL_STRING_push(ssl_args, opt_arg())) {
                BIO_printf(bio_err, "%s: Memory allocation failure\n", prog);
                goto end;
            }
            break;
        case OPT_V_CASES:
            if (!opt_verify(o, vpm))
                goto end;
            vpmtouched++;
            break;
        case OPT_X_CASES:
            if (!args_excert(o, &exc))
                goto end;
            break;
        case OPT_PREXIT:
            prexit = 1;
            break;
        case OPT_CRLF:
            crlf = 1;
            break;
        case OPT_QUIET:
            c_quiet = c_ign_eof = 1;
            break;
        case OPT_NBIO:
            c_nbio = 1;
            break;
        case OPT_NOCMDS:
            cmdletters = 0;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 1);
            break;
        case OPT_SSL_CLIENT_ENGINE:
#ifndef OPENSSL_NO_ENGINE
            ssl_client_engine = ENGINE_by_id(opt_arg());
            if (ssl_client_engine == NULL) {
                BIO_printf(bio_err, "Error getting client auth engine\n");
                goto opthelp;
            }
            break;
#endif
            break;
        case OPT_RAND:
            inrand = opt_arg();
            break;
        case OPT_IGN_EOF:
            c_ign_eof = 1;
            break;
        case OPT_NO_IGN_EOF:
            c_ign_eof = 0;
            break;
        case OPT_PAUSE:
            c_Pause = 1;
            break;
        case OPT_DEBUG:
            c_debug = 1;
            break;
        case OPT_TLSEXTDEBUG:
            c_tlsextdebug = 1;
            break;
        case OPT_STATUS:
            c_status_req = 1;
            break;
        case OPT_WDEBUG:
#ifdef WATT32
            dbug_init();
#endif
            break;
        case OPT_MSG:
            c_msg = 1;
            break;
        case OPT_MSGFILE:
            bio_c_msg = BIO_new_file(opt_arg(), "w");
            break;
        case OPT_TRACE:
#ifndef OPENSSL_NO_SSL_TRACE
            c_msg = 2;
#endif
            break;
        case OPT_SECURITY_DEBUG:
            sdebug = 1;
            break;
        case OPT_SECURITY_DEBUG_VERBOSE:
            sdebug = 2;
            break;
        case OPT_SHOWCERTS:
            c_showcerts = 1;
            break;
        case OPT_NBIO_TEST:
            nbio_test = 1;
            break;
        case OPT_STATE:
            state = 1;
            break;
#ifndef OPENSSL_NO_PSK
        case OPT_PSK_IDENTITY:
            psk_identity = opt_arg();
            break;
        case OPT_PSK:
            for (p = psk_key = opt_arg(); *p; p++) {
                if (isxdigit(*p))
                    continue;
                BIO_printf(bio_err, "Not a hex number '%s'\n", psk_key);
                goto end;
            }
            break;
#else
        case OPT_PSK_IDENTITY:
        case OPT_PSK:
            break;
#endif
#ifndef OPENSSL_NO_SRP
        case OPT_SRPUSER:
            srp_arg.srplogin = opt_arg();
            meth = TLSv1_client_method();
            break;
        case OPT_SRPPASS:
            srppass = opt_arg();
            meth = TLSv1_client_method();
            break;
        case OPT_SRP_STRENGTH:
            srp_arg.strength = atoi(opt_arg());
            BIO_printf(bio_err, "SRP minimal length for N is %d\n",
                       srp_arg.strength);
            meth = TLSv1_client_method();
            break;
        case OPT_SRP_LATEUSER:
            srp_lateuser = 1;
            meth = TLSv1_client_method();
            break;
        case OPT_SRP_MOREGROUPS:
            srp_arg.amp = 1;
            meth = TLSv1_client_method();
            break;
#else
        case OPT_SRPUSER:
        case OPT_SRPPASS:
        case OPT_SRP_STRENGTH:
        case OPT_SRP_LATEUSER:
        case OPT_SRP_MOREGROUPS:
            break;
#endif
        case OPT_SSL3:
#ifndef OPENSSL_NO_SSL3
            meth = SSLv3_client_method();
#endif
            break;
        case OPT_TLS1_2:
            meth = TLSv1_2_client_method();
            break;
        case OPT_TLS1_1:
            meth = TLSv1_1_client_method();
            break;
        case OPT_TLS1:
            meth = TLSv1_client_method();
            break;
#ifndef OPENSSL_NO_DTLS
        case OPT_DTLS:
            meth = DTLS_client_method();
            socket_type = SOCK_DGRAM;
            break;
        case OPT_DTLS1:
            meth = DTLSv1_client_method();
            socket_type = SOCK_DGRAM;
            break;
        case OPT_DTLS1_2:
            meth = DTLSv1_2_client_method();
            socket_type = SOCK_DGRAM;
            break;
        case OPT_TIMEOUT:
            enable_timeouts = 1;
            break;
        case OPT_MTU:
            socket_mtu = atol(opt_arg());
            break;
#else
        case OPT_DTLS:
        case OPT_DTLS1:
        case OPT_DTLS1_2:
        case OPT_TIMEOUT:
        case OPT_MTU:
            break;
#endif
        case OPT_FALLBACKSCSV:
            fallback_scsv = 1;
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &key_format))
                goto opthelp;
            break;
        case OPT_PASS:
            passarg = opt_arg();
            break;
        case OPT_CERT_CHAIN:
            chain_file = opt_arg();
            break;
        case OPT_KEY:
            key_file = opt_arg();
            break;
        case OPT_RECONNECT:
            reconnect = 5;
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_NOCAPATH:
            noCApath = 1;
            break;
        case OPT_CHAINCAPATH:
            chCApath = opt_arg();
            break;
        case OPT_VERIFYCAPATH:
            vfyCApath = opt_arg();
            break;
        case OPT_BUILD_CHAIN:
            build_chain = 1;
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_NOCAFILE:
            noCAfile = 1;
            break;
        case OPT_CHAINCAFILE:
            chCAfile = opt_arg();
            break;
        case OPT_VERIFYCAFILE:
            vfyCAfile = opt_arg();
            break;
        case OPT_NEXTPROTONEG:
            next_proto_neg_in = opt_arg();
            break;
        case OPT_ALPN:
            alpn_in = opt_arg();
            break;
        case OPT_SERVERINFO:
            p = opt_arg();
            len = strlen(p);
            for (start = 0, i = 0; i <= len; ++i) {
                if (i == len || p[i] == ',') {
                    serverinfo_types[serverinfo_count] = atoi(p + start);
                    if (++serverinfo_count == MAX_SI_TYPES)
                        break;
                    start = i + 1;
                }
            }
            break;
        case OPT_STARTTLS:
            if (!opt_pair(opt_arg(), services, &starttls_proto))
                goto end;
        case OPT_SERVERNAME:
            servername = opt_arg();
            break;
        case OPT_JPAKE:
#ifndef OPENSSL_NO_JPAKE
            jpake_secret = opt_arg();
#endif
            break;
        case OPT_USE_SRTP:
            srtp_profiles = opt_arg();
            break;
        case OPT_KEYMATEXPORT:
            keymatexportlabel = opt_arg();
            break;
        case OPT_KEYMATEXPORTLEN:
            keymatexportlen = atoi(opt_arg());
            break;
        case OPT_ASYNC:
            async = 1;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (proxystr) {
        if (connectstr == NULL) {
            BIO_printf(bio_err, "%s: -proxy requires use of -connect\n", prog);
            goto opthelp;
        }
        if (!extract_host_port(proxystr, &host, NULL, &port))
            goto end;
    }
    else if (connectstr != NULL
            && !extract_host_port(connectstr, &host, NULL, &port))
        goto end;

    if (unix_path && (socket_type != SOCK_STREAM)) {
        BIO_printf(bio_err,
                   "Can't use unix sockets and datagrams together\n");
        goto end;
    }
#if !defined(OPENSSL_NO_JPAKE) && !defined(OPENSSL_NO_PSK)
    if (jpake_secret) {
        if (psk_key) {
            BIO_printf(bio_err, "Can't use JPAKE and PSK together\n");
            goto end;
        }
        psk_identity = "JPAKE";
    }
#endif

#if !defined(OPENSSL_NO_NEXTPROTONEG)
    next_proto.status = -1;
    if (next_proto_neg_in) {
        next_proto.data =
            next_protos_parse(&next_proto.len, next_proto_neg_in);
        if (next_proto.data == NULL) {
            BIO_printf(bio_err, "Error parsing -nextprotoneg argument\n");
            goto end;
        }
    } else
        next_proto.data = NULL;
#endif

    if (!app_passwd(passarg, NULL, &pass, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (key_file == NULL)
        key_file = cert_file;

    if (key_file) {
        key = load_key(key_file, key_format, 0, pass, e,
                       "client certificate private key file");
        if (key == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (cert_file) {
        cert = load_cert(cert_file, cert_format,
                         NULL, e, "client certificate file");
        if (cert == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (chain_file) {
        chain = load_certs(chain_file, FORMAT_PEM,
                           NULL, e, "client certificate chain");
        if (!chain)
            goto end;
    }

    if (crl_file) {
        X509_CRL *crl;
        crl = load_crl(crl_file, crl_format);
        if (crl == NULL) {
            BIO_puts(bio_err, "Error loading CRL\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        crls = sk_X509_CRL_new_null();
        if (crls == NULL || !sk_X509_CRL_push(crls, crl)) {
            BIO_puts(bio_err, "Error adding CRL\n");
            ERR_print_errors(bio_err);
            X509_CRL_free(crl);
            goto end;
        }
    }

    if (!load_excert(&exc))
        goto end;

    if (!app_RAND_load_file(NULL, 1) && inrand == NULL
        && !RAND_status()) {
        BIO_printf(bio_err,
                   "warning, not much extra random data, consider using the -rand option\n");
    }
    if (inrand != NULL) {
        randamt = app_RAND_load_files(inrand);
        BIO_printf(bio_err, "%ld semi-random bytes loaded\n", randamt);
    }

    if (bio_c_out == NULL) {
        if (c_quiet && !c_debug) {
            bio_c_out = BIO_new(BIO_s_null());
            if (c_msg && !bio_c_msg)
                bio_c_msg = dup_bio_out(FORMAT_TEXT);
        } else if (bio_c_out == NULL)
            bio_c_out = dup_bio_out(FORMAT_TEXT);
    }
#ifndef OPENSSL_NO_SRP
    if (!app_passwd(srppass, NULL, &srp_arg.srppassin, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }
#endif

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (sdebug)
        ssl_ctx_security_debug(ctx, sdebug);

    if (vpmtouched && !SSL_CTX_set1_param(ctx, vpm)) {
        BIO_printf(bio_err, "Error setting verify params\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (async) {
        SSL_CTX_set_mode(ctx, SSL_MODE_ASYNC);
        ASYNC_init(1, 0, 0);
    }

    if (!config_ctx(cctx, ssl_args, ctx, 1, jpake_secret == NULL))
        goto end;

    if (!ssl_load_stores(ctx, vfyCApath, vfyCAfile, chCApath, chCAfile,
                         crls, crl_download)) {
        BIO_printf(bio_err, "Error loading store locations\n");
        ERR_print_errors(bio_err);
        goto end;
    }
#ifndef OPENSSL_NO_ENGINE
    if (ssl_client_engine) {
        if (!SSL_CTX_set_client_cert_engine(ctx, ssl_client_engine)) {
            BIO_puts(bio_err, "Error setting client auth engine\n");
            ERR_print_errors(bio_err);
            ENGINE_free(ssl_client_engine);
            goto end;
        }
        ENGINE_free(ssl_client_engine);
    }
#endif

#ifndef OPENSSL_NO_PSK
    if (psk_key != NULL || jpake_secret) {
        if (c_debug)
            BIO_printf(bio_c_out,
                       "PSK key given or JPAKE in use, setting client callback\n");
        SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
    }
#endif
#ifndef OPENSSL_NO_SRTP
    if (srtp_profiles != NULL) {
        /* Returns 0 on success! */
        if (SSL_CTX_set_tlsext_use_srtp(ctx, srtp_profiles) != 0) {
            BIO_printf(bio_err, "Error setting SRTP profile\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
#endif

    if (exc)
        ssl_ctx_set_excert(ctx, exc);

#if !defined(OPENSSL_NO_NEXTPROTONEG)
    if (next_proto.data)
        SSL_CTX_set_next_proto_select_cb(ctx, next_proto_cb, &next_proto);
#endif
    if (alpn_in) {
        unsigned short alpn_len;
        unsigned char *alpn = next_protos_parse(&alpn_len, alpn_in);

        if (alpn == NULL) {
            BIO_printf(bio_err, "Error parsing -alpn argument\n");
            goto end;
        }
        /* Returns 0 on success! */
        if (SSL_CTX_set_alpn_protos(ctx, alpn, alpn_len) != 0) {
           BIO_printf(bio_err, "Error setting ALPN\n");
            goto end;
        }
        OPENSSL_free(alpn);
    }

    for (i = 0; i < serverinfo_count; i++) {
        if (!SSL_CTX_add_client_custom_ext(ctx,
                                           serverinfo_types[i],
                                           NULL, NULL, NULL,
                                           serverinfo_cli_parse_cb, NULL)) {
            BIO_printf(bio_err,
                    "Warning: Unable to add custom extension %u, skipping\n",
                    serverinfo_types[i]);
        }
    }

    if (state)
        SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);

    SSL_CTX_set_verify(ctx, verify, verify_callback);

    if (!ctx_set_verify_locations(ctx, CAfile, CApath, noCAfile, noCApath)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    ssl_ctx_add_crls(ctx, crls, crl_download);

    if (!set_cert_key_stuff(ctx, cert, key, chain, build_chain))
        goto end;

    if (servername != NULL) {
        tlsextcbp.biodebug = bio_err;
        SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);
        SSL_CTX_set_tlsext_servername_arg(ctx, &tlsextcbp);
    }
# ifndef OPENSSL_NO_SRP
    if (srp_arg.srplogin) {
        if (!srp_lateuser && !SSL_CTX_set_srp_username(ctx, srp_arg.srplogin)) {
            BIO_printf(bio_err, "Unable to set SRP username\n");
            goto end;
        }
        srp_arg.msg = c_msg;
        srp_arg.debug = c_debug;
        SSL_CTX_set_srp_cb_arg(ctx, &srp_arg);
        SSL_CTX_set_srp_client_pwd_callback(ctx, ssl_give_srp_client_pwd_cb);
        SSL_CTX_set_srp_strength(ctx, srp_arg.strength);
        if (c_msg || c_debug || srp_arg.amp == 0)
            SSL_CTX_set_srp_verify_param_callback(ctx,
                                                  ssl_srp_verify_param_cb);
    }
# endif

    con = SSL_new(ctx);
    if (sess_in) {
        SSL_SESSION *sess;
        BIO *stmp = BIO_new_file(sess_in, "r");
        if (!stmp) {
            BIO_printf(bio_err, "Can't open session file %s\n", sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        sess = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
        BIO_free(stmp);
        if (!sess) {
            BIO_printf(bio_err, "Can't open session file %s\n", sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        if (!SSL_set_session(con, sess)) {
            BIO_printf(bio_err, "Can't set session\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        SSL_SESSION_free(sess);
    }

    if (fallback_scsv)
        SSL_set_mode(con, SSL_MODE_SEND_FALLBACK_SCSV);

    if (servername != NULL) {
        if (!SSL_set_tlsext_host_name(con, servername)) {
            BIO_printf(bio_err, "Unable to set TLS servername extension.\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

 re_start:
#ifdef NO_SYS_UN_H
    if (init_client(&s, host, port, socket_type) == 0)
#else
    if ((!unix_path && (init_client(&s, host, port, socket_type) == 0)) ||
        (unix_path && (init_client_unix(&s, unix_path) == 0)))
#endif
    {
        BIO_printf(bio_err, "connect:errno=%d\n", get_last_socket_error());
        SHUTDOWN(s);
        goto end;
    }
    BIO_printf(bio_c_out, "CONNECTED(%08X)\n", s);

#ifdef FIONBIO
    if (c_nbio) {
        unsigned long l = 1;
        BIO_printf(bio_c_out, "turning on non blocking io\n");
        if (BIO_socket_ioctl(s, FIONBIO, &l) < 0) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }
#endif
    if (c_Pause & 0x01)
        SSL_set_debug(con, 1);

    if (socket_type == SOCK_DGRAM) {

        sbio = BIO_new_dgram(s, BIO_NOCLOSE);
        if (getsockname(s, &peer, (void *)&peerlen) < 0) {
            BIO_printf(bio_err, "getsockname:errno=%d\n",
                       get_last_socket_error());
            SHUTDOWN(s);
            goto end;
        }

        (void)BIO_ctrl_set_connected(sbio, &peer);

        if (enable_timeouts) {
            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_RCV_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_SND_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
        }

        if (socket_mtu) {
            if (socket_mtu < DTLS_get_link_min_mtu(con)) {
                BIO_printf(bio_err, "MTU too small. Must be at least %ld\n",
                           DTLS_get_link_min_mtu(con));
                BIO_free(sbio);
                goto shut;
            }
            SSL_set_options(con, SSL_OP_NO_QUERY_MTU);
            if (!DTLS_set_link_mtu(con, socket_mtu)) {
                BIO_printf(bio_err, "Failed to set MTU\n");
                BIO_free(sbio);
                goto shut;
            }
        } else
            /* want to do MTU discovery */
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);
    } else
        sbio = BIO_new_socket(s, BIO_NOCLOSE);

    if (nbio_test) {
        BIO *test;

        test = BIO_new(BIO_f_nbio_test());
        sbio = BIO_push(test, sbio);
    }

    if (c_debug) {
        SSL_set_debug(con, 1);
        BIO_set_callback(sbio, bio_dump_callback);
        BIO_set_callback_arg(sbio, (char *)bio_c_out);
    }
    if (c_msg) {
#ifndef OPENSSL_NO_SSL_TRACE
        if (c_msg == 2)
            SSL_set_msg_callback(con, SSL_trace);
        else
#endif
            SSL_set_msg_callback(con, msg_cb);
        SSL_set_msg_callback_arg(con, bio_c_msg ? bio_c_msg : bio_c_out);
    }

    if (c_tlsextdebug) {
        SSL_set_tlsext_debug_callback(con, tlsext_cb);
        SSL_set_tlsext_debug_arg(con, bio_c_out);
    }
    if (c_status_req) {
        SSL_set_tlsext_status_type(con, TLSEXT_STATUSTYPE_ocsp);
        SSL_CTX_set_tlsext_status_cb(ctx, ocsp_resp_cb);
        SSL_CTX_set_tlsext_status_arg(ctx, bio_c_out);
    }
#ifndef OPENSSL_NO_JPAKE
    if (jpake_secret)
        jpake_client_auth(bio_c_out, sbio, jpake_secret);
#endif

    SSL_set_bio(con, sbio, sbio);
    SSL_set_connect_state(con);

    /* ok, lets connect */
    width = SSL_get_fd(con) + 1;

    read_tty = 1;
    write_tty = 0;
    tty_on = 0;
    read_ssl = 1;
    write_ssl = 1;

    cbuf_len = 0;
    cbuf_off = 0;
    sbuf_len = 0;
    sbuf_off = 0;

    switch ((PROTOCOL_CHOICE) starttls_proto) {
    case PROTO_OFF:
        break;
    case PROTO_SMTP:
        {
            /*
             * This is an ugly hack that does a lot of assumptions. We do
             * have to handle multi-line responses which may come in a single
             * packet or not. We therefore have to use BIO_gets() which does
             * need a buffering BIO. So during the initial chitchat we do
             * push a buffering BIO into the chain that is removed again
             * later on to not disturb the rest of the s_client operation.
             */
            int foundit = 0;
            BIO *fbio = BIO_new(BIO_f_buffer());
            BIO_push(fbio, sbio);
            /* wait for multi-line response to end from SMTP */
            do {
                mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
            }
            while (mbuf_len > 3 && mbuf[3] == '-');
            BIO_printf(fbio, "EHLO %s\r\n", ehlo);
            (void)BIO_flush(fbio);
            /* wait for multi-line response to end EHLO SMTP response */
            do {
                mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
                if (strstr(mbuf, "STARTTLS"))
                    foundit = 1;
            }
            while (mbuf_len > 3 && mbuf[3] == '-');
            (void)BIO_flush(fbio);
            BIO_pop(fbio);
            BIO_free(fbio);
            if (!foundit)
                BIO_printf(bio_err,
                           "didn't find starttls in server response,"
                           " trying anyway...\n");
            BIO_printf(sbio, "STARTTLS\r\n");
            BIO_read(sbio, sbuf, BUFSIZZ);
        }
        break;
    case PROTO_POP3:
        {
            BIO_read(sbio, mbuf, BUFSIZZ);
            BIO_printf(sbio, "STLS\r\n");
            mbuf_len = BIO_read(sbio, sbuf, BUFSIZZ);
            if (mbuf_len < 0) {
                BIO_printf(bio_err, "BIO_read failed\n");
                goto end;
            }
        }
        break;
    case PROTO_IMAP:
        {
            int foundit = 0;
            BIO *fbio = BIO_new(BIO_f_buffer());
            BIO_push(fbio, sbio);
            BIO_gets(fbio, mbuf, BUFSIZZ);
            /* STARTTLS command requires CAPABILITY... */
            BIO_printf(fbio, ". CAPABILITY\r\n");
            (void)BIO_flush(fbio);
            /* wait for multi-line CAPABILITY response */
            do {
                mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
                if (strstr(mbuf, "STARTTLS"))
                    foundit = 1;
            }
            while (mbuf_len > 3 && mbuf[0] != '.');
            (void)BIO_flush(fbio);
            BIO_pop(fbio);
            BIO_free(fbio);
            if (!foundit)
                BIO_printf(bio_err,
                           "didn't find STARTTLS in server response,"
                           " trying anyway...\n");
            BIO_printf(sbio, ". STARTTLS\r\n");
            BIO_read(sbio, sbuf, BUFSIZZ);
        }
        break;
    case PROTO_FTP:
        {
            BIO *fbio = BIO_new(BIO_f_buffer());
            BIO_push(fbio, sbio);
            /* wait for multi-line response to end from FTP */
            do {
                mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
            }
            while (mbuf_len > 3 && mbuf[3] == '-');
            (void)BIO_flush(fbio);
            BIO_pop(fbio);
            BIO_free(fbio);
            BIO_printf(sbio, "AUTH TLS\r\n");
            BIO_read(sbio, sbuf, BUFSIZZ);
        }
        break;
    case PROTO_XMPP:
    case PROTO_XMPP_SERVER:
        {
            int seen = 0;
            BIO_printf(sbio, "<stream:stream "
                       "xmlns:stream='http://etherx.jabber.org/streams' "
                       "xmlns='jabber:%s' to='%s' version='1.0'>",
                       starttls_proto == PROTO_XMPP ? "client" : "server",
                       xmpphost ? xmpphost : host);
            seen = BIO_read(sbio, mbuf, BUFSIZZ);
            mbuf[seen] = 0;
            while (!strstr
                   (mbuf, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'")
                   && !strstr(mbuf,
                              "<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\""))
            {
                seen = BIO_read(sbio, mbuf, BUFSIZZ);

                if (seen <= 0)
                    goto shut;

                mbuf[seen] = 0;
            }
            BIO_printf(sbio,
                       "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
            seen = BIO_read(sbio, sbuf, BUFSIZZ);
            sbuf[seen] = 0;
            if (!strstr(sbuf, "<proceed"))
                goto shut;
            mbuf[0] = 0;
        }
        break;
    case PROTO_TELNET:
        {
            static const unsigned char tls_do[] = {
                /* IAC    DO   START_TLS */
                   255,   253, 46
            };
            static const unsigned char tls_will[] = {
                /* IAC  WILL START_TLS */
                   255, 251, 46
            };
            static const unsigned char tls_follows[] = {
                /* IAC  SB   START_TLS FOLLOWS IAC  SE */
                   255, 250, 46,       1,      255, 240
            };
            int bytes;

            /* Telnet server should demand we issue START_TLS */
            bytes = BIO_read(sbio, mbuf, BUFSIZZ);
            if (bytes != 3 || memcmp(mbuf, tls_do, 3) != 0)
                goto shut;
            /* Agree to issue START_TLS and send the FOLLOWS sub-command */
            BIO_write(sbio, tls_will, 3);
            BIO_write(sbio, tls_follows, 6);
            (void)BIO_flush(sbio);
            /* Telnet server also sent the FOLLOWS sub-command */
            bytes = BIO_read(sbio, mbuf, BUFSIZZ);
            if (bytes != 6 || memcmp(mbuf, tls_follows, 6) != 0)
                goto shut;
        }
        break;
    case PROTO_CONNECT:
        {
            int foundit = 0;
            BIO *fbio = BIO_new(BIO_f_buffer());

            BIO_push(fbio, sbio);
            BIO_printf(fbio, "CONNECT %s\r\n\r\n", connectstr);
            (void)BIO_flush(fbio);
            /* wait for multi-line response to end CONNECT response */
            do {
                mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
                if (strstr(mbuf, "200") != NULL
                    && strstr(mbuf, "established") != NULL)
                    foundit++;
            } while (mbuf_len > 3 && foundit == 0);
            (void)BIO_flush(fbio);
            BIO_pop(fbio);
            BIO_free(fbio);
            if (!foundit) {
                BIO_printf(bio_err, "%s: HTTP CONNECT failed\n", prog);
                goto shut;
            }
        }
        break;
    case PROTO_IRC:
        {
            int numeric;
            BIO *fbio = BIO_new(BIO_f_buffer());

            BIO_push(fbio, sbio);
            BIO_printf(fbio, "STARTTLS\r\n");
            (void)BIO_flush(fbio);
            width = SSL_get_fd(con) + 1;

            do {
                numeric = 0;

                FD_ZERO(&readfds);
                openssl_fdset(SSL_get_fd(con), &readfds);
                timeout.tv_sec = S_CLIENT_IRC_READ_TIMEOUT;
                timeout.tv_usec = 0;
                /*
                 * If the IRCd doesn't respond within
                 * S_CLIENT_IRC_READ_TIMEOUT seconds, assume
                 * it doesn't support STARTTLS. Many IRCds
                 * will not give _any_ sort of response to a
                 * STARTTLS command when it's not supported.
                 */
                if (!BIO_get_buffer_num_lines(fbio)
                    && !BIO_pending(fbio)
                    && !BIO_pending(sbio)
                    && select(width, (void *)&readfds, NULL, NULL,
                              &timeout) < 1) {
                    BIO_printf(bio_err,
                               "Timeout waiting for response (%d seconds).\n",
                               S_CLIENT_IRC_READ_TIMEOUT);
                    break;
                }

                mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
                if (mbuf_len < 1 || sscanf(mbuf, "%*s %d", &numeric) != 1)
                    break;
                /* :example.net 451 STARTTLS :You have not registered */
                /* :example.net 421 STARTTLS :Unknown command */
                if ((numeric == 451 || numeric == 421)
                    && strstr(mbuf, "STARTTLS") != NULL) {
                    BIO_printf(bio_err, "STARTTLS not supported: %s", mbuf);
                    break;
                }
                if (numeric == 691) {
                    BIO_printf(bio_err, "STARTTLS negotiation failed: ");
                    ERR_print_errors(bio_err);
                    break;
                }
            } while (numeric != 670);

            (void)BIO_flush(fbio);
            BIO_pop(fbio);
            BIO_free(fbio);
            if (numeric != 670) {
                BIO_printf(bio_err, "Server does not support STARTTLS.\n");
                ret = 1;
                goto shut;
            }
        }
    }

    for (;;) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        if ((SSL_version(con) == DTLS1_VERSION) &&
            DTLSv1_get_timeout(con, &timeout))
            timeoutp = &timeout;
        else
            timeoutp = NULL;

        if (SSL_in_init(con) && !SSL_total_renegotiations(con)) {
            in_init = 1;
            tty_on = 0;
        } else {
            tty_on = 1;
            if (in_init) {
                in_init = 0;

                if (servername != NULL && !SSL_session_reused(con)) {
                    BIO_printf(bio_c_out,
                               "Server did %sacknowledge servername extension.\n",
                               tlsextcbp.ack ? "" : "not ");
                }

                if (sess_out) {
                    BIO *stmp = BIO_new_file(sess_out, "w");
                    if (stmp) {
                        PEM_write_bio_SSL_SESSION(stmp, SSL_get_session(con));
                        BIO_free(stmp);
                    } else
                        BIO_printf(bio_err, "Error writing session file %s\n",
                                   sess_out);
                }
                if (c_brief) {
                    BIO_puts(bio_err, "CONNECTION ESTABLISHED\n");
                    print_ssl_summary(con);
                }

                print_stuff(bio_c_out, con, full_log);
                if (full_log > 0)
                    full_log--;

                if (starttls_proto) {
                    BIO_write(bio_err, mbuf, mbuf_len);
                    /* We don't need to know any more */
                    if (!reconnect)
                        starttls_proto = PROTO_OFF;
                }

                if (reconnect) {
                    reconnect--;
                    BIO_printf(bio_c_out,
                               "drop connection and then reconnect\n");
                    SSL_shutdown(con);
                    SSL_set_connect_state(con);
                    SHUTDOWN(SSL_get_fd(con));
                    goto re_start;
                }
            }
        }

        ssl_pending = read_ssl && SSL_pending(con);

        if (!ssl_pending) {
#if !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_NETWARE)
            if (tty_on) {
                if (read_tty)
                    openssl_fdset(fileno(stdin), &readfds);
                if (write_tty)
                    openssl_fdset(fileno(stdout), &writefds);
            }
            if (read_ssl)
                openssl_fdset(SSL_get_fd(con), &readfds);
            if (write_ssl)
                openssl_fdset(SSL_get_fd(con), &writefds);
#else
            if (!tty_on || !write_tty) {
                if (read_ssl)
                    openssl_fdset(SSL_get_fd(con), &readfds);
                if (write_ssl)
                    openssl_fdset(SSL_get_fd(con), &writefds);
            }
#endif

            /*
             * Note: under VMS with SOCKETSHR the second parameter is
             * currently of type (int *) whereas under other systems it is
             * (void *) if you don't have a cast it will choke the compiler:
             * if you do have a cast then you can either go for (int *) or
             * (void *).
             */
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
            /*
             * Under Windows/DOS we make the assumption that we can always
             * write to the tty: therefore if we need to write to the tty we
             * just fall through. Otherwise we timeout the select every
             * second and see if there are any keypresses. Note: this is a
             * hack, in a proper Windows application we wouldn't do this.
             */
            i = 0;
            if (!write_tty) {
                if (read_tty) {
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, &tv);
# if defined(OPENSSL_SYS_WINCE) || defined(OPENSSL_SYS_MSDOS)
                    if (!i && (!_kbhit() || !read_tty))
                        continue;
# else
                    if (!i && (!((_kbhit())
                                 || (WAIT_OBJECT_0 ==
                                     WaitForSingleObject(GetStdHandle
                                                         (STD_INPUT_HANDLE),
                                                         0)))
                               || !read_tty))
                        continue;
# endif
                } else
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, timeoutp);
            }
#elif defined(OPENSSL_SYS_NETWARE)
            if (!write_tty) {
                if (read_tty) {
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, &tv);
                } else
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, timeoutp);
            }
#else
            i = select(width, (void *)&readfds, (void *)&writefds,
                       NULL, timeoutp);
#endif
            if (i < 0) {
                BIO_printf(bio_err, "bad select %d\n",
                           get_last_socket_error());
                goto shut;
                /* goto end; */
            }
        }

        if ((SSL_version(con) == DTLS1_VERSION)
            && DTLSv1_handle_timeout(con) > 0) {
            BIO_printf(bio_err, "TIMEOUT occurred\n");
        }

        if (!ssl_pending && FD_ISSET(SSL_get_fd(con), &writefds)) {
            k = SSL_write(con, &(cbuf[cbuf_off]), (unsigned int)cbuf_len);
            switch (SSL_get_error(con, k)) {
            case SSL_ERROR_NONE:
                cbuf_off += k;
                cbuf_len -= k;
                if (k <= 0)
                    goto end;
                /* we have done a  write(con,NULL,0); */
                if (cbuf_len <= 0) {
                    read_tty = 1;
                    write_ssl = 0;
                } else {        /* if (cbuf_len > 0) */

                    read_tty = 0;
                    write_ssl = 1;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                BIO_printf(bio_c_out, "write W BLOCK\n");
                write_ssl = 1;
                read_tty = 0;
                break;
            case SSL_ERROR_WANT_ASYNC:
                BIO_printf(bio_c_out, "write A BLOCK\n");
                wait_for_async(con);
                write_ssl = 1;
                read_tty = 0;
                break;
            case SSL_ERROR_WANT_READ:
                BIO_printf(bio_c_out, "write R BLOCK\n");
                write_tty = 0;
                read_ssl = 1;
                write_ssl = 0;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                BIO_printf(bio_c_out, "write X BLOCK\n");
                break;
            case SSL_ERROR_ZERO_RETURN:
                if (cbuf_len != 0) {
                    BIO_printf(bio_c_out, "shutdown\n");
                    ret = 0;
                    goto shut;
                } else {
                    read_tty = 1;
                    write_ssl = 0;
                    break;
                }

            case SSL_ERROR_SYSCALL:
                if ((k != 0) || (cbuf_len != 0)) {
                    BIO_printf(bio_err, "write:errno=%d\n",
                               get_last_socket_error());
                    goto shut;
                } else {
                    read_tty = 1;
                    write_ssl = 0;
                }
                break;
            case SSL_ERROR_SSL:
                ERR_print_errors(bio_err);
                goto shut;
            }
        }
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_NETWARE)
        /* Assume Windows/DOS/BeOS can always write */
        else if (!ssl_pending && write_tty)
#else
        else if (!ssl_pending && FD_ISSET(fileno(stdout), &writefds))
#endif
        {
#ifdef CHARSET_EBCDIC
            ascii2ebcdic(&(sbuf[sbuf_off]), &(sbuf[sbuf_off]), sbuf_len);
#endif
            i = raw_write_stdout(&(sbuf[sbuf_off]), sbuf_len);

            if (i <= 0) {
                BIO_printf(bio_c_out, "DONE\n");
                ret = 0;
                goto shut;
                /* goto end; */
            }

            sbuf_len -= i;;
            sbuf_off += i;
            if (sbuf_len <= 0) {
                read_ssl = 1;
                write_tty = 0;
            }
        } else if (ssl_pending || FD_ISSET(SSL_get_fd(con), &readfds)) {
#ifdef RENEG
            {
                static int iiii;
                if (++iiii == 52) {
                    SSL_renegotiate(con);
                    iiii = 0;
                }
            }
#endif
            k = SSL_read(con, sbuf, 1024 /* BUFSIZZ */ );

            switch (SSL_get_error(con, k)) {
            case SSL_ERROR_NONE:
                if (k <= 0)
                    goto end;
                sbuf_off = 0;
                sbuf_len = k;

                read_ssl = 0;
                write_tty = 1;
                break;
            case SSL_ERROR_WANT_ASYNC:
                BIO_printf(bio_c_out, "read A BLOCK\n");
                wait_for_async(con);
                write_tty = 0;
                read_ssl = 1;
                if ((read_tty == 0) && (write_ssl == 0))
                    write_ssl = 1;
                break;
            case SSL_ERROR_WANT_WRITE:
                BIO_printf(bio_c_out, "read W BLOCK\n");
                write_ssl = 1;
                read_tty = 0;
                break;
            case SSL_ERROR_WANT_READ:
                BIO_printf(bio_c_out, "read R BLOCK\n");
                write_tty = 0;
                read_ssl = 1;
                if ((read_tty == 0) && (write_ssl == 0))
                    write_ssl = 1;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                BIO_printf(bio_c_out, "read X BLOCK\n");
                break;
            case SSL_ERROR_SYSCALL:
                ret = get_last_socket_error();
                if (c_brief)
                    BIO_puts(bio_err, "CONNECTION CLOSED BY SERVER\n");
                else
                    BIO_printf(bio_err, "read:errno=%d\n", ret);
                goto shut;
            case SSL_ERROR_ZERO_RETURN:
                BIO_printf(bio_c_out, "closed\n");
                ret = 0;
                goto shut;
            case SSL_ERROR_SSL:
                ERR_print_errors(bio_err);
                goto shut;
                /* break; */
            }
        }
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
# if defined(OPENSSL_SYS_WINCE) || defined(OPENSSL_SYS_MSDOS)
        else if (_kbhit())
# else
        else if ((_kbhit())
                 || (WAIT_OBJECT_0 ==
                     WaitForSingleObject(GetStdHandle(STD_INPUT_HANDLE), 0)))
# endif
#elif defined (OPENSSL_SYS_NETWARE)
        else if (_kbhit())
#else
        else if (FD_ISSET(fileno(stdin), &readfds))
#endif
        {
            if (crlf) {
                int j, lf_num;

                i = raw_read_stdin(cbuf, BUFSIZZ / 2);
                lf_num = 0;
                /* both loops are skipped when i <= 0 */
                for (j = 0; j < i; j++)
                    if (cbuf[j] == '\n')
                        lf_num++;
                for (j = i - 1; j >= 0; j--) {
                    cbuf[j + lf_num] = cbuf[j];
                    if (cbuf[j] == '\n') {
                        lf_num--;
                        i++;
                        cbuf[j + lf_num] = '\r';
                    }
                }
                assert(lf_num == 0);
            } else
                i = raw_read_stdin(cbuf, BUFSIZZ);

            if ((!c_ign_eof) && ((i <= 0) || (cbuf[0] == 'Q' && cmdletters))) {
                BIO_printf(bio_err, "DONE\n");
                ret = 0;
                goto shut;
            }

            if ((!c_ign_eof) && (cbuf[0] == 'R' && cmdletters)) {
                BIO_printf(bio_err, "RENEGOTIATING\n");
                SSL_renegotiate(con);
                cbuf_len = 0;
            }
#ifndef OPENSSL_NO_HEARTBEATS
            else if ((!c_ign_eof) && (cbuf[0] == 'B' && cmdletters)) {
                BIO_printf(bio_err, "HEARTBEATING\n");
                SSL_heartbeat(con);
                cbuf_len = 0;
            }
#endif
            else {
                cbuf_len = i;
                cbuf_off = 0;
#ifdef CHARSET_EBCDIC
                ebcdic2ascii(cbuf, cbuf, i);
#endif
            }

            write_ssl = 1;
            read_tty = 0;
        }
    }

    ret = 0;
 shut:
    if (in_init)
        print_stuff(bio_c_out, con, full_log);
    SSL_shutdown(con);
    SHUTDOWN(SSL_get_fd(con));
 end:
    if (con != NULL) {
        if (prexit != 0)
            print_stuff(bio_c_out, con, 1);
        SSL_free(con);
    }
    if (async) {
        ASYNC_cleanup(1);
    }
#if !defined(OPENSSL_NO_NEXTPROTONEG)
    OPENSSL_free(next_proto.data);
#endif
    SSL_CTX_free(ctx);
    X509_free(cert);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    EVP_PKEY_free(key);
    sk_X509_pop_free(chain, X509_free);
    OPENSSL_free(pass);
#ifndef OPENSSL_NO_SRP
    OPENSSL_free(srp_arg.srppassin);
#endif
    X509_VERIFY_PARAM_free(vpm);
    ssl_excert_free(exc);
    sk_OPENSSL_STRING_free(ssl_args);
    SSL_CONF_CTX_free(cctx);
    OPENSSL_clear_free(cbuf, BUFSIZZ);
    OPENSSL_clear_free(sbuf, BUFSIZZ);
    OPENSSL_clear_free(mbuf, BUFSIZZ);
    BIO_free(bio_c_out);
    bio_c_out = NULL;
    BIO_free(bio_c_msg);
    bio_c_msg = NULL;
    return (ret);
}

static void print_stuff(BIO *bio, SSL *s, int full)
{
    X509 *peer = NULL;
    char buf[BUFSIZ];
    STACK_OF(X509) *sk;
    STACK_OF(X509_NAME) *sk2;
    const SSL_CIPHER *c;
    X509_NAME *xn;
    int i;
#ifndef OPENSSL_NO_COMP
    const COMP_METHOD *comp, *expansion;
#endif
    unsigned char *exportedkeymat;

    if (full) {
        int got_a_chain = 0;

        sk = SSL_get_peer_cert_chain(s);
        if (sk != NULL) {
            got_a_chain = 1;

            BIO_printf(bio, "---\nCertificate chain\n");
            for (i = 0; i < sk_X509_num(sk); i++) {
                X509_NAME_oneline(X509_get_subject_name(sk_X509_value(sk, i)),
                                  buf, sizeof buf);
                BIO_printf(bio, "%2d s:%s\n", i, buf);
                X509_NAME_oneline(X509_get_issuer_name(sk_X509_value(sk, i)),
                                  buf, sizeof buf);
                BIO_printf(bio, "   i:%s\n", buf);
                if (c_showcerts)
                    PEM_write_bio_X509(bio, sk_X509_value(sk, i));
            }
        }

        BIO_printf(bio, "---\n");
        peer = SSL_get_peer_certificate(s);
        if (peer != NULL) {
            BIO_printf(bio, "Server certificate\n");

            /* Redundant if we showed the whole chain */
            if (!(c_showcerts && got_a_chain))
                PEM_write_bio_X509(bio, peer);
            X509_NAME_oneline(X509_get_subject_name(peer), buf, sizeof buf);
            BIO_printf(bio, "subject=%s\n", buf);
            X509_NAME_oneline(X509_get_issuer_name(peer), buf, sizeof buf);
            BIO_printf(bio, "issuer=%s\n", buf);
        } else
            BIO_printf(bio, "no peer certificate available\n");

        sk2 = SSL_get_client_CA_list(s);
        if ((sk2 != NULL) && (sk_X509_NAME_num(sk2) > 0)) {
            BIO_printf(bio, "---\nAcceptable client certificate CA names\n");
            for (i = 0; i < sk_X509_NAME_num(sk2); i++) {
                xn = sk_X509_NAME_value(sk2, i);
                X509_NAME_oneline(xn, buf, sizeof(buf));
                BIO_write(bio, buf, strlen(buf));
                BIO_write(bio, "\n", 1);
            }
        } else {
            BIO_printf(bio, "---\nNo client certificate CA names sent\n");
        }

        ssl_print_sigalgs(bio, s);
        ssl_print_tmp_key(bio, s);

        BIO_printf(bio,
                   "---\nSSL handshake has read %"PRIu64" bytes and written %"PRIu64" bytes\n",
                   BIO_number_read(SSL_get_rbio(s)),
                   BIO_number_written(SSL_get_wbio(s)));
    }
    BIO_printf(bio, (SSL_cache_hit(s) ? "---\nReused, " : "---\nNew, "));
    c = SSL_get_current_cipher(s);
    BIO_printf(bio, "%s, Cipher is %s\n",
               SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));
    if (peer != NULL) {
        EVP_PKEY *pktmp;
        pktmp = X509_get0_pubkey(peer);
        BIO_printf(bio, "Server public key is %d bit\n",
                   EVP_PKEY_bits(pktmp));
    }
    BIO_printf(bio, "Secure Renegotiation IS%s supported\n",
               SSL_get_secure_renegotiation_support(s) ? "" : " NOT");
#ifndef OPENSSL_NO_COMP
    comp = SSL_get_current_compression(s);
    expansion = SSL_get_current_expansion(s);
    BIO_printf(bio, "Compression: %s\n",
               comp ? SSL_COMP_get_name(comp) : "NONE");
    BIO_printf(bio, "Expansion: %s\n",
               expansion ? SSL_COMP_get_name(expansion) : "NONE");
#endif

#ifdef SSL_DEBUG
    {
        /* Print out local port of connection: useful for debugging */
        int sock;
        struct sockaddr_in ladd;
        socklen_t ladd_size = sizeof(ladd);
        sock = SSL_get_fd(s);
        getsockname(sock, (struct sockaddr *)&ladd, &ladd_size);
        BIO_printf(bio_c_out, "LOCAL PORT is %u\n", ntohs(ladd.sin_port));
    }
#endif

#if !defined(OPENSSL_NO_NEXTPROTONEG)
    if (next_proto.status != -1) {
        const unsigned char *proto;
        unsigned int proto_len;
        SSL_get0_next_proto_negotiated(s, &proto, &proto_len);
        BIO_printf(bio, "Next protocol: (%d) ", next_proto.status);
        BIO_write(bio, proto, proto_len);
        BIO_write(bio, "\n", 1);
    }
#endif
    {
        const unsigned char *proto;
        unsigned int proto_len;
        SSL_get0_alpn_selected(s, &proto, &proto_len);
        if (proto_len > 0) {
            BIO_printf(bio, "ALPN protocol: ");
            BIO_write(bio, proto, proto_len);
            BIO_write(bio, "\n", 1);
        } else
            BIO_printf(bio, "No ALPN negotiated\n");
    }

#ifndef OPENSSL_NO_SRTP
    {
        SRTP_PROTECTION_PROFILE *srtp_profile =
            SSL_get_selected_srtp_profile(s);

        if (srtp_profile)
            BIO_printf(bio, "SRTP Extension negotiated, profile=%s\n",
                       srtp_profile->name);
    }
#endif

    SSL_SESSION_print(bio, SSL_get_session(s));
    if (keymatexportlabel != NULL) {
        BIO_printf(bio, "Keying material exporter:\n");
        BIO_printf(bio, "    Label: '%s'\n", keymatexportlabel);
        BIO_printf(bio, "    Length: %i bytes\n", keymatexportlen);
        exportedkeymat = app_malloc(keymatexportlen, "export key");
        if (!SSL_export_keying_material(s, exportedkeymat,
                                        keymatexportlen,
                                        keymatexportlabel,
                                        strlen(keymatexportlabel),
                                        NULL, 0, 0)) {
            BIO_printf(bio, "    Error\n");
        } else {
            BIO_printf(bio, "    Keying material: ");
            for (i = 0; i < keymatexportlen; i++)
                BIO_printf(bio, "%02X", exportedkeymat[i]);
            BIO_printf(bio, "\n");
        }
        OPENSSL_free(exportedkeymat);
    }
    BIO_printf(bio, "---\n");
    X509_free(peer);
    /* flush, or debugging output gets mixed with http response */
    (void)BIO_flush(bio);
}

static int ocsp_resp_cb(SSL *s, void *arg)
{
    const unsigned char *p;
    int len;
    OCSP_RESPONSE *rsp;
    len = SSL_get_tlsext_status_ocsp_resp(s, &p);
    BIO_puts(arg, "OCSP response: ");
    if (!p) {
        BIO_puts(arg, "no response sent\n");
        return 1;
    }
    rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (!rsp) {
        BIO_puts(arg, "response parse error\n");
        BIO_dump_indent(arg, (char *)p, len, 4);
        return 0;
    }
    BIO_puts(arg, "\n======================================\n");
    OCSP_RESPONSE_print(arg, rsp, 0);
    BIO_puts(arg, "======================================\n");
    OCSP_RESPONSE_free(rsp);
    return 1;
}
