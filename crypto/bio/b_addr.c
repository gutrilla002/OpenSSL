/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
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

#include <string.h>

#include "bio_lcl.h"

#include <openssl/err.h>
#include <openssl/buffer.h>

/*
 * Throughout this file and bio_lcl.h, the existence of the macro
 * AI_PASSIVE is used to detect the availability of struct addrinfo,
 * getnameinfo() and getaddrinfo().  If that macro doesn't exist,
 * we use our own implementation instead, using gethostbyname,
 * getservbyname and a few other.
 */

/**********************************************************************
 *
 * Address structure
 *
 */

BIO_ADDR *BIO_ADDR_new(void)
{
    BIO_ADDR *ret = (BIO_ADDR *)OPENSSL_zalloc(sizeof(BIO_ADDR));
    return ret;
}

void BIO_ADDR_free(BIO_ADDR *ap)
{
    OPENSSL_free(ap);
}

/*
 * BIO_ADDR_make - non-public routine to fill a BIO_ADDR with the contents
 * of a struct sockaddr.
 */
int BIO_ADDR_make(BIO_ADDR *ap, const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        ap->sin = *(const struct sockaddr_in *)sa;
        return 1;
    }
#ifdef AF_INET6
    if (sa->sa_family == AF_INET6) {
        ap->sin6 = *(const struct sockaddr_in6 *)sa;
        return 1;
    }
#endif
#ifdef AF_UNIX
    if (ap->sa.sa_family == AF_UNIX) {
        ap->sun = *(const struct sockaddr_un *)sa;
        return 1;
    }
#endif

    return 0;
}

int BIO_ADDR_rawmake(BIO_ADDR *ap, int family,
                     const void *where, size_t wherelen,
                     unsigned short port)
{
#ifdef AF_UNIX
    if (family == AF_UNIX) {
        if (wherelen + 1 > sizeof(ap->sun.sun_path))
            return 0;
        memset(&ap->sun, 0, sizeof(ap->sun));
        ap->sun.sun_family = family;
        strncpy(ap->sun.sun_path, where, sizeof(ap->sun.sun_path) - 1);
        return 1;
    }
#endif
    if (family == AF_INET) {
        if (wherelen != sizeof(struct in_addr))
            return 0;
        memset(&ap->sin, 0, sizeof(ap->sin));
        ap->sin.sin_family = family;
        ap->sin.sin_port = port;
        ap->sin.sin_addr = *(struct in_addr *)where;
        return 1;
    }
#ifdef AF_INET6
    if (family == AF_INET6) {
        if (wherelen != sizeof(struct in6_addr))
            return 0;
        memset(&ap->sin6, 0, sizeof(ap->sin6));
        ap->sin6.sin6_family = family;
        ap->sin6.sin6_port = port;
        ap->sin6.sin6_addr = *(struct in6_addr *)where;
        return 1;
    }
#endif

    return 0;
}

int BIO_ADDR_family(const BIO_ADDR *ap)
{
    return ap->sa.sa_family;
}

int BIO_ADDR_rawaddress(const BIO_ADDR *ap, void *p, size_t *l)
{
    size_t len = 0;
    const void *addrptr = NULL;

    if (ap->sa.sa_family == AF_INET) {
        len = sizeof(ap->sin.sin_addr);
        addrptr = &ap->sin.sin_addr;
    }
#ifdef AF_INET6
    else if (ap->sa.sa_family == AF_INET6) {
        len = sizeof(ap->sin6.sin6_addr);
        addrptr = &ap->sin6.sin6_addr;
    }
#endif
#ifdef AF_UNIX
    else if (ap->sa.sa_family == AF_UNIX) {
        len = strlen(ap->sun.sun_path);
        addrptr = &ap->sun.sun_path;
    }
#endif

    if (addrptr == NULL)
        return 0;

    if (p != NULL) {
        memcpy(p, addrptr, len);
    }
    if (l != NULL)
        *l = len;

    return 1;
}

unsigned short BIO_ADDR_rawport(const BIO_ADDR *ap)
{
    if (ap->sa.sa_family == AF_INET)
        return ap->sin.sin_port;
#ifdef AF_INET6
    if (ap->sa.sa_family == AF_INET6)
        return ap->sin6.sin6_port;
#endif
    return 0;
}

/*-
 * addr_strings - helper function to get host and service names
 * @ap: the BIO_ADDR that has the input info
 * @numeric: 0 if actual names should be returned, 1 if the numeric
 * representation should be returned.
 * @hostname: a pointer to a pointer to a memory area to store the
 * host name or numeric representation.  Unused if NULL.
 * @service: a pointer to a pointer to a memory area to store the
 * service name or numeric representation.  Unused if NULL.
 *
 * The return value is 0 on failure, with the error code in the error
 * stack, and 1 on success.
 */
static int addr_strings(const BIO_ADDR *ap, int numeric,
                        char **hostname, char **service)
{
    if (BIO_sock_init() != 1)
        return 0;

    if (1) {
#ifdef AI_PASSIVE
        int ret = 0;
        char host[NI_MAXHOST], serv[NI_MAXSERV];
        int flags = 0;

        if (numeric)
            flags |= NI_NUMERICHOST | NI_NUMERICSERV;

        if ((ret = getnameinfo(BIO_ADDR_sockaddr(ap),
                               BIO_ADDR_sockaddr_size(ap),
                               host, sizeof(host), serv, sizeof(serv),
                               flags)) != 0) {
# ifdef EAI_SYSTEM
            if (ret == EAI_SYSTEM) {
                SYSerr(SYS_F_GETNAMEINFO, get_last_socket_error());
                BIOerr(BIO_F_ADDR_STRINGS, ERR_R_SYS_LIB);
            } else
# endif
            {
                BIOerr(BIO_F_ADDR_STRINGS, ERR_R_SYS_LIB);
                ERR_add_error_data(1, gai_strerror(ret));
            }
            return 0;
        }
        if (hostname)
            *hostname = OPENSSL_strdup(host);
        if (service)
            *service = OPENSSL_strdup(serv);
    } else {
#endif
        if (hostname)
            *hostname = OPENSSL_strdup(inet_ntoa(ap->sin.sin_addr));
        if (service) {
            char serv[6];        /* port is 16 bits => max 5 decimal digits */
            BIO_snprintf(serv, sizeof(serv), "%d", ntohs(ap->sin.sin_port));
            *service = OPENSSL_strdup(serv);
        }
    }

    return 1;
}

char *BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric)
{
    char *hostname = NULL;

    if (addr_strings(ap, numeric, &hostname, NULL))
        return hostname;

    return NULL;
}

char *BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric)
{
    char *service = NULL;

    if (addr_strings(ap, numeric, NULL, &service))
        return service;

    return NULL;
}

char *BIO_ADDR_path_string(const BIO_ADDR *ap)
{
#ifdef AF_UNIX
    if (ap->sa.sa_family == AF_UNIX)
        return OPENSSL_strdup(ap->sun.sun_path);
#endif
    return NULL;
}

/*
 * BIO_ADDR_sockaddr - non-public routine to return the struct sockaddr
 * for a given BIO_ADDR.  In reality, this is simply a type safe cast.
 * The returned struct sockaddr is const, so it can't be tampered with.
 */
const struct sockaddr *BIO_ADDR_sockaddr(const BIO_ADDR *ap)
{
    return &(ap->sa);
}

/*
 * BIO_ADDR_sockaddr_noconst - non-public function that does the same
 * as BIO_ADDR_sockaddr, but returns a non-const.  USE WITH CARE, as
 * it allows you to tamper with the data (and thereby the contents
 * of the input BIO_ADDR).
 */
struct sockaddr *BIO_ADDR_sockaddr_noconst(BIO_ADDR *ap)
{
    return &(ap->sa);
}

/*
 * BIO_ADDR_sockaddr_size - non-public function that returns the size
 * of the struct sockaddr the BIO_ADDR is using.  If the protocol family
 * isn't set or is something other than AF_INET, AF_INET6 or AF_UNIX,
 * the size of the BIO_ADDR type is returned.
 */
socklen_t BIO_ADDR_sockaddr_size(const BIO_ADDR *ap)
{
    if (ap->sa.sa_family == AF_INET)
        return sizeof(ap->sin);
#ifdef AF_INET6
    if (ap->sa.sa_family == AF_INET6)
        return sizeof(ap->sin6);
#endif
#ifdef AF_UNIX
    if (ap->sa.sa_family == AF_UNIX)
        return sizeof(ap->sun);
#endif
    return sizeof(*ap);
}

/**********************************************************************
 *
 * Address into database
 *
 */

const BIO_ADDRINFO *BIO_ADDRINFO_next(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return bai->bai_next;
    return NULL;
}

int BIO_ADDRINFO_family(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return bai->bai_family;
    return 0;
}

int BIO_ADDRINFO_socktype(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return bai->bai_socktype;
    return 0;
}

int BIO_ADDRINFO_protocol(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return bai->bai_protocol;
    return 0;
}

/*
 * BIO_ADDRINFO_sockaddr_size - non-public function that returns the size
 * of the struct sockaddr inside the BIO_ADDRINFO.
 */
socklen_t BIO_ADDRINFO_sockaddr_size(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return bai->bai_addrlen;
    return 0;
}

/*
 * BIO_ADDRINFO_sockaddr - non-public function that returns bai_addr
 * as the struct sockaddr it is.
 */
const struct sockaddr *BIO_ADDRINFO_sockaddr(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return bai->bai_addr;
    return NULL;
}

const BIO_ADDR *BIO_ADDRINFO_address(const BIO_ADDRINFO *bai)
{
    if (bai != NULL)
        return (BIO_ADDR *)bai->bai_addr;
    return NULL;
}

void BIO_ADDRINFO_free(BIO_ADDRINFO *bai)
{
    if (bai == NULL)
        return;

#ifdef AI_PASSIVE
# ifdef AF_UNIX
#  define _cond bai->bai_family != AF_UNIX
# else
#  define _cond 1
# endif
    if (_cond) {
        freeaddrinfo(bai);
        return;
    }
#endif

    /* Free manually when we know that addrinfo_wrap() was used.
     * See further comment above addrinfo_wrap()
     */
    while (bai != NULL) {
        BIO_ADDRINFO *next = bai->bai_next;
        OPENSSL_free(bai->bai_addr);
        OPENSSL_free(bai);
        bai = next;
    }
}

/**********************************************************************
 *
 * Service functions
 *
 */

/*-
 * The specs in hostserv can take these forms:
 *
 * host:service         => *host = "host", *service = "service"
 * host:*               => *host = "host", *service = NULL
 * host:                => *host = "host", *service = NULL
 * :service             => *host = NULL, *service = "service"
 * *:service            => *host = NULL, *service = "service"
 *
 * in case no : is present in the string, the result depends on
 * hostserv_prio, as follows:
 *
 * when hostserv_prio == BIO_PARSE_PRIO_HOST
 * host                 => *host = "host", *service untouched
 *
 * when hostserv_prio == BIO_PARSE_PRIO_SERV
 * service              => *host untouched, *service = "service"
 *
 */
int BIO_parse_hostserv(const char *hostserv, char **host, char **service,
                       enum BIO_hostserv_priorities hostserv_prio)
{
    const char *h = NULL; size_t hl = 0;
    const char *p = NULL; size_t pl = 0;

    if (*hostserv == '[') {
        if ((p = strchr(hostserv, ']')) == NULL)
            goto spec_err;
        h = hostserv + 1;
        hl = p - h;
        p++;
        if (*p == '\0')
            p = NULL;
        else if (*p != ':')
            goto spec_err;
        else {
            p++;
            pl = strlen(p);
        }
    } else {
        const char *p2 = strrchr(hostserv, ':');
        p = strchr(hostserv, ':');

        /*-
         * Check for more than one colon.  There are three possible
         * interpretations:
         * 1. IPv6 address with port number, last colon being separator.
         * 2. IPv6 address only.
         * 3. IPv6 address only if hostserv_prio == BIO_PARSE_PRIO_HOST,
         *    IPv6 address and port number if hostserv_prio == BIO_PARSE_PRIO_SERV
         * Because of this ambiguity, we currently choose to make it an
         * error.
         */
        if (p != p2)
            goto amb_err;

        if (p != NULL) {
            h = hostserv;
            hl = p - h;
            p++;
            pl = strlen(p);
        } else if (hostserv_prio == BIO_PARSE_PRIO_HOST) {
            h = hostserv;
            hl = strlen(h);
        } else {
            p = hostserv;
            pl = strlen(p);
        }
    }

    if (strchr(p, ':'))
        goto spec_err;

    if (h != NULL && host != NULL) {
        if (hl == 0
            || (hl == 1 && h[0] == '*')) {
            *host = NULL;
        } else {
            *host = OPENSSL_strndup(h, hl);
            if (*host == NULL)
                goto memerr;
        }
    }
    if (p != NULL && service != NULL) {
        if (pl == 0
            || (pl == 1 && p[0] == '*')) {
            *service = NULL;
        } else {
            *service = OPENSSL_strndup(p, pl);
            if (*service == NULL)
                goto memerr;
        }
    }

    return 1;
 amb_err:
    BIOerr(BIO_F_BIO_PARSE_HOSTSERV, BIO_R_AMBIGUOUS_HOST_OR_SERVICE);
    return 0;
 spec_err:
    BIOerr(BIO_F_BIO_PARSE_HOSTSERV, BIO_R_MALFORMED_HOST_OR_SERVICE);
    return 0;
 memerr:
    BIOerr(BIO_F_BIO_PARSE_HOSTSERV, ERR_R_MALLOC_FAILURE);
    return 0;
}

/* addrinfo_wrap is used to build our own addrinfo "chain".
 * (it has only one entry, so calling it a chain may be a stretch)
 * It should ONLY be called when getaddrinfo() and friends
 * aren't available, OR when dealing with a non IP protocol
 * family, such as AF_UNIX
 *
 * the return value is 1 on success, or 0 on failure, which
 * only happens if a memory allocation error occured.
 */
static int addrinfo_wrap(int family, int socktype,
                         const void *where, size_t wherelen,
                         unsigned short port,
                         BIO_ADDRINFO **bai)
{
    OPENSSL_assert(bai != NULL);

    *bai = (BIO_ADDRINFO *)OPENSSL_zalloc(sizeof(**bai));

    if (*bai == NULL)
        return 0;
    (*bai)->bai_family = family;
    (*bai)->bai_socktype = socktype;
    if (socktype == SOCK_STREAM)
        (*bai)->bai_protocol = IPPROTO_TCP;
    if (socktype == SOCK_DGRAM)
        (*bai)->bai_protocol = IPPROTO_UDP;
#ifdef AF_UNIX
    if (family == AF_UNIX)
        (*bai)->bai_protocol = 0;
#endif
    {
        /* Magic: We know that BIO_ADDR_sockaddr_noconst is really
           just an advanced cast of BIO_ADDR* to struct sockaddr *
           by the power of union, so while it may seem that we're
           creating a memory leak here, we are not.  It will be
           all right. */
        BIO_ADDR *addr = BIO_ADDR_new();
        if (addr != NULL) {
            BIO_ADDR_rawmake(addr, family, where, wherelen, port);
            (*bai)->bai_addr = BIO_ADDR_sockaddr_noconst(addr);
        }
    }
    (*bai)->bai_next = NULL;
    if ((*bai)->bai_addr == NULL) {
        BIO_ADDRINFO_free(*bai);
        *bai = NULL;
        return 0;
    }
    return 1;
}

/*-
 * BIO_lookup - look up the node and service you want to connect to.
 * @node: the node you want to connect to.
 * @service: the service you want to connect to.
 * @lookup_type: declare intent with the result, client or server.
 * @family: the address family you want to use.  Use AF_UNSPEC for any, or
 *  AF_INET, AF_INET6 or AF_UNIX.
 * @socktype: The socket type you want to use.  Can be SOCK_STREAM, SOCK_DGRAM
 *  or 0 for all.
 * @res: Storage place for the resulting list of returned addresses
 *
 * This will do a lookup of the node and service that you want to connect to.
 * It returns a linked list of different addresses you can try to connect to.
 *
 * When no longer needed you should call BIO_ADDRINFO_free() to free the result.
 *
 * The return value is 1 on success or 0 in case of error.
 */
int BIO_lookup(const char *host, const char *service,
               enum BIO_lookup_type lookup_type,
               int family, int socktype, BIO_ADDRINFO **res)
{
    int ret = 0;                 /* Assume failure */

    switch(family) {
    case AF_INET:
#ifdef AF_INET6
    case AF_INET6:
#endif
#ifdef AF_UNIX
    case AF_UNIX:
#endif
#ifdef AF_UNSPEC
    case AF_UNSPEC:
#endif
        break;
    default:
        BIOerr(BIO_F_BIO_LOOKUP, BIO_R_UNSUPPORTED_PROTOCOL_FAMILY);
        return 0;
    }

#ifdef AF_UNIX
    if (family == AF_UNIX) {
        if (addrinfo_wrap(family, socktype, host, strlen(host), 0, res))
            return 1;
        else
            BIOerr(BIO_F_BIO_LOOKUP, ERR_R_MALLOC_FAILURE);
        return 0;
    }
#endif

    if (BIO_sock_init() != 1)
        return 0;

    if (1) {
        int gai_ret = 0;
#ifdef AI_PASSIVE
        struct addrinfo hints;

        hints.ai_flags = 0;
# ifdef AI_ADDRCONFIG
        hints.ai_flags = AI_ADDRCONFIG;
# endif
        hints.ai_family = family;
        hints.ai_socktype = socktype;
        hints.ai_protocol = 0;
        hints.ai_addrlen = 0;
        hints.ai_addr = NULL;
        hints.ai_canonname = NULL;
        hints.ai_next = NULL;

        if (lookup_type == BIO_LOOKUP_SERVER)
            hints.ai_flags |= AI_PASSIVE;

        /* Note that |res| SHOULD be a 'struct addrinfo **' thanks to
         * macro magic in bio_lcl.h
         */
        switch ((gai_ret = getaddrinfo(host, service, &hints, res))) {
# ifdef EAI_SYSTEM
        case EAI_SYSTEM:
            SYSerr(SYS_F_GETADDRINFO, get_last_socket_error());
            BIOerr(BIO_F_BIO_LOOKUP, ERR_R_SYS_LIB);
            break;
# endif
        case 0:
            ret = 1;             /* Success */
            break;
        default:
            BIOerr(BIO_F_BIO_LOOKUP, ERR_R_SYS_LIB);
            ERR_add_error_data(1, gai_strerror(gai_ret));
            break;
        }
    } else {
#endif
        const struct hostent *he;
        /* Windows doesn't seem to have in_addr_t */
#ifdef OPENSSL_SYS_WINDOWS
        static uint32_t he_fallback_address;
        static const uint32_t *he_fallback_addresses[] =
            { &he_fallback_address, NULL };
#else
        static in_addr_t he_fallback_address;
        static const in_addr_t *he_fallback_addresses[] =
            { &he_fallback_address, NULL };
#endif
        static const struct hostent he_fallback =
            { NULL, NULL, AF_INET, sizeof(he_fallback_address),
              (char **)&he_fallback_addresses };
        struct servent *se;
        /* Apprently, on WIN64, s_proto and s_port have traded places... */
#ifdef _WIN64
        struct servent se_fallback = { NULL, NULL, NULL, 0 };
#else
        struct servent se_fallback = { NULL, NULL, 0, NULL };
#endif
        char *proto = NULL;

        CRYPTO_w_lock(CRYPTO_LOCK_GETHOSTBYNAME);
        CRYPTO_w_lock(CRYPTO_LOCK_GETSERVBYNAME);
        he_fallback_address = INADDR_ANY;
        if (host == NULL) {
            he = &he_fallback;
            switch(lookup_type) {
            case BIO_LOOKUP_CLIENT:
                he_fallback_address = INADDR_LOOPBACK;
                break;
            case BIO_LOOKUP_SERVER:
                he_fallback_address = INADDR_ANY;
                break;
            default:
                OPENSSL_assert(("We forgot to handle a lookup type!" == 0));
                break;
            }
        } else {
            he = gethostbyname(host);

            if (he == NULL) {
#ifndef OPENSSL_SYS_WINDOWS
                BIOerr(BIO_F_BIO_LOOKUP, ERR_R_SYS_LIB);
                ERR_add_error_data(1, hstrerror(h_errno));
#else
                SYSerr(SYS_F_GETHOSTBYNAME, WSAGetLastError());
#endif
                ret = 0;
                goto err;
            }
        }

        if (service == NULL) {
            se_fallback.s_port = 0;
            se_fallback.s_proto = proto;
            se = &se_fallback;
        } else {
            char *endp = NULL;
            long portnum = strtol(service, &endp, 10);

            if (endp != service && *endp == '\0'
                    && portnum > 0 && portnum < 65536) {
                se_fallback.s_port = htons(portnum);
                se_fallback.s_proto = proto;
                se = &se_fallback;
            } else if (endp == service) {
                switch (socktype) {
                case SOCK_STREAM:
                    proto = "tcp";
                    break;
                case SOCK_DGRAM:
                    proto = "udp";
                    break;
                }
                se = getservbyname(service, proto);

                if (se == NULL) {
#ifndef OPENSSL_SYS_WINDOWS
                    BIOerr(BIO_F_BIO_LOOKUP, ERR_R_SYS_LIB);
                    ERR_add_error_data(1, hstrerror(h_errno));
#else
                    SYSerr(SYS_F_GETSERVBYNAME, WSAGetLastError());
#endif
                    goto err;
                }
            } else {
                BIOerr(BIO_F_BIO_LOOKUP, BIO_R_MALFORMED_HOST_OR_SERVICE);
                goto err;
            }
        }

        *res = NULL;

        {
            char **addrlistp;
            size_t addresses;
            BIO_ADDRINFO *tmp_bai = NULL;

            /* The easiest way to create a linked list from an
               array is to start from the back */
            for(addrlistp = he->h_addr_list; *addrlistp != NULL;
                addrlistp++)
                ;

            for(addresses = addrlistp - he->h_addr_list;
                addrlistp--, addresses-- > 0; ) {
                if (!addrinfo_wrap(he->h_addrtype, socktype,
                                   *addrlistp, he->h_length,
                                   se->s_port, &tmp_bai))
                    goto addrinfo_malloc_err;
                tmp_bai->bai_next = *res;
                *res = tmp_bai;
                continue;
             addrinfo_malloc_err:
                BIO_ADDRINFO_free(*res);
                *res = NULL;
                BIOerr(BIO_F_BIO_LOOKUP, ERR_R_MALLOC_FAILURE);
                ret = 0;
                goto err;
            }

            ret = 1;
        }
     err:
        CRYPTO_w_unlock(CRYPTO_LOCK_GETSERVBYNAME);
        CRYPTO_w_unlock(CRYPTO_LOCK_GETHOSTBYNAME);
    }

    return ret;
}
