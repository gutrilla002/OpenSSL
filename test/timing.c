/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * I compiled this in the source tree this way:
 *      gcc -g -Iinclude a.c libcrypto.a -ldl -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <sys/time.h>
#include <sys/resource.h>

static char *prog = "./a.out";

static void readx509(const char *contents, int size)
{
    X509 *x = NULL;
    BIO *b = BIO_new_mem_buf(contents, size);

    if (b == NULL)
        ERR_print_errors_fp(stderr), exit(1);
    PEM_read_bio_X509(b, &x, 0, NULL);
    if (x == NULL)
        ERR_print_errors_fp(stderr), exit(1);
    X509_free(x);
    BIO_free(b);
}

static void readpkey(const char *contents, int size)
{
    BIO *b = BIO_new_mem_buf(contents, size);
    EVP_PKEY *pkey;

    if (b == NULL)
        ERR_print_errors_fp(stderr), exit(1);
    pkey = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    if (pkey == NULL)
        ERR_print_errors_fp(stderr), exit(1);

    EVP_PKEY_free(pkey);
    BIO_free(b);
}


static void print(const char *what, struct timeval *tp)
{
    printf("%s %ld sec %ld microsec\n", what, tp->tv_sec, tp->tv_usec);
}

static void usage(void)
{
    fprintf(stderr, "Usage: %s [flags] pem-file\n", prog);
    fprintf(stderr, "Flags:\n");
    fprintf(stderr, "  -c #  Repeat count\n");
    fprintf(stderr, "  -d    Debugging output (minimal)\n");
    fprintf(stderr, "  -w C  What to load C is a single character:\n");
    fprintf(stderr, "          c for cert (default)\n");
    fprintf(stderr, "          p for private key\n");
    exit(1);
}

int main(int ac, char **av)
{
    int i, debug = 0, count = 100, what = 'c';
    struct stat sb;
    FILE *fp;
    char *contents;
    struct rusage now, start, end, elapsed;
    struct timeval e_start, e_end, e_elapsed;

    /* Parse JCL. */
    prog = av[0];
    while ((i = getopt(ac, av, "c:dw:")) != EOF) {
        switch (i) {
        default:
            usage();
        case 'c':
            if ((count = atoi(optarg)) < 0)
                usage();
            break;
        case 'd':
            debug = 1;
            break;
        case 'w':
            if (optarg[1] != '\0')
                usage;
            switch (*optarg) {
            default:
                usage();
            case 'c':
            case 'p':
                what = *optarg;
                break;
            }
            break;
        }
    }
    ac -= optind;
    av += optind;

    /* Read input file. */
    if (av[0] == NULL)
        usage();
    if (stat(av[0], &sb) < 0)
        perror(av[0]), exit(1);
    contents = malloc(sb.st_size + 1);
    if (contents == NULL)
        perror("malloc"), exit(1);
    fp = fopen(av[0], "r");
    if (fread(contents, 1, sb.st_size, fp) != sb.st_size)
        perror("fread"), exit(1);
    contents[sb.st_size] = '\0';
    fclose(fp);
    if (debug)
        printf(">%s<\n", contents);

    /* Try to prep system cache, etc. */
    for (i = 10; --i >= 0; ) {
        switch (what) {
        case 'c':
            readx509(contents, (int)sb.st_size);
            break;
        case 'p':
            readpkey(contents, (int)sb.st_size);
            break;
        }
    }

    if (gettimeofday(&e_start, NULL) < 0)
        perror("elapsed start"), exit(1);
    if (getrusage(RUSAGE_SELF, &start) < 0)
        perror("start"), exit(1);
    for (i = count; --i >= 0; ) {
        switch (what) {
        case 'c':
            readx509(contents, (int)sb.st_size);
            break;
        case 'p':
            readpkey(contents, (int)sb.st_size);
            break;
        }
    }
    if (getrusage(RUSAGE_SELF, &end) < 0)
        perror("end"), exit(1);
    if (gettimeofday(&e_end, NULL) < 0)
        perror("end"), exit(1);

    timersub(&end.ru_utime, &start.ru_stime, &elapsed.ru_stime);
    timersub(&end.ru_utime, &start.ru_utime, &elapsed.ru_utime);
    timersub(&e_end, &e_start, &e_elapsed);
    print("user     ", &elapsed.ru_utime);
    print("sys      ", &elapsed.ru_stime);
    if (debug)
        print("elapsed??", &e_elapsed);
    return 0;
}
