/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "apps.h"
#include "progs.h"

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_CONFIGDIR, OPT_ENGINESDIR, OPT_MODULESDIR, OPT_DSOEXT, OPT_DIRNAMESEP,
    OPT_LISTSEP,
} OPTION_CHOICE;

const OPTIONS info_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"configdir", OPT_CONFIGDIR, '-', "Default configuration file directory"},
    {"c", OPT_CONFIGDIR, '-', "Default configuration file directory"},
    {"enginesdir", OPT_ENGINESDIR, '-', "Default engine module directory"},
    {"e", OPT_ENGINESDIR, '-', "Default engine module directory"},
    {"modulesdir", OPT_ENGINESDIR, '-',
     "Default module directory (other than engine modules)"},
    {"m", OPT_ENGINESDIR, '-',
     "Default module directory (other than engine modules)"},
    {"dsoext", OPT_DSOEXT, '-', "Configured extension for modules"},
    {"dirnamesep", OPT_DIRNAMESEP, '-', "Directory-filename separator"},
    {"listsep", OPT_LISTSEP, '-', "List separator character"},
    {NULL}
};

int info_main(int argc, char **argv)
{
    int ret = 1, dirty = 0, type = 0;
    char *prog;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, info_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(info_options);
            ret = 0;
            goto end;
        case OPT_CONFIGDIR:
            type = OPENSSL_INFO_CONFIG_DIR;
            dirty++;
            break;
        case OPT_ENGINESDIR:
            type = OPENSSL_INFO_ENGINES_DIR;
            dirty++;
            break;
        case OPT_MODULESDIR:
            type = OPENSSL_INFO_MODULES_DIR;
            dirty++;
            break;
        case OPT_DSOEXT:
            type = OPENSSL_INFO_DSO_EXTENSION;
            dirty++;
            break;
        case OPT_DIRNAMESEP:
            type = OPENSSL_INFO_DIR_FILENAME_SEPARATOR;
            dirty++;
            break;
        case OPT_LISTSEP:
            type = OPENSSL_INFO_LIST_SEPARATOR;
            dirty++;
            break;
        }
    }
    if (opt_num_rest() != 0) {
        BIO_printf(bio_err, "%s: Extra parameters given.\n", prog);
        goto opthelp;
    }
    if (dirty > 1) {
        BIO_printf(bio_err, "%s: Only one item allowed\n", prog);
        goto opthelp;
    }
    if (dirty == 0) {
        BIO_printf(bio_err, "%s: No items chosen\n", prog);
        goto opthelp;
    }

    BIO_printf(bio_out, "%s\n", OPENSSL_info(type));
    ret = 0;
 end:
    return ret;
}
