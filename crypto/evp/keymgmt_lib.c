/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "crypto/evp.h"
#include "crypto/asn1.h"
#include "internal/core.h"
#include "internal/provider.h"
#include "evp_local.h"

/*
 * match_type() checks if two EVP_KEYMGMT are matching key types.  This
 * function assumes that the caller has made all the necessary NULL checks.
 */
static int match_type(const EVP_KEYMGMT *keymgmt1, const EVP_KEYMGMT *keymgmt2)
{
    const OSSL_PROVIDER *prov2 = EVP_KEYMGMT_provider(keymgmt2);
    const char *name2 = evp_first_name(prov2, EVP_KEYMGMT_number(keymgmt2));

    return EVP_KEYMGMT_is_a(keymgmt1, name2);
}

struct import_data_st {
    EVP_KEYMGMT *keymgmt;
    void *keydata;

    int selection;
};

static int try_import(const OSSL_PARAM params[], void *arg)
{
    struct import_data_st *data = arg;

    /*
     * It's fine if there was no data to transfer, we just end up with an
     * empty destination key.
     */
    if (params[0].key == NULL)
        return 1;

    /* Just in time creation of keydata, if needed */
    if (data->keydata == NULL
        && (data->keydata = evp_keymgmt_newdata(data->keymgmt)) == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return evp_keymgmt_import(data->keymgmt, data->keydata, data->selection,
                              params);
}

void *evp_keymgmt_util_export_to_provider(EVP_PKEY *pk, EVP_KEYMGMT *keymgmt)
{
    struct import_data_st import_data;
    size_t i = 0;

    /* Export to where? */
    if (keymgmt == NULL)
        return NULL;

    /* If we have an unassigned key, give up */
    if (pk->keydata == NULL)
        return NULL;

    /* If |keymgmt| matches the "origin" |keymgmt|, no more to do */
    if (pk->keymgmt == keymgmt)
        return pk->keydata;

    /* If this key is already exported to |keymgmt|, no more to do */
    i = evp_keymgmt_util_find_operation_cache_index(pk, keymgmt);
    if (i < OSSL_NELEM(pk->operation_cache)
        && pk->operation_cache[i].keymgmt != NULL)
        return pk->operation_cache[i].keydata;

    /* If the "origin" |keymgmt| doesn't support exporting, give up */
    /*
     * TODO(3.0) consider an evp_keymgmt_export() return value that indicates
     * that the method is unsupported.
     */
    if (pk->keymgmt->export == NULL)
        return NULL;

    /* Check that we have found an empty slot in the export cache */
    /*
     * TODO(3.0) Right now, we assume we have ample space.  We will have to
     * think about a cache aging scheme, though, if |i| indexes outside the
     * array.
     */
    if (!ossl_assert(i < OSSL_NELEM(pk->operation_cache)))
        return NULL;

    /*
     * Make sure that the type of the keymgmt to export to matches the type
     * of the "origin"
     */
    if (!ossl_assert(match_type(pk->keymgmt, keymgmt)))
        return NULL;

    /*
     * We look at the already cached provider keys, and import from the
     * first that supports it (i.e. use its export function), and export
     * the imported data to the new provider.
     */

    /* Setup for the export callback */
    import_data.keydata = NULL;  /* try_import will create it */
    import_data.keymgmt = keymgmt;
    import_data.selection = OSSL_KEYMGMT_SELECT_ALL;

    /*
     * The export function calls the callback (try_import), which does the
     * import for us.  If successful, we're done.
     */
    if (!evp_keymgmt_export(pk->keymgmt, pk->keydata, OSSL_KEYMGMT_SELECT_ALL,
                            &try_import, &import_data)) {
        /* If there was an error, bail out */
        evp_keymgmt_freedata(keymgmt, import_data.keydata);
        return NULL;
    }

    /* Add the new export to the operation cache */
    if (!evp_keymgmt_util_cache_keydata(pk, i, keymgmt, import_data.keydata)) {
        evp_keymgmt_freedata(keymgmt, import_data.keydata);
        return NULL;
    }

    return import_data.keydata;
}

void evp_keymgmt_util_clear_operation_cache(EVP_PKEY *pk)
{
    size_t i, end = OSSL_NELEM(pk->operation_cache);

    if (pk != NULL) {
        for (i = 0; i < end && pk->operation_cache[i].keymgmt != NULL; i++) {
            EVP_KEYMGMT *keymgmt = pk->operation_cache[i].keymgmt;
            void *keydata = pk->operation_cache[i].keydata;

            pk->operation_cache[i].keymgmt = NULL;
            pk->operation_cache[i].keydata = NULL;
            evp_keymgmt_freedata(keymgmt, keydata);
            EVP_KEYMGMT_free(keymgmt);
        }
    }
}

size_t evp_keymgmt_util_find_operation_cache_index(EVP_PKEY *pk,
                                                   EVP_KEYMGMT *keymgmt)
{
    size_t i, end = OSSL_NELEM(pk->operation_cache);

    for (i = 0; i < end && pk->operation_cache[i].keymgmt != NULL; i++) {
        if (keymgmt == pk->operation_cache[i].keymgmt)
            break;
    }

    return i;
}

int evp_keymgmt_util_cache_keydata(EVP_PKEY *pk, size_t index,
                                   EVP_KEYMGMT *keymgmt, void *keydata)
{
    if (keydata != NULL) {
        if (!EVP_KEYMGMT_up_ref(keymgmt))
            return 0;
        pk->operation_cache[index].keydata = keydata;
        pk->operation_cache[index].keymgmt = keymgmt;
    }
    return 1;
}

void evp_keymgmt_util_cache_keyinfo(EVP_PKEY *pk)
{
    /*
     * Cache information about the provider "origin" key.
     *
     * This services functions like EVP_PKEY_size, EVP_PKEY_bits, etc
     */
    if (pk->keydata != NULL) {
        int bits = 0;
        int security_bits = 0;
        int size = 0;
        OSSL_PARAM params[4];

        params[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, &bits);
        params[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_SECURITY_BITS,
                                             &security_bits);
        params[2] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_MAX_SIZE, &size);
        params[3] = OSSL_PARAM_construct_end();
        if (evp_keymgmt_get_params(pk->keymgmt, pk->keydata, params)) {
            pk->cache.size = size;
            pk->cache.bits = bits;
            pk->cache.security_bits = security_bits;
        }
    }
}

void *evp_keymgmt_util_fromdata(EVP_PKEY *target, EVP_KEYMGMT *keymgmt,
                                int selection, const OSSL_PARAM params[])
{
    void *keydata = NULL;

    if ((keydata = evp_keymgmt_newdata(keymgmt)) == NULL
        || !evp_keymgmt_import(keymgmt, keydata, selection, params)
        || !EVP_PKEY_set_type_by_keymgmt(target, keymgmt)) {
        evp_keymgmt_freedata(keymgmt, keydata);
        keydata = NULL;
    }
    if (keydata != NULL) {
        target->keydata = keydata;
        evp_keymgmt_util_cache_keyinfo(target);
    }

    return keydata;
}

int evp_keymgmt_util_has(EVP_PKEY *pk, int selection)
{
    /* Check if key is even assigned */
    if (pk->keymgmt == NULL)
        return 0;

    return evp_keymgmt_has(pk->keymgmt, pk->keydata, selection);
}

/*
 * evp_keymgmt_util_match() doesn't just look at the provider side "origin",
 * but also in the operation cache to see if there's any common keymgmt that
 * supplies OP_keymgmt_match.
 *
 * evp_keymgmt_util_match() adheres to the return values that EVP_PKEY_eq()
 * and EVP_PKEY_parameters_eq() return, i.e.:
 *
 *  1   same key
 *  0   not same key
 * -1   not same key type
 * -2   unsupported operation
 */
int evp_keymgmt_util_match(EVP_PKEY *pk1, EVP_PKEY *pk2, int selection)
{
    EVP_KEYMGMT *keymgmt1 = NULL, *keymgmt2 = NULL;
    void *keydata1 = NULL, *keydata2 = NULL;

    if (pk1 == NULL || pk2 == NULL) {
        if (pk1 == NULL && pk2 == NULL)
            return 1;
        return 0;
    }

    keymgmt1 = pk1->keymgmt;
    keydata1 = pk1->keydata;
    keymgmt2 = pk2->keymgmt;
    keydata2 = pk2->keydata;

    if (keymgmt1 != keymgmt2) {
        /*
         * The condition for a successful cross export is that the
         * keydata to be exported is NULL (typed, but otherwise empty
         * EVP_PKEY), or that it was possible to export it with
         * evp_keymgmt_util_export_to_provider().
         *
         * We use |ok| to determine if it's ok to cross export one way,
         * but also to determine if we should attempt a cross export
         * the other way.  There's no point doing it both ways.
         */
        int ok = 1;

        /* Complex case, where the keymgmt differ */
        if (keymgmt1 != NULL
            && keymgmt2 != NULL
            && !match_type(keymgmt1, keymgmt2)) {
            ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES);
            return -1;           /* Not the same type */
        }

        /*
         * The key types are determined to match, so we try cross export,
         * but only to keymgmt's that supply a matching function.
         */
        if (keymgmt2 != NULL
            && keymgmt2->match != NULL) {
            void *tmp_keydata = NULL;

            ok = 1;
            if (keydata1 != NULL) {
                tmp_keydata =
                    evp_keymgmt_util_export_to_provider(pk1, keymgmt2);
                ok = (tmp_keydata != NULL);
            }
            if (ok) {
                keymgmt1 = keymgmt2;
                keydata1 = tmp_keydata;
            }
        }
        /*
         * If we've successfully cross exported one way, there's no point
         * doing it the other way, hence the |!ok| check.
         */
        if (!ok
            && keymgmt1 != NULL
            && keymgmt1->match != NULL) {
            void *tmp_keydata = NULL;

            ok = 1;
            if (keydata2 != NULL) {
                tmp_keydata =
                    evp_keymgmt_util_export_to_provider(pk2, keymgmt1);
                ok = (tmp_keydata != NULL);
            }
            if (ok) {
                keymgmt2 = keymgmt1;
                keydata2 = tmp_keydata;
            }
        }
    }

    /* If we still don't have matching keymgmt implementations, we give up */
    if (keymgmt1 != keymgmt2)
        return -2;

    /* If both keydata are NULL, then they're the same key */
    if (keydata1 == NULL && keydata2 == NULL)
        return 1;
    /* If only one of the keydata is NULL, then they're different keys */
    if (keydata1 == NULL || keydata2 == NULL)
        return 0;
    /* If both keydata are non-NULL, we let the backend decide */
    return evp_keymgmt_match(keymgmt1, keydata1, keydata2, selection);
}

int evp_keymgmt_util_copy(EVP_PKEY *to, EVP_PKEY *from, int selection)
{
    /* Save copies of pointers we want to play with without affecting |to| */
    EVP_KEYMGMT *to_keymgmt = to->keymgmt;
    void *to_keydata = to->keydata, *alloc_keydata = NULL;

    /* An unassigned key can't be copied */
    if (from == NULL || from->keydata == NULL)
        return 0;

    /*
     * If |to| is unassigned, ensure it gets the same KEYMGMT as |from|,
     * Note that the final setting of KEYMGMT is done further down, with
     * EVP_PKEY_set_type_by_keymgmt(); we don't want to do that prematurely.
     */
    if (to_keymgmt == NULL)
        to_keymgmt = from->keymgmt;

    if (to_keymgmt == from->keymgmt && to_keymgmt->copy != NULL) {
        /* Make sure there's somewhere to copy to */
        if (to_keydata == NULL
            && ((to_keydata = alloc_keydata = evp_keymgmt_newdata(to_keymgmt))
                == NULL)) {
            ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        /*
         * |to| and |from| have the same keymgmt, and the copy function is
         * implemented, so just copy and be done
         */
        if (!evp_keymgmt_copy(to_keymgmt, to_keydata, from->keydata,
                              selection))
            return 0;
    } else if (match_type(to_keymgmt, from->keymgmt)) {
        struct import_data_st import_data;

        import_data.keymgmt = to_keymgmt;
        import_data.keydata = to_keydata;
        import_data.selection = selection;

        if (!evp_keymgmt_export(from->keymgmt, from->keydata, selection,
                                &try_import, &import_data)) {
            evp_keymgmt_freedata(to_keymgmt, alloc_keydata);
            return 0;
        }

        /*
         * In case to_keydata was previously unallocated, try_import()
         * may have created it for us.
         */
        if (to_keydata == NULL)
            to_keydata = alloc_keydata = import_data.keydata;
    } else {
        ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES);
        return 0;
    }

    if (to->keymgmt == NULL
        && !EVP_PKEY_set_type_by_keymgmt(to, to_keymgmt)) {
        evp_keymgmt_freedata(to_keymgmt, alloc_keydata);
        return 0;
    }
    to->keydata = to_keydata;
    evp_keymgmt_util_cache_keyinfo(to);

    return 1;
}

void *evp_keymgmt_util_gen(EVP_PKEY *target, EVP_KEYMGMT *keymgmt,
                           void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    void *keydata = NULL;

    if ((keydata = evp_keymgmt_gen(keymgmt, genctx, cb, cbarg)) == NULL
        || !EVP_PKEY_set_type_by_keymgmt(target, keymgmt)) {
        evp_keymgmt_freedata(keymgmt, keydata);
        keydata = NULL;
    }
    if (keydata != NULL) {
        target->keydata = keydata;
        evp_keymgmt_util_cache_keyinfo(target);
    }

    return keydata;
}

/*
 * Returns the same numbers as EVP_PKEY_get_default_digest_name()
 * When the string from the EVP_KEYMGMT implementation is "", we use
 * SN_undef, since that corresponds to what EVP_PKEY_get_default_nid()
 * returns for no digest.
 */
int evp_keymgmt_util_get_deflt_digest_name(EVP_KEYMGMT *keymgmt,
                                           void *keydata,
                                           char *mdname, size_t mdname_sz)
{
    OSSL_PARAM params[3];
    char mddefault[100] = "";
    char mdmandatory[100] = "";
    char *result = NULL;
    int rv = -2;

    params[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST,
                                         mddefault, sizeof(mddefault));
    params[1] =
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST,
                                         mdmandatory,
                                         sizeof(mdmandatory));
    params[2] = OSSL_PARAM_construct_end();

    if (!evp_keymgmt_get_params(keymgmt, keydata, params))
        return 0;

    if (OSSL_PARAM_modified(params + 1)) {
        if (params[1].return_size <= 1) /* Only a NUL byte */
            result = SN_undef;
        else
            result = mdmandatory;
        rv = 2;
    } else if (OSSL_PARAM_modified(params)) {
        if (params[0].return_size <= 1) /* Only a NUL byte */
            result = SN_undef;
        else
            result = mddefault;
        rv = 1;
    }
    if (rv > 0)
        OPENSSL_strlcpy(mdname, result, mdname_sz);
    return rv;
}
