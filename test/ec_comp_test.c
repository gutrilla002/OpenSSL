#include "testutil.h"
#include "internal/nelem.h"
#include <string.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>
#endif

#ifndef OPENSSL_NO_EC

static size_t num_known_curves;
static EC_builtin_curve *known_curves;
static const char **known_curve_names;
static int nid_Oakley_EC2N_3;
static int nid_Oakley_EC2N_4;

static const char *const comp_formats[] = {
    "uncompressed",
    "compressed",
    "hybrid",
    "UNSPECIFIED",
};

static const int comp_formats_i[] = {
    POINT_CONVERSION_UNCOMPRESSED,
    POINT_CONVERSION_COMPRESSED,
    POINT_CONVERSION_HYBRID,
    -1,
};

static const char *const param_formats[] = {
    "named_curve",
    "explicit",
    "UNSPECIFIED",
};

static const int param_formats_i[] = {
    OPENSSL_EC_NAMED_CURVE,
    0,
    -1,
};

enum {
    KEY_SRC_EXISTING,
    KEY_SRC_GENERATE
};

enum {
    OBJ_TYPE_PARAMS,
    OBJ_TYPE_KEY
};

static int init_curves(void)
{
    size_t i;

    num_known_curves = EC_get_builtin_curves(NULL, 0);
    known_curves = OPENSSL_malloc(num_known_curves*sizeof(*known_curves));
    if (   known_curves == NULL
        || EC_get_builtin_curves(known_curves, num_known_curves) == 0)
        goto fail;

    known_curve_names = OPENSSL_malloc(sizeof(char *)*num_known_curves);
    if (known_curve_names == NULL)
        goto fail;

    for (i=0; i<num_known_curves; ++i) {
        known_curve_names[i] = OBJ_nid2sn(known_curves[i].nid);
        if (!strcmp(known_curve_names[i], "Oakley-EC2N-3"))
            nid_Oakley_EC2N_3 = known_curves[i].nid;
        if (!strcmp(known_curve_names[i], "Oakley-EC2N-4"))
            nid_Oakley_EC2N_4 = known_curves[i].nid;
    }

    return 1;

fail:
    OPENSSL_free(known_curves);
    known_curves = NULL;
    OPENSSL_free(known_curve_names);
    known_curve_names = NULL;
    return 0;
}

static int should_skip(size_t curve_i, size_t param_format_i, size_t comp_format_i, size_t key_src)
{
    /*
     * If we are loading an existing key it does not make sense to test
     * unspecified formats, since we know what format is used.
     */
    if (   key_src == KEY_SRC_EXISTING
        && (   comp_formats_i[comp_format_i] < 0
            || param_formats_i[param_format_i] < 0))
        return 1;

    /* Skip experimental curves, which behave oddly */
    if (known_curves[curve_i].nid == nid_Oakley_EC2N_3)
        return 1;
    if (known_curves[curve_i].nid == nid_Oakley_EC2N_4)
        return 1;
    return 0;
}

static EC_KEY *generate_new_key(size_t curve_i, size_t param_format_i,
                                size_t comp_format_i, size_t obj_type)
{
    EC_KEY *k = NULL;
    EC_GROUP *g = NULL;

    int asn1_flag = param_formats_i[param_format_i];
    int point_form = comp_formats_i[comp_format_i];

    g = EC_GROUP_new_by_curve_name(known_curves[curve_i].nid);
    if (g == NULL)
        goto fail;

    if (asn1_flag >= 0)
        EC_GROUP_set_asn1_flag(g, asn1_flag);
    if (point_form >= 0)
        EC_GROUP_set_point_conversion_form(g, point_form);

    k = EC_KEY_new();
    if (k == NULL)
        goto fail;

    if (EC_KEY_set_group(k, g) == 0)
        goto fail;

    EC_GROUP_free(g);
    g = NULL;

    if (EC_KEY_generate_key(k) == 0)
        goto fail;

    return k;

fail:
    EC_KEY_free(k);
    EC_GROUP_free(g);
    return NULL;
}

static EC_KEY *get_existing_key(size_t curve_i, size_t param_format_i,
                                size_t comp_format_i, size_t obj_type)
{
    EC_KEY *k = NULL, *res = NULL;
    EC_GROUP *g = NULL;
    FILE *f = NULL;
    BIO *b = NULL;
    char filename[256];

    OPENSSL_assert(param_formats_i[param_format_i] >= 0);
    OPENSSL_assert(comp_formats_i[comp_format_i] >= 0);

    if (obj_type == OBJ_TYPE_PARAMS)
        snprintf(filename, sizeof(filename), "../recipes/15-test_ec_comp_data/%s-%s.param",
                 known_curve_names[curve_i],
                 param_formats[param_format_i]);
    else
        snprintf(filename, sizeof(filename), "../recipes/15-test_ec_comp_data/%s-%s-%s.priv",
                 known_curve_names[curve_i],
                 param_formats[param_format_i],
                 comp_formats[comp_format_i]);

    b = BIO_new(BIO_s_file());
    if (b == NULL)
        goto fail;

    f = fopen(filename, "rb");
    if (f == NULL)
        return NULL;

    BIO_set_fp(b, f, BIO_NOCLOSE);

    if (obj_type == OBJ_TYPE_PARAMS) {
        if (PEM_read_bio_ECPKParameters(b, &g, NULL, NULL) == 0)
            goto fail;

        k = EC_KEY_new();
        if (k == NULL)
            goto fail;

        if (EC_KEY_set_group(k, g) == 0)
            goto fail;

        EC_GROUP_free(g);
        g = NULL;
    } else {
        if (PEM_read_bio_ECPrivateKey(b, &k, NULL, NULL) == 0)
            goto fail;
    }

    res = k;
    k = NULL;
fail:
    EC_GROUP_free(g);
    EC_KEY_free(k);
    BIO_free(b);
    fclose(f);
    return res;
}

static int verify_expected(int param_format, int comp_format, int asn1_flag, int point_form, int obj_type)
{
    if (obj_type == OBJ_TYPE_KEY) {
        /* Only makes sense to test comp format on key */
        if (comp_format >= 0) {
            /*
             * If a compression format was specified, it must be used; however
             * when deserializing conversion to uncompressed always occurs in
             * 1.1
             */
            if (!TEST_int_eq(comp_format, point_form))
                return 0;
        } else {
            /*
             * If a compression format was not specified, uncompressed should be
             * default
             */
            if (!TEST_int_eq(POINT_CONVERSION_UNCOMPRESSED, point_form))
                return 0;
        }
    }

    if (param_format >= 0) {
        /* If a parameter format was specified, it must be used */
        if (!TEST_int_eq(param_format, asn1_flag))
            return 0;
    } else {
        /* If a parameter format was not specified, expect named curve */
        if (!TEST_int_eq(OPENSSL_EC_NAMED_CURVE, asn1_flag))
            return 0;
    }

    return 1;
}

static int test_reserialize(EC_KEY *k,
                            int param_format,
                            int comp_format,
                            int new_param_format,
                            int new_comp_format,
                            size_t key_src,
                            size_t obj_type)
{
    int rv = 0, res_asn1_flag, res_point_form, buf_len;
    unsigned char *buf = NULL, *bufi;
    EC_KEY *k2 = NULL;
    EC_GROUP *g = NULL;
    const EC_GROUP *gref = NULL;

    /*
     * Duplicate k so our changing parameters below does not
     * affect other tests
     */
    k = EC_KEY_dup(k);
    if (k == NULL)
        goto fail;

    if (new_param_format >= 0)
        EC_KEY_set_asn1_flag(k, new_param_format);
    else
        new_param_format = param_format;

    if (new_comp_format >= 0)
        EC_KEY_set_conv_form(k, new_comp_format);
    else if (key_src == KEY_SRC_GENERATE)
        /*
         * If we just generated our key we effectively already set the format,
         * so we need to expect that rather than the default. Otherwise expect
         * reversion to uncompressed.
         */
        new_comp_format = comp_format;
    else
        new_comp_format = POINT_CONVERSION_UNCOMPRESSED;

    if (obj_type == OBJ_TYPE_KEY) {
        /* If we are checking a private key: */
        if (!EC_KEY_check_key(k))
            goto fail;

        buf_len = i2d_ECPrivateKey(k, &buf);
        if (buf_len <= 0 || buf == NULL)
            goto fail;

        bufi = buf;
        k2 = d2i_ECPrivateKey(NULL, (const unsigned char **)&bufi, buf_len);
        if (k2 == NULL)
            goto fail;

        /*
         * When we put keys through serialization and then deserialization, they
         * always become uncompressed. (The same is not true for parameters,
         * however.)
         */
        new_comp_format = POINT_CONVERSION_UNCOMPRESSED;
        gref = EC_KEY_get0_group(k2);
    } else {
        buf_len = i2d_ECPKParameters(EC_KEY_get0_group(k), &buf);
        if (buf_len <= 0 || buf == NULL)
            goto fail;

        bufi = buf;
        gref = g = d2i_ECPKParameters(NULL, (const unsigned char **)&bufi, buf_len);
        if (gref == NULL)
            goto fail;
    }

    res_asn1_flag = EC_GROUP_get_asn1_flag(gref);
    res_point_form = EC_GROUP_get_point_conversion_form(gref);

    if (!verify_expected(new_param_format, new_comp_format, res_asn1_flag, res_point_form, obj_type))
        goto fail;

    rv = 1;
fail:
    EC_KEY_free(k2);
    EC_KEY_free(k);
    EC_GROUP_free(g);
    OPENSSL_free(buf);
    return rv;
}

static int comp_test_actual(size_t curve_i,
                            size_t param_format_i,
                            size_t comp_format_i,
                            size_t key_src /* KEY_SRC_{EXISTING,GENERATE} */,
                            size_t obj_type /* OBJ_TYPE_{PARAMS,KEY} */)
{
    int rc = 0;
    EC_KEY *k = NULL;
    int expected_param_format, expected_comp_format;
    int res_asn1_flag, res_point_form;
    size_t ci, pi;

    if (should_skip(curve_i, param_format_i, comp_format_i, key_src))
        return 1;

    /* Load or generate key. */
    k = (key_src == KEY_SRC_EXISTING)
        ? get_existing_key(curve_i,
                           param_format_i,
                           comp_format_i,
                           obj_type)
        : generate_new_key(curve_i,
                           param_format_i,
                           comp_format_i,
                           obj_type);
    if (k == NULL)
        goto fail;

    /* Verify param/compression formats on loaded/generated key directly. */
    res_asn1_flag = EC_GROUP_get_asn1_flag(EC_KEY_get0_group(k));
    res_point_form = EC_GROUP_get_point_conversion_form(EC_KEY_get0_group(k));

    expected_param_format = param_formats_i[param_format_i];
    expected_comp_format = comp_formats_i[comp_format_i];
    if (key_src == KEY_SRC_EXISTING)
        expected_comp_format = POINT_CONVERSION_UNCOMPRESSED;

    if (!verify_expected(expected_param_format, expected_comp_format,
                         res_asn1_flag, res_point_form, obj_type))
        goto fail;

    /*
     * Test parameter/compression behaviour when round tripping through
     * serialization and deserialization.
     */
    /* For each supported compression format (and unspecified) */
    for (ci=0; ci<OSSL_NELEM(comp_formats_i); ++ci)
        /* For each of (named parameters, explicit parameters, unspecified) */
        for (pi=0; pi<OSSL_NELEM(param_formats_i); ++pi)
            if (!test_reserialize(k, param_formats_i[param_format_i], comp_formats_i[comp_format_i],
                                  param_formats_i[pi], comp_formats_i[ci], key_src, obj_type))
                goto fail;

    rc = 1;
fail:
    EC_KEY_free(k);
    return rc;
}

static int from_deserialized_test(int curve_i, int obj_type)
{
    size_t comp_format_i, param_format_i;

    /* For each of (named parameters, explicit parameters, unspecified) */
    for (param_format_i=0; param_format_i<3; ++param_format_i)
        /* For each supported compression format (and unspecified) */
        for (comp_format_i=0;
             comp_format_i<OSSL_NELEM(comp_formats);
             ++comp_format_i)
            if (comp_test_actual(curve_i, param_format_i,
                                 comp_format_i, KEY_SRC_EXISTING, obj_type) == 0)
                    return 0;

    return 1;
}

static int from_generated_test(int curve_i, int obj_type)
{
    size_t comp_format_i, param_format_i;

    /* For each of (named parameters, explicit parameters, unspecified) */
    for (param_format_i=0; param_format_i<3; ++param_format_i)
        /* For each supported compression format (and unspecified) */
        for (comp_format_i=0;
             comp_format_i<OSSL_NELEM(comp_formats);
             ++comp_format_i)
            if (comp_test_actual(curve_i, param_format_i,
                                 comp_format_i, KEY_SRC_GENERATE, obj_type) == 0)
                    return 0;

    return 1;
}

static int from_deserialized_params_test(int curve_i)
{
    return from_deserialized_test(curve_i, OBJ_TYPE_PARAMS);
}

static int from_deserialized_key_test(int curve_i)
{
    return from_deserialized_test(curve_i, OBJ_TYPE_KEY);
}

static int from_generated_params_test(int curve_i)
{
    return from_generated_test(curve_i, OBJ_TYPE_PARAMS);
}

static int from_generated_key_test(int curve_i)
{
    return from_generated_test(curve_i, OBJ_TYPE_KEY);
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_EC
    if (init_curves() == 0)
        return 0;

    ADD_ALL_TESTS(from_deserialized_params_test, num_known_curves);
    ADD_ALL_TESTS(from_deserialized_key_test, num_known_curves);
    ADD_ALL_TESTS(from_generated_params_test, num_known_curves);
    ADD_ALL_TESTS(from_generated_key_test, num_known_curves);
#endif
    return 1;
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_EC
    OPENSSL_free(known_curves);
    known_curves = NULL;
    OPENSSL_free(known_curve_names);
    known_curve_names = NULL;
#endif
}
