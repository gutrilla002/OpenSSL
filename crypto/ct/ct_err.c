/* ct_err.c */
/* ====================================================================
 * Copyright (c) 1999-2016 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

/*
 * NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <internal/ct_int.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_CT,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_CT,0,reason)

static ERR_STRING_DATA CT_str_functs[] = {
    {ERR_FUNC(CT_F_D2I_SCT_LIST), "d2i_SCT_LIST"},
    {ERR_FUNC(CT_F_I2D_SCT_LIST), "i2d_SCT_LIST"},
    {ERR_FUNC(CT_F_I2O_SCT), "i2o_SCT"},
    {ERR_FUNC(CT_F_I2O_SCT_LIST), "i2o_SCT_LIST"},
    {ERR_FUNC(CT_F_I2O_SCT_SIGNATURE), "i2o_SCT_signature"},
    {ERR_FUNC(CT_F_O2I_SCT), "o2i_SCT"},
    {ERR_FUNC(CT_F_O2I_SCT_LIST), "o2i_SCT_LIST"},
    {ERR_FUNC(CT_F_O2I_SCT_SIGNATURE), "o2i_SCT_signature"},
    {ERR_FUNC(CT_F_SCT_NEW), "SCT_new"},
    {ERR_FUNC(CT_F_SCT_SET0_LOG_ID), "SCT_set0_log_id"},
    {ERR_FUNC(CT_F_SCT_SET1_EXTENSIONS), "SCT_set1_extensions"},
    {ERR_FUNC(CT_F_SCT_SET1_LOG_ID), "SCT_set1_log_id"},
    {ERR_FUNC(CT_F_SCT_SET1_SIGNATURE), "SCT_set1_signature"},
    {ERR_FUNC(CT_F_SCT_SET_LOG_ENTRY_TYPE), "SCT_set_log_entry_type"},
    {ERR_FUNC(CT_F_SCT_SET_SIGNATURE_NID), "SCT_set_signature_nid"},
    {ERR_FUNC(CT_F_SCT_SET_VERSION), "SCT_set_version"},
    {ERR_FUNC(CT_F_SCT_SIGNATURE_IS_VALID), "SCT_signature_is_valid"},
    {0, NULL}
};

static ERR_STRING_DATA CT_str_reasons[] = {
    {ERR_REASON(CT_R_INVALID_LOG_ID_LENGTH), "invalid log id length"},
    {ERR_REASON(CT_R_SCT_INVALID), "sct invalid"},
    {ERR_REASON(CT_R_SCT_INVALID_SIGNATURE), "sct invalid signature"},
    {ERR_REASON(CT_R_SCT_LIST_INVALID), "sct list invalid"},
    {ERR_REASON(CT_R_SCT_NOT_SET), "sct not set"},
    {ERR_REASON(CT_R_UNRECOGNIZED_SIGNATURE_NID),
     "unrecognized signature nid"},
    {ERR_REASON(CT_R_UNSUPPORTED_ENTRY_TYPE), "unsupported entry type"},
    {ERR_REASON(CT_R_UNSUPPORTED_VERSION), "unsupported version"},
    {0, NULL}
};

#endif

void ERR_load_CT_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(CT_str_functs[0].error) == NULL) {
        ERR_load_strings(0, CT_str_functs);
        ERR_load_strings(0, CT_str_reasons);
    }
#endif
}
