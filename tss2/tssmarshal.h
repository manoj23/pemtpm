/********************************************************************************/
/*										*/
/*			 TSS Marshal and Unmarshal    				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssmarshal.h 886 2016-12-21 17:22:26Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* This is a semi-public header. The API should be stable, but is less guaranteed.

   It is useful for applications that have to marshal / unmarshal
   structures for file save / load.
*/

#ifndef TSSMARSHAL_H
#define TSSMARSHAL_H

#ifndef TPM_TSS
#define TPM_TSS
#endif

#include "BaseTypes.h"
#include <tss2/TPM_Types.h>

#include "Import_fp.h"

TPM_RC
TSS_Import_In_Marshal(const Import_In *source, UINT16 *written, BYTE **buffer, INT32 *size);

LIB_EXPORT TPM_RC
TSS_UINT8_Marshal(const UINT8 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_INT8_Marshal(const INT8 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_UINT16_Marshal(const UINT16 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_UINT32_Marshal(const UINT32 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_INT32_Marshal(const INT32 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_UINT64_Marshal(const UINT64 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_Array_Marshal(const BYTE *source, UINT16 sourceSize, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_Marshal(const TPM2B *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_KEY_BITS_Marshal(const TPM_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_GENERATED_Marshal(const TPM_GENERATED *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_ALG_ID_Marshal(const TPM_ALG_ID *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_ECC_CURVE_Marshal(const TPM_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_RC_Marshal(const TPM_RC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_CLOCK_ADJUST_Marshal(const TPM_CLOCK_ADJUST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_EO_Marshal(const TPM_EO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_ST_Marshal(const TPM_ST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_SU_Marshal(const TPM_ST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_SE_Marshal(const TPM_SE  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_CAP_Marshal(const TPM_CAP *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_PT_Marshal(const TPM_PT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_PT_PCR_Marshal(const TPM_PT_PCR *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_HANDLE_Marshal(const TPM_HANDLE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_ALGORITHM_Marshal(const TPMA_ALGORITHM *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_OBJECT_Marshal(const TPMA_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_SESSION_Marshal(const TPMA_SESSION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_LOCALITY_Marshal(const TPMA_LOCALITY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM_CC_Marshal(const TPM_CC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_CC_Marshal(const TPMA_CC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_YES_NO_Marshal(const TPMI_YES_NO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_DH_OBJECT_Marshal(const TPMI_DH_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_DH_PERSISTENT_Marshal(const TPMI_DH_PERSISTENT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_DH_ENTITY_Marshal(const TPMI_DH_ENTITY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_DH_PCR_Marshal(const TPMI_DH_PCR  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_SH_AUTH_SESSION_Marshal(const TPMI_SH_AUTH_SESSION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_SH_HMAC_Marshal(const TPMI_SH_HMAC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_SH_POLICY_Marshal(const TPMI_SH_POLICY*source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_DH_CONTEXT_Marshal(const TPMI_DH_CONTEXT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_HIERARCHY_Marshal(const TPMI_RH_HIERARCHY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_ENABLES_Marshal(const TPMI_RH_ENABLES *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_HIERARCHY_AUTH_Marshal(const TPMI_RH_HIERARCHY_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_PLATFORM_Marshal(const TPMI_RH_PLATFORM *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_ENDORSEMENT_Marshal(const TPMI_RH_ENDORSEMENT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_PROVISION_Marshal(const TPMI_RH_PROVISION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_CLEAR_Marshal(const TPMI_RH_CLEAR *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_NV_AUTH_Marshal(const TPMI_RH_NV_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_LOCKOUT_Marshal(const TPMI_RH_LOCKOUT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RH_NV_INDEX_Marshal(const TPMI_RH_NV_INDEX *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_HASH_Marshal(const TPMI_ALG_HASH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_SYM_Marshal(const TPMI_ALG_SYM *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_SYM_OBJECT_Marshal(const TPMI_ALG_SYM_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_SYM_MODE_Marshal(const TPMI_ALG_SYM_MODE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_KDF_Marshal(const TPMI_ALG_KDF *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_SIG_SCHEME_Marshal(const TPMI_ALG_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ECC_KEY_EXCHANGE_Marshal(const TPMI_ECC_KEY_EXCHANGE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ST_COMMAND_TAG_Marshal(const TPMI_ST_COMMAND_TAG *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_HA_Marshal(const TPMU_HA *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_HA_Marshal(const TPMT_HA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_DIGEST_Marshal(const TPM2B_DIGEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_DATA_Marshal(const TPM2B_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_NONCE_Marshal(const TPM2B_NONCE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_AUTH_Marshal(const TPM2B_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_OPERAND_Marshal(const TPM2B_OPERAND *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_EVENT_Marshal(const TPM2B_EVENT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_MAX_BUFFER_Marshal(const TPM2B_MAX_BUFFER *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_MAX_NV_BUFFER_Marshal(const TPM2B_MAX_NV_BUFFER *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_TIMEOUT_Marshal(const TPM2B_TIMEOUT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_IV_Marshal(const TPM2B_IV *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_NAME_Marshal(const TPM2B_NAME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_PCR_SELECTION_Marshal(const TPMS_PCR_SELECTION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_TK_CREATION_Marshal(const TPMT_TK_CREATION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_TK_VERIFIED_Marshal(const TPMT_TK_VERIFIED *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_TK_AUTH_Marshal(const TPMT_TK_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_TK_HASHCHECK_Marshal(const TPMT_TK_HASHCHECK *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ALG_PROPERTY_Marshal(const TPMS_ALG_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_TAGGED_PROPERTY_Marshal(const TPMS_TAGGED_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_TAGGED_PCR_SELECT_Marshal(const TPMS_TAGGED_PCR_SELECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_CC_Marshal(const TPML_CC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_CCA_Marshal(const TPML_CCA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_ALG_Marshal(const TPML_ALG *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_HANDLE_Marshal(const TPML_HANDLE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_DIGEST_Marshal(const TPML_DIGEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_DIGEST_VALUES_Marshal(const TPML_DIGEST_VALUES *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_PCR_SELECTION_Marshal(const TPML_PCR_SELECTION *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_ALG_PROPERTY_Marshal(const TPML_ALG_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_TAGGED_TPM_PROPERTY_Marshal(const TPML_TAGGED_TPM_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_TAGGED_PCR_PROPERTY_Marshal(const TPML_TAGGED_PCR_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPML_ECC_CURVE_Marshal(const TPML_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_CAPABILITIES_Marshal(const TPMU_CAPABILITIES *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMS_CAPABILITY_DATA_Marshal(const TPMS_CAPABILITY_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_CLOCK_INFO_Marshal(const TPMS_CLOCK_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_TIME_INFO_Marshal(const TPMS_TIME_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_TIME_ATTEST_INFO_Marshal(const TPMS_TIME_ATTEST_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_CERTIFY_INFO_Marshal(const TPMS_CERTIFY_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_QUOTE_INFO_Marshal(const TPMS_QUOTE_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_COMMAND_AUDIT_INFO_Marshal(const TPMS_COMMAND_AUDIT_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SESSION_AUDIT_INFO_Marshal(const TPMS_SESSION_AUDIT_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_CREATION_INFO_Marshal(const TPMS_CREATION_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_NV_CERTIFY_INFO_Marshal(const TPMS_NV_CERTIFY_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ST_ATTEST_Marshal(const TPMI_ST_ATTEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_ATTEST_Marshal(const TPMU_ATTEST  *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMS_ATTEST_Marshal(const TPMS_ATTEST  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_ATTEST_Marshal(const TPM2B_ATTEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_AUTH_COMMAND_Marshal(const TPMS_AUTH_COMMAND *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_AES_KEY_BITS_Marshal(const TPMI_AES_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_SYM_KEY_BITS_Marshal(const TPMU_SYM_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMU_SYM_MODE_Marshal(const TPMU_SYM_MODE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_SYM_DEF_Marshal(const TPMT_SYM_DEF *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_SYM_DEF_OBJECT_Marshal(const TPMT_SYM_DEF_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_SYM_KEY_Marshal(const TPM2B_SYM_KEY *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_LABEL_Marshal(const TPM2B_LABEL *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SYMCIPHER_PARMS_Marshal(const TPMS_SYMCIPHER_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_SENSITIVE_DATA_Marshal(const TPM2B_SENSITIVE_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SENSITIVE_CREATE_Marshal(const TPMS_SENSITIVE_CREATE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_SENSITIVE_CREATE_Marshal(const TPM2B_SENSITIVE_CREATE  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_HASH_Marshal(const TPMS_SCHEME_HASH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_ECDAA_Marshal(const TPMS_SCHEME_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_KEYEDHASH_SCHEME_Marshal(const TPMI_ALG_KEYEDHASH_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_HMAC_Marshal(const TPMS_SCHEME_HMAC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_XOR_Marshal(const TPMS_SCHEME_XOR *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_SCHEME_KEYEDHASH_Marshal(const TPMU_SCHEME_KEYEDHASH *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_KEYEDHASH_SCHEME_Marshal(const TPMT_KEYEDHASH_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_RSASSA_Marshal(const TPMS_SIG_SCHEME_RSASSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_RSAPSS_Marshal(const TPMS_SIG_SCHEME_RSAPSS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_ECDSA_Marshal(const TPMS_SIG_SCHEME_ECDSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_SM2_Marshal(const TPMS_SIG_SCHEME_SM2 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshal(const TPMS_SIG_SCHEME_ECSCHNORR *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIG_SCHEME_ECDAA_Marshal(const TPMS_SIG_SCHEME_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_SIG_SCHEME_Marshal(const TPMU_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_SIG_SCHEME_Marshal(const TPMT_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ENC_SCHEME_OAEP_Marshal(const TPMS_ENC_SCHEME_OAEP *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ENC_SCHEME_RSAES_Marshal(const TPMS_ENC_SCHEME_RSAES *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_KEY_SCHEME_ECDH_Marshal(const TPMS_KEY_SCHEME_ECDH *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_KEY_SCHEME_ECMQV_Marshal(const TPMS_KEY_SCHEME_ECMQV *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_MGF1_Marshal(const TPMS_SCHEME_MGF1 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_56A_Marshal(const TPMS_SCHEME_KDF1_SP800_56A *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_KDF2_Marshal(const TPMS_SCHEME_KDF2 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_108_Marshal(const TPMS_SCHEME_KDF1_SP800_108 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_KDF_SCHEME_Marshal(const TPMU_KDF_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_KDF_SCHEME_Marshal(const TPMT_KDF_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_ASYM_SCHEME_Marshal(const TPMU_ASYM_SCHEME  *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_RSA_SCHEME_Marshal(const TPMI_ALG_RSA_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_RSA_SCHEME_Marshal(const TPMT_RSA_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_RSA_DECRYPT_Marshal(const TPMI_ALG_RSA_DECRYPT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_RSA_DECRYPT_Marshal(const TPMT_RSA_DECRYPT  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(const TPM2B_PUBLIC_KEY_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_RSA_KEY_BITS_Marshal(const TPMI_RSA_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_PRIVATE_KEY_RSA_Marshal(const TPM2B_PRIVATE_KEY_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_ECC_PARAMETER_Marshal(const TPM2B_ECC_PARAMETER *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ECC_POINT_Marshal(const TPMS_ECC_POINT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_ECC_POINT_Marshal(const TPM2B_ECC_POINT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_ECC_SCHEME_Marshal(const TPMI_ALG_ECC_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ECC_CURVE_Marshal(const TPMI_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_ECC_SCHEME_Marshal(const TPMT_ECC_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ALGORITHM_DETAIL_ECC_Marshal(const TPMS_ALGORITHM_DETAIL_ECC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_RSA_Marshal(const TPMS_SIGNATURE_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_RSASSA_Marshal(const TPMS_SIGNATURE_RSASSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_RSAPSS_Marshal(const TPMS_SIGNATURE_RSAPSS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_ECC_Marshal(const TPMS_SIGNATURE_ECC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_ECDSA_Marshal(const TPMS_SIGNATURE_ECDSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_ECDAA_Marshal(const TPMS_SIGNATURE_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_SM2_Marshal(const TPMS_SIGNATURE_SM2 *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_SIGNATURE_ECSCHNORR_Marshal(const TPMS_SIGNATURE_ECSCHNORR *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_SIGNATURE_Marshal(const TPMU_SIGNATURE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_SIGNATURE_Marshal(const TPMT_SIGNATURE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_ENCRYPTED_SECRET_Marshal(const TPM2B_ENCRYPTED_SECRET *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMI_ALG_PUBLIC_Marshal(const TPMI_ALG_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_PUBLIC_ID_Marshal(const TPMU_PUBLIC_ID *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMS_KEYEDHASH_PARMS_Marshal(const TPMS_KEYEDHASH_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_RSA_PARMS_Marshal(const TPMS_RSA_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_ECC_PARMS_Marshal(const TPMS_ECC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_PUBLIC_PARMS_Marshal(const TPMU_PUBLIC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_PUBLIC_PARMS_Marshal(const TPMT_PUBLIC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_PUBLIC_Marshal(const TPMT_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMT_PUBLIC_D_Marshal(const TPMT_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_PUBLIC_Marshal(const TPM2B_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_TEMPLATE_Marshal(const TPM2B_TEMPLATE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMU_SENSITIVE_COMPOSITE_Marshal(const TPMU_SENSITIVE_COMPOSITE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
LIB_EXPORT TPM_RC
TSS_TPMT_SENSITIVE_Marshal(const TPMT_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_SENSITIVE_Marshal(const TPM2B_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_PRIVATE_Marshal(const TPM2B_PRIVATE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_ID_OBJECT_Marshal(const TPM2B_ID_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMA_NV_Marshal(const TPMA_NV *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_NV_PUBLIC_Marshal(const TPMS_NV_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_NV_PUBLIC_Marshal(const TPM2B_NV_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_CONTEXT_SENSITIVE_Marshal(const TPM2B_CONTEXT_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_CONTEXT_DATA_Marshal(const TPM2B_CONTEXT_DATA  *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_CONTEXT_Marshal(const TPMS_CONTEXT *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPMS_CREATION_DATA_Marshal(const TPMS_CREATION_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
LIB_EXPORT TPM_RC
TSS_TPM2B_CREATION_DATA_Marshal(const TPM2B_CREATION_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);

#endif
