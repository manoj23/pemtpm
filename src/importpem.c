/********************************************************************************/
/*										*/
/*			   Import a PEM RSA keypair 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: importpem.c 987 2017-04-17 18:27:09Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016.						*/
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

/* Use OpenSSL to create an RSA  keypair like this

   > openssl genrsa -out tmpprivkey.pem -aes256 -passout pass:rrrr 2048


*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssmarshal.h>
#include <openssl/pem.h>

#define TYPE_SI            5

int tssVerbose = TRUE;

static TPM_RC convertPemToEvpPrivKey(EVP_PKEY **evpPkey,		/* freed by caller */
			      const char *pemKeyFilename,
			      const char *password)
{
    TPM_RC 	rc = 0;
    FILE 	*pemKeyFile = NULL;

    if (rc == 0) {
	rc = TSS_File_Open(&pemKeyFile, pemKeyFilename, "rb"); 	/* closed @2 */
    }
    if (rc == 0) {
	*evpPkey = PEM_read_PrivateKey(pemKeyFile, NULL, NULL, (void *)password);
	if (*evpPkey == NULL) {
	    printf("convertPemToEvpPrivKey: Error reading key file %s\n", pemKeyFilename);
	    rc = EXIT_FAILURE;
	}
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @2 */
    }
    return rc;
}

static TPM_RC convertEvpPkeyToRsakey(RSA **rsaKey,		/* freed by caller */
			      EVP_PKEY *evpPkey)
{
    TPM_RC 	rc = 0;

    if (rc == 0) {
	*rsaKey = EVP_PKEY_get1_RSA(evpPkey);
	if (*rsaKey == NULL) {
	    printf("convertEvpPkeyToRsakey: EVP_PKEY_get1_RSA failed\n");
	    rc = EXIT_FAILURE;
	}
    }
    return rc;
}

/* getRsaKeyParts() gets the RSA key parts from an OpenSSL RSA key token.

   If n is not NULL, returns n, e, and d.  If p is not NULL, returns p and q.
*/

static TPM_RC getRsaKeyParts(const BIGNUM **n,
		     const BIGNUM **e,
		     const BIGNUM **d,
		     const BIGNUM **p,
		     const BIGNUM **q,
		     const RSA *rsaKey)
{
    TPM_RC  	rc = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000
    if (n != NULL) {
	*n = rsaKey->n;
	*e = rsaKey->e;
	*d = rsaKey->d;
    }
    if (p != NULL) {
	*p = rsaKey->p;
	*q = rsaKey->q;
    }
#else
    if (n != NULL) {
	RSA_get0_key(rsaKey, n, e, d);
    }
    if (p != NULL) {
	RSA_get0_factors(rsaKey, p, q);
    }
#endif
    return rc;
}


static TPM_RC convertRsaKeyToPrivateKeyBin(int 	*privateKeyBytes,
				    uint8_t 	**privateKeyBin,	/* freed by caller */
				    const RSA	 *rsaKey)
{
    TPM_RC 		rc = 0;
    const BIGNUM 	*p;
    const BIGNUM 	*q;

    /* get the private primes */
    if (rc == 0) {
	rc = getRsaKeyParts(NULL, NULL, NULL, &p, &q, rsaKey);
    }
    /* allocate a buffer for the private key array */
    if (rc == 0) {
	*privateKeyBytes = BN_num_bytes(p);
	rc = TSS_Malloc(privateKeyBin, *privateKeyBytes);
    }
    /* convert the private key bignum to binary */
    if (rc == 0) {
	BN_bn2bin(p, *privateKeyBin);
    }
    return rc;
}

static TPM_RC convertRsaPrivateKeyBinToPrivate(TPM2B_PRIVATE 	*objectPrivate,
					TPM2B_SENSITIVE *objectSensitive,
					int 		privateKeyBytes,
					uint8_t 	*privateKeyBin,
					const char 	*password)
{
    TPM_RC 		rc = 0;
    TPMT_SENSITIVE	tSensitive;
    TPM2B_SENSITIVE	bSensitive;

    if (rc == 0) {
	if (((objectPrivate == NULL) && (objectSensitive == NULL)) ||
	    ((objectPrivate != NULL) && (objectSensitive != NULL))) {
	    printf("convertRsaPrivateKeyBinToPrivate: Only one result supported\n");
	    rc = EXIT_FAILURE;
	}
    }

    /* In some cases, the sensitive data is not encrypted and the integrity value is not present.
       When an integrity value is not needed, it is not present and it is not represented by an
       Empty Buffer.

       In this case, the TPM2B_PRIVATE will just be a marshaled TPM2B_SENSITIVE, which is a
       marshaled TPMT_SENSITIVE */

    /* construct TPMT_SENSITIVE	*/
    if (rc == 0) {
	/* This shall be the same as the type parameter of the associated public area. */
	tSensitive.sensitiveType = TPM_ALG_RSA;
	tSensitive.seedValue.b.size = 0;
	/* key password converted to TPM2B */
	rc = TSS_TPM2B_StringCopy(&tSensitive.authValue.b, password, sizeof(TPMU_HA));
    }
    if (rc == 0) {
	if ((size_t)privateKeyBytes > sizeof(tSensitive.sensitive.rsa.t.buffer)) {
	    printf("convertRsaPrivateKeyBinToPrivate: "
		   "Error, private key modulus %d greater than %lu\n",
		   privateKeyBytes, (unsigned long)sizeof(tSensitive.sensitive.rsa.t.buffer));
	    rc = EXIT_FAILURE;
	}
    }
    if (rc == 0) {
	tSensitive.sensitive.rsa.t.size = privateKeyBytes;
	memcpy(tSensitive.sensitive.rsa.t.buffer, privateKeyBin, privateKeyBytes);
    }
    /* FIXME common code for EC and RSA */
    /* marshal the TPMT_SENSITIVE into a TPM2B_SENSITIVE */
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    int32_t size = sizeof(bSensitive.t.sensitiveArea);	/* max size */
	    uint8_t *buffer = bSensitive.b.buffer;		/* pointer that can move */
	    bSensitive.t.size = 0;				/* required before marshaling */
	    rc = TSS_TPMT_SENSITIVE_Marshal(&tSensitive,
					    &bSensitive.b.size,	/* marshaled size */
					    &buffer,		/* marshal here */
					    &size);		/* max size */
	}
	else {	/* return TPM2B_SENSITIVE */
	    objectSensitive->t.sensitiveArea = tSensitive;
	}
    }
    /* marshal the TPM2B_SENSITIVE (as a TPM2B_PRIVATE, see above) into a TPM2B_PRIVATE */
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    int32_t size = sizeof(objectPrivate->t.buffer);	/* max size */
	    uint8_t *buffer = objectPrivate->t.buffer;		/* pointer that can move */
	    objectPrivate->t.size = 0;				/* required before marshaling */
	    rc = TSS_TPM2B_PRIVATE_Marshal((TPM2B_PRIVATE *)&bSensitive,
					   &objectPrivate->t.size,	/* marshaled size */
					   &buffer,		/* marshal here */
					   &size);		/* max size */
	}
    }
    return rc;
}


static TPM_RC convertRsaKeyToPrivate(TPM2B_PRIVATE 	*objectPrivate,
			      TPM2B_SENSITIVE 	*objectSensitive,
			      RSA 		*rsaKey,
			      const char 	*password)
{
    TPM_RC 	rc = 0;
    int 	privateKeyBytes;
    uint8_t 	*privateKeyBin = NULL;

    /* convert an openssl RSA key token private prime p to a binary array */
    if (rc == 0) {
	rc = convertRsaKeyToPrivateKeyBin(&privateKeyBytes,
					  &privateKeyBin,	/* freed @1 */
					  rsaKey);
    }
    /* convert an RSA prime 'privateKeyBin' to either a TPM2B_PRIVATE or a TPM2B_SENSITIVE */
    if (rc == 0) {
	rc = convertRsaPrivateKeyBinToPrivate(objectPrivate,
					      objectSensitive,
					      privateKeyBytes,
					      privateKeyBin,
					      password);
    }
    free(privateKeyBin);		/* @1 */
    return rc;
}
static TPM_RC convertRsaPublicKeyBinToPublic(TPM2B_PUBLIC 	*objectPublic,
				      int		keyType,
				      TPMI_ALG_HASH 	nalg,
				      TPMI_ALG_HASH	halg,
				      int 		modulusBytes,
				      uint8_t 		*modulusBin)
{
    TPM_RC 		rc = 0;

    if (rc == 0) {
	if ((size_t)modulusBytes > sizeof(objectPublic->publicArea.unique.rsa.t.buffer)) {
	    printf("convertRsaPublicKeyBinToPublic: Error, "
		   "public key modulus %d greater than %lu\n", modulusBytes,
		   (unsigned long)sizeof(objectPublic->publicArea.unique.rsa.t.buffer));
	    rc = EXIT_FAILURE;
	}
    }
    if (rc == 0) {
	/* Table 184 - Definition of TPMT_PUBLIC Structure */
	objectPublic->publicArea.type = TPM_ALG_RSA;
	objectPublic->publicArea.nameAlg = nalg;
	objectPublic->publicArea.objectAttributes.val = TPMA_OBJECT_NODA;
	objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	if (keyType == TYPE_SI) {
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	}
	else {
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	}
	objectPublic->publicArea.authPolicy.t.size = 0;
	/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	objectPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	if (keyType == TYPE_SI) {
	    objectPublic->publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
	}
	else {
	    objectPublic->publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	}
	objectPublic->publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = halg;
	objectPublic->publicArea.parameters.rsaDetail.keyBits = modulusBytes * 8;
	objectPublic->publicArea.parameters.rsaDetail.exponent = 0;

	objectPublic->publicArea.unique.rsa.t.size = modulusBytes;
	memcpy(objectPublic->publicArea.unique.rsa.t.buffer, modulusBin, modulusBytes);
    }
    return rc;
}


/* convertRsaKeyToPublicKeyBin() converts from an openssl RSA key token to a public modulus */

static TPM_RC convertRsaKeyToPublicKeyBin(int 		*modulusBytes,
				   uint8_t 	**modulusBin,	/* freed by caller */
				   const RSA 	*rsaKey)
{
    TPM_RC 		rc = 0;
    const BIGNUM 	*n;
    const BIGNUM 	*e;
    const BIGNUM 	*d;

    /* get the public modulus from the RSA key token */
    if (rc == 0) {
	rc = getRsaKeyParts(&n, &e, &d, NULL, NULL, rsaKey);
    }
    if (rc == 0) {
	*modulusBytes = BN_num_bytes(n);
    }
    if (rc == 0) {
	rc = TSS_Malloc(modulusBin, *modulusBytes);
    }
    if (rc == 0) {
	BN_bn2bin(n, *modulusBin);
    }
    return rc;
}


static TPM_RC convertRsaKeyToPublic(TPM2B_PUBLIC 	*objectPublic,
			     int		keyType,
			     TPMI_ALG_HASH 	nalg,
			     TPMI_ALG_HASH	halg,
			     RSA 		*rsaKey)
{
    TPM_RC 		rc = 0;
    int 		modulusBytes;
    uint8_t 		*modulusBin = NULL;

    /* openssl RSA key token to a public modulus */
    if (rc == 0) {
	rc = convertRsaKeyToPublicKeyBin(&modulusBytes,
					 &modulusBin,		/* freed @1 */
					 rsaKey);
    }
    /* public modulus to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertRsaPublicKeyBinToPublic(objectPublic,
					    keyType,
					    nalg,
					    halg,
					    modulusBytes,
					    modulusBin);
    }
    free(modulusBin);		/* @1 */
    return rc;
}


static TPM_RC convertRsaPemToKeyPair(TPM2B_PUBLIC 	*objectPublic,
			      TPM2B_PRIVATE 	*objectPrivate,
			      int		keyType,
			      TPMI_ALG_HASH 	nalg,
			      TPMI_ALG_HASH	halg,
			      const char 	*pemKeyFilename,
			      const char 	*password)
{
    TPM_RC 	rc = 0;
    EVP_PKEY 	*evpPkey = NULL;
    RSA		*rsaKey = NULL;

    if (rc == 0) {
	rc = convertPemToEvpPrivKey(&evpPkey,		/* freed @1 */
				    pemKeyFilename,
				    password);
    }
    if (rc == 0) {
	rc = convertEvpPkeyToRsakey(&rsaKey,		/* freed @2 */
				    evpPkey);
    }
    if (rc == 0) {
	rc = convertRsaKeyToPrivate(objectPrivate,
				    NULL,
				    rsaKey,
				    password);
    }
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   nalg,
				   halg,
				   rsaKey);
    }
    if (rsaKey != NULL) {
	RSA_free(rsaKey);		/* @2 */
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TPM2B_PUBLIC		objectPublic;
    TPM2B_PRIVATE		duplicate;
    const char			*pemKeyFilename = NULL;
    const char			*pemKeyPassword = "";	/* default empty password */
    const char			*outPublicFilename = NULL;
    const char			*outPrivateFilename = NULL;
    int				keyType = TYPE_SI;
    TPMI_ALG_PUBLIC 		algPublic = TPM_ALG_RSA;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    TPMI_ALG_HASH		nalg = TPM_ALG_SHA256;

    FILE 			*pemKeyFile = NULL;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ipem") == 0) {
	    i++;
	    if (i < argc) {
		pemKeyFilename = argv[i];
	    }
	    else {
		printf("-ipem option needs a value\n");
	    }
	}
	else if (strcmp(argv[i], "-rsa") == 0) {
	    algPublic = TPM_ALG_RSA;
	}
	else if (strcmp(argv[i],"-pwdk") == 0) {
	    i++;
	    if (i < argc) {
		pemKeyPassword = argv[i];
	    }
	    else {
		printf("-pwdk option needs a value\n");
	    }
	}
	else if (strcmp(argv[i],"-opu") == 0) {
	    i++;
	    if (i < argc) {
		outPublicFilename = argv[i];
	    }
	    else {
		printf("-opu option needs a value\n");
	    }
	}
	else if (strcmp(argv[i],"-opr") == 0) {
	    i++;
	    if (i < argc) {
		outPrivateFilename = argv[i];
	    }
	    else {
		printf("-opr option needs a value\n");
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    halg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    halg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    halg = TPM_ALG_SHA384;
		}
		else {
		    printf("Bad parameter for -halg\n");
		}
	    }
	    else {
		printf("-halg option needs a value\n");
	    }
	}
	else if (strcmp(argv[i],"-nalg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    nalg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    nalg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    nalg = TPM_ALG_SHA384;
		}
		else {
		    printf("Bad parameter for -nalg\n");
		}
	    }
	    else {
		printf("-nalg option needs a value\n");
	    }
	}
    }
    if (pemKeyFilename == NULL) {
	printf("Missing parameter -ipem\n");
	exit(1);
    }
    if (outPublicFilename == NULL) {
	printf("Missing parameter -opu\n");
	exit(1);
    }
    if (outPrivateFilename == NULL) {
	printf("Missing parameter -opr\n");
	exit(1);
    }
    if (rc == 0) {
	if (algPublic == TPM_ALG_RSA) {
	    rc = convertRsaPemToKeyPair(&objectPublic,
					&duplicate,
					keyType,
					nalg,
					halg,
					pemKeyFilename,
					pemKeyPassword);
	}
	else {
	    rc = EXIT_FAILURE;
	}
    }

    if (rc == 0) {
	printf("importpem: success\n");

		rc = TSS_File_WriteStructure(&objectPublic,
				(MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshal, outPublicFilename);
		if (rc == 0) {
			printf("pemtpm: write to %s OK\n", outPublicFilename);
			rc = TSS_File_WriteStructure(&duplicate,
					(MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshal, outPrivateFilename);

			if (rc == 0) {
				printf("pemtpm: write to %s OK duplicate.t.size=%d\n", outPrivateFilename, duplicate.t.size);
			}
		}

    } else {
	rc = EXIT_FAILURE;
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @2 */
    }
    return rc;
}
