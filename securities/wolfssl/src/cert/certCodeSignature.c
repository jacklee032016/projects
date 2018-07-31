/*
* Encode and confirm the signature
*/

#include "cmnCrypto.h"


/* Create and init an new signer */
Signer* MakeSigner(void* heap)
{
	Signer* signer = (Signer*) XMALLOC(sizeof(Signer), heap, DYNAMIC_TYPE_SIGNER);
	if (signer)
	{
		signer->pubKeySize = 0;
		signer->keyOID     = 0;
		signer->publicKey  = NULL;
		signer->nameLen    = 0;
		signer->name       = NULL;
#ifndef IGNORE_NAME_CONSTRAINTS
		signer->permittedNames = NULL;
		signer->excludedNames = NULL;
#endif /* IGNORE_NAME_CONSTRAINTS */
		signer->next       = NULL;
	}
	(void)heap;

	return signer;
}


/* Free an individual signer */
void FreeSigner(Signer* signer, void* heap)
{
	XFREE(signer->name, heap, DYNAMIC_TYPE_SUBJECT_CN);
	XFREE(signer->publicKey, heap, DYNAMIC_TYPE_PUBLIC_KEY);
#ifndef IGNORE_NAME_CONSTRAINTS
	if (signer->permittedNames)
		FreeNameSubtrees(signer->permittedNames, heap);
	if (signer->excludedNames)
		FreeNameSubtrees(signer->excludedNames, heap);
#endif
	XFREE(signer, heap, DYNAMIC_TYPE_SIGNER);

	(void)heap;
}


/* Free the whole singer table with number of rows */
void FreeSignerTable(Signer** table, int rows, void* heap)
{
	int i;

	for (i = 0; i < rows; i++)
	{
		Signer* signer = table[i];
		while (signer)
		{
			Signer* next = signer->next;
			FreeSigner(signer, heap);
			signer = next;
		}
		table[i] = NULL;
	}
}


/* encode into out with sequence (algId, digest). signature algorithm and its digest  */
word32 wc_EncodeSignature(byte* out, const byte* digest, word32 digSz, int hashOID)
{
	byte digArray[MAX_ENCODED_DIG_SZ];
	byte algoArray[MAX_ALGO_SZ];
	byte seqArray[MAX_SEQ_SZ];
	word32 encDigSz, algoSz, seqSz;

	encDigSz = SetDigest(digest, digSz, digArray);
	algoSz   = SetAlgoID(hashOID, algoArray, hashType, 0);
	seqSz    = SetSequence(encDigSz + algoSz, seqArray);

	XMEMCPY(out, seqArray, seqSz);
	XMEMCPY(out + seqSz, algoArray, algoSz);
	XMEMCPY(out + seqSz + algoSz, digArray, encDigSz);

	return encDigSz + algoSz + seqSz;
}



/* return true (1) or false (0) for Confirmation */
int ConfirmSignature(const byte* buf, word32 bufSz,
    const byte* key, word32 keySz, word32 keyOID,
    const byte* sig, word32 sigSz, word32 sigOID,
    void* heap)
{
	int  typeH = 0, digestSz = 0, ret = 0;
#ifdef WOLFSSL_SMALL_STACK
	byte* digest;
#else
	byte digest[MAX_DIGEST_SIZE];
#endif

#ifdef WOLFSSL_SMALL_STACK
	digest = (byte*)XMALLOC(MAX_DIGEST_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (digest == NULL)
		return 0; /* not confirmed */
#endif

	(void)key;
	(void)keySz;
	(void)sig;
	(void)sigSz;
	(void)heap;

	switch (sigOID)
	{
#ifndef NO_MD5
		case CTC_MD5wRSA:
			if (wc_Md5Hash(buf, bufSz, digest) == 0) {
				typeH    = MD5h;
				digestSz = MD5_DIGEST_SIZE;
			}
			break;
#endif
#if defined(WOLFSSL_MD2)
		case CTC_MD2wRSA:
			if (wc_Md2Hash(buf, bufSz, digest) == 0) {
				typeH    = MD2h;
				digestSz = MD2_DIGEST_SIZE;
			}
			break;
#endif
#ifndef NO_SHA
		case CTC_SHAwRSA:
		case CTC_SHAwDSA:
		case CTC_SHAwECDSA:
			if (wc_ShaHash(buf, bufSz, digest) == 0) {    
				typeH    = SHAh;
				digestSz = SHA_DIGEST_SIZE;                
			}
			break;
#endif
#ifndef NO_SHA256
		case CTC_SHA256wRSA:
		case CTC_SHA256wECDSA:
			if (wc_Sha256Hash(buf, bufSz, digest) == 0) {    
			typeH    = SHA256h;
			digestSz = SHA256_DIGEST_SIZE;
			}
			break;
#endif
#ifdef WOLFSSL_SHA512
		case CTC_SHA512wRSA:
		case CTC_SHA512wECDSA:
			if (wc_Sha512Hash(buf, bufSz, digest) == 0) {    
				typeH    = SHA512h;
				digestSz = SHA512_DIGEST_SIZE;
			}
			break;
#endif
#ifdef WOLFSSL_SHA384
		case CTC_SHA384wRSA:
		case CTC_SHA384wECDSA:
			if (wc_Sha384Hash(buf, bufSz, digest) == 0) {    
				typeH    = SHA384h;
				digestSz = SHA384_DIGEST_SIZE;
			}            
			break;
#endif
		default:
			WOLFSSL_MSG("Verify Signautre has unsupported type");
	}

	if (typeH == 0) {
#ifdef WOLFSSL_SMALL_STACK
		XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
	return 0; /* not confirmed */
	}

	switch (keyOID)
	{
#ifndef NO_RSA
		case RSAk:
		{
			word32 idx = 0;
			int    encodedSigSz, verifySz;
			byte*  out;
#ifdef WOLFSSL_SMALL_STACK
			RsaKey* pubKey;
			byte* plain;
			byte* encodedSig;
#else
			RsaKey pubKey[1];
			byte plain[MAX_ENCODED_SIG_SZ];
			byte encodedSig[MAX_ENCODED_SIG_SZ];
#endif

#ifdef WOLFSSL_SMALL_STACK
			pubKey = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
			plain = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
			encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
			if (pubKey == NULL || plain == NULL || encodedSig == NULL)
			{
				WOLFSSL_MSG("Failed to allocate memory at ConfirmSignature");

				if (pubKey)
					XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
				if (plain)
					XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
				if (encodedSig)
					XFREE(encodedSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);

				break; /* not confirmed */
			}
#endif

			if (sigSz > MAX_ENCODED_SIG_SZ) {
				WOLFSSL_MSG("Verify Signautre is too big");
			}
			else if (wc_InitRsaKey(pubKey, heap) != 0) {
				WOLFSSL_MSG("InitRsaKey failed");
			}
			else if (wc_RsaPublicKeyDecode(key, &idx, pubKey, keySz) < 0) {
				WOLFSSL_MSG("ASN Key decode error RSA");
			}
			else
			{
				XMEMCPY(plain, sig, sigSz);

				if ((verifySz = wc_RsaSSL_VerifyInline(plain, sigSz, &out, pubKey)) < 0) {
					WOLFSSL_MSG("Rsa SSL verify error");
				}
				else
				{
					/* make sure we're right justified */
					encodedSigSz = wc_EncodeSignature(encodedSig, digest, digestSz, typeH);
					if (encodedSigSz != verifySz ||XMEMCMP(out, encodedSig, encodedSigSz) != 0)
					{
						WOLFSSL_MSG("Rsa SSL verify match encode error");
					}
					else
						ret = 1; /* match */

#ifdef WOLFSSL_DEBUG_ENCODING
					{
						int x;

						printf("wolfssl encodedSig:\n");

						for (x = 0; x < encodedSigSz; x++) {
							printf("%02x ", encodedSig[x]);
							if ( (x % 16) == 15)
								printf("\n");
						}

						printf("\n");
						printf("actual digest:\n");

						for (x = 0; x < verifySz; x++) {
							printf("%02x ", out[x]);
							if ( (x % 16) == 15)
								printf("\n");
						}

						printf("\n");
					}
#endif /* WOLFSSL_DEBUG_ENCODING */

				}

			}

			wc_FreeRsaKey(pubKey);

#ifdef WOLFSSL_SMALL_STACK
			XFREE(pubKey,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
			XFREE(plain,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
			XFREE(encodedSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
			break;
		}

#endif /* NO_RSA */
#ifdef HAVE_ECC
		case ECDSAk:
		{
			int verify = 0;
#ifdef WOLFSSL_SMALL_STACK
			ecc_key* pubKey;
#else
			ecc_key pubKey[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
			pubKey = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
			if (pubKey == NULL) {
				WOLFSSL_MSG("Failed to allocate pubKey");
				break; /* not confirmed */
			}
#endif

			if (wc_ecc_init(pubKey) < 0) {
				WOLFSSL_MSG("Failed to initialize key");
				break; /* not confirmed */
			}
			if (wc_ecc_import_x963(key, keySz, pubKey) < 0) {
				WOLFSSL_MSG("ASN Key import error ECC");
			}
			else
			{   
				if (wc_ecc_verify_hash(sig, sigSz, digest, digestSz, &verify, pubKey) != 0) {
					WOLFSSL_MSG("ECC verify hash error");
				}
				else if (1 != verify) {
					WOLFSSL_MSG("ECC Verify didn't match");
				}
				else
					ret = 1; /* match */
			}
			wc_ecc_free(pubKey);

#ifdef WOLFSSL_SMALL_STACK
			XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
			break;
		}
#endif /* HAVE_ECC */
		default:
			WOLFSSL_MSG("Verify Key type unknown");
	}

#ifdef WOLFSSL_SMALL_STACK
	XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

	return ret;
}

