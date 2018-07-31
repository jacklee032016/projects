
#include "cmnCrypto.h"

/*
* All get operation from DecodedCert, and used in CertParseCerts.c 
*/
int GetCertHeader(DecodedCert* cert)
{
    int ret = 0, len;
    byte serialTmp[EXTERNAL_SERIAL_SIZE];
#if defined(WOLFSSL_SMALL_STACK) && defined(USE_FAST_MATH)
    mp_int* mpi = NULL;
#else
    mp_int stack_mpi;
    mp_int* mpi = &stack_mpi;
#endif

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    cert->certBegin = cert->srcIdx;

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;
    cert->sigIndex = len + cert->srcIdx;

    if (GetExplicitVersion(cert->source, &cert->srcIdx, &cert->version) < 0)
        return ASN_PARSE_E;

#if defined(WOLFSSL_SMALL_STACK) && defined(USE_FAST_MATH)
    mpi = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (mpi == NULL)
        return MEMORY_E;
#endif

    if (GetInt(mpi, cert->source, &cert->srcIdx, cert->maxIdx) < 0) {
#if defined(WOLFSSL_SMALL_STACK) && defined(USE_FAST_MATH)
        XFREE(mpi, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    len = mp_unsigned_bin_size(mpi);
    if (len < (int)sizeof(serialTmp)) {
        if ( (ret = mp_to_unsigned_bin(mpi, serialTmp)) == MP_OKAY) {
            XMEMCPY(cert->serial, serialTmp, len);
            cert->serialSz = len;
        }
    }
    mp_clear(mpi);

#if defined(WOLFSSL_SMALL_STACK) && defined(USE_FAST_MATH)
    XFREE(mpi, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


#if !defined(NO_RSA)
/* Store Rsa Key, may save later, Dsa could use in future */
static int _StoreRsaKey(DecodedCert* cert)
{
	int    length;
	word32 recvd = cert->srcIdx;

	if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
		return ASN_PARSE_E;

	recvd = cert->srcIdx - recvd;
	length += recvd;

	while (recvd--)
		cert->srcIdx--;

	cert->pubKeySize = length;
	cert->publicKey = cert->source + cert->srcIdx;
	cert->srcIdx += length;

	return 0;
}
#endif

/* publicKey in DecidedCert */
int GetKey(DecodedCert* cert)
{
	int length;
#ifdef HAVE_NTRU
	int tmpIdx = cert->srcIdx;
#endif

	if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
		return ASN_PARSE_E;

	if (GetAlgoId(cert->source, &cert->srcIdx, &cert->keyOID, cert->maxIdx) < 0)
		return ASN_PARSE_E;

	switch (cert->keyOID) {
#ifndef NO_RSA
		case RSAk:
		{
			byte b = cert->source[cert->srcIdx++];
			if (b != ASN_BIT_STRING)
				return ASN_BITSTR_E;

			if (GetLength(cert->source,&cert->srcIdx,&length,cert->maxIdx) < 0)
				return ASN_PARSE_E;
			b = cert->source[cert->srcIdx++];
			if (b != 0x00)
				return ASN_EXPECT_0_E;

			return _StoreRsaKey(cert);
		}

#endif /* NO_RSA */
#ifdef HAVE_NTRU
		case NTRUk:
		{
			const byte* key = &cert->source[tmpIdx];
			byte*       next = (byte*)key;
			word16      keyLen;
			word32      rc;
			word32      remaining = cert->maxIdx - cert->srcIdx;
#ifdef WOLFSSL_SMALL_STACK
			byte*       keyBlob = NULL;
#else
			byte        keyBlob[MAX_NTRU_KEY_SZ];
#endif
			rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(key,
			&keyLen, NULL, &next, &remaining);
			if (rc != NTRU_OK)
				return ASN_NTRU_KEY_E;
			if (keyLen > MAX_NTRU_KEY_SZ)
				return ASN_NTRU_KEY_E;

#ifdef WOLFSSL_SMALL_STACK
			keyBlob = (byte*)XMALLOC(MAX_NTRU_KEY_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
			if (keyBlob == NULL)
				return MEMORY_E;
#endif

			rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(key, &keyLen, keyBlob, &next, &remaining);
			if (rc != NTRU_OK) {
#ifdef WOLFSSL_SMALL_STACK
				XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
				return ASN_NTRU_KEY_E;
			}

			if ( (next - key) < 0) {
#ifdef WOLFSSL_SMALL_STACK
				XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
				return ASN_NTRU_KEY_E;
			}

			cert->srcIdx = tmpIdx + (int)(next - key);

			cert->publicKey = (byte*) XMALLOC(keyLen, cert->heap, DYNAMIC_TYPE_PUBLIC_KEY);
			if (cert->publicKey == NULL) {
#ifdef WOLFSSL_SMALL_STACK
				XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
				return MEMORY_E;
			}
			XMEMCPY(cert->publicKey, keyBlob, keyLen);
			cert->pubKeyStored = 1;
			cert->pubKeySize   = keyLen;

#ifdef WOLFSSL_SMALL_STACK
			XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

			return 0;
		}
#endif /* HAVE_NTRU */
#ifdef HAVE_ECC
		case ECDSAk:
		{
			int    oidSz = 0;
			byte   b = cert->source[cert->srcIdx++];

			if (b != ASN_OBJECT_ID) 
				return ASN_OBJECT_ID_E;

			if (GetLength(cert->source,&cert->srcIdx,&oidSz,cert->maxIdx) < 0)
				return ASN_PARSE_E;

			while(oidSz--)
				cert->pkCurveOID += cert->source[cert->srcIdx++];

			if (CheckCurve(cert->pkCurveOID) < 0)
				return ECC_CURVE_OID_E;

			/* key header */
			b = cert->source[cert->srcIdx++];
			if (b != ASN_BIT_STRING)
				return ASN_BITSTR_E;

			if (GetLength(cert->source,&cert->srcIdx,&length,cert->maxIdx) < 0)
				return ASN_PARSE_E;
			b = cert->source[cert->srcIdx++];
			if (b != 0x00)
				return ASN_EXPECT_0_E;

			/* actual key, use length - 1 since ate preceding 0 */
			length -= 1;

			cert->publicKey = (byte*) XMALLOC(length, cert->heap, DYNAMIC_TYPE_PUBLIC_KEY);
			if (cert->publicKey == NULL)
				return MEMORY_E;
			XMEMCPY(cert->publicKey, &cert->source[cert->srcIdx], length);
			cert->pubKeyStored = 1;
			cert->pubKeySize   = length;

			cert->srcIdx += length;

			return 0;
		}
#endif /* HAVE_ECC */
		default:
		return ASN_UNKNOWN_OID_E;
	}
}


/* process NAME, either issuer or subject */
int GetName(DecodedCert* cert, int nameType)
{
	int    length;  /* length of all distinguished names */
	int    dummy;
	int    ret;
	char*  full;
	byte*  hash;
	word32 idx;
#ifdef OPENSSL_EXTRA
	DecodedName* dName =(nameType == ISSUER) ? &cert->issuerName : &cert->subjectName;
#endif /* OPENSSL_EXTRA */

	if (nameType == ISSUER) {
		full = cert->issuer;
		hash = cert->issuerHash;
	}
	else {
		full = cert->subject;
		hash = cert->subjectHash;
	}

	if (cert->source[cert->srcIdx] == ASN_OBJECT_ID) {
		WOLFSSL_MSG("Trying optional prefix...");

		if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
			return ASN_PARSE_E;

		cert->srcIdx += length;
		WOLFSSL_MSG("Got optional prefix");
	}

	/* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
	* calculated over the entire DER encoding of the Name field, including
	* the tag and length. */
	idx = cert->srcIdx;
	if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
		return ASN_PARSE_E;

#ifdef NO_SHA
	ret = wc_Sha256Hash(&cert->source[idx], length + cert->srcIdx - idx, hash);
#else
	ret = wc_ShaHash(&cert->source[idx], length + cert->srcIdx - idx, hash);
#endif
	if (ret != 0)
		return ret;

	length += cert->srcIdx;
	idx = 0;

#ifdef HAVE_PKCS7
	/* store pointer to raw issuer */
	if (nameType == ISSUER) {
		cert->issuerRaw = &cert->source[cert->srcIdx];
		cert->issuerRawLen = length - cert->srcIdx;
	}
#endif
#ifndef IGNORE_NAME_CONSTRAINTS
	if (nameType == SUBJECT) {
		cert->subjectRaw = &cert->source[cert->srcIdx];
		cert->subjectRawLen = length - cert->srcIdx;
	}
#endif

	while (cert->srcIdx < (word32)length) {
		byte   b;
		byte   joint[2];
		byte   tooBig = FALSE;
		int    oidSz;

		if (GetSet(cert->source, &cert->srcIdx, &dummy, cert->maxIdx) < 0) {
			WOLFSSL_MSG("Cert name lacks set header, trying sequence");
		}

		if (GetSequence(cert->source, &cert->srcIdx, &dummy, cert->maxIdx) < 0)
			return ASN_PARSE_E;

		b = cert->source[cert->srcIdx++];
		if (b != ASN_OBJECT_ID) 
			return ASN_OBJECT_ID_E;

		if (GetLength(cert->source, &cert->srcIdx, &oidSz, cert->maxIdx) < 0)
			return ASN_PARSE_E;

		XMEMCPY(joint, &cert->source[cert->srcIdx], sizeof(joint));

		/* v1 name types */
		if (joint[0] == 0x55 && joint[1] == 0x04) {
			byte   id;
			byte   copy = FALSE;
			int    strLen;

			cert->srcIdx += 2;
			id = cert->source[cert->srcIdx++]; 
			b  = cert->source[cert->srcIdx++]; /* encoding */

			if (GetLength(cert->source, &cert->srcIdx, &strLen, cert->maxIdx) < 0)
				return ASN_PARSE_E;

			if ( (strLen + 14) > (int)(ASN_NAME_MAX - idx)) {
				/* include biggest pre fix header too 4 = "/serialNumber=" */
				WOLFSSL_MSG("ASN Name too big, skipping");
				tooBig = TRUE;
			}

			if (id == ASN_COMMON_NAME) {
				if (nameType == SUBJECT) {
					cert->subjectCN = (char *)&cert->source[cert->srcIdx];
					cert->subjectCNLen = strLen;
					cert->subjectCNEnc = b;
				}

				if (!tooBig) {
					XMEMCPY(&full[idx], "/CN=", 4);
					idx += 4;
					copy = TRUE;
				}
#ifdef OPENSSL_EXTRA
				dName->cnIdx = cert->srcIdx;
				dName->cnLen = strLen;
#endif /* OPENSSL_EXTRA */
			}
			else if (id == ASN_SUR_NAME) {
				if (!tooBig) {
					XMEMCPY(&full[idx], "/SN=", 4);
					idx += 4;
					copy = TRUE;
				}
#ifdef WOLFSSL_CERT_GEN
				if (nameType == SUBJECT) {
					cert->subjectSN = (char*)&cert->source[cert->srcIdx];
					cert->subjectSNLen = strLen;
					cert->subjectSNEnc = b;
				}
#endif /* WOLFSSL_CERT_GEN */
#ifdef OPENSSL_EXTRA
				dName->snIdx = cert->srcIdx;
				dName->snLen = strLen;
#endif /* OPENSSL_EXTRA */
			}
			else if (id == ASN_COUNTRY_NAME) {
				if (!tooBig) {
					XMEMCPY(&full[idx], "/C=", 3);
					idx += 3;
					copy = TRUE;
				}
#ifdef WOLFSSL_CERT_GEN
				if (nameType == SUBJECT) {
					cert->subjectC = (char*)&cert->source[cert->srcIdx];
					cert->subjectCLen = strLen;
					cert->subjectCEnc = b;
				}
#endif /* WOLFSSL_CERT_GEN */
#ifdef OPENSSL_EXTRA
				dName->cIdx = cert->srcIdx;
				dName->cLen = strLen;
#endif /* OPENSSL_EXTRA */
			}
			else if (id == ASN_LOCALITY_NAME) {
				if (!tooBig) {
					XMEMCPY(&full[idx], "/L=", 3);
					idx += 3;
					copy = TRUE;
				}
#ifdef WOLFSSL_CERT_GEN
				if (nameType == SUBJECT) {
					cert->subjectL = (char*)&cert->source[cert->srcIdx];
					cert->subjectLLen = strLen;
					cert->subjectLEnc = b;
				}
#endif /* WOLFSSL_CERT_GEN */
#ifdef OPENSSL_EXTRA
				dName->lIdx = cert->srcIdx;
				dName->lLen = strLen;
#endif /* OPENSSL_EXTRA */
			}
			else if (id == ASN_STATE_NAME) {
				if (!tooBig) {
					XMEMCPY(&full[idx], "/ST=", 4);
					idx += 4;
					copy = TRUE;
				}
#ifdef WOLFSSL_CERT_GEN
				if (nameType == SUBJECT) {
					cert->subjectST = (char*)&cert->source[cert->srcIdx];
					cert->subjectSTLen = strLen;
					cert->subjectSTEnc = b;
				}
#endif /* WOLFSSL_CERT_GEN */
#ifdef OPENSSL_EXTRA
				dName->stIdx = cert->srcIdx;
				dName->stLen = strLen;
#endif /* OPENSSL_EXTRA */
			}
			else if (id == ASN_ORG_NAME) {
				if (!tooBig) {
				XMEMCPY(&full[idx], "/O=", 3);
					idx += 3;
					copy = TRUE;
				}
#ifdef WOLFSSL_CERT_GEN
				if (nameType == SUBJECT) {
					cert->subjectO = (char*)&cert->source[cert->srcIdx];
					cert->subjectOLen = strLen;
					cert->subjectOEnc = b;
				}
#endif /* WOLFSSL_CERT_GEN */
#ifdef OPENSSL_EXTRA
				dName->oIdx = cert->srcIdx;
				dName->oLen = strLen;
#endif /* OPENSSL_EXTRA */
			}
			else if (id == ASN_ORGUNIT_NAME) {
				if (!tooBig) {
					XMEMCPY(&full[idx], "/OU=", 4);
					idx += 4;
					copy = TRUE;
				}
#ifdef WOLFSSL_CERT_GEN
				if (nameType == SUBJECT) {
					cert->subjectOU = (char*)&cert->source[cert->srcIdx];
					cert->subjectOULen = strLen;
					cert->subjectOUEnc = b;
				}
#endif /* WOLFSSL_CERT_GEN */
#ifdef OPENSSL_EXTRA
				dName->ouIdx = cert->srcIdx;
				dName->ouLen = strLen;
#endif /* OPENSSL_EXTRA */
			}
			else if (id == ASN_SERIAL_NUMBER) {
				if (!tooBig) {
					XMEMCPY(&full[idx], "/serialNumber=", 14);
					idx += 14;
					copy = TRUE;
				}
#ifdef OPENSSL_EXTRA
				dName->snIdx = cert->srcIdx;
				dName->snLen = strLen;
#endif /* OPENSSL_EXTRA */
			}

			if (copy && !tooBig) {
				XMEMCPY(&full[idx], &cert->source[cert->srcIdx], strLen);
				idx += strLen;
			}

			cert->srcIdx += strLen;
		}
		else
		{
			/* skip */
			byte email = FALSE;
			byte uid   = FALSE;
			int  adv;

			if (joint[0] == 0x2a && joint[1] == 0x86)  /* email id hdr */
				email = TRUE;

			if (joint[0] == 0x9  && joint[1] == 0x92)  /* uid id hdr */
				uid = TRUE;

			cert->srcIdx += oidSz + 1;

			if (GetLength(cert->source, &cert->srcIdx, &adv, cert->maxIdx) < 0)
				return ASN_PARSE_E;

			if (adv > (int)(ASN_NAME_MAX - idx)) {
				WOLFSSL_MSG("ASN name too big, skipping");
				tooBig = TRUE;
			}

			if (email) {
				if ( (14 + adv) > (int)(ASN_NAME_MAX - idx)) {
				WOLFSSL_MSG("ASN name too big, skipping");
					tooBig = TRUE;
				}
				if (!tooBig) {
					XMEMCPY(&full[idx], "/emailAddress=", 14);
					idx += 14;
				}

#ifdef WOLFSSL_CERT_GEN
				if (nameType == SUBJECT) {
					cert->subjectEmail = (char*)&cert->source[cert->srcIdx];
					cert->subjectEmailLen = adv;
				}
#endif /* WOLFSSL_CERT_GEN */
#ifdef OPENSSL_EXTRA
				dName->emailIdx = cert->srcIdx;
				dName->emailLen = adv;
#endif /* OPENSSL_EXTRA */
#ifndef IGNORE_NAME_CONSTRAINTS
				{
					DNS_entry* emailName = NULL;

					emailName = (DNS_entry*)XMALLOC(sizeof(DNS_entry),  cert->heap, DYNAMIC_TYPE_ALTNAME);
					if (emailName == NULL) {
						WOLFSSL_MSG("\tOut of Memory");
						return MEMORY_E;
					}
					emailName->name = (char*)XMALLOC(adv + 1,  cert->heap, DYNAMIC_TYPE_ALTNAME);
					if (emailName->name == NULL) {
						WOLFSSL_MSG("\tOut of Memory");
						return MEMORY_E;
					}
					XMEMCPY(emailName->name, &cert->source[cert->srcIdx], adv);
					emailName->name[adv] = 0;

					emailName->next = cert->altEmailNames;
					cert->altEmailNames = emailName;
				}
#endif /* IGNORE_NAME_CONSTRAINTS */
				if (!tooBig) {
					XMEMCPY(&full[idx], &cert->source[cert->srcIdx], adv);
					idx += adv;
				}
			}

			if (uid) {
			if ( (5 + adv) > (int)(ASN_NAME_MAX - idx)) {
					WOLFSSL_MSG("ASN name too big, skipping");
					tooBig = TRUE;
				}
				if (!tooBig) {
					XMEMCPY(&full[idx], "/UID=", 5);
					idx += 5;

					XMEMCPY(&full[idx], &cert->source[cert->srcIdx], adv);
					idx += adv;
				}
#ifdef OPENSSL_EXTRA
				dName->uidIdx = cert->srcIdx;
				dName->uidLen = adv;
#endif /* OPENSSL_EXTRA */
			}

			cert->srcIdx += adv;
		}
	}
	full[idx++] = 0;

#ifdef OPENSSL_EXTRA
	{
		int totalLen = 0;

		if (dName->cnLen != 0)
			totalLen += dName->cnLen + 4;
		if (dName->snLen != 0)
			totalLen += dName->snLen + 4;
		if (dName->cLen != 0)
			totalLen += dName->cLen + 3;
		if (dName->lLen != 0)
			totalLen += dName->lLen + 3;
		if (dName->stLen != 0)
			totalLen += dName->stLen + 4;
		if (dName->oLen != 0)
			totalLen += dName->oLen + 3;
		if (dName->ouLen != 0)
			totalLen += dName->ouLen + 4;
		if (dName->emailLen != 0)
			totalLen += dName->emailLen + 14;
		if (dName->uidLen != 0)
			totalLen += dName->uidLen + 5;
		if (dName->serialLen != 0)
			totalLen += dName->serialLen + 14;

		dName->fullName = (char*)XMALLOC(totalLen + 1, NULL, DYNAMIC_TYPE_X509);
		if (dName->fullName != NULL) {
			idx = 0;

			if (dName->cnLen != 0) {
				dName->entryCount++;
				XMEMCPY(&dName->fullName[idx], "/CN=", 4);
				idx += 4;
				XMEMCPY(&dName->fullName[idx],  &cert->source[dName->cnIdx], dName->cnLen);
				dName->cnIdx = idx;
				idx += dName->cnLen;
			}
			
			if (dName->snLen != 0) {
				dName->entryCount++;
				XMEMCPY(&dName->fullName[idx], "/SN=", 4);
				idx += 4;
				XMEMCPY(&dName->fullName[idx],  &cert->source[dName->snIdx], dName->snLen);
				dName->snIdx = idx;
				idx += dName->snLen;
			}
			if (dName->cLen != 0) {
			dName->entryCount++;
			XMEMCPY(&dName->fullName[idx], "/C=", 3);
			idx += 3;
			XMEMCPY(&dName->fullName[idx],
			                   &cert->source[dName->cIdx], dName->cLen);
			dName->cIdx = idx;
			idx += dName->cLen;
			}
			if (dName->lLen != 0) {
			dName->entryCount++;
			XMEMCPY(&dName->fullName[idx], "/L=", 3);
			idx += 3;
			XMEMCPY(&dName->fullName[idx],
			                   &cert->source[dName->lIdx], dName->lLen);
			dName->lIdx = idx;
			idx += dName->lLen;
			}
			if (dName->stLen != 0) {
			dName->entryCount++;
			XMEMCPY(&dName->fullName[idx], "/ST=", 4);
			idx += 4;
			XMEMCPY(&dName->fullName[idx],
			                 &cert->source[dName->stIdx], dName->stLen);
			dName->stIdx = idx;
			idx += dName->stLen;
			}
			if (dName->oLen != 0) {
			dName->entryCount++;
			XMEMCPY(&dName->fullName[idx], "/O=", 3);
			idx += 3;
			XMEMCPY(&dName->fullName[idx],
			                   &cert->source[dName->oIdx], dName->oLen);
			dName->oIdx = idx;
			idx += dName->oLen;
			}
			if (dName->ouLen != 0) {
			dName->entryCount++;
			XMEMCPY(&dName->fullName[idx], "/OU=", 4);
			idx += 4;
			XMEMCPY(&dName->fullName[idx],
			                 &cert->source[dName->ouIdx], dName->ouLen);
			dName->ouIdx = idx;
			idx += dName->ouLen;
			}
			if (dName->emailLen != 0) {
			dName->entryCount++;
			XMEMCPY(&dName->fullName[idx], "/emailAddress=", 14);
			idx += 14;
			XMEMCPY(&dName->fullName[idx],
			           &cert->source[dName->emailIdx], dName->emailLen);
			dName->emailIdx = idx;
			idx += dName->emailLen;
			}
			if (dName->uidLen != 0) {
			dName->entryCount++;
			XMEMCPY(&dName->fullName[idx], "/UID=", 5);
			idx += 5;
			XMEMCPY(&dName->fullName[idx],
			               &cert->source[dName->uidIdx], dName->uidLen);
			dName->uidIdx = idx;
			idx += dName->uidLen;
			}
			if (dName->serialLen != 0) {
			dName->entryCount++;
			XMEMCPY(&dName->fullName[idx], "/serialNumber=", 14);
			idx += 14;
			XMEMCPY(&dName->fullName[idx],
			         &cert->source[dName->serialIdx], dName->serialLen);
			dName->serialIdx = idx;
			idx += dName->serialLen;
			}
			dName->fullName[idx] = '\0';
			dName->fullNameLen = totalLen;
		}
	}
#endif /* OPENSSL_EXTRA */

	return 0;
}


static int _getDate(DecodedCert* cert, int dateType)
{
	int    length;
	byte   date[MAX_DATE_SIZE];
	byte   b;
	word32 startIdx = 0;

	if (dateType == BEFORE)
		cert->beforeDate = &cert->source[cert->srcIdx];
	else
		cert->afterDate = &cert->source[cert->srcIdx];
	startIdx = cert->srcIdx;

	b = cert->source[cert->srcIdx++];
	if (b != ASN_UTC_TIME && b != ASN_GENERALIZED_TIME)
		return ASN_TIME_E;

	if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
		return ASN_PARSE_E;

	if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
		return ASN_DATE_SZ_E;

	XMEMCPY(date, &cert->source[cert->srcIdx], length);
	cert->srcIdx += length;

	if (dateType == BEFORE)
		cert->beforeDateLen = cert->srcIdx - startIdx;
	else
		cert->afterDateLen  = cert->srcIdx - startIdx;

	if (!XVALIDATE_DATE(date, b, dateType)) {
		if (dateType == BEFORE)
			return ASN_BEFORE_DATE_E;
		else
			return ASN_AFTER_DATE_E;
	}

	return 0;
}


int GetValidity(DecodedCert* cert, int verify)
{
	int length;
	int badDate = 0;

	if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
		return ASN_PARSE_E;

	if (_getDate(cert, BEFORE) < 0 && verify)
		badDate = ASN_BEFORE_DATE_E;           /* continue parsing */

	if (_getDate(cert, AFTER) < 0 && verify)
		return ASN_AFTER_DATE_E;

	if (badDate != 0)
		return badDate;

	return 0;
}


int GetSignature(DecodedCert* cert)
{
	int    length;
	byte   b = cert->source[cert->srcIdx++];

	if (b != ASN_BIT_STRING)
		return ASN_BITSTR_E;

	if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
		return ASN_PARSE_E;

	cert->sigLength = length;

	b = cert->source[cert->srcIdx++];
	if (b != 0x00)
		return ASN_EXPECT_0_E;

	cert->sigLength--;
	cert->signature = &cert->source[cert->srcIdx];
	cert->srcIdx += cert->sigLength;

	return 0;
}


