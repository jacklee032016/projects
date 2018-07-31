
#include "cmnCrypto.h"


/* from SSL proper, for locking can't do find here anymore */
#ifdef __cplusplus
    extern "C" {
#endif
    WOLFSSL_LOCAL Signer* GetCA(void* signers, byte* hash);
    #ifndef NO_SKID
        WOLFSSL_LOCAL Signer* GetCAByName(void* signers, byte* hash);
    #endif
#ifdef __cplusplus
    } 
#endif

int decodeCertExtensions(DecodedCert* cert);


int DecodeToKey(DecodedCert* cert, int verify)
{
	int badDate = 0;
	int ret;

	if ( (ret = GetCertHeader(cert)) < 0)
		return ret;

	WOLFSSL_MSG("Got Cert Header");

	if ( (ret = GetAlgoId(cert->source, &cert->srcIdx, &cert->signatureOID, cert->maxIdx)) < 0)
		return ret;

	WOLFSSL_MSG("Got Algo ID");

	if ( (ret = GetName(cert, ISSUER)) < 0)
		return ret;

	if ( (ret = GetValidity(cert, verify)) < 0)
		badDate = ret;

	if ( (ret = GetName(cert, SUBJECT)) < 0)
		return ret;

	WOLFSSL_MSG("Got Subject Name");

	if ( (ret = GetKey(cert)) < 0)
		return ret;

	WOLFSSL_MSG("Got Key");

	if (badDate != 0)
		return badDate;

	return ret;
}

int ParseCertRelative(DecodedCert* cert, CERT_TYPE_T type, int verify, void* cm)
{
	word32 confirmOID;
	int    ret;
	int    badDate     = 0;
	int    criticalExt = 0;

	if ((ret = DecodeToKey(cert, verify)) < 0) {
		if (ret == ASN_BEFORE_DATE_E || ret == ASN_AFTER_DATE_E)
			badDate = ret;
		else
			return ret;
	}

	WOLFSSL_MSG("Parsed Past Key");

	if (cert->srcIdx < cert->sigIndex) {
#ifndef ALLOW_V1_EXTENSIONS
		if (cert->version < 2) {
			WOLFSSL_MSG("    v1 and v2 certs not allowed extensions");
			return ASN_VERSION_E;
		}
#endif
		/* save extensions */
		cert->extensions    = &cert->source[cert->srcIdx];
		cert->extensionsSz  =  cert->sigIndex - cert->srcIdx;
		cert->extensionsIdx = cert->srcIdx;   /* for potential later use */

		if ((ret = decodeCertExtensions(cert)) < 0) {
			if (ret == ASN_CRIT_EXT_E)
				criticalExt = ret;
			else
				return ret;
		}

		/* advance past extensions */
		cert->srcIdx =  cert->sigIndex;
	}

	if ((ret = GetAlgoId(cert->source, &cert->srcIdx, &confirmOID,	cert->maxIdx)) < 0)
		return ret;

	if ((ret = GetSignature(cert)) < 0)
		return ret;

	if (confirmOID != cert->signatureOID)
		return ASN_SIG_OID_E;

#ifndef NO_SKID
	if (cert->extSubjKeyIdSet == 0	&& cert->publicKey != NULL && cert->pubKeySize > 0) {
#ifdef NO_SHA
		ret = wc_Sha256Hash(cert->publicKey, cert->pubKeySize, cert->extSubjKeyId);
#else
		ret = wc_ShaHash(cert->publicKey, cert->pubKeySize, cert->extSubjKeyId);
#endif
		if (ret != 0)
			return ret;
	}
#endif

	if (verify && type != CA_TYPE)
	{
		Signer* ca = NULL;
#if 1//lzj 		
#ifndef NO_SKID
		if (cert->extAuthKeyIdSet)
			ca = GetCA(cm, cert->extAuthKeyId);
		if (ca == NULL)
			ca = GetCAByName(cm, cert->issuerHash);
#else /* NO_SKID */
			ca = GetCA(cm, cert->issuerHash);
#endif /* NO SKID */
#endif
		WOLFSSL_MSG("About to verify certificate signature");

		if (ca) {
#ifdef HAVE_OCSP
			/* Need the ca's public key hash for OCSP */
#ifdef NO_SHA
			ret = wc_Sha256Hash(ca->publicKey, ca->pubKeySize, cert->issuerKeyHash);
#else /* NO_SHA */
			ret = wc_ShaHash(ca->publicKey, ca->pubKeySize, cert->issuerKeyHash);
#endif /* NO_SHA */
			if (ret != 0)
				return ret;
#endif /* HAVE_OCSP */
			/* try to confirm/verify signature */
			if (!ConfirmSignature(cert->source + cert->certBegin, cert->sigIndex - cert->certBegin,
				ca->publicKey, ca->pubKeySize, ca->keyOID,	cert->signature, cert->sigLength, 
				cert->signatureOID, cert->heap))
			{
				WOLFSSL_MSG("Confirm signature failed");
				return ASN_SIG_CONFIRM_E;
			}
#ifndef IGNORE_NAME_CONSTRAINTS
			/* check that this cert's name is permitted by the signer's name constraints */
			if (!ConfirmNameConstraints(ca, cert))
			{
				WOLFSSL_MSG("Confirm name constraint failed");
				return ASN_NAME_INVALID_E;
			}
#endif /* IGNORE_NAME_CONSTRAINTS */
		}
		else {
			/* no signer */
			WOLFSSL_MSG("No CA signer to verify with");
			return ASN_NO_SIGNER_E;
		}
	}

	if (badDate != 0)
		return badDate;

	if (criticalExt != 0)
		return criticalExt;

	return 0;
}


/* after buffer had been assigned into DecodedCert */
int ParseCert(DecodedCert* cert, CERT_TYPE_T type, int verify, void* cm)
{
	int   ret;
	char* ptr;

	ret = ParseCertRelative(cert, type, verify, cm);
	if (ret < 0)
		return ret;

	if (cert->subjectCNLen > 0)
	{/* at first, cert->subjuctCN point to cert->source, so here allocate and copy */
		ptr = (char*) XMALLOC(cert->subjectCNLen + 1, cert->heap, DYNAMIC_TYPE_SUBJECT_CN);
		if (ptr == NULL)
			return MEMORY_E;
		
		XMEMCPY(ptr, cert->subjectCN, cert->subjectCNLen);
		ptr[cert->subjectCNLen] = '\0';
		cert->subjectCN = ptr;
		cert->subjectCNStored = 1;
	}

	if (cert->keyOID == RSAk && cert->publicKey != NULL  && cert->pubKeySize > 0)
	{
		ptr = (char*) XMALLOC(cert->pubKeySize, cert->heap,	DYNAMIC_TYPE_PUBLIC_KEY);
		if (ptr == NULL)
			return MEMORY_E;
		
		XMEMCPY(ptr, cert->publicKey, cert->pubKeySize);
		cert->publicKey = (byte *)ptr;
		cert->pubKeyStored = 1;
	}

	return ret;
}

/**************************************************************************
* Management of DecodedCert. It is used to parse a DER certificate file 
**************************************************************************/
void InitDecodedCert(DecodedCert* cert, byte* source, word32 inSz, void* heap)
{
	cert->publicKey       = 0;
	cert->pubKeySize      = 0;
	cert->pubKeyStored    = 0;
	cert->version         = 0;
	cert->signature       = 0;
	cert->subjectCN       = 0;
	cert->subjectCNLen    = 0;
	cert->subjectCNEnc    = CTC_UTF8;
	cert->subjectCNStored = 0;
	cert->weOwnAltNames   = 0;
	cert->altNames        = NULL;
#ifndef IGNORE_NAME_CONSTRAINTS
	cert->altEmailNames   = NULL;
	cert->permittedNames  = NULL;
	cert->excludedNames   = NULL;
#endif /* IGNORE_NAME_CONSTRAINTS */
	cert->issuer[0]       = '\0';
	cert->subject[0]      = '\0';
	cert->source          = source;  /* don't own */
	cert->srcIdx          = 0;
	cert->maxIdx          = inSz;    /* can't go over this index */
	cert->heap            = heap;
	XMEMSET(cert->serial, 0, EXTERNAL_SERIAL_SIZE);
	cert->serialSz        = 0;
	cert->extensions      = 0;
	cert->extensionsSz    = 0;
	cert->extensionsIdx   = 0;
	cert->extAuthInfo     = NULL;
	cert->extAuthInfoSz   = 0;
	cert->extCrlInfo      = NULL;
	cert->extCrlInfoSz    = 0;
	XMEMSET(cert->extSubjKeyId, 0, KEYID_SIZE);
	cert->extSubjKeyIdSet = 0;
	XMEMSET(cert->extAuthKeyId, 0, KEYID_SIZE);
	cert->extAuthKeyIdSet = 0;
	cert->extKeyUsageSet  = 0;
	cert->extKeyUsage     = 0;
	cert->extExtKeyUsageSet = 0;
	cert->extExtKeyUsage    = 0;
	cert->isCA            = 0;
#ifdef HAVE_PKCS7
	cert->issuerRaw       = NULL;
	cert->issuerRawLen    = 0;
#endif
#ifdef WOLFSSL_CERT_GEN
	cert->subjectSN       = 0;
	cert->subjectSNLen    = 0;
	cert->subjectSNEnc    = CTC_UTF8;
	cert->subjectC        = 0;
	cert->subjectCLen     = 0;
	cert->subjectCEnc     = CTC_PRINTABLE;
	cert->subjectL        = 0;
	cert->subjectLLen     = 0;
	cert->subjectLEnc     = CTC_UTF8;
	cert->subjectST       = 0;
	cert->subjectSTLen    = 0;
	cert->subjectSTEnc    = CTC_UTF8;
	cert->subjectO        = 0;
	cert->subjectOLen     = 0;
	cert->subjectOEnc     = CTC_UTF8;
	cert->subjectOU       = 0;
	cert->subjectOULen    = 0;
	cert->subjectOUEnc    = CTC_UTF8;
	cert->subjectEmail    = 0;
	cert->subjectEmailLen = 0;
#endif /* WOLFSSL_CERT_GEN */
	cert->beforeDate      = NULL;
	cert->beforeDateLen   = 0;
	cert->afterDate       = NULL;
	cert->afterDateLen    = 0;
#ifdef OPENSSL_EXTRA
	XMEMSET(&cert->issuerName, 0, sizeof(DecodedName));
	XMEMSET(&cert->subjectName, 0, sizeof(DecodedName));
	cert->extBasicConstSet = 0;
	cert->extBasicConstCrit = 0;
	cert->extBasicConstPlSet = 0;
	cert->pathLength = 0;
	cert->extSubjAltNameSet = 0;
	cert->extSubjAltNameCrit = 0;
	cert->extAuthKeyIdCrit = 0;
	cert->extSubjKeyIdCrit = 0;
	cert->extKeyUsageCrit = 0;
	cert->extExtKeyUsageCrit = 0;
	cert->extExtKeyUsageSrc = NULL;
	cert->extExtKeyUsageSz = 0;
	cert->extExtKeyUsageCount = 0;
	cert->extAuthKeyIdSrc = NULL;
	cert->extAuthKeyIdSz = 0;
	cert->extSubjKeyIdSrc = NULL;
	cert->extSubjKeyIdSz = 0;
#endif /* OPENSSL_EXTRA */
#if defined(OPENSSL_EXTRA) || !defined(IGNORE_NAME_CONSTRAINTS)
	cert->extNameConstraintSet = 0;
#endif /* OPENSSL_EXTRA || !IGNORE_NAME_CONSTRAINTS */
#ifdef HAVE_ECC
	cert->pkCurveOID = 0;
#endif /* HAVE_ECC */
#ifdef WOLFSSL_SEP
	cert->deviceTypeSz = 0;
	cert->deviceType = NULL;
	cert->hwTypeSz = 0;
	cert->hwType = NULL;
	cert->hwSerialNumSz = 0;
	cert->hwSerialNum = NULL;
#ifdef OPENSSL_EXTRA
	cert->extCertPolicySet = 0;
	cert->extCertPolicyCrit = 0;
#endif /* OPENSSL_EXTRA */
#endif /* WOLFSSL_SEP */
}


void FreeAltNames(DNS_entry* altNames, void* heap)
{
	(void)heap;

	while (altNames) {
		DNS_entry* tmp = altNames->next;

		XFREE(altNames->name, heap, DYNAMIC_TYPE_ALTNAME);
		XFREE(altNames,       heap, DYNAMIC_TYPE_ALTNAME);
		altNames = tmp;
	}
}

#ifndef IGNORE_NAME_CONSTRAINTS

void FreeNameSubtrees(Base_entry* names, void* heap)
{
    (void)heap;

    while (names) {
        Base_entry* tmp = names->next;

        XFREE(names->name, heap, DYNAMIC_TYPE_ALTNAME);
        XFREE(names,       heap, DYNAMIC_TYPE_ALTNAME);
        names = tmp;
    }
}
#endif /* IGNORE_NAME_CONSTRAINTS */

void FreeDecodedCert(DecodedCert* cert)
{
	if (cert->subjectCNStored == 1)
		XFREE(cert->subjectCN, cert->heap, DYNAMIC_TYPE_SUBJECT_CN);
	if (cert->pubKeyStored == 1)
		XFREE(cert->publicKey, cert->heap, DYNAMIC_TYPE_PUBLIC_KEY);
	if (cert->weOwnAltNames && cert->altNames)
		FreeAltNames(cert->altNames, cert->heap);
#ifndef IGNORE_NAME_CONSTRAINTS
	if (cert->altEmailNames)
		FreeAltNames(cert->altEmailNames, cert->heap);
	if (cert->permittedNames)
		FreeNameSubtrees(cert->permittedNames, cert->heap);
	if (cert->excludedNames)
		FreeNameSubtrees(cert->excludedNames, cert->heap);
#endif /* IGNORE_NAME_CONSTRAINTS */

#ifdef WOLFSSL_SEP
	XFREE(cert->deviceType, cert->heap, 0);
	XFREE(cert->hwType, cert->heap, 0);
	XFREE(cert->hwSerialNum, cert->heap, 0);
#endif /* WOLFSSL_SEP */

#ifdef OPENSSL_EXTRA
	if (cert->issuerName.fullName != NULL)
		XFREE(cert->issuerName.fullName, NULL, DYNAMIC_TYPE_X509);
	if (cert->subjectName.fullName != NULL)
		XFREE(cert->subjectName.fullName, NULL, DYNAMIC_TYPE_X509);
#endif /* OPENSSL_EXTRA */
}


