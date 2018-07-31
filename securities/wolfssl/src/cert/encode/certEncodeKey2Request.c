/*
* encoding certificate request (DER buffer) from CERT data structure and RSA key
*/


#include "cmnCrypto.h"

#include "_asnCertEncoding.h"


#ifdef WOLFSSL_CERT_REQ

/* Write a set header to output */
static word32 _SetUTF8String(word32 len, byte* output)
{
    output[0] = ASN_UTF8STRING;
    return SetLength(len, output + 1) + 1;
}

static int _SetReqAttrib(byte* output, char* pw, int extSz)
{
	static const byte cpOid[] = { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x07 };
	static const byte erOid[] = { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e };

	int sz      = 0; /* overall size */
	int cpSz    = 0; /* Challenge Password section size */
	int cpSeqSz = 0;
	int cpSetSz = 0;
	int cpStrSz = 0;
	int pwSz    = 0;
	int erSz    = 0; /* Extension Request section size */
	int erSeqSz = 0;
	int erSetSz = 0;
	byte cpSeq[MAX_SEQ_SZ];
	byte cpSet[MAX_SET_SZ];
	byte cpStr[MAX_PRSTR_SZ];
	byte erSeq[MAX_SEQ_SZ];
	byte erSet[MAX_SET_SZ];

	output[0] = 0xa0;
	sz++;

	if (pw && pw[0]) {
		pwSz = (int)XSTRLEN(pw);
		cpStrSz = _SetUTF8String(pwSz, cpStr);
		cpSetSz = SetSet(cpStrSz + pwSz, cpSet);
		cpSeqSz = SetSequence(sizeof(cpOid) + cpSetSz + cpStrSz + pwSz, cpSeq);
		cpSz = cpSeqSz + sizeof(cpOid) + cpSetSz + cpStrSz + pwSz;
	}

	if (extSz) {
		erSetSz = SetSet(extSz, erSet);
		erSeqSz = SetSequence(erSetSz + sizeof(erOid) + extSz, erSeq);
		erSz = extSz + erSetSz + erSeqSz + sizeof(erOid);
	}

	/* Put the pieces together. */
	sz += SetLength(cpSz + erSz, &output[sz]);

	if (cpSz) {
		XMEMCPY(&output[sz], cpSeq, cpSeqSz);
		sz += cpSeqSz;
		XMEMCPY(&output[sz], cpOid, sizeof(cpOid));
		sz += sizeof(cpOid);
		XMEMCPY(&output[sz], cpSet, cpSetSz);
		sz += cpSetSz;
		XMEMCPY(&output[sz], cpStr, cpStrSz);
		sz += cpStrSz;
		XMEMCPY(&output[sz], pw, pwSz);
		sz += pwSz;
	}

	if (erSz) {
		XMEMCPY(&output[sz], erSeq, erSeqSz);
		sz += erSeqSz;
		XMEMCPY(&output[sz], erOid, sizeof(erOid));
		sz += sizeof(erOid);
		XMEMCPY(&output[sz], erSet, erSetSz);
		sz += erSetSz;
		/* The actual extension data will be tacked onto the output later. */
	}

	return sz;
}


/* encode info from cert into DER encoded format */
static int _EncodeCertReq(Cert* cert, DerCert* der, RsaKey* rsaKey, ecc_key* eccKey)
{
	(void)eccKey;

	/* init */
	XMEMSET(der, 0, sizeof(DerCert));

	/* version */
	der->versionSz = SetMyVersion(cert->version, der->version, FALSE);

	/* subject name */
	der->subjectSz = SetName(der->subject, &cert->subject);
	if (der->subjectSz == 0)
		return SUBJECT_E;

	/* public key */
	if (cert->keyType == RSA_KEY)
	{
		if (rsaKey == NULL)
			return PUBLIC_KEY_E;
		der->publicKeySz = SetRsaPublicKey(der->publicKey, rsaKey);
		if (der->publicKeySz <= 0)
			return PUBLIC_KEY_E;
	}

#ifdef HAVE_ECC
	if (cert->keyType == ECC_KEY)
	{
		if (eccKey == NULL)
			return PUBLIC_KEY_E;
		der->publicKeySz = SetEccPublicKey(der->publicKey, eccKey);
		if (der->publicKeySz <= 0)
			return PUBLIC_KEY_E;
	}
#endif /* HAVE_ECC */

	/* CA */
	if (cert->isCA) {
		der->caSz = SetCa(der->ca);
		if (der->caSz == 0)
			return CA_TRUE_E;
	}
	else
		der->caSz = 0;

	/* extensions, just CA now */
	if (cert->isCA) {
		der->extensionsSz = SetExtensions(der->extensions, der->ca, der->caSz, FALSE);
		if (der->extensionsSz == 0)
			return EXTENSIONS_E;
	}
	else
		der->extensionsSz = 0;

	der->attribSz = _SetReqAttrib(der->attrib, cert->challengePw, der->extensionsSz);
	if (der->attribSz == 0)
		return REQ_ATTRIBUTE_E;

	der->total = der->versionSz + der->subjectSz + der->publicKeySz + der->extensionsSz + der->attribSz;

	return 0;
}


/* write DER encoded cert req(der) into buffer, which can be send out or write to file, size already checked */
static int _WriteCertReqBody(DerCert* der, byte* buffer)
{
	int idx;

	/* signed part header */
	idx = SetSequence(der->total, buffer);
	/* version */
	XMEMCPY(buffer + idx, der->version, der->versionSz);
	idx += der->versionSz;
	/* subject */
	XMEMCPY(buffer + idx, der->subject, der->subjectSz);
	idx += der->subjectSz;
	/* public key */
	XMEMCPY(buffer + idx, der->publicKey, der->publicKeySz);
	idx += der->publicKeySz;
	/* attributes */
	XMEMCPY(buffer + idx, der->attrib, der->attribSz);
	idx += der->attribSz;
	/* extensions */
	if (der->extensionsSz) {
		XMEMCPY(buffer + idx, der->extensions, min(der->extensionsSz, sizeof(der->extensions)));
		idx += der->extensionsSz;
	}

	return idx;
}

/*
* encode into derBuffer with Key(RSA or ECC) and some configuration info in Cert
*/
int certMakeCertReq(byte* derBuffer, word32 derSz, Cert* cert, RsaKey* rsaKey, ecc_key* eccKey)
{
	int ret;
#ifdef WOLFSSL_SMALL_STACK
	DerCert* der;
#else
	DerCert der[1];
#endif

	cert->keyType = eccKey ? ECC_KEY : RSA_KEY;

#ifdef WOLFSSL_SMALL_STACK
	der = (DerCert*)XMALLOC(sizeof(DerCert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (der == NULL)
		return MEMORY_E;
#endif

	ret = _EncodeCertReq(cert, der, rsaKey, eccKey);
	if (ret == 0)
	{
		if (der->total + MAX_SEQ_SZ * 2 > (int)derSz)
			ret = BUFFER_E;
		else
			ret = cert->bodySz = _WriteCertReqBody(der, derBuffer);
	}

#ifdef WOLFSSL_SMALL_STACK
	XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

	return ret;
}

#endif /* WOLFSSL_CERT_REQ */

