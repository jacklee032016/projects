/* pkcs7.c
 */


#include "cmnCrypto.h"

/* placed ASN.1 contentType OID into *output, return idx on success,
 * 0 upon failure */
WOLFSSL_LOCAL int wc_SetContentType(int pkcs7TypeOID, byte* output)
{
	/* PKCS#7 content types, RFC 2315, section 14 */
	static const byte pkcs7[]				= { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07 };
	static const byte data[]					= { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
	static const byte signedData[]			= { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
	static const byte envelopedData[]		= { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03 };
	static const byte signedAndEnveloped[]	= { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x04 };
	static const byte digestedData[]			= { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x05 };
	static const byte encryptedData[]		= { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06 };

	int idSz;
	int typeSz = 0, idx = 0;
	const byte* typeName = 0;
	byte ID_Length[MAX_LENGTH_SZ];

	switch (pkcs7TypeOID)
	{
		case PKCS7_MSG:
			typeSz = sizeof(pkcs7);
			typeName = pkcs7;
			break;

		case DATA:
			typeSz = sizeof(data);
			typeName = data;
			break;

		case SIGNED_DATA:
			typeSz = sizeof(signedData);
			typeName = signedData;
			break;

		case ENVELOPED_DATA:
			typeSz = sizeof(envelopedData);
			typeName = envelopedData;
			break;

		case SIGNED_AND_ENVELOPED_DATA:
			typeSz = sizeof(signedAndEnveloped);
			typeName = signedAndEnveloped;
			break;

		case DIGESTED_DATA:
			typeSz = sizeof(digestedData);
			typeName = digestedData;
			break;

		case ENCRYPTED_DATA:
			typeSz = sizeof(encryptedData);
			typeName = encryptedData;
			break;

		default:
		WOLFSSL_MSG("Unknown PKCS#7 Type");
		return 0;
	};

	idSz  = SetLength(typeSz, ID_Length);
	output[idx++] = ASN_OBJECT_ID;
	XMEMCPY(output + idx, ID_Length, idSz);
	idx += idSz;
	XMEMCPY(output + idx, typeName, typeSz);
	idx += typeSz;

	return idx;
}


/* get ASN.1 contentType OID sum, return 0 on success, <0 on failure */
int wc_GetContentType(const byte* input, word32* inOutIdx, word32* oid, word32 maxIdx)
{
	int length;
	word32 i = *inOutIdx;
	byte b;
	*oid = 0;

	WOLFSSL_ENTER();

	b = input[i++];
	if (b != ASN_OBJECT_ID)
		return ASN_OBJECT_ID_E;

	if (GetLength(input, &i, &length, maxIdx) < 0)
		return ASN_PARSE_E;

	while(length--) {
		*oid += input[i];
		i++;
	}

	*inOutIdx = i;

	return 0;
}


/* init PKCS7 struct with recipient cert, decode into DecodedCert */
int wc_PKCS7_InitWithCert(PKCS7* pkcs7, byte* cert, word32 certSz)
{
	int ret = 0;

	XMEMSET(pkcs7, 0, sizeof(PKCS7));
	if (cert != NULL && certSz > 0)
	{
#ifdef WOLFSSL_SMALL_STACK
		DecodedCert* dCert;

		dCert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (dCert == NULL)
			return MEMORY_E;
#else
		DecodedCert stack_dCert;
		DecodedCert* dCert = &stack_dCert;
#endif

		pkcs7->singleCert = cert;
		pkcs7->singleCertSz = certSz;
		InitDecodedCert(dCert, cert, certSz, 0);

		ret = ParseCert(dCert, CA_TYPE, NO_VERIFY, 0);
		if (ret < 0) {
			FreeDecodedCert(dCert);
#ifdef WOLFSSL_SMALL_STACK
			XFREE(dCert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
			return ret;
		}

		XMEMCPY(pkcs7->publicKey, dCert->publicKey, dCert->pubKeySize);
		pkcs7->publicKeySz = dCert->pubKeySize;
		XMEMCPY(pkcs7->issuerHash, dCert->issuerHash, KEYID_SIZE);
		pkcs7->issuer = dCert->issuerRaw;
		pkcs7->issuerSz = dCert->issuerRawLen;
		XMEMCPY(pkcs7->issuerSn, dCert->serial, dCert->serialSz);
		pkcs7->issuerSnSz = dCert->serialSz;
		FreeDecodedCert(dCert);

#ifdef WOLFSSL_SMALL_STACK
		XFREE(dCert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
	}

	return ret;
}


/* releases any memory allocated by a PKCS7 initializer */
void wc_PKCS7_Free(PKCS7* pkcs7)
{
	(void)pkcs7;
}


/* build PKCS#7 data content type */
int wc_PKCS7_EncodeData(PKCS7* pkcs7, byte* output, word32 outputSz)
{
	static const byte oid[] = { ASN_OBJECT_ID, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
	byte seq[MAX_SEQ_SZ];
	byte octetStr[MAX_OCTET_STR_SZ];
	word32 seqSz;
	word32 octetStrSz;
	word32 oidSz = (word32)sizeof(oid);
	int idx = 0;

	octetStrSz = SetOctetString(pkcs7->contentSz, octetStr);
	seqSz = SetSequence(pkcs7->contentSz + octetStrSz + oidSz, seq);

	if (outputSz < pkcs7->contentSz + octetStrSz + oidSz + seqSz)
		return BUFFER_E;

	XMEMCPY(output, seq, seqSz);
	idx += seqSz;
	XMEMCPY(output + idx, oid, oidSz);
	idx += oidSz;
	XMEMCPY(output + idx, octetStr, octetStrSz);
	idx += octetStrSz;
	XMEMCPY(output + idx, pkcs7->content, pkcs7->contentSz);
	idx += pkcs7->contentSz;

	return idx;
}


