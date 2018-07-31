/*
* Basic ASN.1 Get/Set operation on DER buffer 
* Parse basic data type from stream (operation on buffer, without any structure )
*/

#include "cmnCrypto.h"


/*
* parse and set key/cert from DER format
*/

/* two byte date/time, add to value */
void GetTime(int* value, const byte* date, int* idx)
{
	int i = *idx;

	*value += btoi(date[i++]) * 10;
	*value += btoi(date[i++]);

	*idx = i;
}

WOLFSSL_LOCAL int GetLength(const byte* input, word32* inOutIdx, int* len, word32 maxIdx)
{
	int     length = 0;
	word32  i = *inOutIdx;
	byte    b;

	*len = 0;    /* default length */

	if ( (i+1) > maxIdx) {   /* for first read */
		WOLFSSL_MSG("GetLength bad index on input");
		return BUFFER_E;
	}

	b = input[i++];
	if (b >= ASN_LONG_LENGTH) {        
		word32 bytes = b & 0x7F;

		if ( (i+bytes) > maxIdx) {   /* for reading bytes */
			WOLFSSL_MSG("GetLength bad long length");
			return BUFFER_E;
		}

		while (bytes--) {
			b = input[i++];
			length = (length << 8) | b;
		}
	}
	else
		length = b;

	if ( (i+length) > maxIdx) {   /* for user of length */
		WOLFSSL_MSG("GetLength value exceeds buffer length");
		return BUFFER_E;
	}

	*inOutIdx = i;
	if (length > 0)
		*len = length;

	return length;
}


WOLFSSL_LOCAL int GetInt(mp_int* mpi, const byte* input, word32* inOutIdx, word32 maxIdx)
{
    word32 i = *inOutIdx;
    byte   b = input[i++];
    int    length;

    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;

    if (mp_init(mpi) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(mpi, (byte*)input + i, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }

    *inOutIdx = i + length;
    return 0;
}


#ifndef NO_PWDBASED
/* Get small count integer, 32 bits or less */
int GetShortInt(const byte* input, word32* inOutIdx, int* number)
{
	word32 idx = *inOutIdx;
	word32 len;

	*number = 0;

	if (input[idx++] != ASN_INTEGER)
		return ASN_PARSE_E;

	len = input[idx++];
	if (len > 4)
		return ASN_PARSE_E;

	while (len--) {
		*number  = *number << 8 | input[idx++];
	}

	*inOutIdx = idx;

	return *number;
}
#endif /* !NO_PWDBASED */

/* check the sequene and update index and len params */
WOLFSSL_LOCAL int GetSequence(const byte* input, word32* inOutIdx, int* len, word32 maxIdx)
{
	int    length = -1;
	word32 idx    = *inOutIdx;

	if (input[idx++] != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||GetLength(input, &idx, &length, maxIdx) < 0)
		return ASN_PARSE_E;

	*len      = length;
	*inOutIdx = idx;

	return length;
}


WOLFSSL_LOCAL int GetSet(const byte* input, word32* inOutIdx, int* len, word32 maxIdx)
{
	int    length = -1;
	word32 idx    = *inOutIdx;

	if (input[idx++] != (ASN_SET | ASN_CONSTRUCTED) ||GetLength(input, &idx, &length, maxIdx) < 0)
		return ASN_PARSE_E;

	*len      = length;
	*inOutIdx = idx;

	return length;
}


int GetObjectId(const byte* input, word32* inOutIdx, word32* oid, word32 maxIdx)
{
	int    length;
	word32 i = *inOutIdx;
	byte   b;
	*oid = 0;

	b = input[i++];
	if (b != ASN_OBJECT_ID) 
		return ASN_OBJECT_ID_E;

	if (GetLength(input, &i, &length, maxIdx) < 0)
		return ASN_PARSE_E;

	while(length--)
		*oid += input[i++];
	/* just sum it up for now */

	*inOutIdx = i;

	return 0;
}


WOLFSSL_LOCAL int GetAlgoId(const byte* input, word32* inOutIdx, word32* oid, word32 maxIdx)
{
	int    length;
	word32 i = *inOutIdx;
	byte   b;
	*oid = 0;

	if (GetSequence(input, &i, &length, maxIdx) < 0)
		return ASN_PARSE_E;

	b = input[i++];
	if (b != ASN_OBJECT_ID) 
		return ASN_OBJECT_ID_E;

	if (GetLength(input, &i, &length, maxIdx) < 0)
		return ASN_PARSE_E;

	while(length--) {
		/* odd HC08 compiler behavior here when input[i++] */
		*oid += input[i];
		i++;
	}
	/* just sum it up for now */

	/* could have NULL tag and 0 terminator, but may not */
	b = input[i++];

	if (b == ASN_TAG_NULL) {
		b = input[i++];
		if (b != 0)
			return ASN_EXPECT_0_E;
	}
	else
		/* go back, didn't have it */
		i--;

	*inOutIdx = i;

	return 0;
}


/* winodws header clash for WinCE using GetVersion */
WOLFSSL_LOCAL int GetMyVersion(const byte* input, word32* inOutIdx, int* version)
{
	word32 idx = *inOutIdx;

	if (input[idx++] != ASN_INTEGER)
		return ASN_PARSE_E;

	if (input[idx++] != 0x01)
		return ASN_VERSION_E;

	*version  = input[idx++];
	*inOutIdx = idx;

	return *version;
}


/* May not have one, not an error */
int GetExplicitVersion(const byte* input, word32* inOutIdx, int* version)
{
	word32 idx = *inOutIdx;

	WOLFSSL_ENTER();
	if (input[idx++] == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
	{
		*inOutIdx = ++idx;  /* eat header */
		return GetMyVersion(input, inOutIdx, version);
	}

	/* go back as is */
	*version = 0;

	return 0;
}


//#ifndef NO_RSA

#ifdef HAVE_CAVIUM

static int GetCaviumInt(byte** buff, word16* buffSz, const byte* input,
                        word32* inOutIdx, word32 maxIdx, void* heap)
{
    word32 i = *inOutIdx;
    byte   b = input[i++];
    int    length;

    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;

    *buffSz = (word16)length;
    *buff   = XMALLOC(*buffSz, heap, DYNAMIC_TYPE_CAVIUM_RSA);
    if (*buff == NULL)
        return MEMORY_E;

    XMEMCPY(*buff, input + i, *buffSz);

    *inOutIdx = i + length;
    return 0;
}

static int CaviumRsaPrivateKeyDecode(const byte* input, word32* inOutIdx,
                                     RsaKey* key, word32 inSz)
{
    int   version, length;
    void* h = key->heap;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PRIVATE;

    if (GetCaviumInt(&key->c_n,  &key->c_nSz,   input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_e,  &key->c_eSz,   input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_d,  &key->c_dSz,   input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_p,  &key->c_pSz,   input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_q,  &key->c_qSz,   input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_dP, &key->c_dP_Sz, input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_dQ, &key->c_dQ_Sz, input, inOutIdx, inSz, h) < 0 ||
        GetCaviumInt(&key->c_u,  &key->c_uSz,   input, inOutIdx, inSz, h) < 0 )
            return ASN_RSA_KEY_E;

    return 0;
}
#endif /* HAVE_CAVIUM */


word32 SetDigest(const byte* digest, word32 digSz, byte* output)
{
	output[0] = ASN_OCTET_STRING;
	output[1] = (byte)digSz;
	XMEMCPY(&output[2], digest, digSz);

	return digSz + 2;
} 


WOLFSSL_LOCAL word32 SetLength(word32 length, byte* output)
{
	word32 i = 0, j;

	if (length < ASN_LONG_LENGTH)
		output[i++] = (byte)length;
	else {
		output[i++] = (byte)(BytePrecision(length) | ASN_LONG_LENGTH);

		for (j = BytePrecision(length); j; --j) {
			output[i] = (byte)(length >> ((j - 1) * WOLFSSL_BIT_SIZE));
			i++;
		}
	}

	return i;
}


WOLFSSL_LOCAL word32 SetSequence(word32 len, byte* output)
{
	output[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
	return SetLength(len, output + 1) + 1;
}

WOLFSSL_LOCAL word32 SetOctetString(word32 len, byte* output)
{
	output[0] = ASN_OCTET_STRING;
	return SetLength(len, output + 1) + 1;
}

/* Write a set header to output */
WOLFSSL_LOCAL word32 SetSet(word32 len, byte* output)
{
	output[0] = ASN_SET | ASN_CONSTRUCTED;
	return SetLength(len, output + 1) + 1;
}

WOLFSSL_LOCAL word32 SetImplicit(byte tag, byte number, word32 len, byte* output)
{
	output[0] = ((tag == ASN_SEQUENCE || tag == ASN_SET) ? ASN_CONSTRUCTED : 0) | ASN_CONTEXT_SPECIFIC | number;
	return SetLength(len, output + 1) + 1;
}

WOLFSSL_LOCAL word32 SetExplicit(byte number, word32 len, byte* output)
{
	output[0] = ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | number;
	return SetLength(len, output + 1) + 1;
}


#if defined(HAVE_ECC) && (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))

static word32 SetCurve(ecc_key* key, byte* output)
{
    /* curve types */
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC192)
    static const byte ECC_192v1_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE, 0x3d,
                                             0x03, 0x01, 0x01};
#endif
#if defined(HAVE_ALL_CURVES) || !defined(NO_ECC256)
    static const byte ECC_256v1_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE, 0x3d,
                                            0x03, 0x01, 0x07};
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC160)
    static const byte ECC_160r1_AlgoID[] = { 0x2b, 0x81, 0x04, 0x00,
                                             0x02};
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC224)
    static const byte ECC_224r1_AlgoID[] = { 0x2b, 0x81, 0x04, 0x00,
                                             0x21};
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC384)
    static const byte ECC_384r1_AlgoID[] = { 0x2b, 0x81, 0x04, 0x00,
                                             0x22};
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC521)
    static const byte ECC_521r1_AlgoID[] = { 0x2b, 0x81, 0x04, 0x00,
                                             0x23};
#endif

    int    oidSz = 0;
    int    idx = 0;
    int    lenSz = 0;
    const  byte* oid = 0;

    output[0] = ASN_OBJECT_ID;
    idx++;

    switch (key->dp->size) {
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC160)
        case 20:
            oidSz = sizeof(ECC_160r1_AlgoID);
            oid   =        ECC_160r1_AlgoID;
            break;
#endif

#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC192)
        case 24:
            oidSz = sizeof(ECC_192v1_AlgoID);
            oid   =        ECC_192v1_AlgoID;
            break;
#endif

#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC224)
        case 28:
            oidSz = sizeof(ECC_224r1_AlgoID);
            oid   =        ECC_224r1_AlgoID;
            break;
#endif

#if defined(HAVE_ALL_CURVES) || !defined(NO_ECC256)
        case 32:
            oidSz = sizeof(ECC_256v1_AlgoID);
            oid   =        ECC_256v1_AlgoID;
            break;
#endif

#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC384)
        case 48:
            oidSz = sizeof(ECC_384r1_AlgoID);
            oid   =        ECC_384r1_AlgoID;
            break;
#endif

#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC521)
        case 66:
            oidSz = sizeof(ECC_521r1_AlgoID);
            oid   =        ECC_521r1_AlgoID;
            break;
#endif

        default:
            return ASN_UNKNOWN_OID_E;
    }
    lenSz = SetLength(oidSz, output+idx);
    idx += lenSz;

    XMEMCPY(output+idx, oid, oidSz);
    idx += oidSz;

    return idx;
}

#endif /* HAVE_ECC && WOLFSSL_CERT_GEN */


WOLFSSL_LOCAL word32 SetAlgoID(int algoOID, byte* output, int type, int curveSz)
{
	/* adding TAG_NULL and 0 to end */

	/* hashTypes */
	static const byte shaAlgoID[]    = { 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00 };
	static const byte sha256AlgoID[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00 };
	static const byte sha384AlgoID[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00 };
	static const byte sha512AlgoID[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00 };
	static const byte md5AlgoID[]    = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00  };
	static const byte md2AlgoID[]    = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x05, 0x00};

	/* blkTypes, no NULL tags because IV is there instead */
	static const byte desCbcAlgoID[]  = { 0x2B, 0x0E, 0x03, 0x02, 0x07 };
	static const byte des3CbcAlgoID[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07 };

	/* RSA sigTypes */
#ifndef NO_RSA
	static const byte md5wRSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00};
	static const byte shawRSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00};
	static const byte sha256wRSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00};
	static const byte sha384wRSA_AlgoID[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00};
	static const byte sha512wRSA_AlgoID[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00};
#endif /* NO_RSA */

	/* ECDSA sigTypes */
#ifdef HAVE_ECC 
	static const byte shawECDSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE, 0x3d, 0x04, 0x01, 0x05, 0x00};
	static const byte sha256wECDSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE,0x3d, 0x04, 0x03, 0x02, 0x05, 0x00};
	static const byte sha384wECDSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE,0x3d, 0x04, 0x03, 0x03, 0x05, 0x00};
	static const byte sha512wECDSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE,0x3d, 0x04, 0x03, 0x04, 0x05, 0x00};
#endif /* HAVE_ECC */

	/* RSA keyType */
#ifndef NO_RSA
	static const byte RSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
#endif /* NO_RSA */

#ifdef HAVE_ECC 
	/* ECC keyType */
	/* no tags, so set tagSz smaller later */
	static const byte ECC_AlgoID[] = { 0x2a, 0x86, 0x48, 0xCE, 0x3d,	0x02, 0x01};
#endif /* HAVE_ECC */

	int    algoSz = 0;
	int    tagSz  = 2;   /* tag null and terminator */
	word32 idSz, seqSz;
	const  byte* algoName = 0;
	byte ID_Length[MAX_LENGTH_SZ];
	byte seqArray[MAX_SEQ_SZ + 1];  /* add object_id to end */

	if (type == hashType) {
		switch (algoOID) {
			case SHAh:
			algoSz = sizeof(shaAlgoID);
			algoName = shaAlgoID;
			break;

			case SHA256h:
			algoSz = sizeof(sha256AlgoID);
			algoName = sha256AlgoID;
			break;

			case SHA384h:
			algoSz = sizeof(sha384AlgoID);
			algoName = sha384AlgoID;
			break;

			case SHA512h:
			algoSz = sizeof(sha512AlgoID);
			algoName = sha512AlgoID;
			break;

			case MD2h:
			algoSz = sizeof(md2AlgoID);
			algoName = md2AlgoID;
			break;

			case MD5h:
			algoSz = sizeof(md5AlgoID);
			algoName = md5AlgoID;
			break;

			default:
			WOLFSSL_MSG("Unknown Hash Algo");
			return 0;  /* UNKOWN_HASH_E; */
		}
	}
	else if (type == blkType) {
		switch (algoOID) {
			case DESb:
			algoSz = sizeof(desCbcAlgoID);
			algoName = desCbcAlgoID;
			tagSz = 0;
			break;
			case DES3b:
			algoSz = sizeof(des3CbcAlgoID);
			algoName = des3CbcAlgoID;
			tagSz = 0;
			break;
			default:
			WOLFSSL_MSG("Unknown Block Algo");
			return 0;
		}
	}
	else if (type == sigType) {    /* sigType */
		switch (algoOID) {
#ifndef NO_RSA
			case CTC_MD5wRSA:
			algoSz = sizeof(md5wRSA_AlgoID);
			algoName = md5wRSA_AlgoID;
			break;

			case CTC_SHAwRSA:
			algoSz = sizeof(shawRSA_AlgoID);
			algoName = shawRSA_AlgoID;
			break;

			case CTC_SHA256wRSA:
			algoSz = sizeof(sha256wRSA_AlgoID);
			algoName = sha256wRSA_AlgoID;
			break;

			case CTC_SHA384wRSA:
			algoSz = sizeof(sha384wRSA_AlgoID);
			algoName = sha384wRSA_AlgoID;
			break;

			case CTC_SHA512wRSA:
			algoSz = sizeof(sha512wRSA_AlgoID);
			algoName = sha512wRSA_AlgoID;
			break;
#endif /* NO_RSA */
#ifdef HAVE_ECC 
			case CTC_SHAwECDSA:
			algoSz = sizeof(shawECDSA_AlgoID);
			algoName = shawECDSA_AlgoID;
			break;

			case CTC_SHA256wECDSA:
			algoSz = sizeof(sha256wECDSA_AlgoID);
			algoName = sha256wECDSA_AlgoID;
			break;

			case CTC_SHA384wECDSA:
			algoSz = sizeof(sha384wECDSA_AlgoID);
			algoName = sha384wECDSA_AlgoID;
			break;

			case CTC_SHA512wECDSA:
			algoSz = sizeof(sha512wECDSA_AlgoID);
			algoName = sha512wECDSA_AlgoID;
			break;
#endif /* HAVE_ECC */
			default:
			WOLFSSL_MSG("Unknown Signature Algo");
			return 0;
		}
	}
	else if (type == keyType) {    /* keyType */
		switch (algoOID) {
#ifndef NO_RSA
			case RSAk:
			algoSz = sizeof(RSA_AlgoID);
			algoName = RSA_AlgoID;
			break;
#endif /* NO_RSA */
#ifdef HAVE_ECC 
			case ECDSAk:
			algoSz = sizeof(ECC_AlgoID);
			algoName = ECC_AlgoID;
			tagSz = 0;
			break;
#endif /* HAVE_ECC */
			default:
			WOLFSSL_MSG("Unknown Key Algo");
			return 0;
		}
	}
	else {
		WOLFSSL_MSG("Unknown Algo type");
		return 0;
	}

	idSz  = SetLength(algoSz - tagSz, ID_Length); /* don't include tags */
	seqSz = SetSequence(idSz + algoSz + 1 + curveSz, seqArray); 
	 /* +1 for object id, curveID of curveSz follows for ecc */
	seqArray[seqSz++] = ASN_OBJECT_ID;

	XMEMCPY(output, seqArray, seqSz);
	XMEMCPY(output + seqSz, ID_Length, idSz);
	XMEMCPY(output + seqSz + idSz, algoName, algoSz);

	return seqSz + idSz + algoSz;
}


WOLFSSL_LOCAL int SetMyVersion(word32 version, byte* output, int header)
{
	int i = 0;

	if (header) {
		output[i++] = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED;
		output[i++] = ASN_BIT_STRING;
	}
	output[i++] = ASN_INTEGER;
	output[i++] = 0x01;
	output[i++] = (byte)version;

	return i;
}


WOLFSSL_LOCAL int SetSerialNumber(const byte* sn, word32 snSz, byte* output)
{
	int result = 0;

	WOLFSSL_ENTER();

	if (snSz <= EXTERNAL_SERIAL_SIZE) {
		output[0] = ASN_INTEGER;
		/* The serial number is always positive. When encoding the
		* INTEGER, if the MSB is 1, add a padding zero to keep the
		* number positive. */
		if (sn[0] & 0x80) {
			output[1] = (byte)snSz + 1;
			output[2] = 0;
			XMEMCPY(&output[3], sn, snSz);
			result = snSz + 3;
		}
		else {
			output[1] = (byte)snSz;
			XMEMCPY(&output[2], sn, snSz);
			result = snSz + 2;
		}
	}
	return result;
}

