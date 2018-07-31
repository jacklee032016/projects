/*
* encoding certificate (DER buffer) from CERT data structure and Key (RSA key, ecc key or ntru key)
* utils function makeAnyCert is called in EncodeKey2Cert
*/


#include "cmnCrypto.h"

#include "_asnCertEncoding.h"

#if defined(WOLFSSL_CERT_GEN) && !defined(NO_RSA)


/* Write a serial number to output */
static int __setSerial(const byte* serial, byte* output)
{
    int length = 0;

    output[length++] = ASN_INTEGER;
    length += SetLength(CTC_SERIAL_SIZE, &output[length]);
    XMEMCPY(&output[length], serial, CTC_SERIAL_SIZE);

    return length + CTC_SERIAL_SIZE;
}


#ifdef HAVE_ECC 


/* Write a public ECC key to output */
static int SetEccPublicKey(byte* output, ecc_key* key)
{
    byte len[MAX_LENGTH_SZ + 1];  /* trailing 0 */
    int  algoSz;
    int  curveSz;
    int  lenSz;
    int  idx;
    word32 pubSz = ECC_BUFSIZE;
#ifdef WOLFSSL_SMALL_STACK
    byte* algo = NULL;
    byte* curve = NULL;
    byte* pub = NULL;
#else
    byte algo[MAX_ALGO_SZ];
    byte curve[MAX_ALGO_SZ];
    byte pub[ECC_BUFSIZE];
#endif

#ifdef WOLFSSL_SMALL_STACK
    pub = (byte*)XMALLOC(ECC_BUFSIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pub == NULL)
        return MEMORY_E;
#endif

    int ret = wc_ecc_export_x963(key, pub, &pubSz);
    if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

#ifdef WOLFSSL_SMALL_STACK
    curve = (byte*)XMALLOC(MAX_ALGO_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (curve == NULL) {
        XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    /* headers */
    curveSz = SetCurve(key, curve);
    if (curveSz <= 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(curve, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(pub,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return curveSz;
    }

#ifdef WOLFSSL_SMALL_STACK
    algo = (byte*)XMALLOC(MAX_ALGO_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (algo == NULL) {
        XFREE(curve, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(pub,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    algoSz  = SetAlgoID(ECDSAk, algo, keyType, curveSz);
    lenSz   = SetLength(pubSz + 1, len);
    len[lenSz++] = 0;   /* trailing 0 */

    /* write */
    idx = SetSequence(pubSz + curveSz + lenSz + 1 + algoSz, output);
        /* 1 is for ASN_BIT_STRING */
    /* algo */
    XMEMCPY(output + idx, algo, algoSz);
    idx += algoSz;
    /* curve */
    XMEMCPY(output + idx, curve, curveSz);
    idx += curveSz;
    /* bit string */
    output[idx++] = ASN_BIT_STRING;
    /* length */
    XMEMCPY(output + idx, len, lenSz);
    idx += lenSz;
    /* pub */
    XMEMCPY(output + idx, pub, pubSz);
    idx += pubSz;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(algo,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(curve, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pub,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return idx;
}


#endif /* HAVE_ECC */


/* Write a public RSA key to output */
int SetRsaPublicKey(byte* output, RsaKey* key)
{
#ifdef WOLFSSL_SMALL_STACK
    byte* n = NULL;
    byte* e = NULL;
    byte* algo = NULL;
#else
    byte n[MAX_RSA_INT_SZ];
    byte e[MAX_RSA_E_SZ];
    byte algo[MAX_ALGO_SZ];
#endif
    byte seq[MAX_SEQ_SZ];
    byte len[MAX_LENGTH_SZ + 1];  /* trailing 0 */
    int  nSz;
    int  eSz;
    int  algoSz;
    int  seqSz;
    int  lenSz;
    int  idx;
    int  rawLen;
    int  leadingBit;
    int  err;

    /* n */
#ifdef WOLFSSL_SMALL_STACK
    n = (byte*)XMALLOC(MAX_RSA_INT_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (n == NULL)
        return MEMORY_E;
#endif

    leadingBit = mp_leading_bit(&key->n);
    rawLen = mp_unsigned_bin_size(&key->n) + leadingBit;
    n[0] = ASN_INTEGER;
    nSz  = SetLength(rawLen, n + 1) + 1;  /* int tag */

    if ( (nSz + rawLen) < MAX_RSA_INT_SZ) {
        if (leadingBit)
            n[nSz] = 0;
        err = mp_to_unsigned_bin(&key->n, n + nSz + leadingBit);
        if (err == MP_OKAY)
            nSz += rawLen;
        else {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return MP_TO_E;
        }
    }
    else {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BUFFER_E;
    }

    /* e */
#ifdef WOLFSSL_SMALL_STACK
    e = (byte*)XMALLOC(MAX_RSA_E_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (e == NULL) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return MEMORY_E;
    }
#endif

    leadingBit = mp_leading_bit(&key->e);
    rawLen = mp_unsigned_bin_size(&key->e) + leadingBit;
    e[0] = ASN_INTEGER;
    eSz  = SetLength(rawLen, e + 1) + 1;  /* int tag */

    if ( (eSz + rawLen) < MAX_RSA_E_SZ) {
        if (leadingBit)
            e[eSz] = 0;
        err = mp_to_unsigned_bin(&key->e, e + eSz + leadingBit);
        if (err == MP_OKAY)
            eSz += rawLen;
        else {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(e, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return MP_TO_E;
        }
    }
    else {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(e, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BUFFER_E;
    }

#ifdef WOLFSSL_SMALL_STACK
    algo = (byte*)XMALLOC(MAX_ALGO_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (algo == NULL) {
        XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(e, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    /* headers */
    algoSz = SetAlgoID(RSAk, algo, keyType, 0);
    seqSz  = SetSequence(nSz + eSz, seq);
    lenSz  = SetLength(seqSz + nSz + eSz + 1, len);
    len[lenSz++] = 0;   /* trailing 0 */

    /* write */
    idx = SetSequence(nSz + eSz + seqSz + lenSz + 1 + algoSz, output);
        /* 1 is for ASN_BIT_STRING */
    /* algo */
    XMEMCPY(output + idx, algo, algoSz);
    idx += algoSz;
    /* bit string */
    output[idx++] = ASN_BIT_STRING;
    /* length */
    XMEMCPY(output + idx, len, lenSz);
    idx += lenSz;
    /* seq */
    XMEMCPY(output + idx, seq, seqSz);
    idx += seqSz;
    /* n */
    XMEMCPY(output + idx, n, nSz);
    idx += nSz;
    /* e */
    XMEMCPY(output + idx, e, eSz);
    idx += eSz;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(n,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(e,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(algo, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return idx;
}


static INLINE byte itob(int number)
{
    return (byte)number + 0x30;
}


/* write time to output, format */
static void __setTime(struct tm* date, byte* output)
{
	int i = 0;

	output[i++] = itob((date->tm_year % 10000) / 1000);
	output[i++] = itob((date->tm_year % 1000)  /  100);
	output[i++] = itob((date->tm_year % 100)   /   10);
	output[i++] = itob( date->tm_year % 10);

	output[i++] = itob(date->tm_mon / 10);
	output[i++] = itob(date->tm_mon % 10);

	output[i++] = itob(date->tm_mday / 10);
	output[i++] = itob(date->tm_mday % 10);

	output[i++] = itob(date->tm_hour / 10);
	output[i++] = itob(date->tm_hour % 10);

	output[i++] = itob(date->tm_min / 10);
	output[i++] = itob(date->tm_min % 10);

	output[i++] = itob(date->tm_sec / 10);
	output[i++] = itob(date->tm_sec % 10);

	output[i] = 'Z';  /* Zulu profile */
}


#ifdef WOLFSSL_ALT_NAMES
/* Copy Dates from cert, return bytes written */
static int __copyValidity(byte* output, Cert* cert)
{
	int seqSz;

	/* headers and output */
	seqSz = SetSequence(cert->beforeDateSz + cert->afterDateSz, output);
	XMEMCPY(output + seqSz, cert->beforeDate, cert->beforeDateSz);
	XMEMCPY(output + seqSz + cert->beforeDateSz, cert->afterDate, cert->afterDateSz);
	return seqSz + cert->beforeDateSz + cert->afterDateSz;
}
#endif


/* for systems where mktime() doesn't normalize fully */
static void __rebuildTime(time_t* in, struct tm* out)
{
    #ifdef FREESCALE_MQX
        out = localtime_r(in, out);
    #else
        (void)in;
        (void)out;
    #endif
}


/* Set Date validity from now until now + daysValid */
static int __setValidity(byte* output, int daysValid)
{
	byte before[MAX_DATE_SIZE];
	byte  after[MAX_DATE_SIZE];

	int beforeSz;
	int afterSz;
	int seqSz;

	time_t     ticks;
	time_t     normalTime;
	struct tm* now;
	struct tm* tmpTime = NULL;
	struct tm  local;

#if defined(FREESCALE_MQX) || defined(TIME_OVERRIDES)
	/* for use with gmtime_r */
	struct tm tmpTimeStorage;
	tmpTime = &tmpTimeStorage;
#else
	(void)tmpTime;
#endif

	ticks = XTIME(0);
	now   = XGMTIME(&ticks, tmpTime);

	/* before now */
	local = *now;
	before[0] = ASN_GENERALIZED_TIME;
	beforeSz  = SetLength(ASN_GEN_TIME_SZ, before + 1) + 1;  /* gen tag */

	/* subtract 1 day for more compliance */
	local.tm_mday -= 1;
	normalTime = mktime(&local);
	__rebuildTime(&normalTime, &local);

	/* adjust */
	local.tm_year += 1900;
	local.tm_mon  +=    1;

	__setTime(&local, before + beforeSz);
	beforeSz += ASN_GEN_TIME_SZ;

	/* after now + daysValid */
	local = *now;
	after[0] = ASN_GENERALIZED_TIME;
	afterSz  = SetLength(ASN_GEN_TIME_SZ, after + 1) + 1;  /* gen tag */

	/* add daysValid */
	local.tm_mday += daysValid;
	normalTime = mktime(&local);
	__rebuildTime(&normalTime, &local);

	/* adjust */
	local.tm_year += 1900;
	local.tm_mon  +=    1;

	__setTime(&local, after + afterSz);
	afterSz += ASN_GEN_TIME_SZ;

	/* headers and output */
	seqSz = SetSequence(beforeSz + afterSz, output);
	XMEMCPY(output + seqSz, before, beforeSz);
	XMEMCPY(output + seqSz + beforeSz, after, afterSz);

	return seqSz + beforeSz + afterSz;
}


#ifdef WOLFSSL_ALT_NAMES 

/* Set Alt Names from der cert, return 0 on success */
static int _setAltNamesFromCert(Cert* cert, const byte* der, int derSz)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* decoded;
#else
    DecodedCert decoded[1];
#endif

    if (derSz < 0)
        return derSz;

#ifdef WOLFSSL_SMALL_STACK
    decoded = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (decoded == NULL)
        return MEMORY_E;
#endif
    
    InitDecodedCert(decoded, (byte*)der, derSz, 0);
    ret = ParseCertRelative(decoded, CA_TYPE, NO_VERIFY, 0);

    if (ret < 0) {
        WOLFSSL_MSG("ParseCertRelative error");
    }
    else if (decoded->extensions) {
        byte   b;
        int    length;
        word32 maxExtensionsIdx;

        decoded->srcIdx = decoded->extensionsIdx;
        b = decoded->source[decoded->srcIdx++];
        
        if (b != ASN_EXTENSIONS) {
            ret = ASN_PARSE_E;
        }
        else if (GetLength(decoded->source, &decoded->srcIdx, &length, decoded->maxIdx) < 0) {
            ret = ASN_PARSE_E;
        }
        else if (GetSequence(decoded->source, &decoded->srcIdx, &length, decoded->maxIdx) < 0) {
            ret = ASN_PARSE_E;
        }
        else {
            maxExtensionsIdx = decoded->srcIdx + length;

            while (decoded->srcIdx < maxExtensionsIdx) {
                word32 oid;
                word32 startIdx = decoded->srcIdx;
                word32 tmpIdx;

                if (GetSequence(decoded->source, &decoded->srcIdx, &length,	decoded->maxIdx) < 0) {
                    ret = ASN_PARSE_E;
                    break;
                }

                tmpIdx = decoded->srcIdx;
                decoded->srcIdx = startIdx;

                if (GetAlgoId(decoded->source, &decoded->srcIdx, &oid, decoded->maxIdx) < 0) {
                    ret = ASN_PARSE_E;
                    break;
                }

                if (oid == ALT_NAMES_OID) {
                    cert->altNamesSz = length + (tmpIdx - startIdx);

                    if (cert->altNamesSz < (int)sizeof(cert->altNames))
                        XMEMCPY(cert->altNames, &decoded->source[startIdx], cert->altNamesSz);
                    else {
                        cert->altNamesSz = 0;
                        WOLFSSL_MSG("AltNames extensions too big");
                        ret = ALT_NAME_E;
                        break;
                    }
                }
                decoded->srcIdx = tmpIdx + length;
            }
        }
    }

    FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(decoded, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret < 0 ? ret : 0;
}


/* Set Dates from der cert, return 0 on success */
static int _setDatesFromCert(Cert* cert, const byte* der, int derSz)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* decoded;
#else
    DecodedCert decoded[1];
#endif

    WOLFSSL_ENTER();
    if (derSz < 0)
        return derSz;
    
#ifdef WOLFSSL_SMALL_STACK
    decoded = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (decoded == NULL)
        return MEMORY_E;
#endif

    InitDecodedCert(decoded, (byte*)der, derSz, 0);
    ret = ParseCertRelative(decoded, CA_TYPE, NO_VERIFY, 0);

    if (ret < 0) {
        WOLFSSL_MSG("ParseCertRelative error");
    }
    else if (decoded->beforeDate == NULL || decoded->afterDate == NULL) {
        WOLFSSL_MSG("Couldn't extract dates");
        ret = -1;
    }
    else if (decoded->beforeDateLen > MAX_DATE_SIZE || decoded->afterDateLen > MAX_DATE_SIZE) {
        WOLFSSL_MSG("Bad date size");
        ret = -1;
    }
    else {
        XMEMCPY(cert->beforeDate, decoded->beforeDate, decoded->beforeDateLen);
        XMEMCPY(cert->afterDate,  decoded->afterDate,  decoded->afterDateLen);

        cert->beforeDateSz = decoded->beforeDateLen;
        cert->afterDateSz  = decoded->afterDateLen;
    }

    FreeDecodedCert(decoded);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(decoded, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret < 0 ? ret : 0;
}


#endif /* WOLFSSL_ALT_NAMES && !NO_RSA */


/* Set cn name from der buffer, return 0 on success */
static int _setNameFromCert(CertName* cn, const byte* der, int derSz)
{
    int ret, sz;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* decoded;
#else
    DecodedCert decoded[1];
#endif

    if (derSz < 0)
        return derSz;

#ifdef WOLFSSL_SMALL_STACK
    decoded = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (decoded == NULL)
        return MEMORY_E;
#endif

    InitDecodedCert(decoded, (byte*)der, derSz, 0);
    ret = ParseCertRelative(decoded, CA_TYPE, NO_VERIFY, 0);

    if (ret < 0) {
        WOLFSSL_MSG("ParseCertRelative error");
    }
    else {
        if (decoded->subjectCN) {
            sz = (decoded->subjectCNLen < CTC_NAME_SIZE) ? decoded->subjectCNLen : CTC_NAME_SIZE - 1;
            strncpy(cn->commonName, decoded->subjectCN, CTC_NAME_SIZE);
            cn->commonName[sz] = 0;
            cn->commonNameEnc = decoded->subjectCNEnc;
        }
        if (decoded->subjectC) {
            sz = (decoded->subjectCLen < CTC_NAME_SIZE) ? decoded->subjectCLen : CTC_NAME_SIZE - 1;
            strncpy(cn->country, decoded->subjectC, CTC_NAME_SIZE);
            cn->country[sz] = 0;
            cn->countryEnc = decoded->subjectCEnc;
        }
        if (decoded->subjectST) {
            sz = (decoded->subjectSTLen < CTC_NAME_SIZE) ? decoded->subjectSTLen	: CTC_NAME_SIZE - 1;
            strncpy(cn->state, decoded->subjectST, CTC_NAME_SIZE);
            cn->state[sz] = 0;
            cn->stateEnc = decoded->subjectSTEnc;
        }
        if (decoded->subjectL) {
            sz = (decoded->subjectLLen < CTC_NAME_SIZE) ? decoded->subjectLLen : CTC_NAME_SIZE - 1;
            strncpy(cn->locality, decoded->subjectL, CTC_NAME_SIZE);
            cn->locality[sz] = 0;
            cn->localityEnc = decoded->subjectLEnc;
        }
        if (decoded->subjectO) {
            sz = (decoded->subjectOLen < CTC_NAME_SIZE) ? decoded->subjectOLen : CTC_NAME_SIZE - 1;
            strncpy(cn->org, decoded->subjectO, CTC_NAME_SIZE);
            cn->org[sz] = 0;
            cn->orgEnc = decoded->subjectOEnc;
        }
        if (decoded->subjectOU) {
            sz = (decoded->subjectOULen < CTC_NAME_SIZE) ? decoded->subjectOULen
                                                         : CTC_NAME_SIZE - 1;
            strncpy(cn->unit, decoded->subjectOU, CTC_NAME_SIZE);
            cn->unit[sz] = 0;
            cn->unitEnc = decoded->subjectOUEnc;
        }
        if (decoded->subjectSN) {
            sz = (decoded->subjectSNLen < CTC_NAME_SIZE) ? decoded->subjectSNLen
                                                         : CTC_NAME_SIZE - 1;
            strncpy(cn->sur, decoded->subjectSN, CTC_NAME_SIZE);
            cn->sur[sz] = 0;
            cn->surEnc = decoded->subjectSNEnc;
        }
        if (decoded->subjectEmail) {
            sz = (decoded->subjectEmailLen < CTC_NAME_SIZE)
               ?  decoded->subjectEmailLen : CTC_NAME_SIZE - 1;
            strncpy(cn->email, decoded->subjectEmail, CTC_NAME_SIZE);
            cn->email[sz] = 0;
        }
    }

    FreeDecodedCert(decoded);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(decoded, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret < 0 ? ret : 0;
}


#ifndef NO_FILESYSTEM

/* Set cert issuer from issuerFile in PEM */
int wc_SetIssuer(Cert* cert, const char* issuerFile)
{
    int         ret;
    int         derSz;
    byte*       der = (byte*)XMALLOC(EIGHTK_BUF, NULL, DYNAMIC_TYPE_CERT);

    if (der == NULL) {
        WOLFSSL_MSG("wc_SetIssuer OOF Problem");
        return MEMORY_E;
    }
    derSz = wolfSSL_PemCertToDer(issuerFile, der, EIGHTK_BUF);
    cert->selfSigned = 0;
    ret = _setNameFromCert(&cert->issuer, der, derSz);
    XFREE(der, NULL, DYNAMIC_TYPE_CERT);

    return ret;
}


/* Set cert subject from subjectFile in PEM */
int wc_SetSubject(Cert* cert, const char* subjectFile)
{
    int         ret;
    int         derSz;
    byte*       der = (byte*)XMALLOC(EIGHTK_BUF, NULL, DYNAMIC_TYPE_CERT);

    if (der == NULL) {
        WOLFSSL_MSG("wc_SetSubject OOF Problem");
        return MEMORY_E;
    }
    derSz = wolfSSL_PemCertToDer(subjectFile, der, EIGHTK_BUF);
    ret = _setNameFromCert(&cert->subject, der, derSz);
    XFREE(der, NULL, DYNAMIC_TYPE_CERT);

    return ret;
}


#ifdef WOLFSSL_ALT_NAMES

/* Set atl names from file in PEM */
int wc_SetAltNames(Cert* cert, const char* file)
{
    int         ret;
    int         derSz;
    byte*       der = (byte*)XMALLOC(EIGHTK_BUF, NULL, DYNAMIC_TYPE_CERT);

    if (der == NULL) {
        WOLFSSL_MSG("wc_SetAltNames OOF Problem");
        return MEMORY_E;
    }
    derSz = wolfSSL_PemCertToDer(file, der, EIGHTK_BUF);
    ret = _setAltNamesFromCert(cert, der, derSz);
    XFREE(der, NULL, DYNAMIC_TYPE_CERT);

    return ret;
}

#endif /* WOLFSSL_ALT_NAMES */

#endif /* NO_FILESYSTEM */

/* Set cert issuer from DER buffer */
int wc_SetIssuerBuffer(Cert* cert, const byte* der, int derSz)
{
	cert->selfSigned = 0;
	return _setNameFromCert(&cert->issuer, der, derSz);
}


/* Set cert subject from DER buffer */
int wc_SetSubjectBuffer(Cert* cert, const byte* der, int derSz)
{
	return _setNameFromCert(&cert->subject, der, derSz);
}


#ifdef WOLFSSL_ALT_NAMES

/* Set cert alt names from DER buffer */
int wc_SetAltNamesBuffer(Cert* cert, const byte* der, int derSz)
{
	return _setAltNamesFromCert(cert, der, derSz);
}

/* Set cert dates from DER buffer */
int wc_SetDatesBuffer(Cert* cert, const byte* der, int derSz)
{
    return _setDatesFromCert(cert, der, derSz);
}
#endif /* WOLFSSL_ALT_NAMES */



/* encode info from cert into DER encoded format */
static int _EncodeCert(Cert* cert, DerCert* der, RsaKey* rsaKey, ecc_key* eccKey, RNG* rng, const byte* ntruKey, word16 ntruSz)
{
	int ret;

	(void)eccKey;
	(void)ntruKey;
	(void)ntruSz;

	/* init */
	XMEMSET(der, 0, sizeof(DerCert));

	/* version */
	der->versionSz = SetMyVersion(cert->version, der->version, TRUE);

	/* serial number */
	ret = wc_RNG_GenerateBlock(rng, cert->serial, CTC_SERIAL_SIZE);
	if (ret != 0)
		return ret;

	cert->serial[0] = 0x01;   /* ensure positive */
	der->serialSz  = __setSerial(cert->serial, der->serial);

	/* signature algo */
	der->sigAlgoSz = SetAlgoID(cert->sigType, der->sigAlgo, sigType, 0);
	if (der->sigAlgoSz == 0)
		return ALGO_ID_E;

	/* public key */
	if (cert->keyType == RSA_KEY) {
		if (rsaKey == NULL)
			return PUBLIC_KEY_E;
		der->publicKeySz = SetRsaPublicKey(der->publicKey, rsaKey);
		if (der->publicKeySz <= 0)
			return PUBLIC_KEY_E;
	}

#ifdef HAVE_ECC
	if (cert->keyType == ECC_KEY) {
		if (eccKey == NULL)
			return PUBLIC_KEY_E;
		der->publicKeySz = SetEccPublicKey(der->publicKey, eccKey);
		if (der->publicKeySz <= 0)
			return PUBLIC_KEY_E;
	}
#endif /* HAVE_ECC */

#ifdef HAVE_NTRU
	if (cert->keyType == NTRU_KEY) {
		word32 rc;
		word16 encodedSz;

		rc  = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo( ntruSz, ntruKey, &encodedSz, NULL);
		if (rc != NTRU_OK)
			return PUBLIC_KEY_E;
		if (encodedSz > MAX_PUBLIC_KEY_SZ)
			return PUBLIC_KEY_E;

		rc  = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo( ntruSz, ntruKey, &encodedSz, der->publicKey);
		if (rc != NTRU_OK)
			return PUBLIC_KEY_E;

		der->publicKeySz = encodedSz;
	}
#endif /* HAVE_NTRU */

	der->validitySz = 0;
#ifdef WOLFSSL_ALT_NAMES
	/* date validity copy ? */
	if (cert->beforeDateSz && cert->afterDateSz) {
		der->validitySz = __copyValidity(der->validity, cert);
		if (der->validitySz == 0)
			return DATE_E;
	}
#endif

	/* date validity */
	if (der->validitySz == 0) {
		der->validitySz = __setValidity(der->validity, cert->daysValid);
		if (der->validitySz == 0)
			return DATE_E;
	}

	/* subject name */
	der->subjectSz = SetName(der->subject, &cert->subject);
	if (der->subjectSz == 0)
		return SUBJECT_E;

	/* issuer name */
	der->issuerSz = SetName(der->issuer, cert->selfSigned ?
	&cert->subject : &cert->issuer);
	if (der->issuerSz == 0)
		return ISSUER_E;

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
		der->extensionsSz = SetExtensions(der->extensions, der->ca, der->caSz, TRUE);
		if (der->extensionsSz == 0)
			return EXTENSIONS_E;
	}
	else
		der->extensionsSz = 0;

#ifdef WOLFSSL_ALT_NAMES
	if (der->extensionsSz == 0 && cert->altNamesSz) {
		der->extensionsSz = SetExtensions(der->extensions, cert->altNames, cert->altNamesSz, TRUE);
		if (der->extensionsSz == 0)
			return EXTENSIONS_E;
	}
#endif

	der->total = der->versionSz + der->serialSz + der->sigAlgoSz +
	der->publicKeySz + der->validitySz + der->subjectSz + der->issuerSz +
	der->extensionsSz;

	return 0;
}


/* write DER encoded cert to buffer, size already checked */
static int _WriteCertBody(DerCert* der, byte* buffer)
{
    int idx;

    /* signed part header */
    idx = SetSequence(der->total, buffer);
    /* version */
    XMEMCPY(buffer + idx, der->version, der->versionSz);
    idx += der->versionSz;
    /* serial */
    XMEMCPY(buffer + idx, der->serial, der->serialSz);
    idx += der->serialSz;
    /* sig algo */
    XMEMCPY(buffer + idx, der->sigAlgo, der->sigAlgoSz);
    idx += der->sigAlgoSz;
    /* issuer */
    XMEMCPY(buffer + idx, der->issuer, der->issuerSz);
    idx += der->issuerSz;
    /* validity */
    XMEMCPY(buffer + idx, der->validity, der->validitySz);
    idx += der->validitySz;
    /* subject */
    XMEMCPY(buffer + idx, der->subject, der->subjectSz);
    idx += der->subjectSz;
    /* public key */
    XMEMCPY(buffer + idx, der->publicKey, der->publicKeySz);
    idx += der->publicKeySz;
    if (der->extensionsSz) {
        /* extensions */
        XMEMCPY(buffer + idx, der->extensions, min(der->extensionsSz, sizeof(der->extensions)));
        idx += der->extensionsSz;
    }

    return idx;
}

/* Make an x509 Certificate v3 any key type from cert input, write to buffer */
int makeAnyCert(Cert* cert, byte* derBuffer, word32 derSz,
                       RsaKey* rsaKey, ecc_key* eccKey, RNG* rng,
                       const byte* ntruKey, word16 ntruSz)
{
	int ret;
#ifdef WOLFSSL_SMALL_STACK
	DerCert* der;
#else
	DerCert der[1];
#endif

	cert->keyType = eccKey ? ECC_KEY : (rsaKey ? RSA_KEY : NTRU_KEY);

#ifdef WOLFSSL_SMALL_STACK
	der = (DerCert*)XMALLOC(sizeof(DerCert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (der == NULL)
		return MEMORY_E;
#endif

	ret = _EncodeCert(cert, der, rsaKey, eccKey, rng, ntruKey, ntruSz);

	if (ret == 0) {
		if (der->total + MAX_SEQ_SZ * 2 > (int)derSz)
			ret = BUFFER_E;
		else
			ret = cert->bodySz = _WriteCertBody(der, derBuffer);
	}

#ifdef WOLFSSL_SMALL_STACK
	XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

	return ret;
}


#endif /* WOLFSSL_CERT_GEN */

