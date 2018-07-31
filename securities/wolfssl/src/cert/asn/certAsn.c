/* asn.c
 */

#include "cmnCrypto.h"


#if defined(MICRIUM)

CPU_INT32S NetSecure_ValidateDateHandler(CPU_INT08U *date, CPU_INT08U format,
                                         CPU_INT08U dateType)
{
    CPU_BOOLEAN  rtn_code;
    CPU_INT32S   i;
    CPU_INT32S   val;    
    CPU_INT16U   year;
    CPU_INT08U   month;
    CPU_INT16U   day;
    CPU_INT08U   hour;
    CPU_INT08U   min;
    CPU_INT08U   sec;

    i    = 0;
    year = 0u;

    if (format == ASN_UTC_TIME) {
        if (btoi(date[0]) >= 5)
            year = 1900;
        else
            year = 2000;
    }
    else  { /* format == GENERALIZED_TIME */
        year += btoi(date[i++]) * 1000;
        year += btoi(date[i++]) * 100;
    }    

    val = year;
    GetTime(&val, date, &i);
    year = (CPU_INT16U)val;

    val = 0;
    GetTime(&val, date, &i);   
    month = (CPU_INT08U)val;   

    val = 0;
    GetTime(&val, date, &i);  
    day = (CPU_INT16U)val;

    val = 0;
    GetTime(&val, date, &i);  
    hour = (CPU_INT08U)val;

    val = 0;
    GetTime(&val, date, &i);  
    min = (CPU_INT08U)val;

    val = 0;
    GetTime(&val, date, &i);  
    sec = (CPU_INT08U)val;

    return NetSecure_ValidateDate(year, month, day, hour, min, sec, dateType); 
}

#endif /* MICRIUM */



/* Remove PKCS8 header, move beginning of traditional to beginning of input */
int ToTraditional(byte* input, word32 sz)
{
    word32 inOutIdx = 0, oid;
    int    version, length;

    if (GetSequence(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, &inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    if (GetAlgoId(input, &inOutIdx, &oid, sz) < 0)
        return ASN_PARSE_E;

    if (input[inOutIdx] == ASN_OBJECT_ID) {
        /* pkcs8 ecc uses slightly different format */
        inOutIdx++;  /* past id */
        if (GetLength(input, &inOutIdx, &length, sz) < 0)
            return ASN_PARSE_E;
        inOutIdx += length;  /* over sub id, key input will verify */
    }

    if (input[inOutIdx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;

    if (GetLength(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;

    XMEMMOVE(input, input + inOutIdx, length);

    return length;
}



#ifdef HAVE_ECC

    /* return 0 on sucess if the ECC curve oid sum is supported */
    static int CheckCurve(word32 oid)
    {
        int ret = 0;

        switch (oid) {
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC160)
            case ECC_160R1:
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC192)
            case ECC_192R1:
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC224)
            case ECC_224R1:
#endif
#if defined(HAVE_ALL_CURVES) || !defined(NO_ECC256)
            case ECC_256R1:
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC384)
            case ECC_384R1:
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC521)
            case ECC_521R1:
#endif
                break;

            default:
                ret = ALGO_ID_E;
        }

        return ret;
    }

#endif /* HAVE_ECC */


word32 BytePrecision(word32 value)
{
    word32 i;
    for (i = sizeof(value); i; --i)
        if (value >> ((i - 1) * WOLFSSL_BIT_SIZE))
            break;

    return i;
}


int wc_GetCTC_HashOID(int type)
{
    switch (type) {
#ifdef WOLFSSL_MD2
        case MD2:
            return MD2h;
#endif
#ifndef NO_MD5
        case MD5:
            return MD5h;
#endif
#ifndef NO_SHA
        case SHA:
            return SHAh;
#endif
#ifndef NO_SHA256
        case SHA256:
            return SHA256h;
#endif
#ifdef WOLFSSL_SHA384
        case SHA384:
            return SHA384h;
#endif
#ifdef WOLFSSL_SHA512
        case SHA512:
            return SHA512h;
#endif
        default:
            return 0;
    };
}


#ifndef IGNORE_NAME_CONSTRAINTS

static int __matchBaseName(int type, const char* name, int nameSz, const char* base, int baseSz)
{
	if (base == NULL || baseSz <= 0 || name == NULL || nameSz <= 0 ||
		name[0] == '.' || nameSz < baseSz ||(type != ASN_RFC822_TYPE && type != ASN_DNS_TYPE))
		return 0;

	/* If an email type, handle special cases where the base is only
	* a domain, or is an email address itself. */
	if (type == ASN_RFC822_TYPE)
	{
		const char* p = NULL;
		int count = 0;

		if (base[0] != '.')
		{
			p = base;
			count = 0;

			/* find the '@' in the base */
			while (*p != '@' && count < baseSz) {
				count++;
				p++;
			}

			/* No '@' in base, reset p to NULL */
			if (count >= baseSz)
				p = NULL;
		}

		if (p == NULL) {
			/* Base isn't an email address, it is a domain name,
			* wind the name forward one character past its '@'. */
			p = name;
			count = 0;
			while (*p != '@' && count < baseSz) {
				count++;
				p++;
			}

			if (count < baseSz && *p == '@') {
				name = p + 1;
				nameSz -= count + 1;
			}
		}
	}

	if ((type == ASN_DNS_TYPE || type == ASN_RFC822_TYPE) && base[0] == '.')
	{
		int szAdjust = nameSz - baseSz;
		name += szAdjust;
		nameSz -= szAdjust;
	}

	while (nameSz > 0)
	{
		if (XTOLOWER((unsigned char)*name++) != XTOLOWER((unsigned char)*base++))
			return 0;
		nameSz--;
	}

	return 1;
}


int ConfirmNameConstraints(Signer* signer, DecodedCert* cert)
{
	if (signer == NULL || cert == NULL)
		return 0;

	/* Check against the excluded list */
	if (signer->excludedNames)
	{
		Base_entry* base = signer->excludedNames;

		while (base != NULL)
		{
			if (base->type == ASN_DNS_TYPE)
			{
				DNS_entry* name = cert->altNames;
				while (name != NULL) {
					if (__matchBaseName(ASN_DNS_TYPE, name->name, (int)XSTRLEN(name->name), base->name, base->nameSz))
						return 0;
					name = name->next;
				}
			}
			else if (base->type == ASN_RFC822_TYPE)
			{
				DNS_entry* name = cert->altEmailNames;
				while (name != NULL)
				{
					if (__matchBaseName(ASN_RFC822_TYPE, name->name, (int)XSTRLEN(name->name), base->name, base->nameSz))
						return 0;

					name = name->next;
				}
			}
			else if (base->type == ASN_DIR_TYPE)
			{
				if (cert->subjectRawLen == base->nameSz && XMEMCMP(cert->subjectRaw, base->name, base->nameSz) == 0)
				{
					return 0;
				}
			}
			base = base->next;
		}
	}

	/* Check against the permitted list */
	if (signer->permittedNames != NULL) {
		int needDns = 0;
		int matchDns = 0;
		int needEmail = 0;
		int matchEmail = 0;
		int needDir = 0;
		int matchDir = 0;
		Base_entry* base = signer->permittedNames;

		while (base != NULL) {
			if (base->type == ASN_DNS_TYPE) {
				DNS_entry* name = cert->altNames;

				if (name != NULL)
					needDns = 1;

				while (name != NULL) {
					matchDns = __matchBaseName(ASN_DNS_TYPE, name->name, (int)XSTRLEN(name->name), base->name, base->nameSz);
					name = name->next;
				}
			}
			else if (base->type == ASN_RFC822_TYPE) {
				DNS_entry* name = cert->altEmailNames;

				if (name != NULL)
					needEmail = 1;

				while (name != NULL) {
					matchEmail = __matchBaseName(ASN_DNS_TYPE, name->name, (int)XSTRLEN(name->name), base->name, base->nameSz);
					name = name->next;
				}
			}
			else if (base->type == ASN_DIR_TYPE) {
				needDir = 1;
				if (cert->subjectRaw != NULL && cert->subjectRawLen == base->nameSz &&
					XMEMCMP(cert->subjectRaw, base->name, base->nameSz) == 0)
				{
					matchDir = 1;
				}
			}
			base = base->next;
		}

		if ((needDns && !matchDns) || (needEmail && !matchEmail) ||(needDir && !matchDir))
		{
			return 0;
		}
	}

	return 1;
}
#endif /* IGNORE_NAME_CONSTRAINTS */



#if defined(HAVE_OCSP) || defined(HAVE_CRL)

/* Get raw Date only, no processing, 0 on success */
int GetBasicDate(const byte* source, word32* idx, byte* date,
                        byte* format, int maxIdx)
{
    int    length;

    WOLFSSL_ENTER();

    *format = source[*idx];
    *idx += 1;
    if (*format != ASN_UTC_TIME && *format != ASN_GENERALIZED_TIME)
        return ASN_TIME_E;

    if (GetLength(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DATE_SZ_E;

    XMEMCPY(date, &source[*idx], length);
    *idx += length;

    return 0;
}

#endif




/* store SHA hash of NAME */
WOLFSSL_LOCAL int GetNameHash(const byte* source, word32* idx, byte* hash,
                             int maxIdx)
{
    int    length;  /* length of all distinguished names */
    int    ret;
    word32 dummy;

    WOLFSSL_ENTER();

    if (source[*idx] == ASN_OBJECT_ID) {
        WOLFSSL_MSG("Trying optional prefix...");

        if (GetLength(source, idx, &length, maxIdx) < 0)
            return ASN_PARSE_E;

        *idx += length;
        WOLFSSL_MSG("Got optional prefix");
    }

    /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
     * calculated over the entire DER encoding of the Name field, including
     * the tag and length. */
    dummy = *idx;
    if (GetSequence(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

#ifdef NO_SHA
    ret = wc_Sha256Hash(source + dummy, length + *idx - dummy, hash);
#else
    ret = wc_ShaHash(source + dummy, length + *idx - dummy, hash);
#endif

    *idx += length;

    return ret;
}


