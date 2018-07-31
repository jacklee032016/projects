/*
* Decode Key of different algorithm fom cert file or buffer from cert file
*/

#include "cmnCrypto.h"


/*
* parse private key and public key for for different algorithms(RSA,DH and DSA) with ASN, mainly for cert file
*/

#ifndef NO_PWDBASED

/* Check To see if PKCS version algo is supported, set id if it is return 0; < 0 on error */
static int _checkAlgo(int first, int second, int* id, int* version)
{
	*id      = ALGO_ID_E;
	*version = PKCS5;   /* default */

	if (first == 1) {
		switch (second) {
			case 1:
				*id = PBE_SHA1_RC4_128;
				*version = PKCS12;
				return 0;
				
			case 3:
				*id = PBE_SHA1_DES3;
				*version = PKCS12;
				return 0;
			
			default:
				return ALGO_ID_E;
		}
	}

	if (first != PKCS5)
		return ASN_INPUT_E;  /* VERSION ERROR */

	if (second == PBES2) {
		*version = PKCS5v2;
		return 0;
	}

	switch (second) {
		case 3: /* see RFC 2898 for ids */
			*id = PBE_MD5_DES;
			return 0;
		
		case 10:
			*id = PBE_SHA1_DES;
			return 0;
		
		default:
			return ALGO_ID_E;
	}
}


/* Check To see if PKCS v2 algo is supported, set id if it is return 0;  < 0 on error */
static int _checkAlgoV2(int oid, int* id)
{
	switch (oid) {
		case 69:
			*id = PBE_SHA1_DES;
			return 0;
		
		case 652:
			*id = PBE_SHA1_DES3;
			return 0;
		
		default:
			return ALGO_ID_E;
    }
}


/* Decrypt intput in place from parameters based on id 
* decrypted result is stored in input
*/
static int _decryptKey(const char* password, int passwordSz, byte* salt,
                      int saltSz, int iterations, int id, byte* input,
                      int length, int version, byte* cbcIv)
{
    int typeH;
    int derivedLen;
    int decryptionType;
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* key;
#else
    byte key[MAX_KEY_SIZE];
#endif

    switch (id) {
        case PBE_MD5_DES:
            typeH = MD5;
            derivedLen = 16;           /* may need iv for v1.5 */
            decryptionType = DES_TYPE;
            break;

        case PBE_SHA1_DES:
            typeH = SHA;
            derivedLen = 16;           /* may need iv for v1.5 */
            decryptionType = DES_TYPE;
            break;

        case PBE_SHA1_DES3:
            typeH = SHA;
            derivedLen = 32;           /* may need iv for v1.5 */
            decryptionType = DES3_TYPE;
            break;

        case PBE_SHA1_RC4_128:
            typeH = SHA;
            derivedLen = 16;
            decryptionType = RC4_TYPE;
            break;

        default:
            return ALGO_ID_E;
    }

#ifdef WOLFSSL_SMALL_STACK
    key = (byte*)XMALLOC(MAX_KEY_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL)
        return MEMORY_E;
#endif

	/* calculate hash (eg. key) from passwd and salt */
	if (version == PKCS5v2)
		ret = wc_PBKDF2(key, (byte*)password, passwordSz, salt, saltSz, iterations, derivedLen, typeH);
#ifndef NO_SHA
	else if (version == PKCS5)
		ret = wc_PBKDF1(key, (byte*)password, passwordSz, salt, saltSz, iterations, derivedLen, typeH);
#endif
	else if (version == PKCS12)
	{/* passwd is in unicode */
		int  i, idx = 0;
		byte unicodePasswd[MAX_UNICODE_SZ];

		if ( (passwordSz * 2 + 2) > (int)sizeof(unicodePasswd)) {
#ifdef WOLFSSL_SMALL_STACK
			XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
			return UNICODE_SIZE_E; 
		}

		for (i = 0; i < passwordSz; i++) {
			unicodePasswd[idx++] = 0x00;
			unicodePasswd[idx++] = (byte)password[i];
		}
		/* add trailing NULL */
		unicodePasswd[idx++] = 0x00;
		unicodePasswd[idx++] = 0x00;

		ret =  wc_PKCS12_PBKDF(key, unicodePasswd, idx, salt, saltSz, iterations, derivedLen, typeH, 1);
		if (decryptionType != RC4_TYPE)
			ret += wc_PKCS12_PBKDF(cbcIv, unicodePasswd, idx, salt, saltSz, iterations, 8, typeH, 2);
	}
	else {
#ifdef WOLFSSL_SMALL_STACK
		XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
		return ALGO_ID_E;
	}

	if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
		XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
		return ret;
	}

	/* decipher with DES/DES3/ARC4 into input from input */
	switch (decryptionType)
	{
#ifndef NO_DES3
		case DES_TYPE:
		{
			Des    dec;
			byte*  desIv = key + 8;

			if (version == PKCS5v2 || version == PKCS12)
				desIv = cbcIv;

			ret = wc_Des_SetKey(&dec, key, desIv, DES_DECRYPTION);
			if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
				XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
				return ret;
			}

			wc_Des_CbcDecrypt(&dec, input, input, length);
			break;
		}

		case DES3_TYPE:
		{
			Des3   dec;
			byte*  desIv = key + 24;

			if (version == PKCS5v2 || version == PKCS12)
				desIv = cbcIv;
			ret = wc_Des3_SetKey(&dec, key, desIv, DES_DECRYPTION);
			if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
				XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
				return ret;
			}
			ret = wc_Des3_CbcDecrypt(&dec, input, input, length);
			if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
				XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
				return ret;
			}
			break;
		}
#endif
#ifndef NO_RC4
		case RC4_TYPE:
		{
			Arc4    dec;

			wc_Arc4SetKey(&dec, key, derivedLen);
			wc_Arc4Process(&dec, input, input, length);
			break;
		}
#endif

		default:
#ifdef WOLFSSL_SMALL_STACK
		XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
		return ALGO_ID_E; 
	}

#ifdef WOLFSSL_SMALL_STACK
	XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

	return 0;
}


/* Remove Encrypted PKCS8 header, move beginning of traditional to beginning of input */
int ToTraditionalEnc(byte* input, word32 sz,const char* password,int passwordSz)
{
    word32 inOutIdx = 0, oid;
    int    first, second, length, version, saltSz, id;
    int    iterations = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte*  salt = NULL;
    byte*  cbcIv = NULL;
#else
    byte   salt[MAX_SALT_SIZE];
    byte   cbcIv[MAX_IV_SIZE];
#endif
    
    if (GetSequence(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (GetAlgoId(input, &inOutIdx, &oid, sz) < 0)
        return ASN_PARSE_E;
    
    first  = input[inOutIdx - 2];   /* PKCS version alwyas 2nd to last byte */
    second = input[inOutIdx - 1];   /* version.algo, algo id last byte */

    if (_checkAlgo(first, second, &id, &version) < 0)
        return ASN_INPUT_E;  /* Algo ID error */

    if (version == PKCS5v2) {

        if (GetSequence(input, &inOutIdx, &length, sz) < 0)
            return ASN_PARSE_E;

        if (GetAlgoId(input, &inOutIdx, &oid, sz) < 0)
            return ASN_PARSE_E;

        if (oid != PBKDF2_OID)
            return ASN_PARSE_E;
    }

    if (GetSequence(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (input[inOutIdx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;
    
    if (GetLength(input, &inOutIdx, &saltSz, sz) < 0)
        return ASN_PARSE_E;

    if (saltSz > MAX_SALT_SIZE)
        return ASN_PARSE_E;
     
#ifdef WOLFSSL_SMALL_STACK
    salt = (byte*)XMALLOC(MAX_SALT_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (salt == NULL)
        return MEMORY_E;
#endif

    XMEMCPY(salt, &input[inOutIdx], saltSz);
    inOutIdx += saltSz;

    if (GetShortInt(input, &inOutIdx, &iterations) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

#ifdef WOLFSSL_SMALL_STACK
    cbcIv = (byte*)XMALLOC(MAX_IV_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (cbcIv == NULL) {
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    if (version == PKCS5v2) {
        /* get encryption algo */
        if (GetAlgoId(input, &inOutIdx, &oid, sz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }

        if (_checkAlgoV2(oid, &id) < 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;  /* PKCS v2 algo id error */
        }

        if (input[inOutIdx++] != ASN_OCTET_STRING) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }
    
        if (GetLength(input, &inOutIdx, &length, sz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }

        XMEMCPY(cbcIv, &input[inOutIdx], length);
        inOutIdx += length;
    }

    if (input[inOutIdx++] != ASN_OCTET_STRING) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    if (GetLength(input, &inOutIdx, &length, sz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    if (_decryptKey(password, passwordSz, salt, saltSz, iterations, id,
                   input + inOutIdx, length, version, cbcIv) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_INPUT_E;  /* decrypt failure */
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    XMEMMOVE(input, input + inOutIdx, length);
    return ToTraditional(input, length);
}

#endif /* NO_PWDBASED */

#ifndef NO_RSA

int wc_RsaPublicKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key, word32 inSz)
{
    int    length;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PUBLIC;

#if defined(OPENSSL_EXTRA) || defined(RSA_DECODE_EXTRA)
    {
    byte b = input[*inOutIdx];
    if (b != ASN_INTEGER) {
        /* not from decoded cert, will have algo id, skip past */
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
        
        b = input[(*inOutIdx)++];
        if (b != ASN_OBJECT_ID) 
            return ASN_OBJECT_ID_E;
        
        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
        
        *inOutIdx += length;   /* skip past */
        
        /* could have NULL tag and 0 terminator, but may not */
        b = input[(*inOutIdx)++];
        
        if (b == ASN_TAG_NULL) {
            b = input[(*inOutIdx)++];
            if (b != 0) 
                return ASN_EXPECT_0_E;
        }
        else
        /* go back, didn't have it */
            (*inOutIdx)--;
        
        /* should have bit tag length and seq next */
        b = input[(*inOutIdx)++];
        if (b != ASN_BIT_STRING)
            return ASN_BITSTR_E;
        
        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
        
        /* could have 0 */
        b = input[(*inOutIdx)++];
        if (b != 0)
            (*inOutIdx)--;
        
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
    }  /* end if */
    }  /* openssl var block */
#endif /* OPENSSL_EXTRA */

    if (GetInt(&key->n,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->e,  input, inOutIdx, inSz) < 0 ) 
        return ASN_RSA_KEY_E;

    return 0;
}

/* import RSA public key elements (n, e) into RsaKey structure (key) */
int wc_RsaPublicKeyDecodeRaw(const byte* n, word32 nSz, const byte* e, word32 eSz, RsaKey* key)
{
    if (n == NULL || e == NULL || key == NULL)
        return BAD_FUNC_ARG;

    key->type = RSA_PUBLIC;

    if (mp_init(&key->n) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(&key->n, n, nSz) != 0) {
        mp_clear(&key->n);
        return ASN_GETINT_E;
    }

    if (mp_init(&key->e) != MP_OKAY) {
        mp_clear(&key->n);
        return MP_INIT_E;
    }

    if (mp_read_unsigned_bin(&key->e, e, eSz) != 0) {
        mp_clear(&key->n);
        mp_clear(&key->e);
        return ASN_GETINT_E;
    }

    return 0;
}



int wc_RsaPrivateKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key, word32 inSz)
{
    int    version, length;

#ifdef HAVE_CAVIUM
    if (key->magic == WOLFSSL_RSA_CAVIUM_MAGIC)
        return CaviumRsaPrivateKeyDecode(input, inOutIdx, key, inSz);
#endif

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PRIVATE;

	/*lzj. decode private key and public key simultaneously */
    if (GetInt(&key->n,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->e,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->d,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->q,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->dP, input, inOutIdx, inSz) < 0 ||
        GetInt(&key->dQ, input, inOutIdx, inSz) < 0 ||
        GetInt(&key->u,  input, inOutIdx, inSz) < 0 )  return ASN_RSA_KEY_E;

    return 0;
}

#endif

#ifndef NO_DH

int wc_DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key, word32 inSz)
{
	int    length;

	if (GetSequence(input, inOutIdx, &length, inSz) < 0)
		return ASN_PARSE_E;

	if (GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||GetInt(&key->g,  input, inOutIdx, inSz) < 0 )
		return ASN_DH_KEY_E;

	return 0;
}


int wc_DhParamsLoad(const byte* input, word32 inSz, byte* p, word32* pInOutSz, byte* g, word32* gInOutSz)
{
	word32 i = 0;
	byte   b;
	int    length;

	if (GetSequence(input, &i, &length, inSz) < 0)
		return ASN_PARSE_E;

	b = input[i++];
	if (b != ASN_INTEGER)
		return ASN_PARSE_E;

	if (GetLength(input, &i, &length, inSz) < 0)
		return ASN_PARSE_E;

	if ( (b = input[i++]) == 0x00)
		length--;
	else
		i--;

	if (length <= (int)*pInOutSz) {
		XMEMCPY(p, &input[i], length);
		*pInOutSz = length;
	}
	else
		return BUFFER_E;

	i += length;

	b = input[i++];
	if (b != ASN_INTEGER)
		return ASN_PARSE_E;

	if (GetLength(input, &i, &length, inSz) < 0)
		return ASN_PARSE_E;

	if (length <= (int)*gInOutSz) {
		XMEMCPY(g, &input[i], length);
		*gInOutSz = length;
	}
	else
		return BUFFER_E;

	return 0;
}

#endif /* NO_DH */


#ifndef NO_DSA

int DsaPublicKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key, word32 inSz)
{
	int    length;

	if (GetSequence(input, inOutIdx, &length, inSz) < 0)
		return ASN_PARSE_E;

	if (GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
		GetInt(&key->q,  input, inOutIdx, inSz) < 0 ||
		GetInt(&key->g,  input, inOutIdx, inSz) < 0 ||
		GetInt(&key->y,  input, inOutIdx, inSz) < 0 )
		return ASN_DH_KEY_E;

	key->type = DSA_KEY_TYPE_PUBLIC;
	return 0;
}

/* DER for DSA key, with both private and public key */
int DsaPrivateKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key, word32 inSz)
{
	int    length, version;

	if (GetSequence(input, inOutIdx, &length, inSz) < 0)
		return ASN_PARSE_E;

	if (GetMyVersion(input, inOutIdx, &version) < 0)
		return ASN_PARSE_E;

	if (GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
		GetInt(&key->q,  input, inOutIdx, inSz) < 0 ||
		GetInt(&key->g,  input, inOutIdx, inSz) < 0 ||
		GetInt(&key->y,  input, inOutIdx, inSz) < 0 ||
		GetInt(&key->x,  input, inOutIdx, inSz) < 0 )
		return ASN_DH_KEY_E;
	wolfSslDebug("DSA Private Key length %d, version %d\n", length, version);

	key->type = DSA_KEY_TYPE_PRIVATE;
	return 0;
}

#endif /* NO_DSA */

