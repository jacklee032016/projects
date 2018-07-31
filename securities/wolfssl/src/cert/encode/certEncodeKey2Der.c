/*
* translate RSA Key into DER buffer
* translate DER buffer into PEM buffer (Base64 coding)
*/

#include "cmnCrypto.h"


/*
* functions used to generate key and certificate with ASN.1
*/
#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
static mp_int* _GetRsaInt(RsaKey* key, int idx)
{
	if (idx == 0)
		return &key->n;
	if (idx == 1)
		return &key->e;
	if (idx == 2)
		return &key->d;
	if (idx == 3)
		return &key->p;
	if (idx == 4)
		return &key->q;
	if (idx == 5)
		return &key->dP;
	if (idx == 6)
		return &key->dQ;
	if (idx == 7)
		return &key->u;

	return NULL;
}


/* Release Tmp RSA resources */
static INLINE void _FreeTmpRsas(byte** tmps, void* heap)
{
    int i;

    (void)heap;

    for (i = 0; i < RSA_INTS; i++) 
        XFREE(tmps[i], heap, DYNAMIC_TYPE_RSA);
}


/* Convert RsaKey key to DER format, write to output (inLen), return bytes written */
int wc_RsaKeyToDer(RsaKey* key, byte* output, word32 inLen)
{
	word32 seqSz, verSz, rawLen, intTotalLen = 0;
	word32 sizes[RSA_INTS];
	int    i, j, outLen, ret = 0;

	byte  seq[MAX_SEQ_SZ];
	byte  ver[MAX_VERSION_SZ];
	byte* tmps[RSA_INTS];

	if (!key || !output)
		return BAD_FUNC_ARG;

	if (key->type != RSA_PRIVATE)
		return BAD_FUNC_ARG;

	for (i = 0; i < RSA_INTS; i++)
		tmps[i] = NULL;

	/* write all big ints from key to DER tmps */
	for (i = 0; i < RSA_INTS; i++) {
		mp_int* keyInt = _GetRsaInt(key, i);
		rawLen = mp_unsigned_bin_size(keyInt);
		tmps[i] = (byte*)XMALLOC(rawLen + MAX_SEQ_SZ, key->heap, DYNAMIC_TYPE_RSA);
		if (tmps[i] == NULL) {
			ret = MEMORY_E;
			break;
		}

		tmps[i][0] = ASN_INTEGER;
		sizes[i] = SetLength(rawLen, tmps[i] + 1) + 1;  /* int tag */

		if (sizes[i] <= MAX_SEQ_SZ)
		{
			int err = mp_to_unsigned_bin(keyInt, tmps[i] + sizes[i]);
			if (err == MP_OKAY) {
				sizes[i] += rawLen;
				intTotalLen += sizes[i];
			}
			else {
				ret = err;
				break;
			}
		}
		else {
			ret = ASN_INPUT_E;
			break;
		}
	}

	if (ret != 0) {
		_FreeTmpRsas(tmps, key->heap);
		return ret;
	}

	/* make headers */
	verSz = SetMyVersion(0, ver, FALSE);
	seqSz = SetSequence(verSz + intTotalLen, seq);

	outLen = seqSz + verSz + intTotalLen;
	if (outLen > (int)inLen)
		return BAD_FUNC_ARG;

	/* write to output */
	XMEMCPY(output, seq, seqSz);
	j = seqSz;
	XMEMCPY(output + j, ver, verSz);
	j += verSz;

	for (i = 0; i < RSA_INTS; i++) {
		XMEMCPY(output + j, tmps[i], sizes[i]);
		j += sizes[i];
	}
	_FreeTmpRsas(tmps, key->heap);

	return outLen;
}

#endif /* WOLFSSL_KEY_GEN && !NO_RSA */


#if defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_CERT_GEN)

/* convert der buffer to pem into output, can't do inplace, der and output need to be different */
int wc_DerToPem(const byte* der, word32 derSz, byte* output, word32 outSz, int type)
{
#ifdef WOLFSSL_SMALL_STACK
    char* header = NULL;
    char* footer = NULL;
#else
    char header[80];
    char footer[80];
#endif

    int headerLen = 80;
    int footerLen = 80;
    int i;
    int err;
    int outLen;   /* return length or error */

    if (der == output)      /* no in place conversion */
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
    header = (char*)XMALLOC(headerLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (header == NULL)
        return MEMORY_E;
    
    footer = (char*)XMALLOC(footerLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (footer == NULL) {
        XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    if (type == CERT_TYPE) {
        XSTRNCPY(header, "-----BEGIN CERTIFICATE-----\n", headerLen);
        XSTRNCPY(footer, "-----END CERTIFICATE-----\n",   footerLen);
    }
    else if (type == PRIVATEKEY_TYPE) {
        XSTRNCPY(header, "-----BEGIN RSA PRIVATE KEY-----\n", headerLen);
        XSTRNCPY(footer, "-----END RSA PRIVATE KEY-----\n",   footerLen);
    }
    #ifdef HAVE_ECC
    else if (type == ECC_PRIVATEKEY_TYPE) {
        XSTRNCPY(header, "-----BEGIN EC PRIVATE KEY-----\n", headerLen);
        XSTRNCPY(footer, "-----END EC PRIVATE KEY-----\n",   footerLen);
    }
    #endif
    #ifdef WOLFSSL_CERT_REQ
    else if (type == CERTREQ_TYPE)
    {
        XSTRNCPY(header,
                       "-----BEGIN CERTIFICATE REQUEST-----\n", headerLen);
        XSTRNCPY(footer, "-----END CERTIFICATE REQUEST-----\n", footerLen);
    }
    #endif
    else {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BAD_FUNC_ARG;
    }

    headerLen = (int)XSTRLEN(header);
    footerLen = (int)XSTRLEN(footer);

    if (!der || !output) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BAD_FUNC_ARG;
    }

    /* don't even try if outSz too short */
    if (outSz < headerLen + footerLen + derSz) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BAD_FUNC_ARG;
    }

    /* header */
    XMEMCPY(output, header, headerLen);
    i = headerLen;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    /* body */
    outLen = outSz - (headerLen + footerLen);  /* input to Base64_Encode */
    if ( (err = Base64_Encode(der, derSz, output + i, (word32*)&outLen)) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return err;
    }
    i += outLen;

    /* footer */
    if ( (i + footerLen) > (int)outSz) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BAD_FUNC_ARG;
    }
    XMEMCPY(output + i, footer, footerLen);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return outLen + headerLen + footerLen;
}

#endif /* WOLFSSL_KEY_GEN || WOLFSSL_CERT_GEN */


