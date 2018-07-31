/*
* Encode and decode of ECC key into/frm DER
*/

#include "cmnCrypto.h"


#ifdef HAVE_ECC
/* Der Encode r & s ints into out, outLen is (in/out) size */
int StoreECC_DSA_Sig(byte* out, word32* outLen, mp_int* r, mp_int* s)
{
    word32 idx = 0;
    word32 rSz;                           /* encoding size */
    word32 sSz;
    word32 headerSz = 4;   /* 2*ASN_TAG + 2*LEN(ENUM) */

    /* If the leading bit on the INTEGER is a 1, add a leading zero */
    int rLeadingZero = mp_leading_bit(r);
    int sLeadingZero = mp_leading_bit(s);
    int rLen = mp_unsigned_bin_size(r);   /* big int size */
    int sLen = mp_unsigned_bin_size(s);
    int err;

    if (*outLen < (rLen + rLeadingZero + sLen + sLeadingZero +
                   headerSz + 2))  /* SEQ_TAG + LEN(ENUM) */
        return BAD_FUNC_ARG;

    idx = SetSequence(rLen+rLeadingZero+sLen+sLeadingZero+headerSz, out);

    /* store r */
    out[idx++] = ASN_INTEGER;
    rSz = SetLength(rLen + rLeadingZero, &out[idx]);
    idx += rSz;
    if (rLeadingZero)
        out[idx++] = 0;
    err = mp_to_unsigned_bin(r, &out[idx]);
    if (err != MP_OKAY) return err;
    idx += rLen;

    /* store s */
    out[idx++] = ASN_INTEGER;
    sSz = SetLength(sLen + sLeadingZero, &out[idx]);
    idx += sSz;
    if (sLeadingZero)
        out[idx++] = 0;
    err = mp_to_unsigned_bin(s, &out[idx]);
    if (err != MP_OKAY) return err;
    idx += sLen;

    *outLen = idx;

    return 0;
}


/* Der Decode ECC-DSA Signautre, r & s stored as big ints */
int DecodeECC_DSA_Sig(const byte* sig, word32 sigLen, mp_int* r, mp_int* s)
{
    word32 idx = 0;
    int    len = 0;

    if (GetSequence(sig, &idx, &len, sigLen) < 0)
        return ASN_ECC_KEY_E;

    if ((word32)len > (sigLen - idx))
        return ASN_ECC_KEY_E;

    if (GetInt(r, sig, &idx, sigLen) < 0)
        return ASN_ECC_KEY_E;

    if (GetInt(s, sig, &idx, sigLen) < 0)
        return ASN_ECC_KEY_E;

    return 0;
}


int wc_EccPrivateKeyDecode(const byte* input, word32* inOutIdx, ecc_key* key, word32 inSz)
{
    word32 oid = 0;
    int    version, length;
    int    privSz, pubSz;
    byte   b;
    int    ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* priv;
    byte* pub;
#else
    byte priv[ECC_MAXSIZE];
    byte pub[ECC_MAXSIZE * 2 + 1]; /* public key has two parts plus header */
#endif

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    b = input[*inOutIdx];
    *inOutIdx += 1;

    /* priv type */
    if (b != 4 && b != 6 && b != 7) 
        return ASN_PARSE_E;

    if (GetLength(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (length > ECC_MAXSIZE)
        return BUFFER_E;

#ifdef WOLFSSL_SMALL_STACK
    priv = (byte*)XMALLOC(ECC_MAXSIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv == NULL)
        return MEMORY_E;
    
    pub = (byte*)XMALLOC(ECC_MAXSIZE * 2 + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pub == NULL) {
        XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    /* priv key */
    privSz = length;
    XMEMCPY(priv, &input[*inOutIdx], privSz);
    *inOutIdx += length;

    /* prefix 0, may have */
    b = input[*inOutIdx];
    if (b == ECC_PREFIX_0) {
        *inOutIdx += 1;

        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            ret = ASN_PARSE_E;
        else {
            /* object id */
            b = input[*inOutIdx];
            *inOutIdx += 1;

            if (b != ASN_OBJECT_ID) {
                ret = ASN_OBJECT_ID_E;
            }
            else if (GetLength(input, inOutIdx, &length, inSz) < 0) {
                ret = ASN_PARSE_E;
            }
            else {
                while(length--) {
                    oid += input[*inOutIdx];
                    *inOutIdx += 1;
                }
                if (CheckCurve(oid) < 0)
                    ret = ECC_CURVE_OID_E;
            }
        }
    }

    if (ret == 0) {
        /* prefix 1 */
        b = input[*inOutIdx];
        *inOutIdx += 1;

        if (b != ECC_PREFIX_1) {
            ret = ASN_ECC_KEY_E;
        }
        else if (GetLength(input, inOutIdx, &length, inSz) < 0) {
            ret = ASN_PARSE_E;
        }
        else {
            /* key header */
            b = input[*inOutIdx];
            *inOutIdx += 1;
            
            if (b != ASN_BIT_STRING) {
                ret = ASN_BITSTR_E;
            }
            else if (GetLength(input, inOutIdx, &length, inSz) < 0) {
                ret = ASN_PARSE_E;
            }
            else {
                b = input[*inOutIdx];
                *inOutIdx += 1;

                if (b != 0x00) {
                    ret = ASN_EXPECT_0_E;
                }
                else {
                    /* pub key */
                    pubSz = length - 1;  /* null prefix */
                    if (pubSz < (ECC_MAXSIZE*2 + 1)) {
                        XMEMCPY(pub, &input[*inOutIdx], pubSz);
                        *inOutIdx += length;
                        ret = wc_ecc_import_private_key(priv, privSz, pub, pubSz,
                                                     key);
                    } else
                        ret = BUFFER_E;
                }
            }
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pub,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


#ifdef WOLFSSL_KEY_GEN

/* Write a Private ecc key to DER format, length on success else < 0 */
int wc_EccKeyToDer(ecc_key* key, byte* output, word32 inLen)
{
    byte   curve[MAX_ALGO_SZ];
    byte   ver[MAX_VERSION_SZ];
    byte   seq[MAX_SEQ_SZ];
    int    ret;
    int    curveSz;
    int    verSz;
    int    privHdrSz  = ASN_ECC_HEADER_SZ;
    int    pubHdrSz   = ASN_ECC_CONTEXT_SZ + ASN_ECC_HEADER_SZ;
    int    curveHdrSz = ASN_ECC_CONTEXT_SZ;
    word32 seqSz;
    word32 idx = 0;
    word32 pubSz = ECC_BUFSIZE;
    word32 privSz;
    word32 totalSz;

    if (key == NULL || output == NULL || inLen == 0)
        return BAD_FUNC_ARG;

    ret = wc_ecc_export_x963(key, NULL, &pubSz);
    if (ret != LENGTH_ONLY_E) {
        return ret;
    }
    curveSz = SetCurve(key, curve);
    if (curveSz < 0) {
        return curveSz;
    }

    privSz = key->dp->size;

    verSz = SetMyVersion(1, ver, FALSE);
    if (verSz < 0) {
        return verSz;
    }

    totalSz = verSz + privSz + privHdrSz + curveSz + curveHdrSz +
              pubSz + pubHdrSz + 1;  /* plus null byte b4 public */
    seqSz = SetSequence(totalSz, seq);
    totalSz += seqSz;

    if (totalSz > inLen) {
        return BUFFER_E;
    }

    /* write it out */
    /* seq */
    XMEMCPY(output + idx, seq, seqSz);
    idx += seqSz;

   /* ver */
    XMEMCPY(output + idx, ver, verSz);
    idx += verSz;

    /* private */
    output[idx++] = ASN_OCTET_STRING;
    output[idx++] = (byte)privSz;
    ret = wc_ecc_export_private_only(key, output + idx, &privSz);
    if (ret < 0) {
        return ret;
    }
    idx += privSz;

    /* curve */
    output[idx++] = ECC_PREFIX_0;
    output[idx++] = (byte)curveSz;
    XMEMCPY(output + idx, curve, curveSz);
    idx += curveSz;

    /* public */
    output[idx++] = ECC_PREFIX_1;
    output[idx++] = (byte)pubSz + ASN_ECC_CONTEXT_SZ + 1;  /* plus null byte */
    output[idx++] = ASN_BIT_STRING;
    output[idx++] = (byte)pubSz + 1;  /* plus null byte */
    output[idx++] = (byte)0;          /* null byte */
    ret = wc_ecc_export_x963(key, output + idx, &pubSz);
    if (ret != 0) {
        return ret;
    }
    /* idx += pubSz if do more later */

    return totalSz;
}

#endif /* WOLFSSL_KEY_GEN */

#endif  /* HAVE_ECC */



