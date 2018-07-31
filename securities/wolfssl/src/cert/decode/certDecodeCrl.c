
#include "cmnCrypto.h"


#ifdef HAVE_CRL

/* initialize decoded CRL */
void InitDecodedCRL(DecodedCRL* dcrl)
{
	dcrl->certBegin    = 0;
	dcrl->sigIndex     = 0;
	dcrl->sigLength    = 0;
	dcrl->signatureOID = 0;
	dcrl->certs        = NULL;
	dcrl->totalCerts   = 0;
}


/* free decoded CRL resources */
void FreeDecodedCRL(DecodedCRL* dcrl)
{
	RevokedCert* tmp = dcrl->certs;

	while(tmp) {
		RevokedCert* next = tmp->next;
		XFREE(tmp, NULL, DYNAMIC_TYPE_REVOKED);
		tmp = next;
	}
}


/* Get Revoked Cert list, 0 on success */
static int _getRevoked(const byte* buff, word32* idx, DecodedCRL* dcrl,
                      int maxIdx)
{
    int    len;
    word32 end;
    byte   b;
    RevokedCert* rc;

    if (GetSequence(buff, idx, &len, maxIdx) < 0)
        return ASN_PARSE_E;

    end = *idx + len;

    /* get serial number */
    b = buff[*idx];
    *idx += 1;

    if (b != ASN_INTEGER) {
        WOLFSSL_MSG("Expecting Integer");
        return ASN_PARSE_E;
    }

    if (GetLength(buff, idx, &len, maxIdx) < 0)
        return ASN_PARSE_E;

    if (len > EXTERNAL_SERIAL_SIZE) {
        WOLFSSL_MSG("Serial Size too big");
        return ASN_PARSE_E;
    }

    rc = (RevokedCert*)XMALLOC(sizeof(RevokedCert), NULL, DYNAMIC_TYPE_CRL);
    if (rc == NULL) {
        WOLFSSL_MSG("Alloc Revoked Cert failed");
        return MEMORY_E;
    }

    XMEMCPY(rc->serialNumber, &buff[*idx], len);
    rc->serialSz = len;

    /* add to list */
    rc->next = dcrl->certs;
    dcrl->certs = rc;
    dcrl->totalCerts++;

    *idx += len;

    /* get date */
    b = buff[*idx];
    *idx += 1;

    if (b != ASN_UTC_TIME && b != ASN_GENERALIZED_TIME) {
        WOLFSSL_MSG("Expecting Date");
        return ASN_PARSE_E;
    }

    if (GetLength(buff, idx, &len, maxIdx) < 0)
        return ASN_PARSE_E;

    /* skip for now */
    *idx += len;

    if (*idx != end)  /* skip extensions */
        *idx = end;

    return 0;
}


/* Get CRL Signature, 0 on success */
static int _getCRL_Signature(const byte* source, word32* idx, DecodedCRL* dcrl,
                            int maxIdx)
{
    int    length;
    byte   b;

    b = source[*idx];
    *idx += 1;
    if (b != ASN_BIT_STRING)
        return ASN_BITSTR_E;

    if (GetLength(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    dcrl->sigLength = length;

    b = source[*idx];
    *idx += 1;
    if (b != 0x00)
        return ASN_EXPECT_0_E;

    dcrl->sigLength--;
    dcrl->signature = (byte*)&source[*idx];

    *idx += dcrl->sigLength;

    return 0;
}


/* prase crl buffer into decoded state, 0 on success */
int ParseCRL(DecodedCRL* dcrl, const byte* buff, word32 sz, void* cm)
{
    int     version, len;
    word32  oid, idx = 0;
    Signer* ca = NULL;

    /* raw crl hash */
    /* hash here if needed for optimized comparisons
     * Sha     sha;
     * wc_InitSha(&sha);
     * wc_ShaUpdate(&sha, buff, sz);
     * wc_ShaFinal(&sha, dcrl->crlHash); */

    if (GetSequence(buff, &idx, &len, sz) < 0)
        return ASN_PARSE_E;

    dcrl->certBegin = idx;

    if (GetSequence(buff, &idx, &len, sz) < 0)
        return ASN_PARSE_E;
    dcrl->sigIndex = len + idx;

    /* may have version */
    if (buff[idx] == ASN_INTEGER) {
        if (GetMyVersion(buff, &idx, &version) < 0)
            return ASN_PARSE_E;
    }

    if (GetAlgoId(buff, &idx, &oid, sz) < 0)
        return ASN_PARSE_E;

    if (GetNameHash(buff, &idx, dcrl->issuerHash, sz) < 0)
        return ASN_PARSE_E;

    if (GetBasicDate(buff, &idx, dcrl->lastDate, &dcrl->lastDateFormat, sz) < 0)
        return ASN_PARSE_E;

    if (GetBasicDate(buff, &idx, dcrl->nextDate, &dcrl->nextDateFormat, sz) < 0)
        return ASN_PARSE_E;

    if (!XVALIDATE_DATE(dcrl->nextDate, dcrl->nextDateFormat, AFTER)) {
        WOLFSSL_MSG("CRL after date is no longer valid");
        return ASN_AFTER_DATE_E;
    }

    if (idx != dcrl->sigIndex && buff[idx] != CRL_EXTENSIONS) {
        if (GetSequence(buff, &idx, &len, sz) < 0)
            return ASN_PARSE_E;

        len += idx;

        while (idx < (word32)len) {
            if (_getRevoked(buff, &idx, dcrl, sz) < 0)
                return ASN_PARSE_E;
        }
    }

    if (idx != dcrl->sigIndex)
        idx = dcrl->sigIndex;   /* skip extensions */

    if (GetAlgoId(buff, &idx, &dcrl->signatureOID, sz) < 0)
        return ASN_PARSE_E;

    if (_getCRL_Signature(buff, &idx, dcrl, sz) < 0)
        return ASN_PARSE_E;

    /* openssl doesn't add skid by default for CRLs cause firefox chokes
       we're not assuming it's available yet */
    #if !defined(NO_SKID) && defined(CRL_SKID_READY)
        if (dcrl->extAuthKeyIdSet)
            ca = GetCA(cm, dcrl->extAuthKeyId);
        if (ca == NULL)
            ca = GetCAByName(cm, dcrl->issuerHash);
    #else /* NO_SKID */
        ca = GetCA(cm, dcrl->issuerHash);
    #endif /* NO_SKID */
    WOLFSSL_MSG("About to verify CRL signature");

    if (ca) {
        WOLFSSL_MSG("Found CRL issuer CA");
        /* try to confirm/verify signature */
        #ifndef IGNORE_KEY_EXTENSIONS
            if ((ca->keyUsage & KEYUSE_CRL_SIGN) == 0) {
                WOLFSSL_MSG("CA cannot sign CRLs");
                return ASN_CRL_NO_SIGNER_E;
            }
        #endif /* IGNORE_KEY_EXTENSIONS */
        if (!ConfirmSignature(buff + dcrl->certBegin,
                dcrl->sigIndex - dcrl->certBegin,
                ca->publicKey, ca->pubKeySize, ca->keyOID,
                dcrl->signature, dcrl->sigLength, dcrl->signatureOID, NULL)) {
            WOLFSSL_MSG("CRL Confirm signature failed");
            return ASN_CRL_CONFIRM_E;
        }
    }
    else {
        WOLFSSL_MSG("Did NOT find CRL issuer CA");
        return ASN_CRL_NO_SIGNER_E;
    }

    return 0;
}

#endif /* HAVE_CRL */



