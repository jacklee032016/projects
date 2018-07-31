/* pkcs7.c
 */


#include "cmnCrypto.h"


typedef struct EncodedAttrib {
    byte valueSeq[MAX_SEQ_SZ];
        const byte* oid;
        byte valueSet[MAX_SET_SZ];
        const byte* value;
    word32 valueSeqSz, oidSz, idSz, valueSetSz, valueSz, totalSz;
} EncodedAttrib;


typedef struct ESD {
    Sha sha;
    byte contentDigest[SHA_DIGEST_SIZE + 2]; /* content only + ASN.1 heading */
    byte contentAttribsDigest[SHA_DIGEST_SIZE];
    byte encContentDigest[512];

    byte outerSeq[MAX_SEQ_SZ];
        byte outerContent[MAX_EXP_SZ];
            byte innerSeq[MAX_SEQ_SZ];
                byte version[MAX_VERSION_SZ];
                byte digAlgoIdSet[MAX_SET_SZ];
                    byte singleDigAlgoId[MAX_ALGO_SZ];

                byte contentInfoSeq[MAX_SEQ_SZ];
                    byte innerContSeq[MAX_EXP_SZ];
                        byte innerOctets[MAX_OCTET_STR_SZ];

                byte certsSet[MAX_SET_SZ];

                byte signerInfoSet[MAX_SET_SZ];
                    byte signerInfoSeq[MAX_SEQ_SZ];
                        byte signerVersion[MAX_VERSION_SZ];
                        byte issuerSnSeq[MAX_SEQ_SZ];
                            byte issuerName[MAX_SEQ_SZ];
                            byte issuerSn[MAX_SN_SZ];
                        byte signerDigAlgoId[MAX_ALGO_SZ];
                        byte digEncAlgoId[MAX_ALGO_SZ];
                        byte signedAttribSet[MAX_SET_SZ];
                            EncodedAttrib signedAttribs[6];
                        byte signerDigest[MAX_OCTET_STR_SZ];
    word32 innerOctetsSz, innerContSeqSz, contentInfoSeqSz;
    word32 outerSeqSz, outerContentSz, innerSeqSz, versionSz, digAlgoIdSetSz,
           singleDigAlgoIdSz, certsSetSz;
    word32 signerInfoSetSz, signerInfoSeqSz, signerVersionSz,
           issuerSnSeqSz, issuerNameSz, issuerSnSz,
           signerDigAlgoIdSz, digEncAlgoIdSz, signerDigestSz;
    word32 encContentDigestSz, signedAttribsSz, signedAttribsCount,
           signedAttribSetSz;
} ESD;


static int EncodeAttributes(EncodedAttrib* ea, int eaSz,
                                            PKCS7Attrib* attribs, int attribsSz)
{
    int i;
    int maxSz = min(eaSz, attribsSz);
    int allAttribsSz = 0;

    for (i = 0; i < maxSz; i++)
    {
        int attribSz = 0;

        ea[i].value = attribs[i].value;
        ea[i].valueSz = attribs[i].valueSz;
        attribSz += ea[i].valueSz;
        ea[i].valueSetSz = SetSet(attribSz, ea[i].valueSet);
        attribSz += ea[i].valueSetSz;
        ea[i].oid = attribs[i].oid;
        ea[i].oidSz = attribs[i].oidSz;
        attribSz += ea[i].oidSz;
        ea[i].valueSeqSz = SetSequence(attribSz, ea[i].valueSeq);
        attribSz += ea[i].valueSeqSz;
        ea[i].totalSz = attribSz;

        allAttribsSz += attribSz;
    }
    return allAttribsSz;
}


static int FlattenAttributes(byte* output, EncodedAttrib* ea, int eaSz)
{
    int i, idx;

    idx = 0;
    for (i = 0; i < eaSz; i++) {
        XMEMCPY(output + idx, ea[i].valueSeq, ea[i].valueSeqSz);
        idx += ea[i].valueSeqSz;
        XMEMCPY(output + idx, ea[i].oid, ea[i].oidSz);
        idx += ea[i].oidSz;
        XMEMCPY(output + idx, ea[i].valueSet, ea[i].valueSetSz);
        idx += ea[i].valueSetSz;
        XMEMCPY(output + idx, ea[i].value, ea[i].valueSz);
        idx += ea[i].valueSz;
    }
    return 0;
}


/* build PKCS#7 signedData content type */
int wc_PKCS7_EncodeSignedData(PKCS7* pkcs7, byte* output, word32 outputSz)
{
    static const byte outerOid[] =
        { ASN_OBJECT_ID, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
                         0x07, 0x02 };
    static const byte innerOid[] =
        { ASN_OBJECT_ID, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
                         0x07, 0x01 };

#ifdef WOLFSSL_SMALL_STACK
    ESD* esd = NULL;
#else
    ESD stack_esd;
    ESD* esd = &stack_esd;
#endif

    word32 signerInfoSz = 0;
    word32 totalSz = 0;
    int idx = 0, ret = 0;
    byte* flatSignedAttribs = NULL;
    word32 flatSignedAttribsSz = 0;
    word32 innerOidSz = sizeof(innerOid);
    word32 outerOidSz = sizeof(outerOid);

    if (pkcs7 == NULL || pkcs7->content == NULL || pkcs7->contentSz == 0 ||
        pkcs7->encryptOID == 0 || pkcs7->hashOID == 0 || pkcs7->rng == 0 ||
        pkcs7->singleCert == NULL || pkcs7->singleCertSz == 0 ||
        pkcs7->privateKey == NULL || pkcs7->privateKeySz == 0 ||
        output == NULL || outputSz == 0)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
    esd = (ESD*)XMALLOC(sizeof(ESD), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (esd == NULL)
        return MEMORY_E;
#endif

    XMEMSET(esd, 0, sizeof(ESD));
    ret = wc_InitSha(&esd->sha);
    if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(esd, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

    if (pkcs7->contentSz != 0)
    {
        wc_ShaUpdate(&esd->sha, pkcs7->content, pkcs7->contentSz);
        esd->contentDigest[0] = ASN_OCTET_STRING;
        esd->contentDigest[1] = SHA_DIGEST_SIZE;
        wc_ShaFinal(&esd->sha, &esd->contentDigest[2]);
    }

    esd->innerOctetsSz = SetOctetString(pkcs7->contentSz, esd->innerOctets);
    esd->innerContSeqSz = SetExplicit(0, esd->innerOctetsSz + pkcs7->contentSz,
                                esd->innerContSeq);
    esd->contentInfoSeqSz = SetSequence(pkcs7->contentSz + esd->innerOctetsSz +
                                    innerOidSz + esd->innerContSeqSz,
                                    esd->contentInfoSeq);

    esd->issuerSnSz = SetSerialNumber(pkcs7->issuerSn, pkcs7->issuerSnSz,
                                     esd->issuerSn);
    signerInfoSz += esd->issuerSnSz;
    esd->issuerNameSz = SetSequence(pkcs7->issuerSz, esd->issuerName);
    signerInfoSz += esd->issuerNameSz + pkcs7->issuerSz;
    esd->issuerSnSeqSz = SetSequence(signerInfoSz, esd->issuerSnSeq);
    signerInfoSz += esd->issuerSnSeqSz;
    esd->signerVersionSz = SetMyVersion(1, esd->signerVersion, 0);
    signerInfoSz += esd->signerVersionSz;
    esd->signerDigAlgoIdSz = SetAlgoID(pkcs7->hashOID, esd->signerDigAlgoId,
                                      hashType, 0);
    signerInfoSz += esd->signerDigAlgoIdSz;
    esd->digEncAlgoIdSz = SetAlgoID(pkcs7->encryptOID, esd->digEncAlgoId,
                                   keyType, 0);
    signerInfoSz += esd->digEncAlgoIdSz;

    if (pkcs7->signedAttribsSz != 0) {
        byte contentTypeOid[] =
                { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0d, 0x01,
                                 0x09, 0x03 };
        byte contentType[] =
                { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
                                 0x07, 0x01 };
        byte messageDigestOid[] =
                { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
                                 0x09, 0x04 };

        PKCS7Attrib cannedAttribs[2] =
        {
            { contentTypeOid, sizeof(contentTypeOid),
                             contentType, sizeof(contentType) },
            { messageDigestOid, sizeof(messageDigestOid),
                             esd->contentDigest, sizeof(esd->contentDigest) }
        };
        word32 cannedAttribsCount = sizeof(cannedAttribs)/sizeof(PKCS7Attrib);

        esd->signedAttribsCount += cannedAttribsCount;
        esd->signedAttribsSz += EncodeAttributes(&esd->signedAttribs[0], 2,
                                             cannedAttribs, cannedAttribsCount);

        esd->signedAttribsCount += pkcs7->signedAttribsSz;
        esd->signedAttribsSz += EncodeAttributes(&esd->signedAttribs[2], 4,
                                  pkcs7->signedAttribs, pkcs7->signedAttribsSz);

        flatSignedAttribs = (byte*)XMALLOC(esd->signedAttribsSz, 0, NULL);
        flatSignedAttribsSz = esd->signedAttribsSz;
        if (flatSignedAttribs == NULL) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(esd, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif   
            return MEMORY_E;
        }
        FlattenAttributes(flatSignedAttribs,
                                   esd->signedAttribs, esd->signedAttribsCount);
        esd->signedAttribSetSz = SetImplicit(ASN_SET, 0, esd->signedAttribsSz,
                                                          esd->signedAttribSet);
    }
    /* Calculate the final hash and encrypt it. */
    {
        int result;
        word32 scratch = 0;

#ifdef WOLFSSL_SMALL_STACK
        byte* digestInfo;
        RsaKey* privKey;
#else
        RsaKey stack_privKey;
        RsaKey* privKey = &stack_privKey;
        byte digestInfo[MAX_SEQ_SZ + MAX_ALGO_SZ +
                        MAX_OCTET_STR_SZ + SHA_DIGEST_SIZE];
#endif
        byte digestInfoSeq[MAX_SEQ_SZ];
        byte digestStr[MAX_OCTET_STR_SZ];
        word32 digestInfoSeqSz, digestStrSz;
        int digIdx = 0;

        if (pkcs7->signedAttribsSz != 0) {
            byte attribSet[MAX_SET_SZ];
            word32 attribSetSz;

            attribSetSz = SetSet(flatSignedAttribsSz, attribSet);

            ret = wc_InitSha(&esd->sha);
            if (ret < 0) {
                XFREE(flatSignedAttribs, 0, NULL);
#ifdef WOLFSSL_SMALL_STACK
                XFREE(esd, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ret;
            }
            wc_ShaUpdate(&esd->sha, attribSet, attribSetSz);
            wc_ShaUpdate(&esd->sha, flatSignedAttribs, flatSignedAttribsSz);
        }
        wc_ShaFinal(&esd->sha, esd->contentAttribsDigest);

        digestStrSz = SetOctetString(SHA_DIGEST_SIZE, digestStr);
        digestInfoSeqSz = SetSequence(esd->signerDigAlgoIdSz +
                                      digestStrSz + SHA_DIGEST_SIZE,
                                      digestInfoSeq);

#ifdef WOLFSSL_SMALL_STACK
        digestInfo = (byte*)XMALLOC(MAX_SEQ_SZ + MAX_ALGO_SZ +
                                    MAX_OCTET_STR_SZ + SHA_DIGEST_SIZE,
                                    NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (digestInfo == NULL) {
            if (pkcs7->signedAttribsSz != 0)
                XFREE(flatSignedAttribs, 0, NULL);
            XFREE(esd, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
#endif

        XMEMCPY(digestInfo + digIdx, digestInfoSeq, digestInfoSeqSz);
        digIdx += digestInfoSeqSz;
        XMEMCPY(digestInfo + digIdx,
                                  esd->signerDigAlgoId, esd->signerDigAlgoIdSz);
        digIdx += esd->signerDigAlgoIdSz;
        XMEMCPY(digestInfo + digIdx, digestStr, digestStrSz);
        digIdx += digestStrSz;
        XMEMCPY(digestInfo + digIdx, esd->contentAttribsDigest,
                                                               SHA_DIGEST_SIZE);
        digIdx += SHA_DIGEST_SIZE;

#ifdef WOLFSSL_SMALL_STACK
        privKey = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (privKey == NULL) {
            if (pkcs7->signedAttribsSz != 0)
                XFREE(flatSignedAttribs, 0, NULL);
            XFREE(digestInfo, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(esd,        NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
#endif

        result = wc_InitRsaKey(privKey, NULL);
        if (result == 0)
            result = wc_RsaPrivateKeyDecode(pkcs7->privateKey, &scratch, privKey,
                                         pkcs7->privateKeySz);
        if (result < 0) {
            if (pkcs7->signedAttribsSz != 0)
                XFREE(flatSignedAttribs, 0, NULL);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(privKey,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(digestInfo, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(esd,        NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return PUBLIC_KEY_E;
        }

        result = wc_RsaSSL_Sign(digestInfo, digIdx,
                             esd->encContentDigest,
                             sizeof(esd->encContentDigest),
                             privKey, pkcs7->rng);

        wc_FreeRsaKey(privKey);

#ifdef WOLFSSL_SMALL_STACK
        XFREE(privKey,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(digestInfo, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

        if (result < 0) {
            if (pkcs7->signedAttribsSz != 0)
                XFREE(flatSignedAttribs, 0, NULL);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(esd, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return result;
        }
        esd->encContentDigestSz = (word32)result;
    }
    signerInfoSz += flatSignedAttribsSz + esd->signedAttribSetSz;

    esd->signerDigestSz = SetOctetString(esd->encContentDigestSz,
                                                             esd->signerDigest);
    signerInfoSz += esd->signerDigestSz + esd->encContentDigestSz;

    esd->signerInfoSeqSz = SetSequence(signerInfoSz, esd->signerInfoSeq);
    signerInfoSz += esd->signerInfoSeqSz;
    esd->signerInfoSetSz = SetSet(signerInfoSz, esd->signerInfoSet);
    signerInfoSz += esd->signerInfoSetSz;

    esd->certsSetSz = SetImplicit(ASN_SET, 0, pkcs7->singleCertSz,
                                                                 esd->certsSet);

    esd->singleDigAlgoIdSz = SetAlgoID(pkcs7->hashOID, esd->singleDigAlgoId,
                                      hashType, 0);
    esd->digAlgoIdSetSz = SetSet(esd->singleDigAlgoIdSz, esd->digAlgoIdSet);


    esd->versionSz = SetMyVersion(1, esd->version, 0);

    totalSz = esd->versionSz + esd->singleDigAlgoIdSz + esd->digAlgoIdSetSz +
              esd->contentInfoSeqSz + esd->certsSetSz + pkcs7->singleCertSz +
              esd->innerOctetsSz + esd->innerContSeqSz +
              innerOidSz + pkcs7->contentSz +
              signerInfoSz;
    esd->innerSeqSz = SetSequence(totalSz, esd->innerSeq);
    totalSz += esd->innerSeqSz;
    esd->outerContentSz = SetExplicit(0, totalSz, esd->outerContent);
    totalSz += esd->outerContentSz + outerOidSz;
    esd->outerSeqSz = SetSequence(totalSz, esd->outerSeq);
    totalSz += esd->outerSeqSz;

    if (outputSz < totalSz) {
        if (pkcs7->signedAttribsSz != 0)
            XFREE(flatSignedAttribs, 0, NULL);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(esd, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BUFFER_E;
    }

    idx = 0;
    XMEMCPY(output + idx, esd->outerSeq, esd->outerSeqSz);
    idx += esd->outerSeqSz;
    XMEMCPY(output + idx, outerOid, outerOidSz);
    idx += outerOidSz;
    XMEMCPY(output + idx, esd->outerContent, esd->outerContentSz);
    idx += esd->outerContentSz;
    XMEMCPY(output + idx, esd->innerSeq, esd->innerSeqSz);
    idx += esd->innerSeqSz;
    XMEMCPY(output + idx, esd->version, esd->versionSz);
    idx += esd->versionSz;
    XMEMCPY(output + idx, esd->digAlgoIdSet, esd->digAlgoIdSetSz);
    idx += esd->digAlgoIdSetSz;
    XMEMCPY(output + idx, esd->singleDigAlgoId, esd->singleDigAlgoIdSz);
    idx += esd->singleDigAlgoIdSz;
    XMEMCPY(output + idx, esd->contentInfoSeq, esd->contentInfoSeqSz);
    idx += esd->contentInfoSeqSz;
    XMEMCPY(output + idx, innerOid, innerOidSz);
    idx += innerOidSz;
    XMEMCPY(output + idx, esd->innerContSeq, esd->innerContSeqSz);
    idx += esd->innerContSeqSz;
    XMEMCPY(output + idx, esd->innerOctets, esd->innerOctetsSz);
    idx += esd->innerOctetsSz;
    XMEMCPY(output + idx, pkcs7->content, pkcs7->contentSz);
    idx += pkcs7->contentSz;
    XMEMCPY(output + idx, esd->certsSet, esd->certsSetSz);
    idx += esd->certsSetSz;
    XMEMCPY(output + idx, pkcs7->singleCert, pkcs7->singleCertSz);
    idx += pkcs7->singleCertSz;
    XMEMCPY(output + idx, esd->signerInfoSet, esd->signerInfoSetSz);
    idx += esd->signerInfoSetSz;
    XMEMCPY(output + idx, esd->signerInfoSeq, esd->signerInfoSeqSz);
    idx += esd->signerInfoSeqSz;
    XMEMCPY(output + idx, esd->signerVersion, esd->signerVersionSz);
    idx += esd->signerVersionSz;
    XMEMCPY(output + idx, esd->issuerSnSeq, esd->issuerSnSeqSz);
    idx += esd->issuerSnSeqSz;
    XMEMCPY(output + idx, esd->issuerName, esd->issuerNameSz);
    idx += esd->issuerNameSz;
    XMEMCPY(output + idx, pkcs7->issuer, pkcs7->issuerSz);
    idx += pkcs7->issuerSz;
    XMEMCPY(output + idx, esd->issuerSn, esd->issuerSnSz);
    idx += esd->issuerSnSz;
    XMEMCPY(output + idx, esd->signerDigAlgoId, esd->signerDigAlgoIdSz);
    idx += esd->signerDigAlgoIdSz;

    /* SignerInfo:Attributes */
    if (pkcs7->signedAttribsSz != 0) {
        XMEMCPY(output + idx, esd->signedAttribSet, esd->signedAttribSetSz);
        idx += esd->signedAttribSetSz;
        XMEMCPY(output + idx, flatSignedAttribs, flatSignedAttribsSz);
        idx += flatSignedAttribsSz;
        XFREE(flatSignedAttribs, 0, NULL);
    }

    XMEMCPY(output + idx, esd->digEncAlgoId, esd->digEncAlgoIdSz);
    idx += esd->digEncAlgoIdSz;
    XMEMCPY(output + idx, esd->signerDigest, esd->signerDigestSz);
    idx += esd->signerDigestSz;
    XMEMCPY(output + idx, esd->encContentDigest, esd->encContentDigestSz);
    idx += esd->encContentDigestSz;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(esd, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return idx;
}


/* Finds the certificates in the message and saves it. */
int wc_PKCS7_VerifySignedData(PKCS7* pkcs7, byte* pkiMsg, word32 pkiMsgSz)
{
    word32 idx, contentType;
    int length, version, ret;
    byte* content = NULL;
    byte* sig = NULL;
    byte* cert = NULL;
    int contentSz = 0, sigSz = 0, certSz = 0;

    if (pkcs7 == NULL || pkiMsg == NULL || pkiMsgSz == 0)
        return BAD_FUNC_ARG;

    idx = 0;

    /* Get the contentInfo sequence */
    if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* Get the contentInfo contentType */
    if (wc_GetContentType(pkiMsg, &idx, &contentType, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (contentType != SIGNED_DATA) {
        WOLFSSL_MSG("PKCS#7 input not of type SignedData");
        return PKCS7_OID_E;
    }

    /* get the ContentInfo content */
    if (pkiMsg[idx++] != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* Get the signedData sequence */
    if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* Get the version */
    if (GetMyVersion(pkiMsg, &idx, &version) < 0)
        return ASN_PARSE_E;

    if (version != 1) {
        WOLFSSL_MSG("PKCS#7 signedData needs to be of version 1");
        return ASN_VERSION_E;
    }

    /* Get the set of DigestAlgorithmIdentifiers */
    if (GetSet(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* Skip the set. */
    idx += length;

    /* Get the inner ContentInfo sequence */
    if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* Get the inner ContentInfo contentType */
    if (wc_GetContentType(pkiMsg, &idx, &contentType, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (contentType != DATA) {
        WOLFSSL_MSG("PKCS#7 inner input not of type Data");
        return PKCS7_OID_E;
    }

    if (pkiMsg[idx++] != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (pkiMsg[idx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* Save the inner data as the content. */
    if (length > 0) {
        /* Local pointer for calculating hashes later */
        pkcs7->content = content = &pkiMsg[idx];
        pkcs7->contentSz = contentSz = length;
        idx += length;
    }

    /* Get the implicit[0] set of certificates */
    if (pkiMsg[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0)) {
        idx++;
        if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
            return ASN_PARSE_E;

        if (length > 0) {
            /* At this point, idx is at the first certificate in
             * a set of certificates. There may be more than one,
             * or none, or they may be a PKCS 6 extended
             * certificate. We want to save the first cert if it
             * is X.509. */

            word32 certIdx = idx;

            if (pkiMsg[certIdx++] == (ASN_CONSTRUCTED | ASN_SEQUENCE)) {
                if (GetLength(pkiMsg, &certIdx, &certSz, pkiMsgSz) < 0)
                    return ASN_PARSE_E;

                cert = &pkiMsg[idx];
                certSz += (certIdx - idx);
            }
            wc_PKCS7_InitWithCert(pkcs7, cert, certSz);
        }
        idx += length;
    }

    /* Get the implicit[1] set of crls */
    if (pkiMsg[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1)) {
        idx++;
        if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
            return ASN_PARSE_E;

        /* Skip the set */
        idx += length;
    }

    /* Get the set of signerInfos */
    if (GetSet(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (length > 0) {
        /* Get the sequence of the first signerInfo */
        if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
            return ASN_PARSE_E;

        /* Get the version */
        if (GetMyVersion(pkiMsg, &idx, &version) < 0)
            return ASN_PARSE_E;

        if (version != 1) {
            WOLFSSL_MSG("PKCS#7 signerInfo needs to be of version 1");
            return ASN_VERSION_E;
        }

        /* Get the sequence of IssuerAndSerialNumber */
        if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
            return ASN_PARSE_E;

        /* Skip it */
        idx += length;

        /* Get the sequence of digestAlgorithm */
        if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
            return ASN_PARSE_E;

        /* Skip it */
        idx += length;

        /* Get the IMPLICIT[0] SET OF signedAttributes */
        if (pkiMsg[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0)) {
            idx++;

            if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            idx += length;
        }

        /* Get the sequence of digestEncryptionAlgorithm */
        if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
            return ASN_PARSE_E;

        /* Skip it */
        idx += length;

        /* Get the signature */
        if (pkiMsg[idx] == ASN_OCTET_STRING) {
            idx++;

            if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            /* save pointer and length */
            sig = &pkiMsg[idx];
            sigSz = length;

            idx += length;
        }

        pkcs7->content = content;
        pkcs7->contentSz = contentSz;

        {
            word32 scratch = 0;
            int plainSz = 0;
            int digestSz = MAX_SEQ_SZ + MAX_ALGO_SZ +
                           MAX_OCTET_STR_SZ + SHA_DIGEST_SIZE;

#ifdef WOLFSSL_SMALL_STACK
            byte* digest;
            RsaKey* key;

            digest = (byte*)XMALLOC(digestSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

            if (digest == NULL)
                return MEMORY_E;

            key = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (key == NULL) {
                XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return MEMORY_E;
            }
#else
		/* lzj */
//            byte digest[digestSz];
            byte digest[MAX_SEQ_SZ + MAX_ALGO_SZ + MAX_OCTET_STR_SZ + SHA_DIGEST_SIZE];
            RsaKey stack_key;
            RsaKey* key = &stack_key;
#endif

            XMEMSET(digest, 0, digestSz);

            ret = wc_InitRsaKey(key, NULL);
            if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
                XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                XFREE(key,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ret;
            }
            if (wc_RsaPublicKeyDecode(pkcs7->publicKey, &scratch, key,
                                   pkcs7->publicKeySz) < 0) {
                WOLFSSL_MSG("ASN RSA key decode error");
#ifdef WOLFSSL_SMALL_STACK
                XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                XFREE(key,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return PUBLIC_KEY_E;
            }

            plainSz = wc_RsaSSL_Verify(sig, sigSz, digest, digestSz, key);
            wc_FreeRsaKey(key);

#ifdef WOLFSSL_SMALL_STACK
            XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(key,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

            if (plainSz < 0)
                return plainSz;
        }
    }

    return 0;
}


