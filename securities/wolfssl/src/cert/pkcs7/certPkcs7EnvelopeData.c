/* pkcs7.c
 */


#include "cmnCrypto.h"


/* create ASN.1 fomatted RecipientInfo structure, returns sequence size */
WOLFSSL_LOCAL int wc_CreateRecipientInfo(const byte* cert, word32 certSz,
                                     int keyEncAlgo, int blockKeySz,
                                     RNG* rng, byte* contentKeyPlain,
                                     byte* contentKeyEnc,
                                     int* keyEncSz, byte* out, word32 outSz)
{
    word32 idx = 0;
    int ret = 0, totalSz = 0;
    int verSz, issuerSz, snSz, keyEncAlgSz;
    int issuerSeqSz, recipSeqSz, issuerSerialSeqSz;
    int encKeyOctetStrSz;

    byte ver[MAX_VERSION_SZ];
    byte issuerSerialSeq[MAX_SEQ_SZ];
    byte recipSeq[MAX_SEQ_SZ];
    byte issuerSeq[MAX_SEQ_SZ];
    byte encKeyOctetStr[MAX_OCTET_STR_SZ];

#ifdef WOLFSSL_SMALL_STACK
    byte *serial;
    byte *keyAlgArray;
    
    RsaKey* pubKey;
    DecodedCert* decoded;

    serial = (byte*)XMALLOC(MAX_SN_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    keyAlgArray = (byte*)XMALLOC(MAX_SN_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    decoded = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);

    if (decoded == NULL || serial == NULL || keyAlgArray == NULL) {
        if (serial)      XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (keyAlgArray) XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (decoded)     XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
    
#else
    byte serial[MAX_SN_SZ];
    byte keyAlgArray[MAX_ALGO_SZ];
    
    RsaKey stack_pubKey;
    RsaKey* pubKey = &stack_pubKey;
    DecodedCert stack_decoded;
    DecodedCert* decoded = &stack_decoded;
#endif

    InitDecodedCert(decoded, (byte*)cert, certSz, 0);
    ret = ParseCert(decoded, CA_TYPE, NO_VERIFY, 0);
    if (ret < 0) {
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

    /* version */
    verSz = SetMyVersion(0, ver, 0);

    /* IssuerAndSerialNumber */
    if (decoded->issuerRaw == NULL || decoded->issuerRawLen == 0) {
        WOLFSSL_MSG("DecodedCert lacks raw issuer pointer and length");
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return -1;
    }
    issuerSz    = decoded->issuerRawLen;
    issuerSeqSz = SetSequence(issuerSz, issuerSeq);

    if (decoded->serialSz == 0) {
        WOLFSSL_MSG("DecodedCert missing serial number");
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return -1;
    }
    snSz = SetSerialNumber(decoded->serial, decoded->serialSz, serial);

    issuerSerialSeqSz = SetSequence(issuerSeqSz + issuerSz + snSz,
                                    issuerSerialSeq);

    /* KeyEncryptionAlgorithmIdentifier, only support RSA now */
    if (keyEncAlgo != RSAk) {
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ALGO_ID_E;
    }

    keyEncAlgSz = SetAlgoID(keyEncAlgo, keyAlgArray, keyType, 0);
    if (keyEncAlgSz == 0) {
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    pubKey = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pubKey == NULL) {
        FreeDecodedCert(decoded);
        XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    /* EncryptedKey */
    ret = wc_InitRsaKey(pubKey, 0);
    if (ret != 0) {
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(pubKey,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

    if (wc_RsaPublicKeyDecode(decoded->publicKey, &idx, pubKey,
                           decoded->pubKeySize) < 0) {
        WOLFSSL_MSG("ASN RSA key decode error");
        wc_FreeRsaKey(pubKey);
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(pubKey,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return PUBLIC_KEY_E;
    }

    *keyEncSz = wc_RsaPublicEncrypt(contentKeyPlain, blockKeySz, contentKeyEnc,
                                 MAX_ENCRYPTED_KEY_SZ, pubKey, rng);
    wc_FreeRsaKey(pubKey);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (*keyEncSz < 0) {
        WOLFSSL_MSG("RSA Public Encrypt failed");
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return *keyEncSz;
    }

    encKeyOctetStrSz = SetOctetString(*keyEncSz, encKeyOctetStr);

    /* RecipientInfo */
    recipSeqSz = SetSequence(verSz + issuerSerialSeqSz + issuerSeqSz +
                             issuerSz + snSz + keyEncAlgSz + encKeyOctetStrSz +
                             *keyEncSz, recipSeq);

    if (recipSeqSz + verSz + issuerSerialSeqSz + issuerSeqSz + snSz +
        keyEncAlgSz + encKeyOctetStrSz + *keyEncSz > (int)outSz) {
        WOLFSSL_MSG("RecipientInfo output buffer too small");
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BUFFER_E;
    }

    XMEMCPY(out + totalSz, recipSeq, recipSeqSz);
    totalSz += recipSeqSz;
    XMEMCPY(out + totalSz, ver, verSz);
    totalSz += verSz;
    XMEMCPY(out + totalSz, issuerSerialSeq, issuerSerialSeqSz);
    totalSz += issuerSerialSeqSz;
    XMEMCPY(out + totalSz, issuerSeq, issuerSeqSz);
    totalSz += issuerSeqSz;
    XMEMCPY(out + totalSz, decoded->issuerRaw, issuerSz);
    totalSz += issuerSz;
    XMEMCPY(out + totalSz, serial, snSz);
    totalSz += snSz;
    XMEMCPY(out + totalSz, keyAlgArray, keyEncAlgSz);
    totalSz += keyEncAlgSz;
    XMEMCPY(out + totalSz, encKeyOctetStr, encKeyOctetStrSz);
    totalSz += encKeyOctetStrSz;
    XMEMCPY(out + totalSz, contentKeyEnc, *keyEncSz);
    totalSz += *keyEncSz;

    FreeDecodedCert(decoded);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(serial,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(keyAlgArray, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(decoded,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return totalSz;
}


/* build PKCS#7 envelopedData content type, return enveloped size */
int wc_PKCS7_EncodeEnvelopedData(PKCS7* pkcs7, byte* output, word32 outputSz)
{
    int i, ret = 0, idx = 0;
    int totalSz = 0, padSz = 0, desOutSz = 0;

    int contentInfoSeqSz, outerContentTypeSz, outerContentSz;
    byte contentInfoSeq[MAX_SEQ_SZ];
    byte outerContentType[MAX_ALGO_SZ];
    byte outerContent[MAX_SEQ_SZ];

    int envDataSeqSz, verSz;
    byte envDataSeq[MAX_SEQ_SZ];
    byte ver[MAX_VERSION_SZ];

    RNG rng;
    int contentKeyEncSz, blockKeySz;
    int dynamicFlag = 0;
    byte contentKeyPlain[MAX_CONTENT_KEY_LEN];
#ifdef WOLFSSL_SMALL_STACK
    byte* contentKeyEnc;
#else
    byte contentKeyEnc[MAX_ENCRYPTED_KEY_SZ];
#endif
    byte* plain;
    byte* encryptedContent;

    int recipSz, recipSetSz;
#ifdef WOLFSSL_SMALL_STACK
    byte* recip;
#else
    byte recip[MAX_RECIP_SZ];
#endif
    byte recipSet[MAX_SET_SZ];

    int encContentOctetSz, encContentSeqSz, contentTypeSz;
    int contentEncAlgoSz, ivOctetStringSz;
    byte encContentSeq[MAX_SEQ_SZ];
    byte contentType[MAX_ALGO_SZ];
    byte contentEncAlgo[MAX_ALGO_SZ];
    byte tmpIv[DES_BLOCK_SIZE];
    byte ivOctetString[MAX_OCTET_STR_SZ];
    byte encContentOctet[MAX_OCTET_STR_SZ];

    if (pkcs7 == NULL || pkcs7->content == NULL || pkcs7->contentSz == 0 ||
        pkcs7->encryptOID == 0 || pkcs7->singleCert == NULL)
        return BAD_FUNC_ARG;

    if (output == NULL || outputSz == 0)
        return BAD_FUNC_ARG;

    /* PKCS#7 only supports DES, 3DES for now */
    switch (pkcs7->encryptOID) {
        case DESb:
            blockKeySz = DES_KEYLEN;
            break;

        case DES3b:
            blockKeySz = DES3_KEYLEN;
            break;

        default:
            WOLFSSL_MSG("Unsupported content cipher type");
            return ALGO_ID_E;
    };

    /* outer content type */
    outerContentTypeSz = wc_SetContentType(ENVELOPED_DATA, outerContentType);

    /* version, defined as 0 in RFC 2315 */
    verSz = SetMyVersion(0, ver, 0);

    /* generate random content encryption key */
    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    ret = wc_RNG_GenerateBlock(&rng, contentKeyPlain, blockKeySz);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

#ifdef WOLFSSL_SMALL_STACK
    recip         = (byte*)XMALLOC(MAX_RECIP_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    contentKeyEnc = (byte*)XMALLOC(MAX_ENCRYPTED_KEY_SZ, NULL, 
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (contentKeyEnc == NULL || recip == NULL) {
        if (recip)         XFREE(recip,         NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (contentKeyEnc) XFREE(contentKeyEnc, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return MEMORY_E;
    }
    
#endif

    /* build RecipientInfo, only handle 1 for now */
    recipSz = wc_CreateRecipientInfo(pkcs7->singleCert, pkcs7->singleCertSz, RSAk,
                                  blockKeySz, &rng, contentKeyPlain,
                                  contentKeyEnc, &contentKeyEncSz, recip,
                                  MAX_RECIP_SZ);
                                                                      
    ForceZero(contentKeyEnc, MAX_ENCRYPTED_KEY_SZ);
    
#ifdef WOLFSSL_SMALL_STACK
    XFREE(contentKeyEnc, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (recipSz < 0) {
        WOLFSSL_MSG("Failed to create RecipientInfo");
        wc_FreeRng(&rng);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(recip, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
#endif
        return recipSz;
    }
    recipSetSz = SetSet(recipSz, recipSet);

    /* generate IV for block cipher */
    ret = wc_RNG_GenerateBlock(&rng, tmpIv, DES_BLOCK_SIZE);
    wc_FreeRng(&rng);
    if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(recip, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

    /* EncryptedContentInfo */
    contentTypeSz = wc_SetContentType(pkcs7->contentOID, contentType);
    if (contentTypeSz == 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(recip, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
#endif
        return BAD_FUNC_ARG;
    }

    /* allocate encrypted content buffer, pad if necessary, PKCS#7 padding */
    padSz = DES_BLOCK_SIZE - (pkcs7->contentSz % DES_BLOCK_SIZE);
    desOutSz = pkcs7->contentSz + padSz;

    if (padSz != 0) {
        plain = (byte*)XMALLOC(desOutSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(recip, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
#endif
            return MEMORY_E;
        }
        XMEMCPY(plain, pkcs7->content, pkcs7->contentSz);
        dynamicFlag = 1;

        for (i = 0; i < padSz; i++) {
            plain[pkcs7->contentSz + i] = padSz;
        }

    } else {
        plain = pkcs7->content;
        desOutSz = pkcs7->contentSz;
    }

    encryptedContent = (byte*)XMALLOC(desOutSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (encryptedContent == NULL) {
        if (dynamicFlag)
            XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(recip, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
#endif
        return MEMORY_E;
    }

    /* put together IV OCTET STRING */
    ivOctetStringSz = SetOctetString(DES_BLOCK_SIZE, ivOctetString);

    /* build up our ContentEncryptionAlgorithmIdentifier sequence,
     * adding (ivOctetStringSz + DES_BLOCK_SIZE) for IV OCTET STRING */
    contentEncAlgoSz = SetAlgoID(pkcs7->encryptOID, contentEncAlgo,
                                 blkType, ivOctetStringSz + DES_BLOCK_SIZE);

    if (contentEncAlgoSz == 0) {
        XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (dynamicFlag)
            XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(recip, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
#endif
        return BAD_FUNC_ARG;
    }

    /* encrypt content */
    if (pkcs7->encryptOID == DESb) {
        Des des;

        ret = wc_Des_SetKey(&des, contentKeyPlain, tmpIv, DES_ENCRYPTION);

        if (ret == 0)
            wc_Des_CbcEncrypt(&des, encryptedContent, plain, desOutSz);

        if (ret != 0) {
            XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (dynamicFlag)
                XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(recip, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
#endif
            return ret;
        }
    }
    else if (pkcs7->encryptOID == DES3b) {
        Des3 des3;

        ret = wc_Des3_SetKey(&des3, contentKeyPlain, tmpIv, DES_ENCRYPTION);

        if (ret == 0)
            ret = wc_Des3_CbcEncrypt(&des3, encryptedContent, plain, desOutSz);

        if (ret != 0) {
            XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (dynamicFlag)
                XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(recip, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
#endif
            return ret;
        }
    }

    encContentOctetSz = SetImplicit(ASN_OCTET_STRING, 0,
                                    desOutSz, encContentOctet);

    encContentSeqSz = SetSequence(contentTypeSz + contentEncAlgoSz +
                                  ivOctetStringSz + DES_BLOCK_SIZE +
                                  encContentOctetSz + desOutSz, encContentSeq);

    /* keep track of sizes for outer wrapper layering */
    totalSz = verSz + recipSetSz + recipSz + encContentSeqSz + contentTypeSz +
              contentEncAlgoSz + ivOctetStringSz + DES_BLOCK_SIZE +
              encContentOctetSz + desOutSz;

    /* EnvelopedData */
    envDataSeqSz = SetSequence(totalSz, envDataSeq);
    totalSz += envDataSeqSz;

    /* outer content */
    outerContentSz = SetExplicit(0, totalSz, outerContent);
    totalSz += outerContentTypeSz;
    totalSz += outerContentSz;

    /* ContentInfo */
    contentInfoSeqSz = SetSequence(totalSz, contentInfoSeq);
    totalSz += contentInfoSeqSz;

    if (totalSz > (int)outputSz) {
        WOLFSSL_MSG("Pkcs7_encrypt output buffer too small");
        XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (dynamicFlag)
            XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(recip, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
#endif
        return BUFFER_E;
    }

    XMEMCPY(output + idx, contentInfoSeq, contentInfoSeqSz);
    idx += contentInfoSeqSz;
    XMEMCPY(output + idx, outerContentType, outerContentTypeSz);
    idx += outerContentTypeSz;
    XMEMCPY(output + idx, outerContent, outerContentSz);
    idx += outerContentSz;
    XMEMCPY(output + idx, envDataSeq, envDataSeqSz);
    idx += envDataSeqSz;
    XMEMCPY(output + idx, ver, verSz);
    idx += verSz;
    XMEMCPY(output + idx, recipSet, recipSetSz);
    idx += recipSetSz;
    XMEMCPY(output + idx, recip, recipSz);
    idx += recipSz;
    XMEMCPY(output + idx, encContentSeq, encContentSeqSz);
    idx += encContentSeqSz;
    XMEMCPY(output + idx, contentType, contentTypeSz);
    idx += contentTypeSz;
    XMEMCPY(output + idx, contentEncAlgo, contentEncAlgoSz);
    idx += contentEncAlgoSz;
    XMEMCPY(output + idx, ivOctetString, ivOctetStringSz);
    idx += ivOctetStringSz;
    XMEMCPY(output + idx, tmpIv, DES_BLOCK_SIZE);
    idx += DES_BLOCK_SIZE;
    XMEMCPY(output + idx, encContentOctet, encContentOctetSz);
    idx += encContentOctetSz;
    XMEMCPY(output + idx, encryptedContent, desOutSz);
    idx += desOutSz;

    ForceZero(contentKeyPlain, MAX_CONTENT_KEY_LEN);

    if (dynamicFlag)
        XFREE(plain, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
    XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    
#ifdef WOLFSSL_SMALL_STACK
    XFREE(recip, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
#endif

    return idx;
}

/* unwrap and decrypt PKCS#7 envelopedData object, return decoded size */
WOLFSSL_API int wc_PKCS7_DecodeEnvelopedData(PKCS7* pkcs7, byte* pkiMsg,
                                         word32 pkiMsgSz, byte* output,
                                         word32 outputSz)
{
    int recipFound = 0;
    int ret, version, length;
    word32 savedIdx = 0, idx = 0;
    word32 contentType, encOID;
    byte   issuerHash[SHA_DIGEST_SIZE];

    int encryptedKeySz, keySz;
    byte tmpIv[DES_BLOCK_SIZE];
    byte* decryptedKey = NULL;

#ifdef WOLFSSL_SMALL_STACK
    mp_int* serialNum;
    byte* encryptedKey;
    RsaKey* privKey;
#else
    mp_int stack_serialNum;
    mp_int* serialNum = &stack_serialNum;
    byte encryptedKey[MAX_ENCRYPTED_KEY_SZ];
    
    RsaKey stack_privKey;
    RsaKey* privKey = &stack_privKey;
#endif
    int encryptedContentSz;
    byte padLen;
    byte* encryptedContent = NULL;

    if (pkcs7 == NULL || pkcs7->singleCert == NULL ||
        pkcs7->singleCertSz == 0 || pkcs7->privateKey == NULL ||
        pkcs7->privateKeySz == 0)
        return BAD_FUNC_ARG;

    if (pkiMsg == NULL || pkiMsgSz == 0 ||
        output == NULL || outputSz == 0)
        return BAD_FUNC_ARG;

    /* read past ContentInfo, verify type is envelopedData */
    if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (wc_GetContentType(pkiMsg, &idx, &contentType, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (contentType != ENVELOPED_DATA) {
        WOLFSSL_MSG("PKCS#7 input not of type EnvelopedData");
        return PKCS7_OID_E;
    }

    if (pkiMsg[idx++] != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* remove EnvelopedData and version */
    if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(pkiMsg, &idx, &version) < 0)
        return ASN_PARSE_E;

    if (version != 0) {
        WOLFSSL_MSG("PKCS#7 envelopedData needs to be of version 0");
        return ASN_VERSION_E;
    }

    /* walk through RecipientInfo set, find correct recipient */
    if (GetSet(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;
    
#ifdef WOLFSSL_SMALL_STACK
    encryptedKey = (byte*)XMALLOC(MAX_ENCRYPTED_KEY_SZ, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (encryptedKey == NULL)
        return MEMORY_E;
#endif
    
    savedIdx = idx;
    recipFound = 0;

    /* when looking for next recipient, use first sequence and version to
     * indicate there is another, if not, move on */
    while(recipFound == 0) {

        /* remove RecipientInfo, if we don't have a SEQUENCE, back up idx to
         * last good saved one */
        if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0) {
            idx = savedIdx;
            break;
        }

        if (GetMyVersion(pkiMsg, &idx, &version) < 0) {
            idx = savedIdx;
            break;
        }

        if (version != 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_VERSION_E;
        }
        
        /* remove IssuerAndSerialNumber */
        if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }
        
        if (GetNameHash(pkiMsg, &idx, issuerHash, pkiMsgSz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }
        
        /* if we found correct recipient, issuer hashes will match */
        if (XMEMCMP(issuerHash, pkcs7->issuerHash, SHA_DIGEST_SIZE) == 0) {
            recipFound = 1;
        }
        
#ifdef WOLFSSL_SMALL_STACK
        serialNum = (mp_int*)XMALLOC(sizeof(mp_int), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (serialNum == NULL) {
            XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
#endif
        
        if (GetInt(serialNum, pkiMsg, &idx, pkiMsgSz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(serialNum,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }
        
        mp_clear(serialNum);
        
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serialNum, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        
        if (GetAlgoId(pkiMsg, &idx, &encOID, pkiMsgSz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }
        
        /* key encryption algorithm must be RSA for now */
        if (encOID != RSAk) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ALGO_ID_E;
        }
        
        /* read encryptedKey */
        if (pkiMsg[idx++] != ASN_OCTET_STRING) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }
        
        if (GetLength(pkiMsg, &idx, &encryptedKeySz, pkiMsgSz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }
          
        if (recipFound == 1)
            XMEMCPY(encryptedKey, &pkiMsg[idx], encryptedKeySz);
        idx += encryptedKeySz;

        /* update good idx */
        savedIdx = idx;
    }

    if (recipFound == 0) {
        WOLFSSL_MSG("No recipient found in envelopedData that matches input");
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return PKCS7_RECIP_E;
    }

    /* remove EncryptedContentInfo */
    if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }
    
    if (wc_GetContentType(pkiMsg, &idx, &contentType, pkiMsgSz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    if (GetAlgoId(pkiMsg, &idx, &encOID, pkiMsgSz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }
    
    /* get block cipher IV, stored in OPTIONAL parameter of AlgoID */
    if (pkiMsg[idx++] != ASN_OCTET_STRING) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }
    
    if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }
    
    if (length != DES_BLOCK_SIZE) {
        WOLFSSL_MSG("Incorrect IV length, must be of DES_BLOCK_SIZE");
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    XMEMCPY(tmpIv, &pkiMsg[idx], length);
    idx += length;

    /* read encryptedContent, cont[0] */
    if (pkiMsg[idx++] != (ASN_CONTEXT_SPECIFIC | 0)) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    if (GetLength(pkiMsg, &idx, &encryptedContentSz, pkiMsgSz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }
    
    encryptedContent = (byte*)XMALLOC(encryptedContentSz, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (encryptedContent == NULL) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return MEMORY_E;
    }

    XMEMCPY(encryptedContent, &pkiMsg[idx], encryptedContentSz);

    /* load private key */
#ifdef WOLFSSL_SMALL_STACK
    privKey = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (privKey == NULL) {
        XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(encryptedKey,     NULL, DYNAMIC_TYPE_TMP_BUFFER);        return MEMORY_E;
    }
#endif

    ret = wc_InitRsaKey(privKey, 0);
    if (ret != 0) {
        XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(privKey,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

    idx = 0;

    ret = wc_RsaPrivateKeyDecode(pkcs7->privateKey, &idx, privKey,
                              pkcs7->privateKeySz);
    if (ret != 0) {
        WOLFSSL_MSG("Failed to decode RSA private key");
        XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(privKey,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

    /* decrypt encryptedKey */
    keySz = wc_RsaPrivateDecryptInline(encryptedKey, encryptedKeySz,
                                    &decryptedKey, privKey);
    wc_FreeRsaKey(privKey);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(privKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (keySz <= 0) {
        XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return keySz;
    }

    /* decrypt encryptedContent */
    if (encOID == DESb) {
        Des des;
        ret = wc_Des_SetKey(&des, decryptedKey, tmpIv, DES_DECRYPTION);

        if (ret == 0)
            wc_Des_CbcDecrypt(&des, encryptedContent, encryptedContent,
                                 encryptedContentSz);

        if (ret != 0) {
            XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ret;
        }
    }
    else if (encOID == DES3b) {
        Des3 des;
        ret = wc_Des3_SetKey(&des, decryptedKey, tmpIv, DES_DECRYPTION);
        if (ret == 0)
            ret = wc_Des3_CbcDecrypt(&des, encryptedContent, encryptedContent,
                                  encryptedContentSz);

        if (ret != 0) {
            XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ret;
        }
    } else {
        WOLFSSL_MSG("Unsupported content encryption OID type");
        XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ALGO_ID_E;
    }

    padLen = encryptedContent[encryptedContentSz-1];

    /* copy plaintext to output */
    XMEMCPY(output, encryptedContent, encryptedContentSz - padLen);

    /* free memory, zero out keys */
    ForceZero(encryptedKey, MAX_ENCRYPTED_KEY_SZ);
    ForceZero(encryptedContent, encryptedContentSz);
    XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(encryptedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    
    return encryptedContentSz - padLen;
}


