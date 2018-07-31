
#ifdef HAVE_OCSP

static int GetEnumerated(const byte* input, word32* inOutIdx, int *value)
{
    word32 idx = *inOutIdx;
    word32 len;

    WOLFSSL_ENTER();

    *value = 0;

    if (input[idx++] != ASN_ENUMERATED)
        return ASN_PARSE_E;

    len = input[idx++];
    if (len > 4)
        return ASN_PARSE_E;

    while (len--) {
        *value  = *value << 8 | input[idx++];
    }

    *inOutIdx = idx;

    return *value;
}


static int DecodeSingleResponse(byte* source,
                            word32* ioIndex, OcspResponse* resp, word32 size)
{
    word32 idx = *ioIndex, prevIndex, oid;
    int length, wrapperSz;
    CertStatus* cs = resp->status;

    WOLFSSL_ENTER();

    /* Outer wrapper of the SEQUENCE OF Single Responses. */
    if (GetSequence(source, &idx, &wrapperSz, size) < 0)
        return ASN_PARSE_E;

    prevIndex = idx;

    /* When making a request, we only request one status on one certificate
     * at a time. There should only be one SingleResponse */

    /* Wrapper around the Single Response */
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    /* Wrapper around the CertID */
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    /* Skip the hash algorithm */
    if (GetAlgoId(source, &idx, &oid, size) < 0)
        return ASN_PARSE_E;
    /* Save reference to the hash of CN */
    if (source[idx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;
    if (GetLength(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    resp->issuerHash = source + idx;
    idx += length;
    /* Save reference to the hash of the issuer public key */
    if (source[idx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;
    if (GetLength(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    resp->issuerKeyHash = source + idx;
    idx += length;

    /* Read the serial number, it is handled as a string, not as a 
     * proper number. Just XMEMCPY the data over, rather than load it
     * as an mp_int. */
    if (source[idx++] != ASN_INTEGER)
        return ASN_PARSE_E;
    if (GetLength(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    if (length <= EXTERNAL_SERIAL_SIZE)
    {
        if (source[idx] == 0)
        {
            idx++;
            length--;
        }
        XMEMCPY(cs->serial, source + idx, length);
        cs->serialSz = length;
    }
    else
    {
        return ASN_GETINT_E;
    }
    idx += length;

    /* CertStatus */
    switch (source[idx++])
    {
        case (ASN_CONTEXT_SPECIFIC | CERT_GOOD):
            cs->status = CERT_GOOD;
            idx++;
            break;
        case (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | CERT_REVOKED):
            cs->status = CERT_REVOKED;
            if (GetLength(source, &idx, &length, size) < 0)
                return ASN_PARSE_E;
            idx += length;
            break;
        case (ASN_CONTEXT_SPECIFIC | CERT_UNKNOWN):
            cs->status = CERT_UNKNOWN;
            idx++;
            break;
        default:
            return ASN_PARSE_E;
    }

    if (GetBasicDate(source, &idx, cs->thisDate,
                                                &cs->thisDateFormat, size) < 0)
        return ASN_PARSE_E;
    if (!XVALIDATE_DATE(cs->thisDate, cs->thisDateFormat, BEFORE))
        return ASN_BEFORE_DATE_E;
    
    /* The following items are optional. Only check for them if there is more
     * unprocessed data in the singleResponse wrapper. */
    
    if (((int)(idx - prevIndex) < wrapperSz) &&
        (source[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0)))
    {
        idx++;
        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;
        if (GetBasicDate(source, &idx, cs->nextDate,
                                                &cs->nextDateFormat, size) < 0)
            return ASN_PARSE_E;
    }
    if (((int)(idx - prevIndex) < wrapperSz) &&
        (source[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1)))
    {
        idx++;
        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;
        idx += length;
    }

    *ioIndex = idx;

    return 0;
}

static int DecodeOcspRespExtensions(byte* source,
                            word32* ioIndex, OcspResponse* resp, word32 sz)
{
    word32 idx = *ioIndex;
    int length;
    int ext_bound; /* boundary index for the sequence of extensions */
    word32 oid;

    WOLFSSL_ENTER();

    if (source[idx++] != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1))
        return ASN_PARSE_E;

    if (GetLength(source, &idx, &length, sz) < 0) return ASN_PARSE_E;

    if (GetSequence(source, &idx, &length, sz) < 0) return ASN_PARSE_E;
   
    ext_bound = idx + length;

    while (idx < (word32)ext_bound) {
        if (GetSequence(source, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        oid = 0;
        if (GetObjectId(source, &idx, &oid, sz) < 0) {
            WOLFSSL_MSG("\tfail: OBJECT ID");
            return ASN_PARSE_E;
        }

        /* check for critical flag */
        if (source[idx] == ASN_BOOLEAN) {
            WOLFSSL_MSG("\tfound optional critical flag, moving past");
            idx += (ASN_BOOL_SIZE + 1);
        }

        /* process the extension based on the OID */
        if (source[idx++] != ASN_OCTET_STRING) {
            WOLFSSL_MSG("\tfail: should be an OCTET STRING");
            return ASN_PARSE_E;
        }

        if (GetLength(source, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: extension data length");
            return ASN_PARSE_E;
        }

        if (oid == OCSP_NONCE_OID) {
            resp->nonce = source + idx;
            resp->nonceSz = length;
        }

        idx += length;
    }

    *ioIndex = idx;
    return 0;
}


static int DecodeResponseData(byte* source,
                            word32* ioIndex, OcspResponse* resp, word32 size)
{
    word32 idx = *ioIndex, prev_idx;
    int length;
    int version;
    word32 responderId = 0;

    WOLFSSL_ENTER();

    resp->response = source + idx;
    prev_idx = idx;
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    resp->responseSz = length + idx - prev_idx;

    /* Get version. It is an EXPLICIT[0] DEFAULT(0) value. If this
     * item isn't an EXPLICIT[0], then set version to zero and move
     * onto the next item.
     */
    if (source[idx] == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
    {    
        idx += 2; /* Eat the value and length */
        if (GetMyVersion(source, &idx, &version) < 0)
            return ASN_PARSE_E;
    } else
        version = 0;

    responderId = source[idx++];
    if ((responderId == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1)) ||
        (responderId == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 2)))
    {
        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;
        idx += length;
    }
    else
        return ASN_PARSE_E;
    
    /* save pointer to the producedAt time */
    if (GetBasicDate(source, &idx, resp->producedDate,
                                        &resp->producedDateFormat, size) < 0)
        return ASN_PARSE_E;

    if (DecodeSingleResponse(source, &idx, resp, size) < 0)
        return ASN_PARSE_E;

    if (DecodeOcspRespExtensions(source, &idx, resp, size) < 0)
        return ASN_PARSE_E;

    *ioIndex = idx;
    return 0;
}


static int DecodeCerts(byte* source,
                            word32* ioIndex, OcspResponse* resp, word32 size)
{
    word32 idx = *ioIndex;

    WOLFSSL_ENTER();

    if (source[idx++] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC))
    {
        int length;

        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;

        if (GetSequence(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;

        resp->cert = source + idx;
        resp->certSz = length;

        idx += length;
    }
    *ioIndex = idx;
    return 0;
}

static int DecodeBasicOcspResponse(byte* source,
                            word32* ioIndex, OcspResponse* resp, word32 size)
{
    int length;
    word32 idx = *ioIndex;
    word32 end_index;

    WOLFSSL_ENTER();

    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    if (idx + length > size)
        return ASN_INPUT_E;
    end_index = idx + length;

    if (DecodeResponseData(source, &idx, resp, size) < 0)
        return ASN_PARSE_E;
    
    /* Get the signature algorithm */
    if (GetAlgoId(source, &idx, &resp->sigOID, size) < 0)
        return ASN_PARSE_E;

    /* Obtain pointer to the start of the signature, and save the size */
    if (source[idx++] == ASN_BIT_STRING)
    {
        int sigLength = 0;
        if (GetLength(source, &idx, &sigLength, size) < 0)
            return ASN_PARSE_E;
        resp->sigSz = sigLength;
        resp->sig = source + idx;
        idx += sigLength;
    }

    /*
     * Check the length of the BasicOcspResponse against the current index to
     * see if there are certificates, they are optional.
     */
    if (idx < end_index)
    {
        DecodedCert cert;
        int ret;

        if (DecodeCerts(source, &idx, resp, size) < 0)
            return ASN_PARSE_E;

        InitDecodedCert(&cert, resp->cert, resp->certSz, 0);
        ret = ParseCertRelative(&cert, CA_TYPE, NO_VERIFY, 0);
        if (ret < 0)
            return ret;

        ret = ConfirmSignature(resp->response, resp->responseSz,
                            cert.publicKey, cert.pubKeySize, cert.keyOID,
                            resp->sig, resp->sigSz, resp->sigOID, NULL);
        FreeDecodedCert(&cert);

        if (ret == 0)
        {
            WOLFSSL_MSG("\tOCSP Confirm signature failed");
            return ASN_OCSP_CONFIRM_E;
        }
    }

    *ioIndex = idx;
    return 0;
}


void InitOcspResponse(OcspResponse* resp, CertStatus* status,
                                                    byte* source, word32 inSz)
{
    WOLFSSL_ENTER();

    resp->responseStatus = -1;
    resp->response = NULL;
    resp->responseSz = 0;
    resp->producedDateFormat = 0;
    resp->issuerHash = NULL;
    resp->issuerKeyHash = NULL;
    resp->sig = NULL;
    resp->sigSz = 0;
    resp->sigOID = 0;
    resp->status = status;
    resp->nonce = NULL;
    resp->nonceSz = 0;
    resp->source = source;
    resp->maxIdx = inSz;
}


int OcspResponseDecode(OcspResponse* resp)
{
    int length = 0;
    word32 idx = 0;
    byte* source = resp->source;
    word32 size = resp->maxIdx;
    word32 oid;

    WOLFSSL_ENTER();

    /* peel the outer SEQUENCE wrapper */
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    
    /* First get the responseStatus, an ENUMERATED */
    if (GetEnumerated(source, &idx, &resp->responseStatus) < 0)
        return ASN_PARSE_E;

    if (resp->responseStatus != OCSP_SUCCESSFUL)
        return 0;

    /* Next is an EXPLICIT record called ResponseBytes, OPTIONAL */
    if (idx >= size)
        return ASN_INPUT_E;
    if (source[idx++] != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC))
        return ASN_PARSE_E;
    if (GetLength(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    /* Get the responseBytes SEQUENCE */
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    /* Check ObjectID for the resposeBytes */
    if (GetObjectId(source, &idx, &oid, size) < 0)
        return ASN_PARSE_E;
    if (oid != OCSP_BASIC_OID)
        return ASN_PARSE_E;
    if (source[idx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;

    if (GetLength(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    if (DecodeBasicOcspResponse(source, &idx, resp, size) < 0)
        return ASN_PARSE_E;
    
    return 0;
}


static word32 SetOcspReqExtensions(word32 extSz, byte* output,
                                            const byte* nonce, word32 nonceSz)
{
    static const byte NonceObjId[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
                                       0x30, 0x01, 0x02 };
    byte seqArray[5][MAX_SEQ_SZ];
    word32 seqSz[5], totalSz;

    WOLFSSL_ENTER();

    if (nonce == NULL || nonceSz == 0) return 0;
    
    seqArray[0][0] = ASN_OCTET_STRING;
    seqSz[0] = 1 + SetLength(nonceSz, &seqArray[0][1]);

    seqArray[1][0] = ASN_OBJECT_ID;
    seqSz[1] = 1 + SetLength(sizeof(NonceObjId), &seqArray[1][1]);

    totalSz = seqSz[0] + seqSz[1] + nonceSz + (word32)sizeof(NonceObjId);

    seqSz[2] = SetSequence(totalSz, seqArray[2]);
    totalSz += seqSz[2];

    seqSz[3] = SetSequence(totalSz, seqArray[3]);
    totalSz += seqSz[3];

    seqArray[4][0] = (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 2);
    seqSz[4] = 1 + SetLength(totalSz, &seqArray[4][1]);
    totalSz += seqSz[4];

    if (totalSz < extSz)
    {
        totalSz = 0;
        XMEMCPY(output + totalSz, seqArray[4], seqSz[4]);
        totalSz += seqSz[4];
        XMEMCPY(output + totalSz, seqArray[3], seqSz[3]);
        totalSz += seqSz[3];
        XMEMCPY(output + totalSz, seqArray[2], seqSz[2]);
        totalSz += seqSz[2];
        XMEMCPY(output + totalSz, seqArray[1], seqSz[1]);
        totalSz += seqSz[1];
        XMEMCPY(output + totalSz, NonceObjId, sizeof(NonceObjId));
        totalSz += (word32)sizeof(NonceObjId);
        XMEMCPY(output + totalSz, seqArray[0], seqSz[0]);
        totalSz += seqSz[0];
        XMEMCPY(output + totalSz, nonce, nonceSz);
        totalSz += nonceSz;
    }

    return totalSz;
}


int EncodeOcspRequest(OcspRequest* req)
{
    byte seqArray[5][MAX_SEQ_SZ];
    /* The ASN.1 of the OCSP Request is an onion of sequences */
    byte algoArray[MAX_ALGO_SZ];
    byte issuerArray[MAX_ENCODED_DIG_SZ];
    byte issuerKeyArray[MAX_ENCODED_DIG_SZ];
    byte snArray[MAX_SN_SZ];
    byte extArray[MAX_OCSP_EXT_SZ];
    byte* output = req->dest;
    word32 seqSz[5], algoSz, issuerSz, issuerKeySz, snSz, extSz, totalSz;
    int i;

    WOLFSSL_ENTER();

#ifdef NO_SHA
    algoSz = SetAlgoID(SHA256h, algoArray, hashType, 0);
#else
    algoSz = SetAlgoID(SHAh, algoArray, hashType, 0);
#endif

    req->issuerHash = req->cert->issuerHash;
    issuerSz = SetDigest(req->cert->issuerHash, KEYID_SIZE, issuerArray);

    req->issuerKeyHash = req->cert->issuerKeyHash;
    issuerKeySz = SetDigest(req->cert->issuerKeyHash,
                                                    KEYID_SIZE, issuerKeyArray);

    req->serial = req->cert->serial;
    req->serialSz = req->cert->serialSz;
    snSz = SetSerialNumber(req->cert->serial, req->cert->serialSz, snArray);

    extSz = 0;
    if (req->useNonce) {
        RNG rng;
        if (wc_InitRng(&rng) != 0) {
            WOLFSSL_MSG("\tCannot initialize RNG. Skipping the OSCP Nonce.");
        } else {
            if (wc_RNG_GenerateBlock(&rng, req->nonce, MAX_OCSP_NONCE_SZ) != 0)
                WOLFSSL_MSG("\tCannot run RNG. Skipping the OSCP Nonce.");
            else {
                req->nonceSz = MAX_OCSP_NONCE_SZ;
                extSz = SetOcspReqExtensions(MAX_OCSP_EXT_SZ, extArray,
                                                      req->nonce, req->nonceSz);
            }
            wc_FreeRng(&rng);
        }
    }

    totalSz = algoSz + issuerSz + issuerKeySz + snSz;

    for (i = 4; i >= 0; i--) {
        seqSz[i] = SetSequence(totalSz, seqArray[i]);
        totalSz += seqSz[i];
        if (i == 2) totalSz += extSz;
    }
    totalSz = 0;
    for (i = 0; i < 5; i++) {
        XMEMCPY(output + totalSz, seqArray[i], seqSz[i]);
        totalSz += seqSz[i];
    }
    XMEMCPY(output + totalSz, algoArray, algoSz);
    totalSz += algoSz;
    XMEMCPY(output + totalSz, issuerArray, issuerSz);
    totalSz += issuerSz;
    XMEMCPY(output + totalSz, issuerKeyArray, issuerKeySz);
    totalSz += issuerKeySz;
    XMEMCPY(output + totalSz, snArray, snSz);
    totalSz += snSz;
    if (extSz != 0) {
        XMEMCPY(output + totalSz, extArray, extSz);
        totalSz += extSz;
    }

    return totalSz;
}


void InitOcspRequest(OcspRequest* req, DecodedCert* cert, byte useNonce,
                                                    byte* dest, word32 destSz)
{
    WOLFSSL_ENTER();

    req->cert = cert;
    req->useNonce = useNonce;
    req->nonceSz = 0;
    req->issuerHash = NULL;
    req->issuerKeyHash = NULL;
    req->serial = NULL;
    req->dest = dest;
    req->destSz = destSz;
}


int CompareOcspReqResp(OcspRequest* req, OcspResponse* resp)
{
    int cmp;

    WOLFSSL_ENTER();

    if (req == NULL)
    {
        WOLFSSL_MSG("\tReq missing");
        return -1;
    }

    if (resp == NULL)
    {
        WOLFSSL_MSG("\tResp missing");
        return 1;
    }

    /* Nonces are not critical. The responder may not necessarily add
     * the nonce to the response. */
    if (req->useNonce && resp->nonceSz != 0) {
        cmp = req->nonceSz - resp->nonceSz;
        if (cmp != 0)
        {
            WOLFSSL_MSG("\tnonceSz mismatch");
            return cmp;
        }
    
        cmp = XMEMCMP(req->nonce, resp->nonce, req->nonceSz);
        if (cmp != 0)
        {
            WOLFSSL_MSG("\tnonce mismatch");
            return cmp;
        }
    }

    cmp = XMEMCMP(req->issuerHash, resp->issuerHash, KEYID_SIZE);
    if (cmp != 0)
    {
        WOLFSSL_MSG("\tissuerHash mismatch");
        return cmp;
    }

    cmp = XMEMCMP(req->issuerKeyHash, resp->issuerKeyHash, KEYID_SIZE);
    if (cmp != 0)
    {
        WOLFSSL_MSG("\tissuerKeyHash mismatch");
        return cmp;
    }

    cmp = req->serialSz - resp->status->serialSz;
    if (cmp != 0)
    {
        WOLFSSL_MSG("\tserialSz mismatch");
        return cmp;
    }

    cmp = XMEMCMP(req->serial, resp->status->serial, req->serialSz);
    if (cmp != 0)
    {
        WOLFSSL_MSG("\tserial mismatch");
        return cmp;
    }

    return 0;
}

#endif

