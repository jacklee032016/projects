
#include "cmnSsl.h"


#ifndef NO_CERTS

/* Match names with wildcards, each wildcard can represent a single name
   component or fragment but not mulitple names, i.e.,
   *.z.com matches y.z.com but not x.y.z.com

   return 1 on success */
static int __matchDomainName(const char* pattern, int len, const char* str)
{
    char p, s;

    if (pattern == NULL || str == NULL || len <= 0)
        return 0;

    while (len > 0) {

        p = (char)XTOLOWER((unsigned char)*pattern++);
        if (p == 0)
            break;

        if (p == '*') {
            while (--len > 0 &&
                         (p = (char)XTOLOWER((unsigned char)*pattern++)) == '*')
                ;

            if (len == 0)
                p = '\0';

            while ( (s = (char)XTOLOWER((unsigned char) *str)) != '\0') {
                if (s == p)
                    break;
                if (s == '.')
                    return 0;
                str++;
            }
        }
        else {
            if (p != (char)XTOLOWER((unsigned char) *str))
                return 0;
        }

        if (*str != '\0')
            str++;

        if (len > 0)
            len--;
    }

    return *str == '\0';
}


/* try to find an altName match to domain, return 1 on success */
static int __checkAltNames(DecodedCert* dCert, char* domain)
{
    int        match = 0;
    DNS_entry* altName = NULL;

    WOLFSSL_MSG("Checking AltNames");

    if (dCert)
        altName = dCert->altNames;

    while (altName) {
        WOLFSSL_MSG("    individual AltName check");

        if (__matchDomainName(altName->name,(int)XSTRLEN(altName->name), domain)){
            match = 1;
            break;
        }

        altName = altName->next;
    }

    return match;
}
#endif


/* called in DoHandShakeMsgType */
int _doCertificate(WOLFSSL* ssl, byte* input, word32* inOutIdx, word32 size)
{
    word32 listSz;
    word32 begin = *inOutIdx;
    int    ret = 0;
    int    anyError = 0;
    int    totalCerts = 0;    /* number of certs in certs buffer */
    int    count;
    buffer certs[MAX_CHAIN_DEPTH];

#ifdef WOLFSSL_SMALL_STACK
    char*                  domain = NULL;
    DecodedCert*           dCert  = NULL;
    WOLFSSL_X509_STORE_CTX* store  = NULL;
#else
    char                   domain[ASN_NAME_MAX];
    DecodedCert            dCert[1];
    WOLFSSL_X509_STORE_CTX  store[1];
#endif

    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Certificate", &ssl->handShakeInfo);
        if (ssl->toInfoOn) AddLateName("Certificate", &ssl->timeoutInfo);
    #endif

    if ((*inOutIdx - begin) + OPAQUE24_LEN > size)
        return BUFFER_ERROR;

    c24to32(input + *inOutIdx, &listSz);
    *inOutIdx += OPAQUE24_LEN;

#ifdef HAVE_MAX_FRAGMENT
    if (listSz > ssl->max_fragment) {
        SendAlert(ssl, alert_fatal, record_overflow);
        return BUFFER_E;
    }
#else
    if (listSz > MAX_RECORD_SIZE)
        return BUFFER_E;
#endif

    if ((*inOutIdx - begin) + listSz != size)
        return BUFFER_ERROR;

    WOLFSSL_MSG("Loading peer's cert chain");
    /* first put cert chain into buffer so can verify top down
       we're sent bottom up */
    while (listSz) {
        word32 certSz;

        if (totalCerts >= MAX_CHAIN_DEPTH)
            return MAX_CHAIN_ERROR;

        if ((*inOutIdx - begin) + OPAQUE24_LEN > size)
            return BUFFER_ERROR;

        c24to32(input + *inOutIdx, &certSz);
        *inOutIdx += OPAQUE24_LEN;

        if ((*inOutIdx - begin) + certSz > size)
            return BUFFER_ERROR;

        certs[totalCerts].length = certSz;
        certs[totalCerts].buffer = input + *inOutIdx;

#ifdef SESSION_CERTS
        if (ssl->session.chain.count < MAX_CHAIN_DEPTH &&
                                       certSz < MAX_X509_SIZE) {
            ssl->session.chain.certs[ssl->session.chain.count].length = certSz;
            XMEMCPY(ssl->session.chain.certs[ssl->session.chain.count].buffer,
                    input + *inOutIdx, certSz);
            ssl->session.chain.count++;
        } else {
            WOLFSSL_MSG("Couldn't store chain cert for session");
        }
#endif

        *inOutIdx += certSz;
        listSz -= certSz + CERT_HEADER_SZ;

        totalCerts++;
        WOLFSSL_MSG("    Put another cert into chain");
    }

    count = totalCerts;

#ifdef WOLFSSL_SMALL_STACK
    dCert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (dCert == NULL)
        return MEMORY_E;
#endif

    /* verify up to peer's first */
    while (count > 1) {
        buffer myCert = certs[count - 1];
        byte* subjectHash;

        InitDecodedCert(dCert, myCert.buffer, myCert.length, ssl->heap);
        ret = ParseCertRelative(dCert, CERT_TYPE, !ssl->options.verifyNone,
                                ssl->ctx->cm);
        #ifndef NO_SKID
            subjectHash = dCert->extSubjKeyId;
        #else
            subjectHash = dCert->subjectHash;
        #endif

        if (ret == 0 && dCert->isCA == 0) {
            WOLFSSL_MSG("Chain cert is not a CA, not adding as one");
        }
        else if (ret == 0 && ssl->options.verifyNone) {
            WOLFSSL_MSG("Chain cert not verified by option, not adding as CA");
        }
        else if (ret == 0 && !AlreadySigner(ssl->ctx->cm, subjectHash)) {
            buffer add;
            add.length = myCert.length;
            add.buffer = (byte*)XMALLOC(myCert.length, ssl->heap,
                                        DYNAMIC_TYPE_CA);
            WOLFSSL_MSG("Adding CA from chain");

            if (add.buffer == NULL)
                return MEMORY_E;
            XMEMCPY(add.buffer, myCert.buffer, myCert.length);

            ret = AddCA(ssl->ctx->cm, add, WOLFSSL_CHAIN_CA,
                        ssl->ctx->verifyPeer);
            if (ret == 1) ret = 0;   /* SSL_SUCCESS for external */
        }
        else if (ret != 0) {
            WOLFSSL_MSG("Failed to verify CA from chain");
        }
        else {
            WOLFSSL_MSG("Verified CA from chain and already had it");
        }

#if defined(HAVE_OCSP) || defined(HAVE_CRL)
        if (ret == 0) {
            int doCrlLookup = 1;
            (void)doCrlLookup;
#ifdef HAVE_OCSP
            if (ssl->ctx->cm->ocspEnabled && ssl->ctx->cm->ocspCheckAll) {
                WOLFSSL_MSG("Doing Non Leaf OCSP check");
                ret = CheckCertOCSP(ssl->ctx->cm->ocsp, dCert);
                doCrlLookup = (ret == OCSP_CERT_UNKNOWN);
                if (ret != 0) {
                    doCrlLookup = 0;
                    WOLFSSL_MSG("\tOCSP Lookup not ok");
                }
            }
#endif /* HAVE_OCSP */

#ifdef HAVE_CRL
            if (doCrlLookup && ssl->ctx->cm->crlEnabled
                                                 && ssl->ctx->cm->crlCheckAll) {
                WOLFSSL_MSG("Doing Non Leaf CRL check");
                ret = CheckCertCRL(ssl->ctx->cm->crl, dCert);

                if (ret != 0) {
                    WOLFSSL_MSG("\tCRL check not ok");
                }
            }
#endif /* HAVE_CRL */
        }
#endif /* HAVE_OCSP || HAVE_CRL */

        if (ret != 0 && anyError == 0)
            anyError = ret;   /* save error from last time */

        FreeDecodedCert(dCert);
        count--;
    }

    /* peer's, may not have one if blank client cert sent by TLSv1.2 */
    if (count) {
        buffer myCert = certs[0];
        int    fatal  = 0;

        WOLFSSL_MSG("Verifying Peer's cert");

        InitDecodedCert(dCert, myCert.buffer, myCert.length, ssl->heap);
        ret = ParseCertRelative(dCert, CERT_TYPE, !ssl->options.verifyNone,
                                ssl->ctx->cm);
        if (ret == 0) {
            WOLFSSL_MSG("Verified Peer's cert");
            fatal = 0;
        }
        else if (ret == ASN_PARSE_E) {
            WOLFSSL_MSG("Got Peer cert ASN PARSE ERROR, fatal");
            fatal = 1;
        }
        else {
            WOLFSSL_MSG("Failed to verify Peer's cert");
            if (ssl->verifyCallback) {
                WOLFSSL_MSG("\tCallback override available, will continue");
                fatal = 0;
            }
            else {
                WOLFSSL_MSG("\tNo callback override available, fatal");
                fatal = 1;
            }
        }

#ifdef HAVE_SECURE_RENEGOTIATION
        if (fatal == 0 && ssl->secure_renegotiation
                       && ssl->secure_renegotiation->enabled) {

            if (ssl->keys.encryptionOn) {
                /* compare against previous time */
                if (XMEMCMP(dCert->subjectHash,
                            ssl->secure_renegotiation->subject_hash,
                            SHA_DIGEST_SIZE) != 0) {
                    WOLFSSL_MSG("Peer sent different cert during scr, fatal");
                    fatal = 1;
                    ret   = SCR_DIFFERENT_CERT_E;
                }
            }

            /* cache peer's hash */
            if (fatal == 0) {
                XMEMCPY(ssl->secure_renegotiation->subject_hash,
                        dCert->subjectHash, SHA_DIGEST_SIZE);
            }
        }
#endif

#if defined(HAVE_OCSP) || defined(HAVE_CRL)
        if (fatal == 0) {
            int doCrlLookup = 1;
            (void)doCrlLookup;
#ifdef HAVE_OCSP
            if (ssl->ctx->cm->ocspEnabled) {
                ret = CheckCertOCSP(ssl->ctx->cm->ocsp, dCert);
                doCrlLookup = (ret == OCSP_CERT_UNKNOWN);
                if (ret != 0) {
                    WOLFSSL_MSG("\tOCSP Lookup not ok");
                    fatal = 0;
                }
            }
#endif /* HAVE_OCSP */

#ifdef HAVE_CRL
            if (doCrlLookup && ssl->ctx->cm->crlEnabled) {
                WOLFSSL_MSG("Doing Leaf CRL check");
                ret = CheckCertCRL(ssl->ctx->cm->crl, dCert);
                if (ret != 0) {
                    WOLFSSL_MSG("\tCRL check not ok");
                    fatal = 0;
                }
            }
#endif /* HAVE_CRL */
        }
#endif /* HAVE_OCSP || HAVE_CRL */

#ifdef KEEP_PEER_CERT
        {
        /* set X509 format for peer cert even if fatal */
        int copyRet = CopyDecodedToX509(&ssl->peerCert, dCert);
        if (copyRet == MEMORY_E)
            fatal = 1;
        }
#endif

#ifndef IGNORE_KEY_EXTENSIONS
        if (dCert->extKeyUsageSet) {
            if ((ssl->specs.kea == rsa_kea) &&
                (dCert->extKeyUsage & KEYUSE_KEY_ENCIPHER) == 0) {
                ret = KEYUSE_ENCIPHER_E;
            }
            if ((ssl->specs.sig_algo == rsa_sa_algo ||
                    (ssl->specs.sig_algo == ecc_dsa_sa_algo &&
                         !ssl->specs.static_ecdh)) &&
                (dCert->extKeyUsage & KEYUSE_DIGITAL_SIG) == 0) {
                WOLFSSL_MSG("KeyUse Digital Sig not set");
                ret = KEYUSE_SIGNATURE_E;
            }
        }

        if (dCert->extExtKeyUsageSet) {
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                if ((dCert->extExtKeyUsage &
                        (EXTKEYUSE_ANY | EXTKEYUSE_SERVER_AUTH)) == 0) {
                    WOLFSSL_MSG("ExtKeyUse Server Auth not set");
                    ret = EXTKEYUSE_AUTH_E;
                }
            }
            else {
                if ((dCert->extExtKeyUsage &
                        (EXTKEYUSE_ANY | EXTKEYUSE_CLIENT_AUTH)) == 0) {
                    WOLFSSL_MSG("ExtKeyUse Client Auth not set");
                    ret = EXTKEYUSE_AUTH_E;
                }
            }
        }
#endif /* IGNORE_KEY_EXTENSIONS */

        if (fatal) {
            FreeDecodedCert(dCert);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(dCert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            ssl->error = ret;
            return ret;
        }
        ssl->options.havePeerCert = 1;

#ifdef WOLFSSL_SMALL_STACK
        domain = (char*)XMALLOC(ASN_NAME_MAX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (domain == NULL) {
            FreeDecodedCert(dCert);
            XFREE(dCert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
#endif
        /* store for callback use */
        if (dCert->subjectCNLen < ASN_NAME_MAX) {
            XMEMCPY(domain, dCert->subjectCN, dCert->subjectCNLen);
            domain[dCert->subjectCNLen] = '\0';
        }
        else
            domain[0] = '\0';

        if (!ssl->options.verifyNone && ssl->buffers.domainName.buffer) {
            if (__matchDomainName(dCert->subjectCN, dCert->subjectCNLen,
                                (char*)ssl->buffers.domainName.buffer) == 0) {
                WOLFSSL_MSG("DomainName match on common name failed");
                if (__checkAltNames(dCert,
                                 (char*)ssl->buffers.domainName.buffer) == 0 ) {
                    WOLFSSL_MSG("DomainName match on alt names failed too");
                    ret = DOMAIN_NAME_MISMATCH; /* try to get peer key still */
                }
            }
        }

        /* decode peer key */
        switch (dCert->keyOID) {
        #ifndef NO_RSA
            case RSAk:
                {
                    word32 idx = 0;
                    int    keyRet = 0;

                    if (ssl->peerRsaKey == NULL) {
                        ssl->peerRsaKey = (RsaKey*)XMALLOC(sizeof(RsaKey),
                                                   ssl->heap, DYNAMIC_TYPE_RSA);
                        if (ssl->peerRsaKey == NULL) {
                            WOLFSSL_MSG("PeerRsaKey Memory error");
                            keyRet = MEMORY_E;
                        } else {
                            keyRet = wc_InitRsaKey(ssl->peerRsaKey,
                                                   ssl->ctx->heap);
                        }
                    } else if (ssl->peerRsaKeyPresent) {
                        /* don't leak on reuse */
                        wc_FreeRsaKey(ssl->peerRsaKey);
                        ssl->peerRsaKeyPresent = 0;
                        keyRet = wc_InitRsaKey(ssl->peerRsaKey, ssl->heap);
                    }

                    if (keyRet != 0 || wc_RsaPublicKeyDecode(dCert->publicKey,
                               &idx, ssl->peerRsaKey, dCert->pubKeySize) != 0) {
                        ret = PEER_KEY_ERROR;
                    }
                    else {
                        ssl->peerRsaKeyPresent = 1;
                        #ifdef HAVE_PK_CALLBACKS
                            #ifndef NO_RSA
                                ssl->buffers.peerRsaKey.buffer =
                                       (byte*)XMALLOC(dCert->pubKeySize,
                                               ssl->heap, DYNAMIC_TYPE_RSA);
                                if (ssl->buffers.peerRsaKey.buffer == NULL)
                                    ret = MEMORY_ERROR;
                                else {
                                    XMEMCPY(ssl->buffers.peerRsaKey.buffer,
                                           dCert->publicKey, dCert->pubKeySize);
                                    ssl->buffers.peerRsaKey.length =
                                            dCert->pubKeySize;
                                }
                            #endif /* NO_RSA */
                        #endif /*HAVE_PK_CALLBACKS */
                    }
                }
                break;
        #endif /* NO_RSA */
        #ifdef HAVE_NTRU
            case NTRUk:
                {
                    if (dCert->pubKeySize > sizeof(ssl->peerNtruKey)) {
                        ret = PEER_KEY_ERROR;
                    }
                    else {
                        XMEMCPY(ssl->peerNtruKey, dCert->publicKey,
                                                             dCert->pubKeySize);
                        ssl->peerNtruKeyLen = (word16)dCert->pubKeySize;
                        ssl->peerNtruKeyPresent = 1;
                    }
                }
                break;
        #endif /* HAVE_NTRU */
        #ifdef HAVE_ECC
            case ECDSAk:
                {
                    if (ssl->peerEccDsaKey == NULL) {
                        /* alloc/init on demand */
                        ssl->peerEccDsaKey = (ecc_key*)XMALLOC(sizeof(ecc_key),
                                              ssl->ctx->heap, DYNAMIC_TYPE_ECC);
                        if (ssl->peerEccDsaKey == NULL) {
                            WOLFSSL_MSG("PeerEccDsaKey Memory error");
                            return MEMORY_E;
                        }
                        wc_ecc_init(ssl->peerEccDsaKey);
                    } else if (ssl->peerEccDsaKeyPresent) {
                        /* don't leak on reuse */
                        wc_ecc_free(ssl->peerEccDsaKey);
                        ssl->peerEccDsaKeyPresent = 0;
                        wc_ecc_init(ssl->peerEccDsaKey);
                    }
                    if (wc_ecc_import_x963(dCert->publicKey, dCert->pubKeySize,
                                        ssl->peerEccDsaKey) != 0) {
                        ret = PEER_KEY_ERROR;
                    }
                    else {
                        ssl->peerEccDsaKeyPresent = 1;
                        #ifdef HAVE_PK_CALLBACKS
                            #ifdef HAVE_ECC
                                ssl->buffers.peerEccDsaKey.buffer =
                                       (byte*)XMALLOC(dCert->pubKeySize,
                                               ssl->heap, DYNAMIC_TYPE_ECC);
                                if (ssl->buffers.peerEccDsaKey.buffer == NULL)
                                    ret = MEMORY_ERROR;
                                else {
                                    XMEMCPY(ssl->buffers.peerEccDsaKey.buffer,
                                           dCert->publicKey, dCert->pubKeySize);
                                    ssl->buffers.peerEccDsaKey.length =
                                            dCert->pubKeySize;
                                }
                            #endif /* HAVE_ECC */
                        #endif /*HAVE_PK_CALLBACKS */
                    }
                }
                break;
        #endif /* HAVE_ECC */
            default:
                break;
        }

        FreeDecodedCert(dCert);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(dCert, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    store = (WOLFSSL_X509_STORE_CTX*)XMALLOC(sizeof(WOLFSSL_X509_STORE_CTX),
                                                 NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (store == NULL) {
        XFREE(domain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    if (anyError != 0 && ret == 0)
        ret = anyError;

    if (ret != 0) {
        if (!ssl->options.verifyNone) {
            int why = bad_certificate;

            if (ret == ASN_AFTER_DATE_E || ret == ASN_BEFORE_DATE_E)
                why = certificate_expired;
            if (ssl->verifyCallback) {
                int ok;

                store->error = ret;
                store->error_depth = totalCerts;
                store->discardSessionCerts = 0;
                store->domain = domain;
                store->userCtx = ssl->verifyCbCtx;
#ifdef KEEP_PEER_CERT
                store->current_cert = &ssl->peerCert;
#else
                store->current_cert = NULL;
#endif
#ifdef FORTRESS
                store->ex_data = ssl;
#endif
                ok = ssl->verifyCallback(0, store);
                if (ok) {
                    WOLFSSL_MSG("Verify callback overriding error!");
                    ret = 0;
                }
                #ifdef SESSION_CERTS
                if (store->discardSessionCerts) {
                    WOLFSSL_MSG("Verify callback requested discard sess certs");
                    ssl->session.chain.count = 0;
                }
                #endif
            }
            if (ret != 0) {
                SendAlert(ssl, alert_fatal, why);   /* try to send */
                ssl->options.isClosed = 1;
            }
        }
        ssl->error = ret;
    }
#ifdef WOLFSSL_ALWAYS_VERIFY_CB
    else {
        if (ssl->verifyCallback) {
            int ok;

            store->error = ret;
            store->error_depth = totalCerts;
            store->discardSessionCerts = 0;
            store->domain = domain;
            store->userCtx = ssl->verifyCbCtx;
#ifdef KEEP_PEER_CERT
            store->current_cert = &ssl->peerCert;
#endif
            store->ex_data = ssl;

            ok = ssl->verifyCallback(1, store);
            if (!ok) {
                WOLFSSL_MSG("Verify callback overriding valid certificate!");
                ret = -1;
                SendAlert(ssl, alert_fatal, bad_certificate);
                ssl->options.isClosed = 1;
            }
            #ifdef SESSION_CERTS
            if (store->discardSessionCerts) {
                WOLFSSL_MSG("Verify callback requested discard sess certs");
                ssl->session.chain.count = 0;
            }
            #endif
        }
    }
#endif

    if (ssl->options.verifyNone &&
                              (ret == CRL_MISSING || ret == CRL_CERT_REVOKED)) {
        WOLFSSL_MSG("Ignoring CRL problem based on verify setting");
        ret = ssl->error = 0;
    }

    if (ret == 0 && ssl->options.side == WOLFSSL_CLIENT_END)
        ssl->options.serverState = SERVER_CERT_COMPLETE;

    if (ssl->keys.encryptionOn) {
        *inOutIdx += ssl->keys.padSz;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(store,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(domain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

