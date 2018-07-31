
#include "cmnSsl.h"

/* Initialze SSL context, return 0 on success */
int InitSSL_Ctx(WOLFSSL_CTX* ctx, WOLFSSL_METHOD* method)
{
	XMEMSET(ctx, 0, sizeof(WOLFSSL_CTX));

	ctx->method   = method;
	ctx->refCount = 1;          /* so either CTX_free or SSL_free can release */
	ctx->heap     = ctx;        /* defaults to self */
	ctx->timeout  = WOLFSSL_SESSION_TIMEOUT;
	ctx->minDowngrade = TLSv1_MINOR;     /* current default */

	if (InitMutex(&ctx->countMutex) < 0) {
		WOLFSSL_MSG("Mutex error on CTX init");
		return BAD_MUTEX_E;
	}

#ifndef NO_DH
	ctx->minDhKeySz = MIN_DHKEY_SZ;
#endif

#ifdef HAVE_ECC
	ctx->eccTempKeySz = ECDHE_SIZE;
#endif

#ifndef WOLFSSL_USER_IO
	ctx->CBIORecv = EmbedReceive;
	ctx->CBIOSend = EmbedSend;
#ifdef WOLFSSL_DTLS
	if (method->version.major == DTLS_MAJOR) {
		ctx->CBIORecv   = EmbedReceiveFrom;
		ctx->CBIOSend   = EmbedSendTo;
		ctx->CBIOCookie = EmbedGenerateCookie;
	}
#endif
#endif /* WOLFSSL_USER_IO */

#ifdef HAVE_NETX
	ctx->CBIORecv = NetX_Receive;
	ctx->CBIOSend = NetX_Send;
#endif

#ifdef HAVE_NTRU
	if (method->side == WOLFSSL_CLIENT_END)
		ctx->haveNTRU = 1;           /* always on cliet side */
	         /* server can turn on by loading key */
#endif
#ifdef HAVE_ECC
	if (method->side == WOLFSSL_CLIENT_END) {
		ctx->haveECDSAsig  = 1;        /* always on cliet side */
		ctx->haveStaticECC = 1;        /* server can turn on by loading key */
	}
#endif

#ifdef HAVE_CAVIUM
	ctx->devId = NO_CAVIUM_DEVICE;
#endif

#ifndef NO_CERTS
	ctx->cm = wolfSSL_CertManagerNew();
	if (ctx->cm == NULL) {
		WOLFSSL_MSG("Bad Cert Manager New");
		return BAD_CERT_MANAGER_ERROR;
	}
#endif

#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER)
	ctx->ticketHint = SESSION_TICKET_HINT_DEFAULT;
#endif

	return 0;
	}


/* In case contexts are held in array and don't want to free actual ctx */
void SSL_CtxResourceFree(WOLFSSL_CTX* ctx)
{
    XFREE(ctx->method, ctx->heap, DYNAMIC_TYPE_METHOD);
    if (ctx->suites)
        XFREE(ctx->suites, ctx->heap, DYNAMIC_TYPE_SUITES);

#ifndef NO_DH
    XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_DH);
    XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
#endif
#ifndef NO_CERTS
    XFREE(ctx->privateKey.buffer, ctx->heap, DYNAMIC_TYPE_KEY);
    XFREE(ctx->certificate.buffer, ctx->heap, DYNAMIC_TYPE_CERT);
    XFREE(ctx->certChain.buffer, ctx->heap, DYNAMIC_TYPE_CERT);
    wolfSSL_CertManagerFree(ctx->cm);
#endif
#ifdef HAVE_TLS_EXTENSIONS
    TLSX_FreeAll(ctx->extensions);
#endif
}


void FreeSSL_Ctx(WOLFSSL_CTX* ctx)
{
    int doFree = 0;

    if (LockMutex(&ctx->countMutex) != 0) {
        WOLFSSL_MSG("Couldn't lock count mutex");
        return;
    }
    ctx->refCount--;
    if (ctx->refCount == 0)
        doFree = 1;
    UnLockMutex(&ctx->countMutex);

    if (doFree) {
        WOLFSSL_MSG("CTX ref count down to 0, doing full free");
        SSL_CtxResourceFree(ctx);
        FreeMutex(&ctx->countMutex);
        XFREE(ctx, ctx->heap, DYNAMIC_TYPE_CTX);
    }
    else {
        (void)ctx;
        WOLFSSL_MSG("CTX ref count not 0 yet, no free");
    }
}


/* Set cipher pointers to null */
void InitCiphers(WOLFSSL* ssl)
{
#ifdef BUILD_ARC4
    ssl->encrypt.arc4 = NULL;
    ssl->decrypt.arc4 = NULL;
#endif
#ifdef BUILD_DES3
    ssl->encrypt.des3 = NULL;
    ssl->decrypt.des3 = NULL;
#endif
#ifdef BUILD_AES
    ssl->encrypt.aes = NULL;
    ssl->decrypt.aes = NULL;
#endif
#ifdef HAVE_CAMELLIA
    ssl->encrypt.cam = NULL;
    ssl->decrypt.cam = NULL;
#endif
#ifdef HAVE_HC128
    ssl->encrypt.hc128 = NULL;
    ssl->decrypt.hc128 = NULL;
#endif
#ifdef BUILD_RABBIT
    ssl->encrypt.rabbit = NULL;
    ssl->decrypt.rabbit = NULL;
#endif
#ifdef HAVE_CHACHA
    ssl->encrypt.chacha = NULL;
    ssl->decrypt.chacha = NULL;
#endif
#ifdef HAVE_POLY1305
/* lzj. when this is enabled, build failed. 2015.08.24 */
    ssl->auth.poly1305 = NULL;
#endif
    ssl->encrypt.setup = 0;
    ssl->decrypt.setup = 0;
#ifdef HAVE_ONE_TIME_AUTH
    ssl->auth.setup    = 0;
#endif
}


/* Free ciphers */
void FreeCiphers(WOLFSSL* ssl)
{
    (void)ssl;
#ifdef BUILD_ARC4
    #ifdef HAVE_CAVIUM
    if (ssl->devId != NO_CAVIUM_DEVICE) {
        wc_Arc4FreeCavium(ssl->encrypt.arc4);
        wc_Arc4FreeCavium(ssl->decrypt.arc4);
    }
    #endif
    XFREE(ssl->encrypt.arc4, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.arc4, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef BUILD_DES3
    #ifdef HAVE_CAVIUM
    if (ssl->devId != NO_CAVIUM_DEVICE) {
        wc_Des3_FreeCavium(ssl->encrypt.des3);
        wc_Des3_FreeCavium(ssl->decrypt.des3);
    }
    #endif
    XFREE(ssl->encrypt.des3, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.des3, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef BUILD_AES
    #ifdef HAVE_CAVIUM
    if (ssl->devId != NO_CAVIUM_DEVICE) {
        wc_AesFreeCavium(ssl->encrypt.aes);
        wc_AesFreeCavium(ssl->decrypt.aes);
    }
    #endif
    XFREE(ssl->encrypt.aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_CAMELLIA
    XFREE(ssl->encrypt.cam, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.cam, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_HC128
    XFREE(ssl->encrypt.hc128, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.hc128, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef BUILD_RABBIT
    XFREE(ssl->encrypt.rabbit, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.rabbit, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_CHACHA
    XFREE(ssl->encrypt.chacha, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.chacha, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_POLY1305
    XFREE(ssl->auth.poly1305, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
}


void InitCipherSpecs(CipherSpecs* cs)
{
    cs->bulk_cipher_algorithm = INVALID_BYTE;
    cs->cipher_type           = INVALID_BYTE;
    cs->mac_algorithm         = INVALID_BYTE;
    cs->kea                   = INVALID_BYTE;
    cs->sig_algo              = INVALID_BYTE;

    cs->hash_size   = 0;
    cs->static_ecdh = 0;
    cs->key_size    = 0;
    cs->iv_size     = 0;
    cs->block_size  = 0;
}


#ifndef NO_CERTS
void InitX509Name(WOLFSSL_X509_NAME* name, int dynamicFlag)
{
	(void)dynamicFlag;

	if (name != NULL) {
		name->name        = name->staticName;
		name->dynamicName = 0;
#ifdef OPENSSL_EXTRA
		XMEMSET(&name->fullName, 0, sizeof(DecodedName));
#endif /* OPENSSL_EXTRA */
	}
}


void FreeX509Name(WOLFSSL_X509_NAME* name)
{
    if (name != NULL) {
        if (name->dynamicName)
            XFREE(name->name, NULL, DYNAMIC_TYPE_SUBJECT_CN);
#ifdef OPENSSL_EXTRA
        if (name->fullName.fullName != NULL)
            XFREE(name->fullName.fullName, NULL, DYNAMIC_TYPE_X509);
#endif /* OPENSSL_EXTRA */
    }
}


/* Initialize wolfSSL X509 type */
void InitX509(WOLFSSL_X509* x509, int dynamicFlag)
{
    InitX509Name(&x509->issuer, 0);
    InitX509Name(&x509->subject, 0);
    x509->version        = 0;
    x509->pubKey.buffer  = NULL;
    x509->sig.buffer     = NULL;
    x509->derCert.buffer = NULL;
    x509->altNames       = NULL;
    x509->altNamesNext   = NULL;
    x509->dynamicMemory  = (byte)dynamicFlag;
    x509->isCa           = 0;
#ifdef HAVE_ECC
    x509->pkCurveOID = 0;
#endif /* HAVE_ECC */
#ifdef OPENSSL_EXTRA
    x509->pathLength     = 0;
    x509->basicConstSet  = 0;
    x509->basicConstCrit = 0;
    x509->basicConstPlSet = 0;
    x509->subjAltNameSet = 0;
    x509->subjAltNameCrit = 0;
    x509->authKeyIdSet   = 0;
    x509->authKeyIdCrit  = 0;
    x509->authKeyId      = NULL;
    x509->authKeyIdSz    = 0;
    x509->subjKeyIdSet   = 0;
    x509->subjKeyIdCrit  = 0;
    x509->subjKeyId      = NULL;
    x509->subjKeyIdSz    = 0;
    x509->keyUsageSet    = 0;
    x509->keyUsageCrit   = 0;
    x509->keyUsage       = 0;
    #ifdef WOLFSSL_SEP
        x509->certPolicySet  = 0;
        x509->certPolicyCrit = 0;
    #endif /* WOLFSSL_SEP */
#endif /* OPENSSL_EXTRA */
}


/* Free wolfSSL X509 type */
void FreeX509(WOLFSSL_X509* x509)
{
    if (x509 == NULL)
        return;

    FreeX509Name(&x509->issuer);
    FreeX509Name(&x509->subject);
    if (x509->pubKey.buffer)
        XFREE(x509->pubKey.buffer, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(x509->derCert.buffer, NULL, DYNAMIC_TYPE_SUBJECT_CN);
    XFREE(x509->sig.buffer, NULL, DYNAMIC_TYPE_SIGNATURE);
    #ifdef OPENSSL_EXTRA
        XFREE(x509->authKeyId, NULL, 0);
        XFREE(x509->subjKeyId, NULL, 0);
    #endif /* OPENSSL_EXTRA */
    if (x509->altNames)
        FreeAltNames(x509->altNames, NULL);
    if (x509->dynamicMemory)
        XFREE(x509, NULL, DYNAMIC_TYPE_X509);
}

#endif /* NO_CERTS */


/* init everything to 0, NULL, default values before calling anything that may
   fail so that desctructor has a "good" state to cleanup */
int InitSSL(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    int  ret;
    byte haveRSA = 0;
    byte havePSK = 0;
    byte haveAnon = 0;

    (void) haveAnon;

    XMEMSET(ssl, 0, sizeof(WOLFSSL));

    ssl->ctx     = ctx; /* only for passing to calls, options could change */
    ssl->version = ctx->method->version;

#ifndef NO_RSA
    haveRSA = 1;
#endif

    ssl->buffers.inputBuffer.buffer = ssl->buffers.inputBuffer.staticBuffer;
    ssl->buffers.inputBuffer.bufferSize  = STATIC_BUFFER_LEN;

    ssl->buffers.outputBuffer.buffer = ssl->buffers.outputBuffer.staticBuffer;
    ssl->buffers.outputBuffer.bufferSize  = STATIC_BUFFER_LEN;

#ifdef KEEP_PEER_CERT
    InitX509(&ssl->peerCert, 0);
#endif

#ifdef HAVE_ECC
    ssl->eccTempKeySz = ctx->eccTempKeySz;
    ssl->pkCurveOID = ctx->pkCurveOID;
#endif

    ssl->timeout = ctx->timeout;
    ssl->rfd = -1;   /* set to invalid descriptor */
    ssl->wfd = -1;

    ssl->IOCB_ReadCtx  = &ssl->rfd;  /* prevent invalid pointer access if not */
    ssl->IOCB_WriteCtx = &ssl->wfd;  /* correctly set */

#ifdef HAVE_NETX
    ssl->IOCB_ReadCtx  = &ssl->nxCtx;  /* default NetX IO ctx, same for read */
    ssl->IOCB_WriteCtx = &ssl->nxCtx;  /* and write */
#endif
#ifdef WOLFSSL_DTLS
    ssl->dtls_expected_rx = MAX_MTU;
#endif

    ssl->verifyCallback    = ctx->verifyCallback;

    ssl->options.side      = ctx->method->side;
    ssl->options.downgrade    = ctx->method->downgrade;
    ssl->options.minDowngrade = ctx->minDowngrade;

    if (ssl->options.side == WOLFSSL_SERVER_END)
        ssl->options.haveDH = ctx->haveDH;

    ssl->options.haveNTRU      = ctx->haveNTRU;
    ssl->options.haveECDSAsig  = ctx->haveECDSAsig;
    ssl->options.haveStaticECC = ctx->haveStaticECC;

#ifndef NO_PSK
    havePSK = ctx->havePSK;
    ssl->options.havePSK   = ctx->havePSK;
    ssl->options.client_psk_cb = ctx->client_psk_cb;
    ssl->options.server_psk_cb = ctx->server_psk_cb;
#endif /* NO_PSK */

#ifdef HAVE_ANON
    haveAnon = ctx->haveAnon;
    ssl->options.haveAnon = ctx->haveAnon;
#endif

    ssl->options.serverState = NULL_STATE;
    ssl->options.clientState = NULL_STATE;
    ssl->options.connectState = CONNECT_BEGIN;
    ssl->options.acceptState  = ACCEPT_BEGIN;
    ssl->options.handShakeState  = NULL_STATE;
    ssl->options.processReply = doProcessInit;

#ifndef NO_DH
    ssl->options.minDhKeySz = ctx->minDhKeySz;
#endif

#ifdef WOLFSSL_DTLS
    ssl->dtls_timeout_init              = DTLS_TIMEOUT_INIT;
    ssl->dtls_timeout_max               = DTLS_TIMEOUT_MAX;
    ssl->dtls_timeout                   = ssl->dtls_timeout_init;
#endif

    ssl->options.sessionCacheOff      = ctx->sessionCacheOff;
    ssl->options.sessionCacheFlushOff = ctx->sessionCacheFlushOff;

    ssl->options.verifyPeer = ctx->verifyPeer;
    ssl->options.verifyNone = ctx->verifyNone;
    ssl->options.failNoCert = ctx->failNoCert;
    ssl->options.sendVerify = ctx->sendVerify;

    #ifndef NO_OLD_TLS
        ssl->hmac = SSL_hmac; /* default to SSLv3 */
    #else
        ssl->hmac = TLS_hmac;
    #endif

    ssl->heap = ctx->heap;    /* defaults to self */

    ssl->options.dtls = ssl->version.major == DTLS_MAJOR;
    ssl->options.partialWrite  = ctx->partialWrite;
    ssl->options.quietShutdown = ctx->quietShutdown;
    ssl->options.groupMessages = ctx->groupMessages;

#ifndef NO_DH
    if (ssl->options.side == WOLFSSL_SERVER_END) {
        ssl->buffers.serverDH_P = ctx->serverDH_P;
        ssl->buffers.serverDH_G = ctx->serverDH_G;
    }
#endif
#ifndef NO_CERTS
    /* ctx still owns certificate, certChain, key, dh, and cm */
    ssl->buffers.certificate = ctx->certificate;
    ssl->buffers.certChain = ctx->certChain;
    ssl->buffers.key = ctx->privateKey;
#endif

#ifdef WOLFSSL_DTLS
    ssl->buffers.dtlsCtx.fd = -1;
#endif

    ssl->cipher.ssl = ssl;

#ifdef HAVE_CAVIUM
    ssl->devId = ctx->devId;
#endif

#ifdef HAVE_TLS_EXTENSIONS
#ifdef HAVE_MAX_FRAGMENT
    ssl->max_fragment = MAX_RECORD_SIZE;
#endif
#endif

    /* default alert state (none) */
    ssl->alert_history.last_rx.code  = -1;
    ssl->alert_history.last_rx.level = -1;
    ssl->alert_history.last_tx.code  = -1;
    ssl->alert_history.last_tx.level = -1;

    InitCiphers(ssl);
    InitCipherSpecs(&ssl->specs);

    /* all done with init, now can return errors, call other stuff */

    /* hsHashes */
    ssl->hsHashes = (HS_Hashes*)XMALLOC(sizeof(HS_Hashes), ssl->heap, DYNAMIC_TYPE_HASHES);
    if (ssl->hsHashes == NULL) {
        WOLFSSL_MSG("HS_Hashes Memory error");
        return MEMORY_E;
    }

#ifndef NO_OLD_TLS
#ifndef NO_MD5
    wc_InitMd5(&ssl->hsHashes->hashMd5);
#endif
#ifndef NO_SHA
    ret = wc_InitSha(&ssl->hsHashes->hashSha);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
#ifndef NO_SHA256
    ret = wc_InitSha256(&ssl->hsHashes->hashSha256);
    if (ret != 0) {
        return ret;
    }
#endif
#ifdef WOLFSSL_SHA384
    ret = wc_InitSha384(&ssl->hsHashes->hashSha384);
    if (ret != 0) {
        return ret;
    }
#endif
#ifdef WOLFSSL_SHA512
    ret = wc_InitSha512(&ssl->hsHashes->hashSha512);
    if (ret != 0) {
        return ret;
    }
#endif

    /* increment CTX reference count */
    if (LockMutex(&ctx->countMutex) != 0) {
        WOLFSSL_MSG("Couldn't lock CTX count mutex");
        return BAD_MUTEX_E;
    }
    ctx->refCount++;
    UnLockMutex(&ctx->countMutex);

    /* arrays */
    ssl->arrays = (Arrays*)XMALLOC(sizeof(Arrays), ssl->heap,
                                                           DYNAMIC_TYPE_ARRAYS);
    if (ssl->arrays == NULL) {
        WOLFSSL_MSG("Arrays Memory error");
        return MEMORY_E;
    }
    XMEMSET(ssl->arrays, 0, sizeof(Arrays));

#ifndef NO_PSK
    if (ctx->server_hint[0]) {   /* set in CTX */
        XSTRNCPY(ssl->arrays->server_hint, ctx->server_hint, MAX_PSK_ID_LEN);
        ssl->arrays->server_hint[MAX_PSK_ID_LEN - 1] = '\0';
    }
#endif /* NO_PSK */

    /* RNG */
    ssl->rng = (RNG*)XMALLOC(sizeof(RNG), ssl->heap, DYNAMIC_TYPE_RNG);
    if (ssl->rng == NULL) {
        WOLFSSL_MSG("RNG Memory error");
        return MEMORY_E;
    }

    if ( (ret = wc_InitRng(ssl->rng)) != 0) {
        WOLFSSL_MSG("RNG Init error");
        return ret;
    }

    /* suites */
    ssl->suites = (Suites*)XMALLOC(sizeof(Suites), ssl->heap,
                                   DYNAMIC_TYPE_SUITES);
    if (ssl->suites == NULL) {
        WOLFSSL_MSG("Suites Memory error");
        return MEMORY_E;
    }
    if (ctx->suites)
        *ssl->suites = *ctx->suites;
    else
        XMEMSET(ssl->suites, 0, sizeof(Suites));


#ifndef NO_CERTS
    /* make sure server has cert and key unless using PSK or Anon */
    if (ssl->options.side == WOLFSSL_SERVER_END && !havePSK && !haveAnon)
        if (!ssl->buffers.certificate.buffer || !ssl->buffers.key.buffer) {
            WOLFSSL_MSG("Server missing certificate and/or private key");
            return NO_PRIVATE_KEY;
        }
#endif
#ifdef HAVE_SECRET_CALLBACK
    ssl->sessionSecretCb  = NULL;
    ssl->sessionSecretCtx = NULL;
#endif

    /* make sure server has DH parms, and add PSK if there, add NTRU too */
    if (ssl->options.side == WOLFSSL_SERVER_END)
        InitSuites(ssl->suites, ssl->version, haveRSA, havePSK,
                   ssl->options.haveDH, ssl->options.haveNTRU,
                   ssl->options.haveECDSAsig, ssl->options.haveStaticECC,
                   ssl->options.side);
    else
        InitSuites(ssl->suites, ssl->version, haveRSA, havePSK, TRUE,
                   ssl->options.haveNTRU, ssl->options.haveECDSAsig,
                   ssl->options.haveStaticECC, ssl->options.side);

    return 0;
}


/* free use of temporary arrays */
void FreeArrays(WOLFSSL* ssl, int keep)
{
    if (ssl->arrays && keep) {
        /* keeps session id for user retrieval */
        XMEMCPY(ssl->session.sessionID, ssl->arrays->sessionID, ID_LEN);
        ssl->session.sessionIDSz = ssl->arrays->sessionIDSz;
    }
    XFREE(ssl->arrays, ssl->heap, DYNAMIC_TYPE_ARRAYS);
    ssl->arrays = NULL;
}


/* In case holding SSL object in array and don't want to free actual ssl */
void SSL_ResourceFree(WOLFSSL* ssl)
{
    /* Note: any resources used during the handshake should be released in the
     * function FreeHandshakeResources(). Be careful with the special cases
     * like the RNG which may optionally be kept for the whole session. (For
     * example with the RNG, it isn't used beyond the handshake except when
     * using stream ciphers where it is retained. */

    FreeCiphers(ssl);
    FreeArrays(ssl, 0);
    wc_FreeRng(ssl->rng);
    XFREE(ssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
    XFREE(ssl->suites, ssl->heap, DYNAMIC_TYPE_SUITES);
    XFREE(ssl->hsHashes, ssl->heap, DYNAMIC_TYPE_HASHES);
    XFREE(ssl->buffers.domainName.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);

#ifndef NO_DH
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    /* parameters (p,g) may be owned by ctx */
    if (ssl->buffers.weOwnDH || ssl->options.side == WOLFSSL_CLIENT_END) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap, DYNAMIC_TYPE_DH);
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    }
#endif
#ifndef NO_CERTS
    if (ssl->buffers.weOwnCert)
        XFREE(ssl->buffers.certificate.buffer, ssl->heap, DYNAMIC_TYPE_CERT);
    if (ssl->buffers.weOwnCertChain)
        XFREE(ssl->buffers.certChain.buffer, ssl->heap, DYNAMIC_TYPE_CERT);
    if (ssl->buffers.weOwnKey)
        XFREE(ssl->buffers.key.buffer, ssl->heap, DYNAMIC_TYPE_KEY);
#endif
#ifndef NO_RSA
    if (ssl->peerRsaKey) {
        wc_FreeRsaKey(ssl->peerRsaKey);
        XFREE(ssl->peerRsaKey, ssl->heap, DYNAMIC_TYPE_RSA);
    }
#endif
    if (ssl->buffers.inputBuffer.dynamicFlag)
        ShrinkInputBuffer(ssl, FORCED_FREE);
    if (ssl->buffers.outputBuffer.dynamicFlag)
        ShrinkOutputBuffer(ssl);
#ifdef WOLFSSL_DTLS
    if (ssl->dtls_pool != NULL) {
        DtlsPoolReset(ssl);
        XFREE(ssl->dtls_pool, ssl->heap, DYNAMIC_TYPE_NONE);
    }
    if (ssl->dtls_msg_list != NULL) {
        DtlsMsgListDelete(ssl->dtls_msg_list, ssl->heap);
        ssl->dtls_msg_list = NULL;
    }
    XFREE(ssl->buffers.dtlsCtx.peer.sa, ssl->heap, DYNAMIC_TYPE_SOCKADDR);
    ssl->buffers.dtlsCtx.peer.sa = NULL;
#endif
#if defined(KEEP_PEER_CERT) || defined(GOAHEAD_WS)
    FreeX509(&ssl->peerCert);
#endif
#if defined(OPENSSL_EXTRA) || defined(GOAHEAD_WS)
    wolfSSL_BIO_free(ssl->biord);
    if (ssl->biord != ssl->biowr)        /* in case same as write */
        wolfSSL_BIO_free(ssl->biowr);
#endif
#ifdef HAVE_LIBZ
    FreeStreams(ssl);
#endif
#ifdef HAVE_ECC
    if (ssl->peerEccKey) {
        if (ssl->peerEccKeyPresent)
            wc_ecc_free(ssl->peerEccKey);
        XFREE(ssl->peerEccKey, ssl->heap, DYNAMIC_TYPE_ECC);
    }
    if (ssl->peerEccDsaKey) {
        if (ssl->peerEccDsaKeyPresent)
            wc_ecc_free(ssl->peerEccDsaKey);
        XFREE(ssl->peerEccDsaKey, ssl->heap, DYNAMIC_TYPE_ECC);
    }
    if (ssl->eccTempKey) {
        if (ssl->eccTempKeyPresent)
            wc_ecc_free(ssl->eccTempKey);
        XFREE(ssl->eccTempKey, ssl->heap, DYNAMIC_TYPE_ECC);
    }
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        XFREE(ssl->buffers.peerEccDsaKey.buffer, ssl->heap, DYNAMIC_TYPE_ECC);
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        XFREE(ssl->buffers.peerRsaKey.buffer, ssl->heap, DYNAMIC_TYPE_RSA);
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */
#ifdef HAVE_TLS_EXTENSIONS
    TLSX_FreeAll(ssl->extensions);
#endif
#ifdef HAVE_NETX
    if (ssl->nxCtx.nxPacket)
        nx_packet_release(ssl->nxCtx.nxPacket);
#endif
}

#ifdef WOLFSSL_TI_HASH
static void HashFinal(WOLFSSL * ssl) {
    byte dummyHash[32] ;
#ifndef NO_MD5
    wc_Md5Final(&(ssl->hsHashes->hashMd5), dummyHash) ;
#endif
#ifndef NO_SHA
    wc_ShaFinal(&(ssl->hsHashes->hashSha), dummyHash) ;
#endif
#ifndef NO_SHA256
    wc_Sha256Final(&(ssl->hsHashes->hashSha256), dummyHash) ;
#endif
}
#else

    #define HashFinal(ssl)

#endif

/* Free any handshake resources no longer needed */
void FreeHandshakeResources(WOLFSSL* ssl)
{

    HashFinal(ssl) ;
#ifdef HAVE_SECURE_RENEGOTIATION
    if (ssl->secure_renegotiation && ssl->secure_renegotiation->enabled) {
        WOLFSSL_MSG("Secure Renegotiation needs to retain handshake resources");
        return;
    }
#endif

    /* input buffer */
    if (ssl->buffers.inputBuffer.dynamicFlag)
        ShrinkInputBuffer(ssl, NO_FORCED_FREE);

    /* suites */
    XFREE(ssl->suites, ssl->heap, DYNAMIC_TYPE_SUITES);
    ssl->suites = NULL;

    /* hsHashes */
    XFREE(ssl->hsHashes, ssl->heap, DYNAMIC_TYPE_HASHES);
    ssl->hsHashes = NULL;

    /* RNG */
    if (ssl->specs.cipher_type == stream || ssl->options.tls1_1 == 0) {
        wc_FreeRng(ssl->rng);
        XFREE(ssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
        ssl->rng = NULL;
    }

#ifdef WOLFSSL_DTLS
    /* DTLS_POOL */
    if (ssl->options.dtls && ssl->dtls_pool != NULL) {
        DtlsPoolReset(ssl);
        XFREE(ssl->dtls_pool, ssl->heap, DYNAMIC_TYPE_DTLS_POOL);
        ssl->dtls_pool = NULL;
    }
#endif

    /* arrays */
    if (ssl->options.saveArrays == 0)
        FreeArrays(ssl, 1);

#ifndef NO_RSA
    /* peerRsaKey */
    if (ssl->peerRsaKey) {
        wc_FreeRsaKey(ssl->peerRsaKey);
        XFREE(ssl->peerRsaKey, ssl->heap, DYNAMIC_TYPE_RSA);
        ssl->peerRsaKey = NULL;
    }
#endif

#ifdef HAVE_ECC
    if (ssl->peerEccKey)
    {
        if (ssl->peerEccKeyPresent) {
            wc_ecc_free(ssl->peerEccKey);
            ssl->peerEccKeyPresent = 0;
        }
        XFREE(ssl->peerEccKey, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->peerEccKey = NULL;
    }
    if (ssl->peerEccDsaKey)
    {
        if (ssl->peerEccDsaKeyPresent) {
            wc_ecc_free(ssl->peerEccDsaKey);
            ssl->peerEccDsaKeyPresent = 0;
        }
        XFREE(ssl->peerEccDsaKey, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->peerEccDsaKey = NULL;
    }
    if (ssl->eccTempKey)
    {
        if (ssl->eccTempKeyPresent) {
            wc_ecc_free(ssl->eccTempKey);
            ssl->eccTempKeyPresent = 0;
        }
        XFREE(ssl->eccTempKey, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->eccTempKey = NULL;
    }
#endif
#ifndef NO_DH
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    ssl->buffers.serverDH_Priv.buffer = NULL;
    XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    ssl->buffers.serverDH_Pub.buffer = NULL;
    /* parameters (p,g) may be owned by ctx */
    if (ssl->buffers.weOwnDH || ssl->options.side == WOLFSSL_CLIENT_END) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap, DYNAMIC_TYPE_DH);
        ssl->buffers.serverDH_G.buffer = NULL;
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap, DYNAMIC_TYPE_DH);
        ssl->buffers.serverDH_P.buffer = NULL;
    }
#endif
#ifndef NO_CERTS
    if (ssl->buffers.weOwnCert) {
        XFREE(ssl->buffers.certificate.buffer, ssl->heap, DYNAMIC_TYPE_CERT);
        ssl->buffers.certificate.buffer = NULL;
    }
    if (ssl->buffers.weOwnCertChain) {
        XFREE(ssl->buffers.certChain.buffer, ssl->heap, DYNAMIC_TYPE_CERT);
        ssl->buffers.certChain.buffer = NULL;
    }
    if (ssl->buffers.weOwnKey) {
        XFREE(ssl->buffers.key.buffer, ssl->heap, DYNAMIC_TYPE_KEY);
        ssl->buffers.key.buffer = NULL;
    }
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        XFREE(ssl->buffers.peerEccDsaKey.buffer, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->buffers.peerEccDsaKey.buffer = NULL;
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        XFREE(ssl->buffers.peerRsaKey.buffer, ssl->heap, DYNAMIC_TYPE_RSA);
        ssl->buffers.peerRsaKey.buffer = NULL;
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */
}


void FreeSSL(WOLFSSL* ssl)
{
    FreeSSL_Ctx(ssl->ctx);  /* will decrement and free underyling CTX if 0 */
    SSL_ResourceFree(ssl);
    XFREE(ssl, ssl->heap, DYNAMIC_TYPE_SSL);
}


