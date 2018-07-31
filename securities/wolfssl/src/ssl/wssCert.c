
#include "cmnSsl.h"


#ifndef NO_CERTS


/* Verify the ceritficate, SSL_SUCCESS for ok, < 0 for error */
int wolfSSL_CertManagerVerifyBuffer(WOLFSSL_CERT_MANAGER* cm, const byte* buff,
                                   long sz, int format)
{
    int ret = 0;
    buffer der;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endif

    WOLFSSL_ENTER();

#ifdef WOLFSSL_SMALL_STACK
    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL)
        return MEMORY_E;
#endif

    der.buffer = NULL;
    der.length = 0;

    if (format == SSL_FILETYPE_PEM) {
        int eccKey = 0; /* not used */
    #ifdef WOLFSSL_SMALL_STACK
        EncryptedInfo* info = NULL;
    #else
        EncryptedInfo  info[1];
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (info == NULL) {
            XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
    #endif

        info->set      = 0;
        info->ctx      = NULL;
        info->consumed = 0;

        ret = PemToDer(buff, sz, CERT_TYPE, &der, cm->heap, info, &eccKey);

        if (ret == 0)
            InitDecodedCert(cert, der.buffer, der.length, cm->heap);

    #ifdef WOLFSSL_SMALL_STACK
        XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }
    else
        InitDecodedCert(cert, (byte*)buff, (word32)sz, cm->heap);

    if (ret == 0)
        ret = ParseCertRelative(cert, CERT_TYPE, 1, cm);

#ifdef HAVE_CRL
    if (ret == 0 && cm->crlEnabled)
        ret = CheckCertCRL(cm->crl, cert);
#endif

    FreeDecodedCert(cert);

    XFREE(der.buffer, cm->heap, DYNAMIC_TYPE_CERT);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret == 0 ? SSL_SUCCESS : ret;
}

/* turn on OCSP if off and compiled in, set options */
int wolfSSL_CertManagerEnableOCSP(WOLFSSL_CERT_MANAGER* cm, int options)
{
    int ret = SSL_SUCCESS;

    (void)options;

    WOLFSSL_ENTER();
    if (cm == NULL)
        return BAD_FUNC_ARG;

    #ifdef HAVE_OCSP
        if (cm->ocsp == NULL) {
            cm->ocsp = (WOLFSSL_OCSP*)XMALLOC(sizeof(WOLFSSL_OCSP), cm->heap,
                                                             DYNAMIC_TYPE_OCSP);
            if (cm->ocsp == NULL)
                return MEMORY_E;

            if (InitOCSP(cm->ocsp, cm) != 0) {
                WOLFSSL_MSG("Init OCSP failed");
                FreeOCSP(cm->ocsp, 1);
                cm->ocsp = NULL;
                return SSL_FAILURE;
            }
        }
        cm->ocspEnabled = 1;
        if (options & WOLFSSL_OCSP_URL_OVERRIDE)
            cm->ocspUseOverrideURL = 1;
        if (options & WOLFSSL_OCSP_NO_NONCE)
            cm->ocspSendNonce = 0;
        else
            cm->ocspSendNonce = 1;
        if (options & WOLFSSL_OCSP_CHECKALL)
            cm->ocspCheckAll = 1;
        #ifndef WOLFSSL_USER_IO
            cm->ocspIOCb = EmbedOcspLookup;
            cm->ocspRespFreeCb = EmbedOcspRespFree;
        #endif /* WOLFSSL_USER_IO */
    #else
        ret = NOT_COMPILED_IN;
    #endif

    return ret;
}


int wolfSSL_CertManagerDisableOCSP(WOLFSSL_CERT_MANAGER* cm)
{
    if (cm == NULL)
        return BAD_FUNC_ARG;

    cm->ocspEnabled = 0;

    return SSL_SUCCESS;
}


#ifdef HAVE_OCSP


/* check CRL if enabled, SSL_SUCCESS  */
int wolfSSL_CertManagerCheckOCSP(WOLFSSL_CERT_MANAGER* cm, byte* der, int sz)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endif

    WOLFSSL_ENTER();

    if (cm == NULL)
        return BAD_FUNC_ARG;

    if (cm->ocspEnabled == 0)
        return SSL_SUCCESS;

#ifdef WOLFSSL_SMALL_STACK
    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL)
        return MEMORY_E;
#endif

    InitDecodedCert(cert, der, sz, NULL);

    if ((ret = ParseCertRelative(cert, CERT_TYPE, NO_VERIFY, cm)) != 0) {
        WOLFSSL_MSG("ParseCert failed");
    }
    else if ((ret = CheckCertOCSP(cm->ocsp, cert)) != 0) {
        WOLFSSL_MSG("CheckCertOCSP failed");
    }

    FreeDecodedCert(cert);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret == 0 ? SSL_SUCCESS : ret;
}


int wolfSSL_CertManagerSetOCSPOverrideURL(WOLFSSL_CERT_MANAGER* cm, const char* url)
{
    WOLFSSL_ENTER();
    if (cm == NULL)
        return BAD_FUNC_ARG;

    XFREE(cm->ocspOverrideURL, cm->heap, 0);
    if (url != NULL) {
        int urlSz = (int)XSTRLEN(url) + 1;
        cm->ocspOverrideURL = (char*)XMALLOC(urlSz, cm->heap, 0);
        if (cm->ocspOverrideURL != NULL) {
            XMEMCPY(cm->ocspOverrideURL, url, urlSz);
        }
        else
            return MEMORY_E;
    }
    else
        cm->ocspOverrideURL = NULL;

    return SSL_SUCCESS;
}


int wolfSSL_CertManagerSetOCSP_Cb(WOLFSSL_CERT_MANAGER* cm,
                        CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    WOLFSSL_ENTER();
    if (cm == NULL)
        return BAD_FUNC_ARG;

    cm->ocspIOCb = ioCb;
    cm->ocspRespFreeCb = respFreeCb;
    cm->ocspIOCtx = ioCbCtx;

    return SSL_SUCCESS;
}


int wolfSSL_EnableOCSP(WOLFSSL* ssl, int options)
{
    WOLFSSL_ENTER();
    if (ssl)
        return wolfSSL_CertManagerEnableOCSP(ssl->ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_DisableOCSP(WOLFSSL* ssl)
{
    WOLFSSL_ENTER();
    if (ssl)
        return wolfSSL_CertManagerDisableOCSP(ssl->ctx->cm);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url)
{
    WOLFSSL_ENTER();
    if (ssl)
        return wolfSSL_CertManagerSetOCSPOverrideURL(ssl->ctx->cm, url);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_SetOCSP_Cb(WOLFSSL* ssl,
                        CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    WOLFSSL_ENTER();
    if (ssl)
        return wolfSSL_CertManagerSetOCSP_Cb(ssl->ctx->cm,
                                                     ioCb, respFreeCb, ioCbCtx);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX* ctx, int options)
{
    WOLFSSL_ENTER();
    if (ctx)
        return wolfSSL_CertManagerEnableOCSP(ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER();
    if (ctx)
        return wolfSSL_CertManagerDisableOCSP(ctx->cm);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX* ctx, const char* url)
{
    WOLFSSL_ENTER();
    if (ctx)
        return wolfSSL_CertManagerSetOCSPOverrideURL(ctx->cm, url);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX* ctx,
                        CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    WOLFSSL_ENTER();
    if (ctx)
        return wolfSSL_CertManagerSetOCSP_Cb(ctx->cm, ioCb, respFreeCb, ioCbCtx);
    else
        return BAD_FUNC_ARG;
}


#endif /* HAVE_OCSP */


#ifndef NO_FILESYSTEM

/* Verify the ceritficate, SSL_SUCCESS for ok, < 0 for error */
int wolfSSL_CertManagerVerify(WOLFSSL_CERT_MANAGER* cm, const char* fname,
                             int format)
{
    int    ret = SSL_FATAL_ERROR;
#ifdef WOLFSSL_SMALL_STACK
    byte   staticBuffer[1]; /* force heap usage */
#else
    byte   staticBuffer[FILE_BUFFER_SIZE];
#endif
    byte*  myBuffer = staticBuffer;
    int    dynamic = 0;
    long   sz = 0;
    XFILE  file = XFOPEN(fname, "rb");

    WOLFSSL_ENTER();

    if (file == XBADFILE) return SSL_BAD_FILE;
    XFSEEK(file, 0, XSEEK_END);
    sz = XFTELL(file);
    XREWIND(file);

    if (sz > MAX_WOLFSSL_FILE_SIZE || sz < 0) {
        WOLFSSL_MSG("CertManagerVerify file bad size");
        XFCLOSE(file);
        return SSL_BAD_FILE;
    }

    if (sz > (long)sizeof(staticBuffer)) {
        WOLFSSL_MSG("Getting dynamic buffer");
        myBuffer = (byte*) XMALLOC(sz, cm->heap, DYNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
            XFCLOSE(file);
            return SSL_BAD_FILE;
        }
        dynamic = 1;
    }

    if ( (ret = (int)XFREAD(myBuffer, sz, 1, file)) < 0)
        ret = SSL_BAD_FILE;
    else
        ret = wolfSSL_CertManagerVerifyBuffer(cm, myBuffer, sz, format);

    XFCLOSE(file);
    if (dynamic)
        XFREE(myBuffer, cm->heap, DYNAMIC_TYPE_FILE);

    return ret;
}


static INLINE WOLFSSL_METHOD* cm_pick_method(void)
{
    #ifndef NO_WOLFSSL_CLIENT
        #ifdef NO_OLD_TLS
            return wolfTLSv1_2_client_method();
        #else
            return wolfSSLv3_client_method();
        #endif      
    #elif !defined(NO_WOLFSSL_SERVER)
        #ifdef NO_OLD_TLS
            return wolfTLSv1_2_server_method();
        #else
            return wolfSSLv3_server_method();
        #endif
    #else
        return NULL;
    #endif
}


/* like load verify locations, 1 for success, < 0 for error */
int wolfSSL_CertManagerLoadCA(WOLFSSL_CERT_MANAGER* cm, const char* file, const char* path)
{
    int ret = SSL_FATAL_ERROR;
    WOLFSSL_CTX* tmp;

    WOLFSSL_ENTER();

    if (cm == NULL) {
        WOLFSSL_MSG("No CertManager error");
        return ret;
    }
    tmp = wolfSSL_CTX_new(cm_pick_method());

    if (tmp == NULL) {
        WOLFSSL_MSG("CTX new failed");
        return ret;
    }

    /* for tmp use */
    wolfSSL_CertManagerFree(tmp->cm);
    tmp->cm = cm;

    ret = wolfSSL_CTX_load_verify_locations(tmp, file, path);

    /* don't loose our good one */
    tmp->cm = NULL;
    wolfSSL_CTX_free(tmp);

    return ret;
}



/* turn on CRL if off and compiled in, set options */
int wolfSSL_CertManagerEnableCRL(WOLFSSL_CERT_MANAGER* cm, int options)
{
    int ret = SSL_SUCCESS;

    (void)options;

    WOLFSSL_ENTER();
    if (cm == NULL)
        return BAD_FUNC_ARG;

    #ifdef HAVE_CRL
        if (cm->crl == NULL) {
            cm->crl = (WOLFSSL_CRL*)XMALLOC(sizeof(WOLFSSL_CRL), cm->heap,
                                           DYNAMIC_TYPE_CRL);
            if (cm->crl == NULL)
                return MEMORY_E;

            if (InitCRL(cm->crl, cm) != 0) {
                WOLFSSL_MSG("Init CRL failed");
                FreeCRL(cm->crl, 1);
                cm->crl = NULL;
                return SSL_FAILURE;
            }
        }
        cm->crlEnabled = 1;
        if (options & WOLFSSL_CRL_CHECKALL)
            cm->crlCheckAll = 1;
    #else
        ret = NOT_COMPILED_IN;
    #endif

    return ret;
}


int wolfSSL_CertManagerDisableCRL(WOLFSSL_CERT_MANAGER* cm)
{
    WOLFSSL_ENTER();
    if (cm == NULL)
        return BAD_FUNC_ARG;

    cm->crlEnabled = 0;

    return SSL_SUCCESS;
}


int wolfSSL_CTX_check_private_key(WOLFSSL_CTX* ctx)
{
    /* TODO: check private against public for RSA match */
    (void)ctx;
    WOLFSSL_ENTER();
    return SSL_SUCCESS;
}


#ifdef HAVE_CRL


/* check CRL if enabled, SSL_SUCCESS  */
int wolfSSL_CertManagerCheckCRL(WOLFSSL_CERT_MANAGER* cm, byte* der, int sz)
{
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endif

    WOLFSSL_ENTER();

    if (cm == NULL)
        return BAD_FUNC_ARG;

    if (cm->crlEnabled == 0)
        return SSL_SUCCESS;

#ifdef WOLFSSL_SMALL_STACK
    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL)
        return MEMORY_E;
#endif

    InitDecodedCert(cert, der, sz, NULL);

    if ((ret = ParseCertRelative(cert, CERT_TYPE, NO_VERIFY, cm)) != 0) {
        WOLFSSL_MSG("ParseCert failed");
    }
    else if ((ret = CheckCertCRL(cm->crl, cert)) != 0) {
        WOLFSSL_MSG("CheckCertCRL failed");
    }

    FreeDecodedCert(cert);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret == 0 ? SSL_SUCCESS : ret;
}


int wolfSSL_CertManagerSetCRL_Cb(WOLFSSL_CERT_MANAGER* cm, CbMissingCRL cb)
{
    WOLFSSL_ENTER();
    if (cm == NULL)
        return BAD_FUNC_ARG;

    cm->cbMissingCRL = cb;

    return SSL_SUCCESS;
}


int wolfSSL_CertManagerLoadCRL(WOLFSSL_CERT_MANAGER* cm, const char* path, int type, int monitor)
{
    WOLFSSL_ENTER();
    if (cm == NULL)
        return BAD_FUNC_ARG;

    if (cm->crl == NULL) {
        if (wolfSSL_CertManagerEnableCRL(cm, 0) != SSL_SUCCESS) {
            WOLFSSL_MSG("Enable CRL failed");
            return SSL_FATAL_ERROR;
        }
    }

    return LoadCRL(cm->crl, path, type, monitor);
}


int wolfSSL_EnableCRL(WOLFSSL* ssl, int options)
{
    WOLFSSL_ENTER();
    if (ssl)
        return wolfSSL_CertManagerEnableCRL(ssl->ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_DisableCRL(WOLFSSL* ssl)
{
    WOLFSSL_ENTER();
    if (ssl)
        return wolfSSL_CertManagerDisableCRL(ssl->ctx->cm);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type, int monitor)
{
    WOLFSSL_ENTER();
    if (ssl)
        return wolfSSL_CertManagerLoadCRL(ssl->ctx->cm, path, type, monitor);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_SetCRL_Cb(WOLFSSL* ssl, CbMissingCRL cb)
{
    WOLFSSL_ENTER();
    if (ssl)
        return wolfSSL_CertManagerSetCRL_Cb(ssl->ctx->cm, cb);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options)
{
    WOLFSSL_ENTER();
    if (ctx)
        return wolfSSL_CertManagerEnableCRL(ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER();
    if (ctx)
        return wolfSSL_CertManagerDisableCRL(ctx->cm);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX* ctx, const char* path, int type, int monitor)
{
    WOLFSSL_ENTER();
    if (ctx)
        return wolfSSL_CertManagerLoadCRL(ctx->cm, path, type, monitor);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX* ctx, CbMissingCRL cb)
{
    WOLFSSL_ENTER(;
    if (ctx)
        return wolfSSL_CertManagerSetCRL_Cb(ctx->cm, cb);
    else
        return BAD_FUNC_ARG;
}


#endif /* HAVE_CRL */





/* get cert chaining depth using ssl struct */
long wolfSSL_get_verify_depth(WOLFSSL* ssl)
{
    if(ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    return MAX_CHAIN_DEPTH;
}


/* get cert chaining depth using ctx struct */
long wolfSSL_CTX_get_verify_depth(WOLFSSL_CTX* ctx)
{
    if(ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    return MAX_CHAIN_DEPTH;
}



#ifndef NO_DH

/* server wrapper for ctx or ssl Diffie-Hellman parameters */
static int wolfSSL_SetTmpDH_buffer_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
                                  const unsigned char* buf, long sz, int format)
{
    buffer der;
    int    ret      = 0;
    int    weOwnDer = 0;
    word32 pSz = MAX_DH_SIZE;
    word32 gSz = MAX_DH_SIZE;
#ifdef WOLFSSL_SMALL_STACK
    byte*  p = NULL;
    byte*  g = NULL;
#else
    byte   p[MAX_DH_SIZE];
    byte   g[MAX_DH_SIZE];
#endif

    der.buffer = (byte*)buf;
    der.length = (word32)sz;

#ifdef WOLFSSL_SMALL_STACK
    p = (byte*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    g = (byte*)XMALLOC(gSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (p == NULL || g == NULL) {
        XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    if (format != SSL_FILETYPE_ASN1 && format != SSL_FILETYPE_PEM)
        ret = SSL_BAD_FILETYPE;
    else {
        if (format == SSL_FILETYPE_PEM) {
            der.buffer = NULL;
            ret = PemToDer(buf, sz, DH_PARAM_TYPE, &der, ctx->heap, NULL,NULL);
            weOwnDer = 1;
        }
        
        if (ret == 0) {
            if (wc_DhParamsLoad(der.buffer, der.length, p, &pSz, g, &gSz) < 0)
                ret = SSL_BAD_FILETYPE;
            else if (ssl)
                ret = wolfSSL_SetTmpDH(ssl, p, pSz, g, gSz);
            else
                ret = wolfSSL_CTX_SetTmpDH(ctx, p, pSz, g, gSz);
        }
    }

    if (weOwnDer)
        XFREE(der.buffer, ctx->heap, DYNAMIC_TYPE_KEY);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


/* server Diffie-Hellman parameters, SSL_SUCCESS on ok */
int wolfSSL_SetTmpDH_buffer(WOLFSSL* ssl, const unsigned char* buf, long sz,
                           int format)
{
    return wolfSSL_SetTmpDH_buffer_wrapper(ssl->ctx, ssl, buf, sz, format);
}


/* server ctx Diffie-Hellman parameters, SSL_SUCCESS on ok */
int wolfSSL_CTX_SetTmpDH_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf,
                               long sz, int format)
{
    return wolfSSL_SetTmpDH_buffer_wrapper(ctx, NULL, buf, sz, format);
}


/* server Diffie-Hellman parameters */
static int wolfSSL_SetTmpDH_file_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
                                        const char* fname, int format)
{
#ifdef WOLFSSL_SMALL_STACK
    byte   staticBuffer[1]; /* force heap usage */
#else
    byte   staticBuffer[FILE_BUFFER_SIZE];
#endif
    byte*  myBuffer = staticBuffer;
    int    dynamic = 0;
    int    ret;
    long   sz = 0;
    XFILE  file = XFOPEN(fname, "rb");

    if (file == XBADFILE) return SSL_BAD_FILE;
    XFSEEK(file, 0, XSEEK_END);
    sz = XFTELL(file);
    XREWIND(file);

    if (sz > (long)sizeof(staticBuffer)) {
        WOLFSSL_MSG("Getting dynamic buffer");
        myBuffer = (byte*) XMALLOC(sz, ctx->heap, DYNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
            XFCLOSE(file);
            return SSL_BAD_FILE;
        }
        dynamic = 1;
    }
    else if (sz < 0) {
        XFCLOSE(file);
        return SSL_BAD_FILE;
    }

    if ( (ret = (int)XFREAD(myBuffer, sz, 1, file)) < 0)
        ret = SSL_BAD_FILE;
    else {
        if (ssl)
            ret = wolfSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
        else
            ret = wolfSSL_CTX_SetTmpDH_buffer(ctx, myBuffer, sz, format);
    }

    XFCLOSE(file);
    if (dynamic)
        XFREE(myBuffer, ctx->heap, DYNAMIC_TYPE_FILE);

    return ret;
}

/* server Diffie-Hellman parameters */
int wolfSSL_SetTmpDH_file(WOLFSSL* ssl, const char* fname, int format)
{
    return wolfSSL_SetTmpDH_file_wrapper(ssl->ctx, ssl, fname, format);
}


/* server Diffie-Hellman parameters */
int wolfSSL_CTX_SetTmpDH_file(WOLFSSL_CTX* ctx, const char* fname, int format)
{
    return wolfSSL_SetTmpDH_file_wrapper(ctx, NULL, fname, format);
}


int wolfSSL_CTX_SetMinDhKey_Sz(WOLFSSL_CTX* ctx, word16 keySz)
{
    if (ctx == NULL || keySz > 16000 || keySz % 8 != 0)
        return BAD_FUNC_ARG;

    ctx->minDhKeySz = keySz / 8;
    return SSL_SUCCESS;
}


int wolfSSL_SetMinDhKey_Sz(WOLFSSL* ssl, word16 keySz)
{
    if (ssl == NULL || keySz > 16000 || keySz % 8 != 0)
        return BAD_FUNC_ARG;

    ssl->options.minDhKeySz = keySz / 8;
    return SSL_SUCCESS;
}


int wolfSSL_GetDhKey_Sz(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return (ssl->options.dhKeySz * 8);
}


#endif /* NO_DH */


#ifdef OPENSSL_EXTRA
/* put SSL type in extra for now, not very common */



#ifdef HAVE_ECC

/* Set Temp CTX EC-DHE size in octets, should be 20 - 66 for 160 - 521 bit */
int wolfSSL_CTX_SetTmpEC_DHE_Sz(WOLFSSL_CTX* ctx, word16 sz)
{
    if (ctx == NULL || sz < ECC_MINSIZE || sz > ECC_MAXSIZE)
        return BAD_FUNC_ARG;

    ctx->eccTempKeySz = sz;

    return SSL_SUCCESS;
}


/* Set Temp SSL EC-DHE size in octets, should be 20 - 66 for 160 - 521 bit */
int wolfSSL_SetTmpEC_DHE_Sz(WOLFSSL* ssl, word16 sz)
{
    if (ssl == NULL || sz < ECC_MINSIZE || sz > ECC_MAXSIZE)
        return BAD_FUNC_ARG;

    ssl->eccTempKeySz = sz;

    return SSL_SUCCESS;
}

#endif /* HAVE_ECC */




int wolfSSL_CTX_use_RSAPrivateKey_file(WOLFSSL_CTX* ctx,const char* file, int format)
{
	WOLFSSL_ENTER();

	return wolfSSL_CTX_use_PrivateKey_file(ctx, file, format);
}


int wolfSSL_use_RSAPrivateKey_file(WOLFSSL* ssl, const char* file, int format)
{
    WOLFSSL_ENTER();

    return wolfSSL_use_PrivateKey_file(ssl, file, format);
}

#endif /* OPENSSL_EXTRA */



#endif /* NO_FILESYSTEM */


void wolfSSL_CTX_set_verify(WOLFSSL_CTX* ctx, int mode, VerifyCallback vc)
{
	WOLFSSL_ENTER();
	if (mode & SSL_VERIFY_PEER) {
		ctx->verifyPeer = 1;
		ctx->verifyNone = 0;  /* in case perviously set */
	}

	if (mode == SSL_VERIFY_NONE) {
		ctx->verifyNone = 1;
		ctx->verifyPeer = 0;  /* in case previously set */
	}

	if (mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
		ctx->failNoCert = 1;

	ctx->verifyCallback = vc;
}


void wolfSSL_set_verify(WOLFSSL* ssl, int mode, VerifyCallback vc)
{
    WOLFSSL_ENTER();
    if (mode & SSL_VERIFY_PEER) {
        ssl->options.verifyPeer = 1;
        ssl->options.verifyNone = 0;  /* in case perviously set */
    }

    if (mode == SSL_VERIFY_NONE) {
        ssl->options.verifyNone = 1;
        ssl->options.verifyPeer = 0;  /* in case previously set */
    }

    if (mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
        ssl->options.failNoCert = 1;

    ssl->verifyCallback = vc;
}


/* store user ctx for verify callback */
void wolfSSL_SetCertCbCtx(WOLFSSL* ssl, void* ctx)
{
    WOLFSSL_ENTER();
    if (ssl)
        ssl->verifyCbCtx = ctx;
}


/* store context CA Cache addition callback */
void wolfSSL_CTX_SetCACb(WOLFSSL_CTX* ctx, CallbackCACache cb)
{
    if (ctx && ctx->cm)
        ctx->cm->caCacheCallback = cb;
}


#if defined(PERSIST_CERT_CACHE)

#if !defined(NO_FILESYSTEM)

/* Persist cert cache to file */
int wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX* ctx, const char* fname)
{
    WOLFSSL_ENTER();

    if (ctx == NULL || fname == NULL)
        return BAD_FUNC_ARG;

    return CM_SaveCertCache(ctx->cm, fname);
}


/* Persist cert cache from file */
int wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX* ctx, const char* fname)
{
    WOLFSSL_ENTER(;

    if (ctx == NULL || fname == NULL)
        return BAD_FUNC_ARG;

    return CM_RestoreCertCache(ctx->cm, fname);
}

#endif /* NO_FILESYSTEM */

/* Persist cert cache to memory */
int wolfSSL_CTX_memsave_cert_cache(WOLFSSL_CTX* ctx, void* mem, int sz, int* used)
{
	WOLFSSL_ENTER();

	if (ctx == NULL || mem == NULL || used == NULL || sz <= 0)
		return BAD_FUNC_ARG;

	return CM_MemSaveCertCache(ctx->cm, mem, sz, used);
}


/* Restore cert cache from memory */
int wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX* ctx, const void* mem, int sz)
{
	WOLFSSL_ENTER();

	if (ctx == NULL || mem == NULL || sz <= 0)
		return BAD_FUNC_ARG;

	return CM_MemRestoreCertCache(ctx->cm, mem, sz);
}


/* get how big the the cert cache save buffer needs to be */
int wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX* ctx)
{
	WOLFSSL_ENTER();

	if (ctx == NULL)
		return BAD_FUNC_ARG;

	return CM_GetCertCacheMemSize(ctx->cm);
}

#endif /* PERSISTE_CERT_CACHE */




#endif /* !NO_CERTS */



