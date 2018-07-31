/* ssl.c
 */

#include "cmnSsl.h"

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    #include <wolfssl/openssl/evp.h>
#endif

#ifdef OPENSSL_EXTRA
    /* openssl headers begin */
    #include <wolfssl/openssl/hmac.h>
    #include <wolfssl/openssl/crypto.h>
    #include <wolfssl/openssl/des.h>
    #include <wolfssl/openssl/bn.h>
    #include <wolfssl/openssl/dh.h>
    #include <wolfssl/openssl/rsa.h>
    #include <wolfssl/openssl/pem.h>
    /* openssl headers end, wolfssl internal headers next */
    #include <wolfssl/wolfcrypt/hmac.h>
    #include <wolfssl/wolfcrypt/random.h>
    #include <wolfssl/wolfcrypt/des3.h>
    #include <wolfssl/wolfcrypt/md4.h>
    #include <wolfssl/wolfcrypt/md5.h>
    #include <wolfssl/wolfcrypt/arc4.h>
    #ifdef WOLFSSL_SHA512
        #include <wolfssl/wolfcrypt/sha512.h>
    #endif
#endif

#ifndef NO_FILESYSTEM
    #if !defined(USE_WINDOWS_API) && !defined(NO_WOLFSSL_DIR) \
            && !defined(EBSNET)
        #include <dirent.h>
        #include <sys/stat.h>
    #endif
    #ifdef EBSNET
        #include "vfapi.h"
        #include "vfile.h"
    #endif
#endif /* NO_FILESYSTEM */

#ifndef TRUE
    #define TRUE  1
#endif
#ifndef FALSE
    #define FALSE 0
#endif


#ifndef WOLFSSL_HAVE_MAX
#define WOLFSSL_HAVE_MAX

#ifdef WOLFSSL_DTLS
    static INLINE word32 max(word32 a, word32 b)
    {
        return a > b ? a : b;
    }
#endif /* WOLFSSL_DTLS */

#endif /* WOLFSSL_HAVE_MAX */


#ifndef WOLFSSL_LEANPSK
char* mystrnstr(const char* s1, const char* s2, unsigned int n)
{
    unsigned int s2_len = (unsigned int)XSTRLEN(s2);

    if (s2_len == 0)
        return (char*)s1;

    while (n >= s2_len && s1[0]) {
        if (s1[0] == s2[0])
            if (XMEMCMP(s1, s2, s2_len) == 0)
                return (char*)s1;
        s1++;
        n--;
    }

    return NULL;
}
#endif


/* prevent multiple mutex initializations */
volatile int initRefCount = 0;
wolfSSL_Mutex count_mutex;   /* init ref count mutex */

#ifdef HAVE_POLY1305
/* set if to use old poly 1 for yes 0 to use new poly */
int wolfSSL_use_old_poly(WOLFSSL* ssl, int value)
{
	ssl->options.oldPoly = value;
	WOLFSSL_LEAVE( 0);
	return 0;
}
#endif

int wolfSSL_set_fd(WOLFSSL* ssl, int fd)
{
	WOLFSSL_ENTER();
	ssl->rfd = fd;      /* not used directly to allow IO callbacks */
	ssl->wfd = fd;

	ssl->IOCB_ReadCtx  = &ssl->rfd;
	ssl->IOCB_WriteCtx = &ssl->wfd;

#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls) {
		ssl->IOCB_ReadCtx = &ssl->buffers.dtlsCtx;
		ssl->IOCB_WriteCtx = &ssl->buffers.dtlsCtx;
		ssl->buffers.dtlsCtx.fd = fd;
	}
#endif

	WOLFSSL_LEAVE( SSL_SUCCESS);
	return SSL_SUCCESS;
}


/**
  * Get the name of cipher at priotity level passed in.
  */
char* wolfSSL_get_cipher_list(int priority)
{
    const char* const* ciphers = GetCipherNames();

    if (priority >= GetCipherNamesSize() || priority < 0) {
        return 0;
    }

    return (char*)ciphers[priority];
}


int wolfSSL_get_ciphers(char* buf, int len)
{
    const char* const* ciphers = GetCipherNames();
    int  totalInc = 0;
    int  step     = 0;
    char delim    = ':';
    int  size     = GetCipherNamesSize();
    int  i;

    if (buf == NULL || len <= 0)
        return BAD_FUNC_ARG;

    /* Add each member to the buffer delimitted by a : */
    for (i = 0; i < size; i++) {
        step = (int)(XSTRLEN(ciphers[i]) + 1);  /* delimiter */
        totalInc += step;

        /* Check to make sure buf is large enough and will not overflow */
        if (totalInc < len) {
            XSTRNCPY(buf, ciphers[i], XSTRLEN(ciphers[i]));
            buf += XSTRLEN(ciphers[i]);

            if (i < size - 1)
                *buf++ = delim;
        }
        else
            return BUFFER_E;
    }
    return SSL_SUCCESS;
}


int wolfSSL_get_fd(const WOLFSSL* ssl)
{
	return ssl->rfd;
}


int wolfSSL_get_using_nonblock(WOLFSSL* ssl)
{
	return ssl->options.usingNonblock;
}


int wolfSSL_dtls(WOLFSSL* ssl)
{
    return ssl->options.dtls;
}


#ifndef WOLFSSL_LEANPSK
void wolfSSL_set_using_nonblock(WOLFSSL* ssl, int nonblock)
{
    ssl->options.usingNonblock = (nonblock != 0);
}


int wolfSSL_dtls_set_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz)
{
#ifdef WOLFSSL_DTLS
    void* sa = (void*)XMALLOC(peerSz, ssl->heap, DYNAMIC_TYPE_SOCKADDR);
    if (sa != NULL) {
        if (ssl->buffers.dtlsCtx.peer.sa != NULL)
            XFREE(ssl->buffers.dtlsCtx.peer.sa,ssl->heap,DYNAMIC_TYPE_SOCKADDR);
        XMEMCPY(sa, peer, peerSz);
        ssl->buffers.dtlsCtx.peer.sa = sa;
        ssl->buffers.dtlsCtx.peer.sz = peerSz;
        return SSL_SUCCESS;
    }
    return SSL_FAILURE;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return SSL_NOT_IMPLEMENTED;
#endif
}

int wolfSSL_dtls_get_peer(WOLFSSL* ssl, void* peer, unsigned int* peerSz)
{
#ifdef WOLFSSL_DTLS
    if (peer != NULL && peerSz != NULL
            && *peerSz >= ssl->buffers.dtlsCtx.peer.sz) {
        *peerSz = ssl->buffers.dtlsCtx.peer.sz;
        XMEMCPY(peer, ssl->buffers.dtlsCtx.peer.sa, *peerSz);
        return SSL_SUCCESS;
    }
    return SSL_FAILURE;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return SSL_NOT_IMPLEMENTED;
#endif
}
#endif /* WOLFSSL_LEANPSK */



#ifndef WOLFSSL_LEANPSK
/* object size based on build */
int wolfSSL_GetObjectSize(void)
{
#ifdef SHOW_SIZES
    printf("sizeof suites           = %lu\n", sizeof(Suites));
    printf("sizeof ciphers(2)       = %lu\n", sizeof(Ciphers));
#ifndef NO_RC4
    printf("    sizeof arc4         = %lu\n", sizeof(Arc4));
#endif
    printf("    sizeof aes          = %lu\n", sizeof(Aes));
#ifndef NO_DES3
    printf("    sizeof des3         = %lu\n", sizeof(Des3));
#endif
#ifndef NO_RABBIT
    printf("    sizeof rabbit       = %lu\n", sizeof(Rabbit));
#endif
#ifdef HAVE_CHACHA
    printf("    sizeof chacha       = %lu\n", sizeof(Chacha));
#endif
    printf("sizeof cipher specs     = %lu\n", sizeof(CipherSpecs));
    printf("sizeof keys             = %lu\n", sizeof(Keys));
    printf("sizeof Hashes(2)        = %lu\n", sizeof(Hashes));
#ifndef NO_MD5
    printf("    sizeof MD5          = %lu\n", sizeof(Md5));
#endif
#ifndef NO_SHA
    printf("    sizeof SHA          = %lu\n", sizeof(Sha));
#endif
#ifndef NO_SHA256
    printf("    sizeof SHA256       = %lu\n", sizeof(Sha256));
#endif
#ifdef WOLFSSL_SHA384
    printf("    sizeof SHA384       = %lu\n", sizeof(Sha384));
#endif
#ifdef WOLFSSL_SHA384
    printf("    sizeof SHA512       = %lu\n", sizeof(Sha512));
#endif
    printf("sizeof Buffers          = %lu\n", sizeof(Buffers));
    printf("sizeof Options          = %lu\n", sizeof(Options));
    printf("sizeof Arrays           = %lu\n", sizeof(Arrays));
#ifndef NO_RSA
    printf("sizeof RsaKey           = %lu\n", sizeof(RsaKey));
#endif
#ifdef HAVE_ECC
    printf("sizeof ecc_key          = %lu\n", sizeof(ecc_key));
#endif
    printf("sizeof WOLFSSL_CIPHER    = %lu\n", sizeof(WOLFSSL_CIPHER));
    printf("sizeof WOLFSSL_SESSION   = %lu\n", sizeof(WOLFSSL_SESSION));
    printf("sizeof WOLFSSL           = %lu\n", sizeof(WOLFSSL));
    printf("sizeof WOLFSSL_CTX       = %lu\n", sizeof(WOLFSSL_CTX));
#endif

    return sizeof(WOLFSSL);
}
#endif


#ifndef NO_DH
/* server Diffie-Hellman parameters, SSL_SUCCESS on ok */
int wolfSSL_SetTmpDH(WOLFSSL* ssl, const unsigned char* p, int pSz,
                    const unsigned char* g, int gSz)
{
    byte havePSK = 0;
    byte haveRSA = 1;

	WOLFSSL_ENTER();
    if (ssl == NULL || p == NULL || g == NULL) return BAD_FUNC_ARG;

    if (pSz < ssl->options.minDhKeySz)
        return DH_KEY_SIZE_E;

    if (ssl->options.side != WOLFSSL_SERVER_END)
        return SIDE_ERROR;

    if (ssl->buffers.serverDH_P.buffer && ssl->buffers.weOwnDH)
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->ctx->heap, DYNAMIC_TYPE_DH);
    if (ssl->buffers.serverDH_G.buffer && ssl->buffers.weOwnDH)
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->ctx->heap, DYNAMIC_TYPE_DH);

    ssl->buffers.weOwnDH = 1;  /* SSL owns now */
    ssl->buffers.serverDH_P.buffer = (byte*)XMALLOC(pSz, ssl->ctx->heap,
                                                    DYNAMIC_TYPE_DH);
    if (ssl->buffers.serverDH_P.buffer == NULL)
        return MEMORY_E;

    ssl->buffers.serverDH_G.buffer = (byte*)XMALLOC(gSz, ssl->ctx->heap,
                                                    DYNAMIC_TYPE_DH);
    if (ssl->buffers.serverDH_G.buffer == NULL) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->ctx->heap, DYNAMIC_TYPE_DH);
        return MEMORY_E;
    }

    ssl->buffers.serverDH_P.length = pSz;
    ssl->buffers.serverDH_G.length = gSz;

    XMEMCPY(ssl->buffers.serverDH_P.buffer, p, pSz);
    XMEMCPY(ssl->buffers.serverDH_G.buffer, g, gSz);

    ssl->options.haveDH = 1;
    #ifndef NO_PSK
        havePSK = ssl->options.havePSK;
    #endif
    #ifdef NO_RSA
        haveRSA = 0;
    #endif
    InitSuites(ssl->suites, ssl->version, haveRSA, havePSK, ssl->options.haveDH,
               ssl->options.haveNTRU, ssl->options.haveECDSAsig,
               ssl->options.haveStaticECC, ssl->options.side);

    WOLFSSL_LEAVE( 0);
    return SSL_SUCCESS;
}

/* server ctx Diffie-Hellman parameters, SSL_SUCCESS on ok */
int wolfSSL_CTX_SetTmpDH(WOLFSSL_CTX* ctx, const unsigned char* p, int pSz,
                         const unsigned char* g, int gSz)
{
	WOLFSSL_ENTER();
    if (ctx == NULL || p == NULL || g == NULL) return BAD_FUNC_ARG;

    if (pSz < ctx->minDhKeySz)
        return DH_KEY_SIZE_E;

    XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
    XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_DH);

    ctx->serverDH_P.buffer = (byte*)XMALLOC(pSz, ctx->heap,DYNAMIC_TYPE_DH);
    if (ctx->serverDH_P.buffer == NULL)
       return MEMORY_E;

    ctx->serverDH_G.buffer = (byte*)XMALLOC(gSz, ctx->heap,DYNAMIC_TYPE_DH);
    if (ctx->serverDH_G.buffer == NULL) {
        XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
        return MEMORY_E;
    }

    ctx->serverDH_P.length = pSz;
    ctx->serverDH_G.length = gSz;

    XMEMCPY(ctx->serverDH_P.buffer, p, pSz);
    XMEMCPY(ctx->serverDH_G.buffer, g, gSz);

    ctx->haveDH = 1;

    WOLFSSL_LEAVE( 0);
    return SSL_SUCCESS;
}

#endif /* !NO_DH */



#ifdef HAVE_CAVIUM

/* let's use cavium, SSL_SUCCESS on ok */
int wolfSSL_UseCavium(WOLFSSL* ssl, int devId)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->devId = devId;

    return SSL_SUCCESS;
}


/* let's use cavium, SSL_SUCCESS on ok */
int wolfSSL_CTX_UseCavium(WOLFSSL_CTX* ctx, int devId)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->devId = devId;

    return SSL_SUCCESS;
}


#endif /* HAVE_CAVIUM */

#ifdef HAVE_SNI

int wolfSSL_UseSNI(WOLFSSL* ssl, byte type, const void* data, word16 size)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ssl->extensions, type, data, size);
}

int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, byte type, const void* data, word16 size)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ctx->extensions, type, data, size);
}

#ifndef NO_WOLFSSL_SERVER

void wolfSSL_SNI_SetOptions(WOLFSSL* ssl, byte type, byte options)
{
    if (ssl && ssl->extensions)
        TLSX_SNI_SetOptions(ssl->extensions, type, options);
}

void wolfSSL_CTX_SNI_SetOptions(WOLFSSL_CTX* ctx, byte type, byte options)
{
    if (ctx && ctx->extensions)
        TLSX_SNI_SetOptions(ctx->extensions, type, options);
}

byte wolfSSL_SNI_Status(WOLFSSL* ssl, byte type)
{
    return TLSX_SNI_Status(ssl ? ssl->extensions : NULL, type);
}

word16 wolfSSL_SNI_GetRequest(WOLFSSL* ssl, byte type, void** data)
{
    if (data)
        *data = NULL;

    if (ssl && ssl->extensions)
        return TLSX_SNI_GetRequest(ssl->extensions, type, data);

    return 0;
}

int wolfSSL_SNI_GetFromBuffer(const byte* clientHello, word32 helloSz, byte type,
                                                     byte* sni, word32* inOutSz)
{
	if (clientHello && helloSz > 0 && sni && inOutSz && *inOutSz > 0)
		return TLSX_SNI_GetFromBuffer(clientHello, helloSz, type, sni, inOutSz);

	return BAD_FUNC_ARG;
}

#endif /* NO_WOLFSSL_SERVER */

#endif /* HAVE_SNI */


#ifdef HAVE_MAX_FRAGMENT
#ifndef NO_WOLFSSL_CLIENT
int wolfSSL_UseMaxFragment(WOLFSSL* ssl, byte mfl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseMaxFragment(&ssl->extensions, mfl);
}

int wolfSSL_CTX_UseMaxFragment(WOLFSSL_CTX* ctx, byte mfl)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseMaxFragment(&ctx->extensions, mfl);
}
#endif /* NO_WOLFSSL_CLIENT */
#endif /* HAVE_MAX_FRAGMENT */

#ifdef HAVE_TRUNCATED_HMAC
#ifndef NO_WOLFSSL_CLIENT
int wolfSSL_UseTruncatedHMAC(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseTruncatedHMAC(&ssl->extensions);
}

int wolfSSL_CTX_UseTruncatedHMAC(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseTruncatedHMAC(&ctx->extensions);
}
#endif /* NO_WOLFSSL_CLIENT */
#endif /* HAVE_TRUNCATED_HMAC */

/* Elliptic Curves */
#ifdef HAVE_SUPPORTED_CURVES
#ifndef NO_WOLFSSL_CLIENT

int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, word16 name)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    switch (name) {
        case WOLFSSL_ECC_SECP160R1:
        case WOLFSSL_ECC_SECP192R1:
        case WOLFSSL_ECC_SECP224R1:
        case WOLFSSL_ECC_SECP256R1:
        case WOLFSSL_ECC_SECP384R1:
        case WOLFSSL_ECC_SECP521R1:
            break;

        default:
            return BAD_FUNC_ARG;
    }

    return TLSX_UseSupportedCurve(&ssl->extensions, name);
}

int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx, word16 name)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    switch (name) {
        case WOLFSSL_ECC_SECP160R1:
        case WOLFSSL_ECC_SECP192R1:
        case WOLFSSL_ECC_SECP224R1:
        case WOLFSSL_ECC_SECP256R1:
        case WOLFSSL_ECC_SECP384R1:
        case WOLFSSL_ECC_SECP521R1:
            break;

        default:
            return BAD_FUNC_ARG;
    }

    return TLSX_UseSupportedCurve(&ctx->extensions, name);
}

#endif /* NO_WOLFSSL_CLIENT */
#endif /* HAVE_SUPPORTED_CURVES */


/* Session Ticket */
#if !defined(NO_WOLFSSL_SERVER) && defined(HAVE_SESSION_TICKET)
/* SSL_SUCCESS on ok */
int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx, SessionTicketEncCb cb)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->ticketEncCb = cb;

    return SSL_SUCCESS;
}

/* set hint interval, SSL_SUCCESS on ok */
int wolfSSL_CTX_set_TicketHint(WOLFSSL_CTX* ctx, int hint)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->ticketHint = hint;

    return SSL_SUCCESS;
}

/* set user context, SSL_SUCCESS on ok */
int wolfSSL_CTX_set_TicketEncCtx(WOLFSSL_CTX* ctx, void* userCtx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->ticketEncCtx = userCtx;

    return SSL_SUCCESS;
}

#endif /* !defined(NO_WOLFSSL_CLIENT) && defined(HAVE_SESSION_TICKET) */

/* Session Ticket */
#if !defined(NO_WOLFSSL_CLIENT) && defined(HAVE_SESSION_TICKET)
int wolfSSL_UseSessionTicket(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSessionTicket(&ssl->extensions, NULL);
}

int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSessionTicket(&ctx->extensions, NULL);
}

WOLFSSL_API int wolfSSL_get_SessionTicket(WOLFSSL* ssl, byte* buf, word32* bufSz)
{
    if (ssl == NULL || buf == NULL || bufSz == NULL || *bufSz == 0)
        return BAD_FUNC_ARG;

    if (ssl->session.ticketLen <= *bufSz) {
        XMEMCPY(buf, ssl->session.ticket, ssl->session.ticketLen);
        *bufSz = ssl->session.ticketLen;
    }
    else
        *bufSz = 0;

    return SSL_SUCCESS;
}

WOLFSSL_API int wolfSSL_set_SessionTicket(WOLFSSL* ssl, byte* buf, word32 bufSz)
{
    if (ssl == NULL || (buf == NULL && bufSz > 0))
        return BAD_FUNC_ARG;

    if (bufSz > 0)
        XMEMCPY(ssl->session.ticket, buf, bufSz);
    ssl->session.ticketLen = (word16)bufSz;

    return SSL_SUCCESS;
}


WOLFSSL_API int wolfSSL_set_SessionTicket_cb(WOLFSSL* ssl,
                                            CallbackSessionTicket cb, void* ctx)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->session_ticket_cb = cb;
    ssl->session_ticket_ctx = ctx;

    return SSL_SUCCESS;
}
#endif

#ifndef WOLFSSL_LEANPSK

int wolfSSL_send(WOLFSSL* ssl, const void* data, int sz, int flags)
{
    int ret;
    int oldFlags;

	WOLFSSL_ENTER();

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

    oldFlags = ssl->wflags;

    ssl->wflags = flags;
    ret = wolfSSL_write(ssl, data, sz);
    ssl->wflags = oldFlags;

    WOLFSSL_LEAVE( ret);

    return ret;
}


int wolfSSL_recv(WOLFSSL* ssl, void* data, int sz, int flags)
{
    int ret;
    int oldFlags;

	WOLFSSL_ENTER();

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

    oldFlags = ssl->rflags;

    ssl->rflags = flags;
    ret = wolfSSL_read(ssl, data, sz);
    ssl->rflags = oldFlags;

    WOLFSSL_LEAVE( ret);

    return ret;
}
#endif



#ifdef ATOMIC_USER

void  wolfSSL_CTX_SetMacEncryptCb(WOLFSSL_CTX* ctx, CallbackMacEncrypt cb)
{
    if (ctx)
        ctx->MacEncryptCb = cb;
}


void  wolfSSL_SetMacEncryptCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->MacEncryptCtx = ctx;
}


void* wolfSSL_GetMacEncryptCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->MacEncryptCtx;

    return NULL;
}


void  wolfSSL_CTX_SetDecryptVerifyCb(WOLFSSL_CTX* ctx, CallbackDecryptVerify cb)
{
    if (ctx)
        ctx->DecryptVerifyCb = cb;
}


void  wolfSSL_SetDecryptVerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->DecryptVerifyCtx = ctx;
}


void* wolfSSL_GetDecryptVerifyCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->DecryptVerifyCtx;

    return NULL;
}


const byte* wolfSSL_GetClientWriteKey(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->keys.client_write_key;

    return NULL;
}


const byte* wolfSSL_GetClientWriteIV(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->keys.client_write_IV;

    return NULL;
}


const byte* wolfSSL_GetServerWriteKey(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->keys.server_write_key;

    return NULL;
}


const byte* wolfSSL_GetServerWriteIV(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->keys.server_write_IV;

    return NULL;
}


int wolfSSL_GetKeySize(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->specs.key_size;

    return BAD_FUNC_ARG;
}


int wolfSSL_GetIVSize(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->specs.iv_size;

    return BAD_FUNC_ARG;
}


int wolfSSL_GetBulkCipher(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->specs.bulk_cipher_algorithm;

    return BAD_FUNC_ARG;
}


int wolfSSL_GetCipherType(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->specs.cipher_type == block)
        return WOLFSSL_BLOCK_TYPE;
    if (ssl->specs.cipher_type == stream)
        return WOLFSSL_STREAM_TYPE;
    if (ssl->specs.cipher_type == aead)
        return WOLFSSL_AEAD_TYPE;

    return -1;
}


int wolfSSL_GetCipherBlockSize(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return ssl->specs.block_size;
}


int wolfSSL_GetAeadMacSize(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return ssl->specs.aead_mac_size;
}


int wolfSSL_IsTLSv1_1(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.tls1_1)
        return 1;

    return 0;
}


int wolfSSL_GetSide(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->options.side;

    return BAD_FUNC_ARG;
}


int wolfSSL_GetHmacSize(WOLFSSL* ssl)
{
    /* AEAD ciphers don't have HMAC keys */
    if (ssl)
        return (ssl->specs.cipher_type != aead) ? ssl->specs.hash_size : 0;

    return BAD_FUNC_ARG;
}

#endif /* ATOMIC_USER */


int wolfSSL_pending(WOLFSSL* ssl)
{
    return ssl->buffers.clearOutputBuffer.length;
}


#ifndef WOLFSSL_LEANPSK
/* trun on handshake group messages for context */
int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
       return BAD_FUNC_ARG;

    ctx->groupMessages = 1;

    return SSL_SUCCESS;
}
#endif


#ifndef WOLFSSL_LEANPSK
/* trun on handshake group messages for ssl object */
int wolfSSL_set_group_messages(WOLFSSL* ssl)
{
    if (ssl == NULL)
       return BAD_FUNC_ARG;

    ssl->options.groupMessages = 1;

    return SSL_SUCCESS;
}


/* make minVersion the internal equivilant SSL version */
static int SetMinVersionHelper(byte* minVersion, int version)
{
    switch (version) {
#ifndef NO_OLD_TLS
        case WOLFSSL_SSLV3:
            *minVersion = SSLv3_MINOR;
            break;
#endif

#ifndef NO_TLS
    #ifndef NO_OLD_TLS
        case WOLFSSL_TLSV1:
            *minVersion = TLSv1_MINOR;
            break;

        case WOLFSSL_TLSV1_1:
            *minVersion = TLSv1_1_MINOR;
            break;
    #endif
        case WOLFSSL_TLSV1_2:
            *minVersion = TLSv1_2_MINOR;
            break;
#endif

        default:
            WOLFSSL_MSG("Bad function argument");
            return BAD_FUNC_ARG;
    }

    return SSL_SUCCESS;
}


/* Set minimum downgrade version allowed, SSL_SUCCESS on ok */
int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX* ctx, int version)
{
	WOLFSSL_ENTER();

    if (ctx == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

    return SetMinVersionHelper(&ctx->minDowngrade, version);
}


/* Set minimum downgrade version allowed, SSL_SUCCESS on ok */
int wolfSSL_SetMinVersion(WOLFSSL* ssl, int version)
{
	WOLFSSL_ENTER();

    if (ssl == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

    return SetMinVersionHelper(&ssl->options.minDowngrade, version);
}


int wolfSSL_SetVersion(WOLFSSL* ssl, int version)
{
    byte haveRSA = 1;
    byte havePSK = 0;

	WOLFSSL_ENTER();

    if (ssl == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

    switch (version) {
#ifndef NO_OLD_TLS
        case WOLFSSL_SSLV3:
            ssl->version = MakeSSLv3();
            break;
#endif

#ifndef NO_TLS
    #ifndef NO_OLD_TLS
        case WOLFSSL_TLSV1:
            ssl->version = MakeTLSv1();
            break;

        case WOLFSSL_TLSV1_1:
            ssl->version = MakeTLSv1_1();
            break;
    #endif
        case WOLFSSL_TLSV1_2:
            ssl->version = MakeTLSv1_2();
            break;
#endif

        default:
            WOLFSSL_MSG("Bad function argument");
            return BAD_FUNC_ARG;
    }

    #ifdef NO_RSA
        haveRSA = 0;
    #endif
    #ifndef NO_PSK
        havePSK = ssl->options.havePSK;
    #endif

    InitSuites(ssl->suites, ssl->version, haveRSA, havePSK, ssl->options.haveDH,
                ssl->options.haveNTRU, ssl->options.haveECDSAsig,
                ssl->options.haveStaticECC, ssl->options.side);

    return SSL_SUCCESS;
}
#endif /* !leanpsk */



#ifndef NO_SESSION_CACHE

    /* basic config gives a cache with 33 sessions, adequate for clients and
       embedded servers

       MEDIUM_SESSION_CACHE allows 1055 sessions, adequate for servers that
       aren't under heavy load, basically allows 200 new sessions per minute

       BIG_SESSION_CACHE yields 20,027 sessions

       HUGE_SESSION_CACHE yields 65,791 sessions, for servers under heavy load,
       allows over 13,000 new sessions per minute or over 200 new sessions per
       second

       SMALL_SESSION_CACHE only stores 6 sessions, good for embedded clients
       or systems where the default of nearly 3kB is too much RAM, this define
       uses less than 500 bytes RAM

       default SESSION_CACHE stores 33 sessions (no XXX_SESSION_CACHE defined)
    */
    #ifdef HUGE_SESSION_CACHE
        #define SESSIONS_PER_ROW 11
        #define SESSION_ROWS 5981
    #elif defined(BIG_SESSION_CACHE)
        #define SESSIONS_PER_ROW 7
        #define SESSION_ROWS 2861
    #elif defined(MEDIUM_SESSION_CACHE)
        #define SESSIONS_PER_ROW 5
        #define SESSION_ROWS 211
    #elif defined(SMALL_SESSION_CACHE)
        #define SESSIONS_PER_ROW 2
        #define SESSION_ROWS 3
    #else
        #define SESSIONS_PER_ROW 3
        #define SESSION_ROWS 11
    #endif

    typedef struct SessionRow {
        int nextIdx;                           /* where to place next one   */
        int totalCount;                        /* sessions ever on this row */
        WOLFSSL_SESSION Sessions[SESSIONS_PER_ROW];
    } SessionRow;

    SessionRow SessionCache[SESSION_ROWS];

    #if defined(WOLFSSL_SESSION_STATS) && defined(WOLFSSL_PEAK_SESSIONS)
        word32 PeakSessions;
    #endif

    wolfSSL_Mutex session_mutex;   /* SessionCache mutex */

    #ifndef NO_CLIENT_CACHE

        typedef struct ClientSession {
            word16 serverRow;            /* SessionCache Row id */
            word16 serverIdx;            /* SessionCache Idx (column) */
        } ClientSession;

        typedef struct ClientRow {
            int nextIdx;                /* where to place next one   */
            int totalCount;             /* sessions ever on this row */
            ClientSession Clients[SESSIONS_PER_ROW];
        } ClientRow;

        ClientRow ClientCache[SESSION_ROWS];  /* Client Cache */
                                                     /* uses session mutex */
    #endif  /* NO_CLIENT_CACHE */

#endif /* NO_SESSION_CACHE */


#ifndef NO_SESSION_CACHE

WOLFSSL_SESSION* wolfSSL_get_session(WOLFSSL* ssl)
{
	WOLFSSL_ENTER();
    if (ssl)
        return GetSession(ssl, 0);

    return NULL;
}


int wolfSSL_set_session(WOLFSSL* ssl, WOLFSSL_SESSION* session)
{
	WOLFSSL_ENTER();
    if (session)
        return SetSession(ssl, session);

    return SSL_FAILURE;
}


#ifndef NO_CLIENT_CACHE

/* Associate client session with serverID, find existing or store for saving
   if newSession flag on, don't reuse existing session
   SSL_SUCCESS on ok */
int wolfSSL_SetServerID(WOLFSSL* ssl, const byte* id, int len, int newSession)
{
    WOLFSSL_SESSION* session = NULL;

	WOLFSSL_ENTER();

    if (ssl == NULL || id == NULL || len <= 0)
        return BAD_FUNC_ARG;

    if (newSession == 0) {
        session = GetSessionClient(ssl, id, len);
        if (session) {
            if (SetSession(ssl, session) != SSL_SUCCESS) {
                WOLFSSL_MSG("SetSession failed");
                session = NULL;
            }
        }
    }

    if (session == NULL) {
        WOLFSSL_MSG("Valid ServerID not cached already");

        ssl->session.idLen = (word16)min(SERVER_ID_LEN, (word32)len);
        XMEMCPY(ssl->session.serverID, id, ssl->session.idLen);
    }

    return SSL_SUCCESS;
}

#endif /* NO_CLIENT_CACHE */

#if defined(PERSIST_SESSION_CACHE)

/* for persistance, if changes to layout need to increment and modify
   save_session_cache() and restore_session_cache and memory versions too */
#define WOLFSSL_CACHE_VERSION 2

/* Session Cache Header information */
typedef struct {
    int version;     /* cache layout version id */
    int rows;        /* session rows */
    int columns;     /* session columns */
    int sessionSz;   /* sizeof WOLFSSL_SESSION */
} cache_header_t;

/* current persistence layout is:

   1) cache_header_t
   2) SessionCache
   3) ClientCache

   update WOLFSSL_CACHE_VERSION if change layout for the following
   PERSISTENT_SESSION_CACHE functions
*/


/* get how big the the session cache save buffer needs to be */
int wolfSSL_get_session_cache_memsize(void)
{
    int sz  = (int)(sizeof(SessionCache) + sizeof(cache_header_t));

    #ifndef NO_CLIENT_CACHE
        sz += (int)(sizeof(ClientCache));
    #endif

    return sz;
}


/* Persist session cache to memory */
int wolfSSL_memsave_session_cache(void* mem, int sz)
{
    int i;
    cache_header_t cache_header;
    SessionRow*    row  = (SessionRow*)((byte*)mem + sizeof(cache_header));
#ifndef NO_CLIENT_CACHE
    ClientRow*     clRow;
#endif

	WOLFSSL_ENTER();

    if (sz < wolfSSL_get_session_cache_memsize()) {
        WOLFSSL_MSG("Memory buffer too small");
        return BUFFER_E;
    }

    cache_header.version   = WOLFSSL_CACHE_VERSION;
    cache_header.rows      = SESSION_ROWS;
    cache_header.columns   = SESSIONS_PER_ROW;
    cache_header.sessionSz = (int)sizeof(WOLFSSL_SESSION);
    XMEMCPY(mem, &cache_header, sizeof(cache_header));

    if (LockMutex(&session_mutex) != 0) {
        WOLFSSL_MSG("Session cache mutex lock failed");
        return BAD_MUTEX_E;
    }

    for (i = 0; i < cache_header.rows; ++i)
        XMEMCPY(row++, SessionCache + i, sizeof(SessionRow));

#ifndef NO_CLIENT_CACHE
    clRow = (ClientRow*)row;
    for (i = 0; i < cache_header.rows; ++i)
        XMEMCPY(clRow++, ClientCache + i, sizeof(ClientRow));
#endif

    UnLockMutex(&session_mutex);

    WOLFSSL_LEAVE( SSL_SUCCESS);

    return SSL_SUCCESS;
}


/* Restore the persistant session cache from memory */
int wolfSSL_memrestore_session_cache(const void* mem, int sz)
{
    int    i;
    cache_header_t cache_header;
    SessionRow*    row  = (SessionRow*)((byte*)mem + sizeof(cache_header));
#ifndef NO_CLIENT_CACHE
    ClientRow*     clRow;
#endif

	WOLFSSL_ENTER();

    if (sz < wolfSSL_get_session_cache_memsize()) {
        WOLFSSL_MSG("Memory buffer too small");
        return BUFFER_E;
    }

    XMEMCPY(&cache_header, mem, sizeof(cache_header));
    if (cache_header.version   != WOLFSSL_CACHE_VERSION ||
        cache_header.rows      != SESSION_ROWS ||
        cache_header.columns   != SESSIONS_PER_ROW ||
        cache_header.sessionSz != (int)sizeof(WOLFSSL_SESSION)) {

        WOLFSSL_MSG("Session cache header match failed");
        return CACHE_MATCH_ERROR;
    }

    if (LockMutex(&session_mutex) != 0) {
        WOLFSSL_MSG("Session cache mutex lock failed");
        return BAD_MUTEX_E;
    }

    for (i = 0; i < cache_header.rows; ++i)
        XMEMCPY(SessionCache + i, row++, sizeof(SessionRow));

#ifndef NO_CLIENT_CACHE
    clRow = (ClientRow*)row;
    for (i = 0; i < cache_header.rows; ++i)
        XMEMCPY(ClientCache + i, clRow++, sizeof(ClientRow));
#endif

    UnLockMutex(&session_mutex);

    WOLFSSL_LEAVE( SSL_SUCCESS);

    return SSL_SUCCESS;
}

#if !defined(NO_FILESYSTEM)

/* Persist session cache to file */
/* doesn't use memsave because of additional memory use */
int wolfSSL_save_session_cache(const char *fname)
{
    XFILE  file;
    int    ret;
    int    rc = SSL_SUCCESS;
    int    i;
    cache_header_t cache_header;

	WOLFSSL_ENTER();

    file = XFOPEN(fname, "w+b");
    if (file == XBADFILE) {
        WOLFSSL_MSG("Couldn't open session cache save file");
        return SSL_BAD_FILE;
    }
    cache_header.version   = WOLFSSL_CACHE_VERSION;
    cache_header.rows      = SESSION_ROWS;
    cache_header.columns   = SESSIONS_PER_ROW;
    cache_header.sessionSz = (int)sizeof(WOLFSSL_SESSION);

    /* cache header */
    ret = (int)XFWRITE(&cache_header, sizeof cache_header, 1, file);
    if (ret != 1) {
        WOLFSSL_MSG("Session cache header file write failed");
        XFCLOSE(file);
        return FWRITE_ERROR;
    }

    if (LockMutex(&session_mutex) != 0) {
        WOLFSSL_MSG("Session cache mutex lock failed");
        XFCLOSE(file);
        return BAD_MUTEX_E;
    }

    /* session cache */
    for (i = 0; i < cache_header.rows; ++i) {
        ret = (int)XFWRITE(SessionCache + i, sizeof(SessionRow), 1, file);
        if (ret != 1) {
            WOLFSSL_MSG("Session cache member file write failed");
            rc = FWRITE_ERROR;
            break;
        }
    }

#ifndef NO_CLIENT_CACHE
    /* client cache */
    for (i = 0; i < cache_header.rows; ++i) {
        ret = (int)XFWRITE(ClientCache + i, sizeof(ClientRow), 1, file);
        if (ret != 1) {
            WOLFSSL_MSG("Client cache member file write failed");
            rc = FWRITE_ERROR;
            break;
        }
    }
#endif /* NO_CLIENT_CACHE */

    UnLockMutex(&session_mutex);

    XFCLOSE(file);
    WOLFSSL_LEAVE( rc);

    return rc;
}


/* Restore the persistant session cache from file */
/* doesn't use memstore because of additional memory use */
int wolfSSL_restore_session_cache(const char *fname)
{
    XFILE  file;
    int    rc = SSL_SUCCESS;
    int    ret;
    int    i;
    cache_header_t cache_header;

	WOLFSSL_ENTER();

    file = XFOPEN(fname, "rb");
    if (file == XBADFILE) {
        WOLFSSL_MSG("Couldn't open session cache save file");
        return SSL_BAD_FILE;
    }
    /* cache header */
    ret = (int)XFREAD(&cache_header, sizeof cache_header, 1, file);
    if (ret != 1) {
        WOLFSSL_MSG("Session cache header file read failed");
        XFCLOSE(file);
        return FREAD_ERROR;
    }
    if (cache_header.version   != WOLFSSL_CACHE_VERSION ||
        cache_header.rows      != SESSION_ROWS ||
        cache_header.columns   != SESSIONS_PER_ROW ||
        cache_header.sessionSz != (int)sizeof(WOLFSSL_SESSION)) {

        WOLFSSL_MSG("Session cache header match failed");
        XFCLOSE(file);
        return CACHE_MATCH_ERROR;
    }

    if (LockMutex(&session_mutex) != 0) {
        WOLFSSL_MSG("Session cache mutex lock failed");
        XFCLOSE(file);
        return BAD_MUTEX_E;
    }

    /* session cache */
    for (i = 0; i < cache_header.rows; ++i) {
        ret = (int)XFREAD(SessionCache + i, sizeof(SessionRow), 1, file);
        if (ret != 1) {
            WOLFSSL_MSG("Session cache member file read failed");
            XMEMSET(SessionCache, 0, sizeof SessionCache);
            rc = FREAD_ERROR;
            break;
        }
    }

#ifndef NO_CLIENT_CACHE
    /* client cache */
    for (i = 0; i < cache_header.rows; ++i) {
        ret = (int)XFREAD(ClientCache + i, sizeof(ClientRow), 1, file);
        if (ret != 1) {
            WOLFSSL_MSG("Client cache member file read failed");
            XMEMSET(ClientCache, 0, sizeof ClientCache);
            rc = FREAD_ERROR;
            break;
        }
    }

#endif /* NO_CLIENT_CACHE */

    UnLockMutex(&session_mutex);

    XFCLOSE(file);
    WOLFSSL_LEAVE( rc);

    return rc;
}

#endif /* !NO_FILESYSTEM */
#endif /* PERSIST_SESSION_CACHE */
#endif /* NO_SESSION_CACHE */



#ifdef HAVE_SECRET_CALLBACK

int wolfSSL_set_session_secret_cb(WOLFSSL* ssl, SessionSecretCb cb, void* ctx)
{
	WOLFSSL_ENTER();
    if (ssl == NULL)
        return SSL_FATAL_ERROR;

    ssl->sessionSecretCb = cb;
    ssl->sessionSecretCtx = ctx;
    /* If using a pre-set key, assume session resumption. */
    ssl->session.sessionIDSz = 0;
    ssl->options.resuming = 1;

    return SSL_SUCCESS;
}

#endif


#ifndef NO_SESSION_CACHE

/* on by default if built in but allow user to turn off */
long wolfSSL_CTX_set_session_cache_mode(WOLFSSL_CTX* ctx, long mode)
{
	WOLFSSL_ENTER();
    if (mode == SSL_SESS_CACHE_OFF)
        ctx->sessionCacheOff = 1;

    if (mode == SSL_SESS_CACHE_NO_AUTO_CLEAR)
        ctx->sessionCacheFlushOff = 1;

    return SSL_SUCCESS;
}

#endif /* NO_SESSION_CACHE */


#if !defined(NO_CERTS)
#if defined(PERSIST_CERT_CACHE)


#define WOLFSSL_CACHE_CERT_VERSION 1

typedef struct {
    int version;                 /* cache cert layout version id */
    int rows;                    /* hash table rows, CA_TABLE_SIZE */
    int columns[CA_TABLE_SIZE];  /* columns per row on list */
    int signerSz;                /* sizeof Signer object */
} CertCacheHeader;

/* current cert persistance layout is:

   1) CertCacheHeader
   2) caTable

   update WOLFSSL_CERT_CACHE_VERSION if change layout for the following
   PERSIST_CERT_CACHE functions
*/


/* Return memory needed to persist this signer, have lock */
static INLINE int GetSignerMemory(Signer* signer)
{
    int sz = sizeof(signer->pubKeySize) + sizeof(signer->keyOID)
           + sizeof(signer->nameLen)    + sizeof(signer->subjectNameHash);

#if !defined(NO_SKID)
        sz += (int)sizeof(signer->subjectKeyIdHash);
#endif

    /* add dynamic bytes needed */
    sz += signer->pubKeySize;
    sz += signer->nameLen;

    return sz;
}


/* Return memory needed to persist this row, have lock */
static INLINE int GetCertCacheRowMemory(Signer* row)
{
    int sz = 0;

    while (row) {
        sz += GetSignerMemory(row);
        row = row->next;
    }

    return sz;
}


/* get the size of persist cert cache, have lock */
static INLINE int GetCertCacheMemSize(WOLFSSL_CERT_MANAGER* cm)
{
    int sz;
    int i;

    sz = sizeof(CertCacheHeader);

    for (i = 0; i < CA_TABLE_SIZE; i++)
        sz += GetCertCacheRowMemory(cm->caTable[i]);

    return sz;
}


/* Store cert cache header columns with number of items per list, have lock */
static INLINE void SetCertHeaderColumns(WOLFSSL_CERT_MANAGER* cm, int* columns)
{
    int     i;
    Signer* row;

    for (i = 0; i < CA_TABLE_SIZE; i++) {
        int count = 0;
        row = cm->caTable[i];

        while (row) {
            ++count;
            row = row->next;
        }
        columns[i] = count;
    }
}


/* Restore whole cert row from memory, have lock, return bytes consumed,
   < 0 on error, have lock */
static INLINE int RestoreCertRow(WOLFSSL_CERT_MANAGER* cm, byte* current,
                                 int row, int listSz, const byte* end)
{
    int idx = 0;

    if (listSz < 0) {
        WOLFSSL_MSG("Row header corrupted, negative value");
        return PARSE_ERROR;
    }

    while (listSz) {
        Signer* signer;
        byte*   start = current + idx;  /* for end checks on this signer */
        int     minSz = sizeof(signer->pubKeySize) + sizeof(signer->keyOID) +
                      sizeof(signer->nameLen) + sizeof(signer->subjectNameHash);
        #ifndef NO_SKID
                minSz += (int)sizeof(signer->subjectKeyIdHash);
        #endif

        if (start + minSz > end) {
            WOLFSSL_MSG("Would overread restore buffer");
            return BUFFER_E;
        }
        signer = MakeSigner(cm->heap);
        if (signer == NULL)
            return MEMORY_E;

        /* pubKeySize */
        XMEMCPY(&signer->pubKeySize, current + idx, sizeof(signer->pubKeySize));
        idx += (int)sizeof(signer->pubKeySize);

        /* keyOID */
        XMEMCPY(&signer->keyOID, current + idx, sizeof(signer->keyOID));
        idx += (int)sizeof(signer->keyOID);

        /* pulicKey */
        if (start + minSz + signer->pubKeySize > end) {
            WOLFSSL_MSG("Would overread restore buffer");
            FreeSigner(signer, cm->heap);
            return BUFFER_E;
        }
        signer->publicKey = (byte*)XMALLOC(signer->pubKeySize, cm->heap,
                                           DYNAMIC_TYPE_KEY);
        if (signer->publicKey == NULL) {
            FreeSigner(signer, cm->heap);
            return MEMORY_E;
        }

        XMEMCPY(signer->publicKey, current + idx, signer->pubKeySize);
        idx += signer->pubKeySize;

        /* nameLen */
        XMEMCPY(&signer->nameLen, current + idx, sizeof(signer->nameLen));
        idx += (int)sizeof(signer->nameLen);

        /* name */
        if (start + minSz + signer->pubKeySize + signer->nameLen > end) {
            WOLFSSL_MSG("Would overread restore buffer");
            FreeSigner(signer, cm->heap);
            return BUFFER_E;
        }
        signer->name = (char*)XMALLOC(signer->nameLen, cm->heap,
                                      DYNAMIC_TYPE_SUBJECT_CN);
        if (signer->name == NULL) {
            FreeSigner(signer, cm->heap);
            return MEMORY_E;
        }

        XMEMCPY(signer->name, current + idx, signer->nameLen);
        idx += signer->nameLen;

        /* subjectNameHash */
        XMEMCPY(signer->subjectNameHash, current + idx, SIGNER_DIGEST_SIZE);
        idx += SIGNER_DIGEST_SIZE;

        #ifndef NO_SKID
            /* subjectKeyIdHash */
            XMEMCPY(signer->subjectKeyIdHash, current + idx,SIGNER_DIGEST_SIZE);
            idx += SIGNER_DIGEST_SIZE;
        #endif

        signer->next = cm->caTable[row];
        cm->caTable[row] = signer;

        --listSz;
    }

    return idx;
}


/* Store whole cert row into memory, have lock, return bytes added */
static INLINE int StoreCertRow(WOLFSSL_CERT_MANAGER* cm, byte* current, int row)
{
    int     added  = 0;
    Signer* list   = cm->caTable[row];

    while (list) {
        XMEMCPY(current + added, &list->pubKeySize, sizeof(list->pubKeySize));
        added += (int)sizeof(list->pubKeySize);

        XMEMCPY(current + added, &list->keyOID,     sizeof(list->keyOID));
        added += (int)sizeof(list->keyOID);

        XMEMCPY(current + added, list->publicKey, list->pubKeySize);
        added += list->pubKeySize;

        XMEMCPY(current + added, &list->nameLen, sizeof(list->nameLen));
        added += (int)sizeof(list->nameLen);

        XMEMCPY(current + added, list->name, list->nameLen);
        added += list->nameLen;

        XMEMCPY(current + added, list->subjectNameHash, SIGNER_DIGEST_SIZE);
        added += SIGNER_DIGEST_SIZE;

        #ifndef NO_SKID
            XMEMCPY(current + added, list->subjectKeyIdHash,SIGNER_DIGEST_SIZE);
            added += SIGNER_DIGEST_SIZE;
        #endif

        list = list->next;
    }

    return added;
}


/* Persist cert cache to memory, have lock */
static INLINE int DoMemSaveCertCache(WOLFSSL_CERT_MANAGER* cm, void* mem, int sz)
{
    int realSz;
    int ret = SSL_SUCCESS;
    int i;

	WOLFSSL_ENTER();

    realSz = GetCertCacheMemSize(cm);
    if (realSz > sz) {
        WOLFSSL_MSG("Mem output buffer too small");
        ret = BUFFER_E;
    }
    else {
        byte*           current;
        CertCacheHeader hdr;

        hdr.version  = WOLFSSL_CACHE_CERT_VERSION;
        hdr.rows     = CA_TABLE_SIZE;
        SetCertHeaderColumns(cm, hdr.columns);
        hdr.signerSz = (int)sizeof(Signer);

        XMEMCPY(mem, &hdr, sizeof(CertCacheHeader));
        current = (byte*)mem + sizeof(CertCacheHeader);

        for (i = 0; i < CA_TABLE_SIZE; ++i)
            current += StoreCertRow(cm, current, i);
    }

    return ret;
}


#if !defined(NO_FILESYSTEM)

/* Persist cert cache to file */
int CM_SaveCertCache(WOLFSSL_CERT_MANAGER* cm, const char* fname)
{
    XFILE file;
    int   rc = SSL_SUCCESS;
    int   memSz;
    byte* mem;

	WOLFSSL_ENTER();

    file = XFOPEN(fname, "w+b");
    if (file == XBADFILE) {
       WOLFSSL_MSG("Couldn't open cert cache save file");
       return SSL_BAD_FILE;
    }

    if (LockMutex(&cm->caLock) != 0) {
        WOLFSSL_MSG("LockMutex on caLock failed");
        XFCLOSE(file);
        return BAD_MUTEX_E;
    }

    memSz = GetCertCacheMemSize(cm);
    mem   = (byte*)XMALLOC(memSz, cm->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (mem == NULL) {
        WOLFSSL_MSG("Alloc for tmp buffer failed");
        rc = MEMORY_E;
    } else {
        rc = DoMemSaveCertCache(cm, mem, memSz);
        if (rc == SSL_SUCCESS) {
            int ret = (int)XFWRITE(mem, memSz, 1, file);
            if (ret != 1) {
                WOLFSSL_MSG("Cert cache file write failed");
                rc = FWRITE_ERROR;
            }
        }
        XFREE(mem, cm->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    UnLockMutex(&cm->caLock);
    XFCLOSE(file);

    return rc;
}


/* Restore cert cache from file */
int CM_RestoreCertCache(WOLFSSL_CERT_MANAGER* cm, const char* fname)
{
    XFILE file;
    int   rc = SSL_SUCCESS;
    int   ret;
    int   memSz;
    byte* mem;

	WOLFSSL_ENTER();

    file = XFOPEN(fname, "rb");
    if (file == XBADFILE) {
       WOLFSSL_MSG("Couldn't open cert cache save file");
       return SSL_BAD_FILE;
    }

    XFSEEK(file, 0, XSEEK_END);
    memSz = (int)XFTELL(file);
    XREWIND(file);

    if (memSz <= 0) {
        WOLFSSL_MSG("Bad file size");
        XFCLOSE(file);
        return SSL_BAD_FILE;
    }

    mem = (byte*)XMALLOC(memSz, cm->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (mem == NULL) {
        WOLFSSL_MSG("Alloc for tmp buffer failed");
        XFCLOSE(file);
        return MEMORY_E;
    }

    ret = (int)XFREAD(mem, memSz, 1, file);
    if (ret != 1) {
        WOLFSSL_MSG("Cert file read error");
        rc = FREAD_ERROR;
    } else {
        rc = CM_MemRestoreCertCache(cm, mem, memSz);
        if (rc != SSL_SUCCESS) {
            WOLFSSL_MSG("Mem restore cert cache failed");
        }
    }

    XFREE(mem, cm->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFCLOSE(file);

    return rc;
}

#endif /* NO_FILESYSTEM */


/* Persist cert cache to memory */
int CM_MemSaveCertCache(WOLFSSL_CERT_MANAGER* cm, void* mem, int sz, int* used)
{
    int ret = SSL_SUCCESS;

	WOLFSSL_ENTER();

    if (LockMutex(&cm->caLock) != 0) {
        WOLFSSL_MSG("LockMutex on caLock failed");
        return BAD_MUTEX_E;
    }

    ret = DoMemSaveCertCache(cm, mem, sz);
    if (ret == SSL_SUCCESS)
        *used  = GetCertCacheMemSize(cm);

    UnLockMutex(&cm->caLock);

    return ret;
}


/* Restore cert cache from memory */
int CM_MemRestoreCertCache(WOLFSSL_CERT_MANAGER* cm, const void* mem, int sz)
{
    int ret = SSL_SUCCESS;
    int i;
    CertCacheHeader* hdr = (CertCacheHeader*)mem;
    byte*            current = (byte*)mem + sizeof(CertCacheHeader);
    byte*            end     = (byte*)mem + sz;  /* don't go over */

	WOLFSSL_ENTER();

    if (current > end) {
        WOLFSSL_MSG("Cert Cache Memory buffer too small");
        return BUFFER_E;
    }

    if (hdr->version  != WOLFSSL_CACHE_CERT_VERSION ||
        hdr->rows     != CA_TABLE_SIZE ||
        hdr->signerSz != (int)sizeof(Signer)) {

        WOLFSSL_MSG("Cert Cache Memory header mismatch");
        return CACHE_MATCH_ERROR;
    }

    if (LockMutex(&cm->caLock) != 0) {
        WOLFSSL_MSG("LockMutex on caLock failed");
        return BAD_MUTEX_E;
    }

    FreeSignerTable(cm->caTable, CA_TABLE_SIZE, cm->heap);

    for (i = 0; i < CA_TABLE_SIZE; ++i) {
        int added = RestoreCertRow(cm, current, i, hdr->columns[i], end);
        if (added < 0) {
            WOLFSSL_MSG("RestoreCertRow error");
            ret = added;
            break;
        }
        current += added;
    }

    UnLockMutex(&cm->caLock);

    return ret;
}


/* get how big the the cert cache save buffer needs to be */
int CM_GetCertCacheMemSize(WOLFSSL_CERT_MANAGER* cm)
{
    int sz;

	WOLFSSL_ENTER();

    if (LockMutex(&cm->caLock) != 0) {
        WOLFSSL_MSG("LockMutex on caLock failed");
        return BAD_MUTEX_E;
    }

    sz = GetCertCacheMemSize(cm);

    UnLockMutex(&cm->caLock);

    return sz;
}

#endif /* PERSIST_CERT_CACHE */
#endif /* NO_CERTS */


#ifndef WOLFSSL_LEANPSK
#ifdef WOLFSSL_DTLS

int wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl)
{
    (void)ssl;

    return ssl->dtls_timeout;
}


/* user may need to alter init dtls recv timeout, SSL_SUCCESS on ok */
int wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int timeout)
{
    if (ssl == NULL || timeout < 0)
        return BAD_FUNC_ARG;

    if (timeout > ssl->dtls_timeout_max) {
        WOLFSSL_MSG("Can't set dtls timeout init greater than dtls timeout max");
        return BAD_FUNC_ARG;
    }

    ssl->dtls_timeout_init = timeout;
    ssl->dtls_timeout = timeout;

    return SSL_SUCCESS;
}


/* user may need to alter max dtls recv timeout, SSL_SUCCESS on ok */
int wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int timeout)
{
    if (ssl == NULL || timeout < 0)
        return BAD_FUNC_ARG;

    if (timeout < ssl->dtls_timeout_init) {
        WOLFSSL_MSG("Can't set dtls timeout max less than dtls timeout init");
        return BAD_FUNC_ARG;
    }

    ssl->dtls_timeout_max = timeout;

    return SSL_SUCCESS;
}


int wolfSSL_dtls_got_timeout(WOLFSSL* ssl)
{
    int result = SSL_SUCCESS;

    DtlsMsgListDelete(ssl->dtls_msg_list, ssl->heap);
    ssl->dtls_msg_list = NULL;
    if (DtlsPoolTimeout(ssl) < 0 || DtlsPoolSend(ssl) < 0) {
        result = SSL_FATAL_ERROR;
    }
    return result;
}

#endif /* DTLS */
#endif /* LEANPSK */



#ifndef NO_HANDSHAKE_DONE_CB

int wolfSSL_SetHsDoneCb(WOLFSSL* ssl, HandShakeDoneCb cb, void* user_ctx)
{
	WOLFSSL_ENTER();

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->hsDoneCb  = cb;
    ssl->hsDoneCtx = user_ctx;


    return SSL_SUCCESS;
}

#endif /* NO_HANDSHAKE_DONE_CB */


#ifndef NO_SESSION_CACHE


/* some session IDs aren't random afterall, let's make them random */
static INLINE word32 HashSession(const byte* sessionID, word32 len, int* error)
{
    byte digest[MAX_DIGEST_SIZE];

#ifndef NO_MD5
    *error =  wc_Md5Hash(sessionID, len, digest);
#elif !defined(NO_SHA)
    *error =  wc_ShaHash(sessionID, len, digest);
#elif !defined(NO_SHA256)
    *error =  wc_Sha256Hash(sessionID, len, digest);
#else
    #error "We need a digest to hash the session IDs"
#endif

    return *error == 0 ? MakeWordFromHash(digest) : 0; /* 0 on failure */
}


void wolfSSL_flush_sessions(WOLFSSL_CTX* ctx, long tm)
{
    /* static table now, no flusing needed */
    (void)ctx;
    (void)tm;
}


/* set ssl session timeout in seconds */
int wolfSSL_set_timeout(WOLFSSL* ssl, unsigned int to)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->timeout = to;

    return SSL_SUCCESS;
}


/* set ctx session timeout in seconds */
int wolfSSL_CTX_set_timeout(WOLFSSL_CTX* ctx, unsigned int to)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->timeout = to;

    return SSL_SUCCESS;
}


#ifndef NO_CLIENT_CACHE

/* Get Session from Client cache based on id/len, return NULL on failure */
WOLFSSL_SESSION* GetSessionClient(WOLFSSL* ssl, const byte* id, int len)
{
    WOLFSSL_SESSION* ret = NULL;
    word32          row;
    int             idx;
    int             count;
    int             error = 0;

	WOLFSSL_ENTER();

    if (ssl->options.side == WOLFSSL_SERVER_END)
        return NULL;

    len = min(SERVER_ID_LEN, (word32)len);
    row = HashSession(id, len, &error) % SESSION_ROWS;
    if (error != 0) {
        WOLFSSL_MSG("Hash session failed");
        return NULL;
    }

    if (LockMutex(&session_mutex) != 0) {
        WOLFSSL_MSG("Lock session mutex failed");
        return NULL;
    }

    /* start from most recently used */
    count = min((word32)ClientCache[row].totalCount, SESSIONS_PER_ROW);
    idx = ClientCache[row].nextIdx - 1;
    if (idx < 0)
        idx = SESSIONS_PER_ROW - 1; /* if back to front, the previous was end */

    for (; count > 0; --count, idx = idx ? idx - 1 : SESSIONS_PER_ROW - 1) {
        WOLFSSL_SESSION* current;
        ClientSession   clSess;

        if (idx >= SESSIONS_PER_ROW || idx < 0) { /* sanity check */
            WOLFSSL_MSG("Bad idx");
            break;
        }

        clSess = ClientCache[row].Clients[idx];

        current = &SessionCache[clSess.serverRow].Sessions[clSess.serverIdx];
        if (XMEMCMP(current->serverID, id, len) == 0) {
            WOLFSSL_MSG("Found a serverid match for client");
            if (LowResTimer() < (current->bornOn + current->timeout)) {
                WOLFSSL_MSG("Session valid");
                ret = current;
                break;
            } else {
                WOLFSSL_MSG("Session timed out");  /* could have more for id */
            }
        } else {
            WOLFSSL_MSG("ServerID not a match from client table");
        }
    }

    UnLockMutex(&session_mutex);

    return ret;
}

#endif /* NO_CLIENT_CACHE */


WOLFSSL_SESSION* GetSession(WOLFSSL* ssl, byte* masterSecret)
{
    WOLFSSL_SESSION* ret = 0;
    const byte*  id = NULL;
    word32       row;
    int          idx;
    int          count;
    int          error = 0;

    if (ssl->options.sessionCacheOff)
        return NULL;

    if (ssl->options.haveSessionId == 0)
        return NULL;

#ifdef HAVE_SESSION_TICKET
    if (ssl->options.side == WOLFSSL_SERVER_END && ssl->options.useTicket == 1)
        return NULL;
#endif

    if (ssl->arrays)
        id = ssl->arrays->sessionID;
    else
        id = ssl->session.sessionID;

    row = HashSession(id, ID_LEN, &error) % SESSION_ROWS;
    if (error != 0) {
        WOLFSSL_MSG("Hash session failed");
        return NULL;
    }

    if (LockMutex(&session_mutex) != 0)
        return 0;

    /* start from most recently used */
    count = min((word32)SessionCache[row].totalCount, SESSIONS_PER_ROW);
    idx = SessionCache[row].nextIdx - 1;
    if (idx < 0)
        idx = SESSIONS_PER_ROW - 1; /* if back to front, the previous was end */

    for (; count > 0; --count, idx = idx ? idx - 1 : SESSIONS_PER_ROW - 1) {
        WOLFSSL_SESSION* current;

        if (idx >= SESSIONS_PER_ROW || idx < 0) { /* sanity check */
            WOLFSSL_MSG("Bad idx");
            break;
        }

        current = &SessionCache[row].Sessions[idx];
        if (XMEMCMP(current->sessionID, id, ID_LEN) == 0) {
            WOLFSSL_MSG("Found a session match");
            if (LowResTimer() < (current->bornOn + current->timeout)) {
                WOLFSSL_MSG("Session valid");
                ret = current;
                if (masterSecret)
                    XMEMCPY(masterSecret, current->masterSecret, SECRET_LEN);
            } else {
                WOLFSSL_MSG("Session timed out");
            }
            break;  /* no more sessionIDs whether valid or not that match */
        } else {
            WOLFSSL_MSG("SessionID not a match at this idx");
        }
    }

    UnLockMutex(&session_mutex);

    return ret;
}


int SetSession(WOLFSSL* ssl, WOLFSSL_SESSION* session)
{
    if (ssl->options.sessionCacheOff)
        return SSL_FAILURE;

    if (LowResTimer() < (session->bornOn + session->timeout)) {
        ssl->session  = *session;
        ssl->options.resuming = 1;

#ifdef SESSION_CERTS
        ssl->version              = session->version;
        ssl->options.cipherSuite0 = session->cipherSuite0;
        ssl->options.cipherSuite  = session->cipherSuite;
#endif

        return SSL_SUCCESS;
    }
    return SSL_FAILURE;  /* session timed out */
}


#ifdef WOLFSSL_SESSION_STATS
static int get_locked_session_stats(word32* active, word32* total,
                                    word32* peak);
#endif

int AddSession(WOLFSSL* ssl)
{
    word32 row, idx;
    int    error = 0;

    if (ssl->options.sessionCacheOff)
        return 0;

    if (ssl->options.haveSessionId == 0)
        return 0;

#ifdef HAVE_SESSION_TICKET
    if (ssl->options.side == WOLFSSL_SERVER_END && ssl->options.useTicket == 1)
        return 0;
#endif

    row = HashSession(ssl->arrays->sessionID, ID_LEN, &error) % SESSION_ROWS;
    if (error != 0) {
        WOLFSSL_MSG("Hash session failed");
        return error;
    }

    if (LockMutex(&session_mutex) != 0)
        return BAD_MUTEX_E;

    idx = SessionCache[row].nextIdx++;
#ifdef SESSION_INDEX
    ssl->sessionIndex = (row << SESSIDX_ROW_SHIFT) | idx;
#endif

    XMEMCPY(SessionCache[row].Sessions[idx].masterSecret,
           ssl->arrays->masterSecret, SECRET_LEN);
    XMEMCPY(SessionCache[row].Sessions[idx].sessionID, ssl->arrays->sessionID,
           ID_LEN);
    SessionCache[row].Sessions[idx].sessionIDSz = ssl->arrays->sessionIDSz;

    SessionCache[row].Sessions[idx].timeout = ssl->timeout;
    SessionCache[row].Sessions[idx].bornOn  = LowResTimer();

#ifdef HAVE_SESSION_TICKET
    SessionCache[row].Sessions[idx].ticketLen     = ssl->session.ticketLen;
    XMEMCPY(SessionCache[row].Sessions[idx].ticket,
                                   ssl->session.ticket, ssl->session.ticketLen);
#endif

#ifdef SESSION_CERTS
    SessionCache[row].Sessions[idx].chain.count = ssl->session.chain.count;
    XMEMCPY(SessionCache[row].Sessions[idx].chain.certs,
           ssl->session.chain.certs, sizeof(x509_buffer) * MAX_CHAIN_DEPTH);

    SessionCache[row].Sessions[idx].version      = ssl->version;
    SessionCache[row].Sessions[idx].cipherSuite0 = ssl->options.cipherSuite0;
    SessionCache[row].Sessions[idx].cipherSuite  = ssl->options.cipherSuite;
#endif /* SESSION_CERTS */

    SessionCache[row].totalCount++;
    if (SessionCache[row].nextIdx == SESSIONS_PER_ROW)
        SessionCache[row].nextIdx = 0;

#ifndef NO_CLIENT_CACHE
    if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->session.idLen) {
        word32 clientRow, clientIdx;

        WOLFSSL_MSG("Adding client cache entry");

        SessionCache[row].Sessions[idx].idLen = ssl->session.idLen;
        XMEMCPY(SessionCache[row].Sessions[idx].serverID, ssl->session.serverID,
                ssl->session.idLen);

        clientRow = HashSession(ssl->session.serverID, ssl->session.idLen,
                                &error) % SESSION_ROWS;
        if (error != 0) {
            WOLFSSL_MSG("Hash session failed");
        } else {
            clientIdx = ClientCache[clientRow].nextIdx++;

            ClientCache[clientRow].Clients[clientIdx].serverRow = (word16)row;
            ClientCache[clientRow].Clients[clientIdx].serverIdx = (word16)idx;

            ClientCache[clientRow].totalCount++;
            if (ClientCache[clientRow].nextIdx == SESSIONS_PER_ROW)
                ClientCache[clientRow].nextIdx = 0;
        }
    }
    else
        SessionCache[row].Sessions[idx].idLen = 0;
#endif /* NO_CLIENT_CACHE */

#if defined(WOLFSSL_SESSION_STATS) && defined(WOLFSSL_PEAK_SESSIONS)
    if (error == 0) {
        word32 active = 0;

        error = get_locked_session_stats(&active, NULL, NULL);
        if (error == SSL_SUCCESS) {
            error = 0;  /* back to this function ok */

            if (active > PeakSessions)
                PeakSessions = active;
        }
    }
#endif /* defined(WOLFSSL_SESSION_STATS) && defined(WOLFSSL_PEAK_SESSIONS) */

    if (UnLockMutex(&session_mutex) != 0)
        return BAD_MUTEX_E;

    return error;
}


#ifdef SESSION_INDEX

int wolfSSL_GetSessionIndex(WOLFSSL* ssl)
{
	WOLFSSL_ENTER();
    WOLFSSL_LEAVE(ssl->sessionIndex);
    return ssl->sessionIndex;
}


int wolfSSL_GetSessionAtIndex(int idx, WOLFSSL_SESSION* session)
{
    int row, col, result = SSL_FAILURE;

	WOLFSSL_ENTER();

    row = idx >> SESSIDX_ROW_SHIFT;
    col = idx & SESSIDX_IDX_MASK;

    if (LockMutex(&session_mutex) != 0) {
        return BAD_MUTEX_E;
    }

    if (row < SESSION_ROWS &&
        col < (int)min(SessionCache[row].totalCount, SESSIONS_PER_ROW)) {
        XMEMCPY(session,
                 &SessionCache[row].Sessions[col], sizeof(WOLFSSL_SESSION));
        result = SSL_SUCCESS;
    }

    if (UnLockMutex(&session_mutex) != 0)
        result = BAD_MUTEX_E;

    WOLFSSL_LEAVE( result);
    return result;
}

#endif /* SESSION_INDEX */

#if defined(SESSION_INDEX) && defined(SESSION_CERTS)

WOLFSSL_X509_CHAIN* wolfSSL_SESSION_get_peer_chain(WOLFSSL_SESSION* session)
{
    WOLFSSL_X509_CHAIN* chain = NULL;

	WOLFSSL_ENTER();
    if (session)
        chain = &session->chain;

    WOLFSSL_LEAVE(chain ? 1 : 0);
    return chain;
}

#endif /* SESSION_INDEX && SESSION_CERTS */


#ifdef WOLFSSL_SESSION_STATS

/* requires session_mutex lock held, SSL_SUCCESS on ok */
static int get_locked_session_stats(word32* active, word32* total, word32* peak)
{
    int result = SSL_SUCCESS;
    int i;
    int count;
    int idx;
    word32 now   = 0;
    word32 seen  = 0;
    word32 ticks = LowResTimer();

    (void)peak;

	WOLFSSL_ENTER();

    for (i = 0; i < SESSION_ROWS; i++) {
        seen += SessionCache[i].totalCount;

        if (active == NULL)
            continue;  /* no need to calculate what we can't set */

        count = min((word32)SessionCache[i].totalCount, SESSIONS_PER_ROW);
        idx   = SessionCache[i].nextIdx - 1;
        if (idx < 0)
            idx = SESSIONS_PER_ROW - 1; /* if back to front previous was end */

        for (; count > 0; --count, idx = idx ? idx - 1 : SESSIONS_PER_ROW - 1) {
            if (idx >= SESSIONS_PER_ROW || idx < 0) {  /* sanity check */
                WOLFSSL_MSG("Bad idx");
                break;
            }

            /* if not expried then good */
            if (ticks < (SessionCache[i].Sessions[idx].bornOn +
                         SessionCache[i].Sessions[idx].timeout) ) {
                now++;
            }
        }
    }

    if (active)
        *active = now;

    if (total)
        *total = seen;

#ifdef WOLFSSL_PEAK_SESSIONS
    if (peak)
        *peak = PeakSessions;
#endif

    WOLFSSL_LEAVE(result);

    return result;
}


/* return SSL_SUCCESS on ok */
int wolfSSL_get_session_stats(word32* active, word32* total, word32* peak,
                              word32* maxSessions)
{
    int result = SSL_SUCCESS;

	WOLFSSL_ENTER();

    if (maxSessions) {
        *maxSessions = SESSIONS_PER_ROW * SESSION_ROWS;

        if (active == NULL && total == NULL && peak == NULL)
            return result;  /* we're done */
    }

    /* user must provide at least one query value */
    if (active == NULL && total == NULL && peak == NULL)
        return BAD_FUNC_ARG;

    if (LockMutex(&session_mutex) != 0) {
        return BAD_MUTEX_E;
    }

    result = get_locked_session_stats(active, total, peak);

    if (UnLockMutex(&session_mutex) != 0)
        result = BAD_MUTEX_E;

    WOLFSSL_LEAVE( result);

    return result;
}

#endif /* WOLFSSL_SESSION_STATS */


#ifdef PRINT_SESSION_STATS
    /* SSL_SUCCESS on ok */
    int wolfSSL_PrintSessionStats(void)
    {
        word32 totalSessionsSeen = 0;
        word32 totalSessionsNow = 0;
        word32 peak = 0;
        word32 maxSessions = 0;
        int    i;
        int    ret;
        double E;               /* expected freq */
        double chiSquare = 0;

        ret = wolfSSL_get_session_stats(&totalSessionsNow, &totalSessionsSeen,
                                        &peak, &maxSessions);
        if (ret != SSL_SUCCESS)
            return ret;
        printf("Total Sessions Seen = %d\n", totalSessionsSeen);
        printf("Total Sessions Now  = %d\n", totalSessionsNow);
#ifdef WOLFSSL_PEAK_SESSIONS
        printf("Peak  Sessions      = %d\n", peak);
#endif
        printf("Max   Sessions      = %d\n", maxSessions);

        E = (double)totalSessionsSeen / SESSION_ROWS;

        for (i = 0; i < SESSION_ROWS; i++) {
            double diff = SessionCache[i].totalCount - E;
            diff *= diff;                /* square    */
            diff /= E;                   /* normalize */

            chiSquare += diff;
        }
        printf("  chi-square = %5.1f, d.f. = %d\n", chiSquare,
                                                     SESSION_ROWS - 1);
        #if (SESSION_ROWS == 11)
            printf(" .05 p value =  18.3, chi-square should be less\n");
        #elif (SESSION_ROWS == 211)
            printf(".05 p value  = 244.8, chi-square should be less\n");
        #elif (SESSION_ROWS == 5981)
            printf(".05 p value  = 6161.0, chi-square should be less\n");
        #elif (SESSION_ROWS == 3)
            printf(".05 p value  =   6.0, chi-square should be less\n");
        #elif (SESSION_ROWS == 2861)
            printf(".05 p value  = 2985.5, chi-square should be less\n");
        #endif
        printf("\n");

        return ret;
    }
#endif

#else  /* NO_SESSION_CACHE */

/* No session cache version */
WOLFSSL_SESSION* GetSession(WOLFSSL* ssl, byte* masterSecret)
{
    (void)ssl;
    (void)masterSecret;

    return NULL;
}

#endif /* NO_SESSION_CACHE */


/* call before SSL_connect, if verifying will add name check to
   date check and signature check */
int wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn)
{
	WOLFSSL_ENTER();
    if (ssl->buffers.domainName.buffer)
        XFREE(ssl->buffers.domainName.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);

    ssl->buffers.domainName.length = (word32)XSTRLEN(dn) + 1;
    ssl->buffers.domainName.buffer = (byte*) XMALLOC( ssl->buffers.domainName.length, ssl->heap, DYNAMIC_TYPE_DOMAIN);

    if (ssl->buffers.domainName.buffer) {
        XSTRNCPY((char*)ssl->buffers.domainName.buffer, dn, ssl->buffers.domainName.length);
        return SSL_SUCCESS;
    }
    else {
        ssl->error = MEMORY_ERROR;
        return SSL_FAILURE;
    }
}


/* turn on wolfSSL zlib compression
   returns SSL_SUCCESS for success, else error (not built in)
*/
int wolfSSL_set_compression(WOLFSSL* ssl)
{
	WOLFSSL_ENTER();
    (void)ssl;
#ifdef HAVE_LIBZ
    ssl->options.usingCompression = 1;
    return SSL_SUCCESS;
#else
    return NOT_COMPILED_IN;
#endif
}


#ifndef USE_WINDOWS_API
    #ifndef NO_WRITEV

        /* simulate writev semantics, doesn't actually do block at a time though
           because of SSL_write behavior and because front adds may be small */
        int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov, int iovcnt)
        {
        #ifdef WOLFSSL_SMALL_STACK
            byte   staticBuffer[1]; /* force heap usage */
        #else
            byte   staticBuffer[FILE_BUFFER_SIZE];
        #endif
            byte* myBuffer  = staticBuffer;
            int   dynamic   = 0;
            int   sending   = 0;
            int   idx       = 0;
            int   i;
            int   ret;

	WOLFSSL_ENTER();

            for (i = 0; i < iovcnt; i++)
                sending += (int)iov[i].iov_len;

            if (sending > (int)sizeof(staticBuffer)) {
                myBuffer = (byte*)XMALLOC(sending, ssl->heap,
                                                           DYNAMIC_TYPE_WRITEV);
                if (!myBuffer)
                    return MEMORY_ERROR;

                dynamic = 1;
            }

            for (i = 0; i < iovcnt; i++) {
                XMEMCPY(&myBuffer[idx], iov[i].iov_base, iov[i].iov_len);
                idx += (int)iov[i].iov_len;
            }

            ret = wolfSSL_write(ssl, myBuffer, sending);

            if (dynamic)
                XFREE(myBuffer, ssl->heap, DYNAMIC_TYPE_WRITEV);

            return ret;
        }
    #endif
#endif


#ifdef WOLFSSL_CALLBACKS

    typedef struct itimerval Itimerval;

    /* don't keep calling simple functions while setting up timer and singals
       if no inlining these are the next best */

    #define AddTimes(a, b, c)                       \
        do {                                        \
            c.tv_sec  = a.tv_sec  + b.tv_sec;       \
            c.tv_usec = a.tv_usec + b.tv_usec;      \
            if (c.tv_usec >=  1000000) {            \
                c.tv_sec++;                         \
                c.tv_usec -= 1000000;               \
            }                                       \
        } while (0)


    #define SubtractTimes(a, b, c)                  \
        do {                                        \
            c.tv_sec  = a.tv_sec  - b.tv_sec;       \
            c.tv_usec = a.tv_usec - b.tv_usec;      \
            if (c.tv_usec < 0) {                    \
                c.tv_sec--;                         \
                c.tv_usec += 1000000;               \
            }                                       \
        } while (0)

    #define CmpTimes(a, b, cmp)                     \
        ((a.tv_sec  ==  b.tv_sec) ?                 \
            (a.tv_usec cmp b.tv_usec) :             \
            (a.tv_sec  cmp b.tv_sec))               \


    /* do nothing handler */
    static void myHandler(int signo)
    {
        (void)signo;
        return;
    }


    static int wolfSSL_ex_wrapper(WOLFSSL* ssl, HandShakeCallBack hsCb,
                                 TimeoutCallBack toCb, Timeval timeout)
    {
        int       ret        = SSL_FATAL_ERROR;
        int       oldTimerOn = 0;   /* was timer already on */
        Timeval   startTime;
        Timeval   endTime;
        Timeval   totalTime;
        Itimerval myTimeout;
        Itimerval oldTimeout; /* if old timer adjust from total time to reset */
        struct sigaction act, oact;

        #define ERR_OUT(x) { ssl->hsInfoOn = 0; ssl->toInfoOn = 0; return x; }

        if (hsCb) {
            ssl->hsInfoOn = 1;
            InitHandShakeInfo(&ssl->handShakeInfo);
        }
        if (toCb) {
            ssl->toInfoOn = 1;
            InitTimeoutInfo(&ssl->timeoutInfo);

            if (gettimeofday(&startTime, 0) < 0)
                ERR_OUT(GETTIME_ERROR);

            /* use setitimer to simulate getitimer, init 0 myTimeout */
            myTimeout.it_interval.tv_sec  = 0;
            myTimeout.it_interval.tv_usec = 0;
            myTimeout.it_value.tv_sec     = 0;
            myTimeout.it_value.tv_usec    = 0;
            if (setitimer(ITIMER_REAL, &myTimeout, &oldTimeout) < 0)
                ERR_OUT(SETITIMER_ERROR);

            if (oldTimeout.it_value.tv_sec || oldTimeout.it_value.tv_usec) {
                oldTimerOn = 1;

                /* is old timer going to expire before ours */
                if (CmpTimes(oldTimeout.it_value, timeout, <)) {
                    timeout.tv_sec  = oldTimeout.it_value.tv_sec;
                    timeout.tv_usec = oldTimeout.it_value.tv_usec;
                }
            }
            myTimeout.it_value.tv_sec  = timeout.tv_sec;
            myTimeout.it_value.tv_usec = timeout.tv_usec;

            /* set up signal handler, don't restart socket send/recv */
            act.sa_handler = myHandler;
            sigemptyset(&act.sa_mask);
            act.sa_flags = 0;
#ifdef SA_INTERRUPT
            act.sa_flags |= SA_INTERRUPT;
#endif
            if (sigaction(SIGALRM, &act, &oact) < 0)
                ERR_OUT(SIGACT_ERROR);

            if (setitimer(ITIMER_REAL, &myTimeout, 0) < 0)
                ERR_OUT(SETITIMER_ERROR);
        }

        /* do main work */
#ifndef NO_WOLFSSL_CLIENT
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            ret = wolfSSL_connect(ssl);
#endif
#ifndef NO_WOLFSSL_SERVER
        if (ssl->options.side == WOLFSSL_SERVER_END)
            ret = wolfSSL_accept(ssl);
#endif

        /* do callbacks */
        if (toCb) {
            if (oldTimerOn) {
                gettimeofday(&endTime, 0);
                SubtractTimes(endTime, startTime, totalTime);
                /* adjust old timer for elapsed time */
                if (CmpTimes(totalTime, oldTimeout.it_value, <))
                    SubtractTimes(oldTimeout.it_value, totalTime,
                                  oldTimeout.it_value);
                else {
                    /* reset value to interval, may be off */
                    oldTimeout.it_value.tv_sec = oldTimeout.it_interval.tv_sec;
                    oldTimeout.it_value.tv_usec =oldTimeout.it_interval.tv_usec;
                }
                /* keep iter the same whether there or not */
            }
            /* restore old handler */
            if (sigaction(SIGALRM, &oact, 0) < 0)
                ret = SIGACT_ERROR;    /* more pressing error, stomp */
            else
                /* use old settings which may turn off (expired or not there) */
                if (setitimer(ITIMER_REAL, &oldTimeout, 0) < 0)
                    ret = SETITIMER_ERROR;

            /* if we had a timeout call callback */
            if (ssl->timeoutInfo.timeoutName[0]) {
                ssl->timeoutInfo.timeoutValue.tv_sec  = timeout.tv_sec;
                ssl->timeoutInfo.timeoutValue.tv_usec = timeout.tv_usec;
                (toCb)(&ssl->timeoutInfo);
            }
            /* clean up */
            FreeTimeoutInfo(&ssl->timeoutInfo, ssl->heap);
            ssl->toInfoOn = 0;
        }
        if (hsCb) {
            FinishHandShakeInfo(&ssl->handShakeInfo, ssl);
            (hsCb)(&ssl->handShakeInfo);
            ssl->hsInfoOn = 0;
        }
        return ret;
    }


#ifndef NO_WOLFSSL_CLIENT
int wolfSSL_connect_ex(WOLFSSL* ssl, HandShakeCallBack hsCb, TimeoutCallBack toCb, Timeval timeout)
{
	WOLFSSL_ENTER();
	return wolfSSL_ex_wrapper(ssl, hsCb, toCb, timeout);
}
#endif


#ifndef NO_WOLFSSL_SERVER
int wolfSSL_accept_ex(WOLFSSL* ssl, HandShakeCallBack hsCb, TimeoutCallBack toCb,Timeval timeout)
{
	WOLFSSL_ENTER();
	return wolfSSL_ex_wrapper(ssl, hsCb, toCb, timeout);
}
#endif

#endif /* WOLFSSL_CALLBACKS */


#ifndef NO_PSK

    void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX* ctx,
                                         psk_client_callback cb)
    {
	WOLFSSL_ENTER();
        ctx->havePSK = 1;
        ctx->client_psk_cb = cb;
    }


    void wolfSSL_set_psk_client_callback(WOLFSSL* ssl, psk_client_callback cb)
    {
        byte haveRSA = 1;

	WOLFSSL_ENTER();
        ssl->options.havePSK = 1;
        ssl->options.client_psk_cb = cb;

        #ifdef NO_RSA
            haveRSA = 0;
        #endif
        InitSuites(ssl->suites, ssl->version, haveRSA, TRUE,
                   ssl->options.haveDH, ssl->options.haveNTRU,
                   ssl->options.haveECDSAsig, ssl->options.haveStaticECC,
                   ssl->options.side);
    }


	void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX* ctx, psk_server_callback cb)
	{
		WOLFSSL_ENTER();
		ctx->havePSK = 1;
		ctx->server_psk_cb = cb;
	}


    void wolfSSL_set_psk_server_callback(WOLFSSL* ssl, psk_server_callback cb)
    {
        byte haveRSA = 1;

	WOLFSSL_ENTER();
        ssl->options.havePSK = 1;
        ssl->options.server_psk_cb = cb;

        #ifdef NO_RSA
            haveRSA = 0;
        #endif
        InitSuites(ssl->suites, ssl->version, haveRSA, TRUE,
                   ssl->options.haveDH, ssl->options.haveNTRU,
                   ssl->options.haveECDSAsig, ssl->options.haveStaticECC,
                   ssl->options.side);
    }


    const char* wolfSSL_get_psk_identity_hint(const WOLFSSL* ssl)
    {
	WOLFSSL_ENTER();

        if (ssl == NULL || ssl->arrays == NULL)
            return NULL;

        return ssl->arrays->server_hint;
    }


    const char* wolfSSL_get_psk_identity(const WOLFSSL* ssl)
    {
	WOLFSSL_ENTER();

        if (ssl == NULL || ssl->arrays == NULL)
            return NULL;

        return ssl->arrays->client_identity;
    }


    int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX* ctx, const char* hint)
    {
	WOLFSSL_ENTER();
        if (hint == 0)
            ctx->server_hint[0] = 0;
        else {
            XSTRNCPY(ctx->server_hint, hint, MAX_PSK_ID_LEN);
            ctx->server_hint[MAX_PSK_ID_LEN - 1] = '\0';
        }
        return SSL_SUCCESS;
    }


    int wolfSSL_use_psk_identity_hint(WOLFSSL* ssl, const char* hint)
    {
	WOLFSSL_ENTER();

        if (ssl == NULL || ssl->arrays == NULL)
            return SSL_FAILURE;

        if (hint == 0)
            ssl->arrays->server_hint[0] = 0;
        else {
            XSTRNCPY(ssl->arrays->server_hint, hint, MAX_PSK_ID_LEN);
            ssl->arrays->server_hint[MAX_PSK_ID_LEN - 1] = '\0';
        }
        return SSL_SUCCESS;
    }

#endif /* NO_PSK */


#ifdef HAVE_ANON

    int wolfSSL_CTX_allow_anon_cipher(WOLFSSL_CTX* ctx)
    {
	WOLFSSL_ENTER();

        if (ctx == NULL)
            return SSL_FAILURE;

        ctx->haveAnon = 1;

        return SSL_SUCCESS;
    }

#endif /* HAVE_ANON */


#ifndef NO_CERTS
/* used to be defined on NO_FILESYSTEM only, but are generally useful */

    /* wolfSSL extension allows DER files to be loaded from buffers as well */
    int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
                                      long sz, int format)
    {
        if (format == SSL_FILETYPE_PEM)
            return ProcessChainBuffer(ctx, in, sz, format, CA_TYPE, NULL);
        else
            return ProcessBuffer(ctx, in, sz, format, CA_TYPE, NULL,NULL,0);
    }


    int wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx,
                                 const unsigned char* in, long sz, int format)
    {
        return ProcessBuffer(ctx, in, sz, format, CERT_TYPE, NULL, NULL, 0);
    }


    int wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx,
                                 const unsigned char* in, long sz, int format)
    {
        return ProcessBuffer(ctx, in, sz, format, PRIVATEKEY_TYPE, NULL,NULL,0);
    }


    int wolfSSL_CTX_use_certificate_chain_buffer(WOLFSSL_CTX* ctx,
                                 const unsigned char* in, long sz)
    {
        return ProcessBuffer(ctx, in, sz, SSL_FILETYPE_PEM, CERT_TYPE, NULL, NULL, 1);
    }

    int wolfSSL_use_certificate_buffer(WOLFSSL* ssl,
                                 const unsigned char* in, long sz, int format)
    {
        return ProcessBuffer(ssl->ctx, in, sz, format,CERT_TYPE,ssl,NULL,0);
    }


    int wolfSSL_use_PrivateKey_buffer(WOLFSSL* ssl,
                                 const unsigned char* in, long sz, int format)
    {
        return ProcessBuffer(ssl->ctx, in, sz, format, PRIVATEKEY_TYPE,
                             ssl, NULL, 0);
    }


    int wolfSSL_use_certificate_chain_buffer(WOLFSSL* ssl,
                                 const unsigned char* in, long sz)
    {
        return ProcessBuffer(ssl->ctx, in, sz, SSL_FILETYPE_PEM, CERT_TYPE,
                             ssl, NULL, 1);
    }


    /* unload any certs or keys that SSL owns, leave CTX as is
       SSL_SUCCESS on ok */
    int wolfSSL_UnloadCertsKeys(WOLFSSL* ssl)
    {
        if (ssl == NULL) {
            WOLFSSL_MSG("Null function arg");
            return BAD_FUNC_ARG;
        }

        if (ssl->buffers.weOwnCert) {
            WOLFSSL_MSG("Unloading cert");
            XFREE(ssl->buffers.certificate.buffer, ssl->heap,DYNAMIC_TYPE_CERT);
            ssl->buffers.weOwnCert = 0;
            ssl->buffers.certificate.length = 0;
            ssl->buffers.certificate.buffer = NULL;
        }

        if (ssl->buffers.weOwnCertChain) {
            WOLFSSL_MSG("Unloading cert chain");
            XFREE(ssl->buffers.certChain.buffer, ssl->heap,DYNAMIC_TYPE_CERT);
            ssl->buffers.weOwnCertChain = 0;
            ssl->buffers.certChain.length = 0;
            ssl->buffers.certChain.buffer = NULL;
        }

        if (ssl->buffers.weOwnKey) {
            WOLFSSL_MSG("Unloading key");
            XFREE(ssl->buffers.key.buffer, ssl->heap, DYNAMIC_TYPE_KEY);
            ssl->buffers.weOwnKey = 0;
            ssl->buffers.key.length = 0;
            ssl->buffers.key.buffer = NULL;
        }

        return SSL_SUCCESS;
    }


    int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX* ctx)
    {
	WOLFSSL_ENTER();

        if (ctx == NULL)
            return BAD_FUNC_ARG;

        return wolfSSL_CertManagerUnloadCAs(ctx->cm);
    }

/* old NO_FILESYSTEM end */
#endif /* !NO_CERTS */


#if defined(OPENSSL_EXTRA) || defined(GOAHEAD_WS)


    int wolfSSL_add_all_algorithms(void)
    {
	WOLFSSL_ENTER();
        wolfSSL_Init();
        return SSL_SUCCESS;
    }


    long wolfSSL_CTX_sess_set_cache_size(WOLFSSL_CTX* ctx, long sz)
    {
        /* cache size fixed at compile time in wolfSSL */
        (void)ctx;
        (void)sz;
        return 0;
    }


    void wolfSSL_CTX_set_quiet_shutdown(WOLFSSL_CTX* ctx, int mode)
    {
	WOLFSSL_ENTER();
        if (mode)
            ctx->quietShutdown = 1;
    }


    void wolfSSL_set_quiet_shutdown(WOLFSSL* ssl, int mode)
    {
	WOLFSSL_ENTER();
        if (mode)
            ssl->options.quietShutdown = 1;
    }


    void wolfSSL_set_bio(WOLFSSL* ssl, WOLFSSL_BIO* rd, WOLFSSL_BIO* wr)
    {
	WOLFSSL_ENTER();
        wolfSSL_set_rfd(ssl, rd->fd);
        wolfSSL_set_wfd(ssl, wr->fd);

        ssl->biord = rd;
        ssl->biowr = wr;
    }


    void wolfSSL_CTX_set_client_CA_list(WOLFSSL_CTX* ctx,
                                       STACK_OF(WOLFSSL_X509_NAME)* names)
    {
        (void)ctx;
        (void)names;
    }


    STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_load_client_CA_file(const char* fname)
    {
        (void)fname;
        return 0;
    }


    int wolfSSL_CTX_set_default_verify_paths(WOLFSSL_CTX* ctx)
    {
        /* TODO:, not needed in goahead */
        (void)ctx;
        return SSL_NOT_IMPLEMENTED;
    }


    /* keyblock size in bytes or -1 */
    int wolfSSL_get_keyblock_size(WOLFSSL* ssl)
    {
        if (ssl == NULL)
            return SSL_FATAL_ERROR;

        return 2 * (ssl->specs.key_size + ssl->specs.iv_size +
                    ssl->specs.hash_size);
    }


    /* store keys returns SSL_SUCCESS or -1 on error */
    int wolfSSL_get_keys(WOLFSSL* ssl, unsigned char** ms, unsigned int* msLen,
                                     unsigned char** sr, unsigned int* srLen,
                                     unsigned char** cr, unsigned int* crLen)
    {
        if (ssl == NULL || ssl->arrays == NULL)
            return SSL_FATAL_ERROR;

        *ms = ssl->arrays->masterSecret;
        *sr = ssl->arrays->serverRandom;
        *cr = ssl->arrays->clientRandom;

        *msLen = SECRET_LEN;
        *srLen = RAN_LEN;
        *crLen = RAN_LEN;

        return SSL_SUCCESS;
    }


    void wolfSSL_set_accept_state(WOLFSSL* ssl)
    {
        byte haveRSA = 1;
        byte havePSK = 0;

        ssl->options.side = WOLFSSL_SERVER_END;
        /* reset suites in case user switched */

        #ifdef NO_RSA
            haveRSA = 0;
        #endif
        #ifndef NO_PSK
            havePSK = ssl->options.havePSK;
        #endif
        InitSuites(ssl->suites, ssl->version, haveRSA, havePSK,
                   ssl->options.haveDH, ssl->options.haveNTRU,
                   ssl->options.haveECDSAsig, ssl->options.haveStaticECC,
                   ssl->options.side);
    }
#endif

    /* return true if connection established */
    int wolfSSL_is_init_finished(WOLFSSL* ssl)
    {
        if (ssl == NULL)
            return 0;

        if (ssl->options.handShakeState == HANDSHAKE_DONE)
            return 1;

        return 0;
    }

#if defined(OPENSSL_EXTRA) || defined(GOAHEAD_WS)
    void wolfSSL_CTX_set_tmp_rsa_callback(WOLFSSL_CTX* ctx, WOLFSSL_RSA*(*f)(WOLFSSL*, int, int))
    {
        /* wolfSSL verifies all these internally */
        (void)ctx;
        (void)f;
    }


    void wolfSSL_set_shutdown(WOLFSSL* ssl, int opt)
    {
        (void)ssl;
        (void)opt;
    }


    long wolfSSL_CTX_set_options(WOLFSSL_CTX* ctx, long opt)
    {
        /* goahead calls with 0, do nothing */
        (void)ctx;
        return opt;
    }


    int wolfSSL_set_rfd(WOLFSSL* ssl, int rfd)
    {
        ssl->rfd = rfd;      /* not used directly to allow IO callbacks */
        ssl->IOCB_ReadCtx  = &ssl->rfd;

        return SSL_SUCCESS;
    }


    int wolfSSL_set_wfd(WOLFSSL* ssl, int wfd)
    {
        ssl->wfd = wfd;      /* not used directly to allow IO callbacks */

        ssl->IOCB_WriteCtx  = &ssl->wfd;

        return SSL_SUCCESS;
    }


    WOLFSSL_RSA* wolfSSL_RSA_generate_key(int len, unsigned long bits, void(*f)(int, int, void*), void* data)
    {
        /* no tmp key needed, actual generation not supported */
        (void)len;
        (void)bits;
        (void)f;
        (void)data;
        return NULL;
    }



    WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get_current_cert(
                                                     WOLFSSL_X509_STORE_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    int wolfSSL_X509_STORE_CTX_get_error(WOLFSSL_X509_STORE_CTX* ctx)
    {
        if (ctx != NULL)
            return ctx->error;
        return 0;
    }


    int wolfSSL_X509_STORE_CTX_get_error_depth(WOLFSSL_X509_STORE_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_buffer(void)
    {
        static WOLFSSL_BIO_METHOD meth;

        meth.type = BIO_BUFFER;

        return &meth;
    }


    long wolfSSL_BIO_set_write_buffer_size(WOLFSSL_BIO* bio, long size)
    {
        /* wolfSSL has internal buffer, compatibility only */
        (void)bio;
        return size;
    }


    WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_ssl(void)
    {
        static WOLFSSL_BIO_METHOD meth;

        meth.type = BIO_SSL;

        return &meth;
    }


    WOLFSSL_BIO* wolfSSL_BIO_new_socket(int sfd, int closeF)
    {
        WOLFSSL_BIO* bio = (WOLFSSL_BIO*) XMALLOC(sizeof(WOLFSSL_BIO), 0, DYNAMIC_TYPE_OPENSSL);
        if (bio) {
            bio->type  = BIO_SOCKET;
            bio->close = (byte)closeF;
            bio->eof   = 0;
            bio->ssl   = 0;
            bio->fd    = sfd;
            bio->prev  = 0;
            bio->next  = 0;
            bio->mem   = NULL;
            bio->memLen = 0;
        }
        return bio;
    }


    int wolfSSL_BIO_eof(WOLFSSL_BIO* b)
    {
        if (b->eof)
            return 1;

        return 0;
    }


    long wolfSSL_BIO_set_ssl(WOLFSSL_BIO* b, WOLFSSL* ssl, int closeF)
    {
        b->ssl   = ssl;
        b->close = (byte)closeF;
    /* add to ssl for bio free if SSL_free called before/instead of free_all? */

        return 0;
    }


    WOLFSSL_BIO* wolfSSL_BIO_new(WOLFSSL_BIO_METHOD* method)
    {
        WOLFSSL_BIO* bio = (WOLFSSL_BIO*) XMALLOC(sizeof(WOLFSSL_BIO), 0, DYNAMIC_TYPE_OPENSSL);
        if (bio) {
            bio->type   = method->type;
            bio->close  = 0;
            bio->eof    = 0;
            bio->ssl    = NULL;
            bio->mem    = NULL;
            bio->memLen = 0;
            bio->fd     = 0;
            bio->prev   = NULL;
            bio->next   = NULL;
        }
        return bio;
    }


    int wolfSSL_BIO_get_mem_data(WOLFSSL_BIO* bio, const byte** p)
    {
        if (bio == NULL || p == NULL)
            return SSL_FATAL_ERROR;

        *p = bio->mem;

        return bio->memLen;
    }


    WOLFSSL_BIO* wolfSSL_BIO_new_mem_buf(void* buf, int len)
    {
        WOLFSSL_BIO* bio = NULL;
        if (buf == NULL)
            return bio;

        bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
        if (bio == NULL)
            return bio;

        bio->memLen = len;
        bio->mem    = (byte*)XMALLOC(len, 0, DYNAMIC_TYPE_OPENSSL);
        if (bio->mem == NULL) {
            XFREE(bio, 0, DYNAMIC_TYPE_OPENSSL);
            return NULL;
        }

        XMEMCPY(bio->mem, buf, len);

        return bio;
    }


#ifdef USE_WINDOWS_API
    #define CloseSocket(s) closesocket(s)
#elif defined(WOLFSSL_MDK_ARM)
    #define CloseSocket(s) closesocket(s)
    extern int closesocket(int) ;
#else
    #define CloseSocket(s) close(s)
#endif

    int wolfSSL_BIO_free(WOLFSSL_BIO* bio)
    {
        /* unchain?, doesn't matter in goahead since from free all */
        if (bio) {
            if (bio->close) {
                if (bio->ssl)
                    wolfSSL_free(bio->ssl);
                if (bio->fd)
                    CloseSocket(bio->fd);
            }
            if (bio->mem)
                XFREE(bio->mem, 0, DYNAMIC_TYPE_OPENSSL);
            XFREE(bio, 0, DYNAMIC_TYPE_OPENSSL);
        }
        return 0;
    }


    int wolfSSL_BIO_free_all(WOLFSSL_BIO* bio)
    {
        while (bio) {
            WOLFSSL_BIO* next = bio->next;
            wolfSSL_BIO_free(bio);
            bio = next;
        }
        return 0;
    }


    int wolfSSL_BIO_read(WOLFSSL_BIO* bio, void* buf, int len)
    {
        int  ret;
        WOLFSSL* ssl = 0;
        WOLFSSL_BIO* front = bio;

	WOLFSSL_ENTER();
        /* already got eof, again is error */
        if (front->eof)
            return SSL_FATAL_ERROR;

        while(bio && ((ssl = bio->ssl) == 0) )
            bio = bio->next;

        if (ssl == 0) return BAD_FUNC_ARG;

        ret = wolfSSL_read(ssl, buf, len);
        if (ret == 0)
            front->eof = 1;
        else if (ret < 0) {
            int err = wolfSSL_get_error(ssl, 0);
            if ( !(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) )
                front->eof = 1;
        }
        return ret;
    }


    int wolfSSL_BIO_write(WOLFSSL_BIO* bio, const void* data, int len)
    {
        int  ret;
        WOLFSSL* ssl = 0;
        WOLFSSL_BIO* front = bio;

	WOLFSSL_ENTER();
        /* already got eof, again is error */
        if (front->eof)
            return SSL_FATAL_ERROR;

        while(bio && ((ssl = bio->ssl) == 0) )
            bio = bio->next;

        if (ssl == 0) return BAD_FUNC_ARG;

        ret = wolfSSL_write(ssl, data, len);
        if (ret == 0)
            front->eof = 1;
        else if (ret < 0) {
            int err = wolfSSL_get_error(ssl, 0);
            if ( !(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) )
                front->eof = 1;
        }

        return ret;
    }


    WOLFSSL_BIO* wolfSSL_BIO_push(WOLFSSL_BIO* top, WOLFSSL_BIO* append)
    {
	WOLFSSL_ENTER();
        top->next    = append;
        append->prev = top;

        return top;
    }


    int wolfSSL_BIO_flush(WOLFSSL_BIO* bio)
    {
        /* for wolfSSL no flushing needed */
	WOLFSSL_ENTER();
        (void)bio;
        return 1;
    }


#endif /* OPENSSL_EXTRA || GOAHEAD_WS */


#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)

    void wolfSSL_CTX_set_default_passwd_cb_userdata(WOLFSSL_CTX* ctx,
                                                   void* userdata)
    {
	WOLFSSL_ENTER();
        ctx->userdata = userdata;
    }


    void wolfSSL_CTX_set_default_passwd_cb(WOLFSSL_CTX* ctx, pem_password_cb cb)
    {
	WOLFSSL_ENTER();
        ctx->passwd_cb = cb;
    }

    int wolfSSL_num_locks(void)
    {
        return 0;
    }

    void wolfSSL_set_locking_callback(void (*f)(int, int, const char*, int))
    {
        (void)f;
    }

    void wolfSSL_set_id_callback(unsigned long (*f)(void))
    {
        (void)f;
    }

    unsigned long wolfSSL_ERR_get_error(void)
    {
        /* TODO: */
        return 0;
    }

#ifndef NO_MD5

    int wolfSSL_EVP_BytesToKey(const WOLFSSL_EVP_CIPHER* type,
                       const WOLFSSL_EVP_MD* md, const byte* salt,
                       const byte* data, int sz, int count, byte* key, byte* iv)
    {
        int  keyLen = 0;
        int  ivLen  = 0;
        int  j;
        int  keyLeft;
        int  ivLeft;
        int  keyOutput = 0;
        byte digest[MD5_DIGEST_SIZE];
    #ifdef WOLFSSL_SMALL_STACK
        Md5* md5 = NULL;
    #else
        Md5  md5[1];
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        md5 = (Md5*)XMALLOC(sizeof(Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (md5 == NULL)
            return 0;
    #endif

	WOLFSSL_ENTER();
        wc_InitMd5(md5);

        /* only support MD5 for now */
        if (XSTRNCMP(md, "MD5", 3) != 0) return 0;

        /* only support CBC DES and AES for now */
        if (XSTRNCMP(type, "DES-CBC", 7) == 0) {
            keyLen = DES_KEY_SIZE;
            ivLen  = DES_IV_SIZE;
        }
        else if (XSTRNCMP(type, "DES-EDE3-CBC", 12) == 0) {
            keyLen = DES3_KEY_SIZE;
            ivLen  = DES_IV_SIZE;
        }
        else if (XSTRNCMP(type, "AES-128-CBC", 11) == 0) {
            keyLen = AES_128_KEY_SIZE;
            ivLen  = AES_IV_SIZE;
        }
        else if (XSTRNCMP(type, "AES-192-CBC", 11) == 0) {
            keyLen = AES_192_KEY_SIZE;
            ivLen  = AES_IV_SIZE;
        }
        else if (XSTRNCMP(type, "AES-256-CBC", 11) == 0) {
            keyLen = AES_256_KEY_SIZE;
            ivLen  = AES_IV_SIZE;
        }
        else {
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(md5, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return 0;
        }

        keyLeft   = keyLen;
        ivLeft    = ivLen;

        while (keyOutput < (keyLen + ivLen)) {
            int digestLeft = MD5_DIGEST_SIZE;
            /* D_(i - 1) */
            if (keyOutput)                      /* first time D_0 is empty */
                wc_Md5Update(md5, digest, MD5_DIGEST_SIZE);
            /* data */
            wc_Md5Update(md5, data, sz);
            /* salt */
            if (salt)
                wc_Md5Update(md5, salt, EVP_SALT_SIZE);
            wc_Md5Final(md5, digest);
            /* count */
            for (j = 1; j < count; j++) {
                wc_Md5Update(md5, digest, MD5_DIGEST_SIZE);
                wc_Md5Final(md5, digest);
            }

            if (keyLeft) {
                int store = min(keyLeft, MD5_DIGEST_SIZE);
                XMEMCPY(&key[keyLen - keyLeft], digest, store);

                keyOutput  += store;
                keyLeft    -= store;
                digestLeft -= store;
            }

            if (ivLeft && digestLeft) {
                int store = min(ivLeft, digestLeft);
                XMEMCPY(&iv[ivLen - ivLeft], &digest[MD5_DIGEST_SIZE -
                                                    digestLeft], store);
                keyOutput += store;
                ivLeft    -= store;
            }
        }

    #ifdef WOLFSSL_SMALL_STACK
        XFREE(md5, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif

        return keyOutput == (keyLen + ivLen) ? keyOutput : 0;
    }

#endif /* NO_MD5 */

#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */


#if defined(KEEP_PEER_CERT)

    WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL* ssl)
    {
	WOLFSSL_ENTER();
        if (ssl->peerCert.issuer.sz)
            return &ssl->peerCert;
        else
            return 0;
    }

#endif /* KEEP_PEER_CERT */


#ifdef OPENSSL_EXTRA
int wolfSSL_set_ex_data(WOLFSSL* ssl, int idx, void* data)
{
#ifdef FORTRESS
    if (ssl != NULL && idx < MAX_EX_DATA)
    {
        ssl->ex_data[idx] = data;
        return SSL_SUCCESS;
    }
#else
    (void)ssl;
    (void)idx;
    (void)data;
#endif
    return SSL_FAILURE;
}


int wolfSSL_set_session_id_context(WOLFSSL* ssl, const unsigned char* id,
                               unsigned int len)
{
    (void)ssl;
    (void)id;
    (void)len;
    return 0;
}


void wolfSSL_set_connect_state(WOLFSSL* ssl)
{
    (void)ssl;
    /* client by default */
}
#endif

int wolfSSL_get_shutdown(const WOLFSSL* ssl)
{
    return (ssl->options.isClosed  ||
            ssl->options.connReset ||
            ssl->options.sentNotify);
}


int wolfSSL_session_reused(WOLFSSL* ssl)
{
    return ssl->options.resuming;
}

#ifdef OPENSSL_EXTRA
void wolfSSL_SESSION_free(WOLFSSL_SESSION* session)
{
    (void)session;
}
#endif


#ifdef OPENSSL_EXTRA
char* wolfSSL_CIPHER_description(WOLFSSL_CIPHER* cipher, char* in, int len)
{
    (void)cipher;
    (void)in;
    (void)len;
    return 0;
}


WOLFSSL_SESSION* wolfSSL_get1_session(WOLFSSL* ssl)  /* what's ref count */
{
    (void)ssl;
    return 0;
}


void wolfSSL_X509_free(WOLFSSL_X509* buf)
{
    FreeX509(buf);
}


/* was do nothing */
/*
void OPENSSL_free(void* buf)
{
    (void)buf;
}
*/


int wolfSSL_OCSP_parse_url(char* url, char** host, char** port, char** path,
                   int* ssl)
{
    (void)url;
    (void)host;
    (void)port;
    (void)path;
    (void)ssl;
    return 0;
}


WOLFSSL_METHOD* wolfSSLv2_client_method(void)
{
    return 0;
}


WOLFSSL_METHOD* wolfSSLv2_server_method(void)
{
    return 0;
}


#ifndef NO_MD4

void wolfSSL_MD4_Init(WOLFSSL_MD4_CTX* md4)
{
    /* make sure we have a big enough buffer */
    typedef char ok[sizeof(md4->buffer) >= sizeof(Md4) ? 1 : -1];
    (void) sizeof(ok);

	WOLFSSL_ENTER();
    wc_InitMd4((Md4*)md4);
}


void wolfSSL_MD4_Update(WOLFSSL_MD4_CTX* md4, const void* data,
                       unsigned long len)
{
	WOLFSSL_ENTER();
    wc_Md4Update((Md4*)md4, (const byte*)data, (word32)len);
}


void wolfSSL_MD4_Final(unsigned char* digest, WOLFSSL_MD4_CTX* md4)
{
	WOLFSSL_ENTER();
    wc_Md4Final((Md4*)md4, digest);
}

#endif /* NO_MD4 */


WOLFSSL_BIO* wolfSSL_BIO_pop(WOLFSSL_BIO* top)
{
    (void)top;
    return 0;
}


int wolfSSL_BIO_pending(WOLFSSL_BIO* bio)
{
    (void)bio;
    return 0;
}



WOLFSSL_BIO_METHOD* wolfSSL_BIO_s_mem(void)
{
    static WOLFSSL_BIO_METHOD meth;

	WOLFSSL_ENTER();
    meth.type = BIO_MEMORY;

    return &meth;
}


WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_base64(void)
{
    return 0;
}


void wolfSSL_BIO_set_flags(WOLFSSL_BIO* bio, int flags)
{
    (void)bio;
    (void)flags;
}



void wolfSSL_RAND_screen(void)
{

}


const char* wolfSSL_RAND_file_name(char* fname, unsigned long len)
{
    (void)fname;
    (void)len;
    return 0;
}


int wolfSSL_RAND_write_file(const char* fname)
{
    (void)fname;
    return 0;
}


int wolfSSL_RAND_load_file(const char* fname, long len)
{
    (void)fname;
    /* wolfCrypt provides enough entropy internally or will report error */
    if (len == -1)
        return 1024;
    else
        return (int)len;
}


int wolfSSL_RAND_egd(const char* path)
{
    (void)path;
    return 0;
}



WOLFSSL_COMP_METHOD* wolfSSL_COMP_zlib(void)
{
    return 0;
}


WOLFSSL_COMP_METHOD* wolfSSL_COMP_rle(void)
{
    return 0;
}


int wolfSSL_COMP_add_compression_method(int method, void* data)
{
    (void)method;
    (void)data;
    return 0;
}



int wolfSSL_get_ex_new_index(long idx, void* data, void* cb1, void* cb2,
                         void* cb3)
{
    (void)idx;
    (void)data;
    (void)cb1;
    (void)cb2;
    (void)cb3;
    return 0;
}


void wolfSSL_set_dynlock_create_callback(WOLFSSL_dynlock_value* (*f)(
                                                          const char*, int))
{
    (void)f;
}


void wolfSSL_set_dynlock_lock_callback(
             void (*f)(int, WOLFSSL_dynlock_value*, const char*, int))
{
    (void)f;
}


void wolfSSL_set_dynlock_destroy_callback(
                  void (*f)(WOLFSSL_dynlock_value*, const char*, int))
{
    (void)f;
}



const char* wolfSSL_X509_verify_cert_error_string(long err)
{
    (void)err;
    return 0;
}



int wolfSSL_X509_LOOKUP_add_dir(WOLFSSL_X509_LOOKUP* lookup, const char* dir,
                               long len)
{
    (void)lookup;
    (void)dir;
    (void)len;
    return 0;
}


int wolfSSL_X509_LOOKUP_load_file(WOLFSSL_X509_LOOKUP* lookup,
                                 const char* file, long len)
{
    (void)lookup;
    (void)file;
    (void)len;
    return 0;
}


WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_hash_dir(void)
{
    return 0;
}


WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_file(void)
{
    return 0;
}



WOLFSSL_X509_LOOKUP* wolfSSL_X509_STORE_add_lookup(WOLFSSL_X509_STORE* store,
                                               WOLFSSL_X509_LOOKUP_METHOD* m)
{
    (void)store;
    (void)m;
    return 0;
}


int wolfSSL_X509_STORE_add_cert(WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509)
{
    int result = SSL_FATAL_ERROR;

	WOLFSSL_ENTER();
    if (store != NULL && store->cm != NULL && x509 != NULL) {
        buffer derCert;
        derCert.buffer = (byte*)XMALLOC(x509->derCert.length,
                                                   NULL, DYNAMIC_TYPE_CERT);
        if (derCert.buffer != NULL) {
            derCert.length = x509->derCert.length;
                /* AddCA() frees the buffer. */
            XMEMCPY(derCert.buffer,
                                x509->derCert.buffer, x509->derCert.length);
            result = AddCA(store->cm, derCert, WOLFSSL_USER_CA, 1);
            if (result != SSL_SUCCESS) result = SSL_FATAL_ERROR;
        }
    }

    WOLFSSL_LEAVE( result);
    return result;
}


WOLFSSL_X509_STORE* wolfSSL_X509_STORE_new(void)
{
    WOLFSSL_X509_STORE* store = NULL;

    store = (WOLFSSL_X509_STORE*)XMALLOC(sizeof(WOLFSSL_X509_STORE), NULL, 0);
    if (store != NULL) {
        store->cm = wolfSSL_CertManagerNew();
        if (store->cm == NULL) {
            XFREE(store, NULL, 0);
            store = NULL;
        }
    }

    return store;
}


void wolfSSL_X509_STORE_free(WOLFSSL_X509_STORE* store)
{
    if (store != NULL) {
        if (store->cm != NULL)
        wolfSSL_CertManagerFree(store->cm);
        XFREE(store, NULL, 0);
    }
}


int wolfSSL_X509_STORE_set_default_paths(WOLFSSL_X509_STORE* store)
{
    (void)store;
    return SSL_SUCCESS;
}


int wolfSSL_X509_STORE_get_by_subject(WOLFSSL_X509_STORE_CTX* ctx, int idx,
                            WOLFSSL_X509_NAME* name, WOLFSSL_X509_OBJECT* obj)
{
    (void)ctx;
    (void)idx;
    (void)name;
    (void)obj;
    return 0;
}


WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new(void)
{
    WOLFSSL_X509_STORE_CTX* ctx = (WOLFSSL_X509_STORE_CTX*)XMALLOC(
                                    sizeof(WOLFSSL_X509_STORE_CTX), NULL, 0);

    if (ctx != NULL)
        wolfSSL_X509_STORE_CTX_init(ctx, NULL, NULL, NULL);

    return ctx;
}


int wolfSSL_X509_STORE_CTX_init(WOLFSSL_X509_STORE_CTX* ctx,
     WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509, STACK_OF(WOLFSSL_X509)* sk)
{
    (void)sk;
    if (ctx != NULL) {
        ctx->store = store;
        ctx->current_cert = x509;
        ctx->domain = NULL;
        ctx->ex_data = NULL;
        ctx->userCtx = NULL;
        ctx->error = 0;
        ctx->error_depth = 0;
        ctx->discardSessionCerts = 0;
        return SSL_SUCCESS;
    }
    return SSL_FATAL_ERROR;
}


void wolfSSL_X509_STORE_CTX_free(WOLFSSL_X509_STORE_CTX* ctx)
{
    if (ctx != NULL) {
        if (ctx->store != NULL)
            wolfSSL_X509_STORE_free(ctx->store);
        if (ctx->current_cert != NULL)
            wolfSSL_FreeX509(ctx->current_cert);
        XFREE(ctx, NULL, 0);
    }
}


void wolfSSL_X509_STORE_CTX_cleanup(WOLFSSL_X509_STORE_CTX* ctx)
{
    (void)ctx;
}


int wolfSSL_X509_verify_cert(WOLFSSL_X509_STORE_CTX* ctx)
{
    if (ctx != NULL && ctx->store != NULL && ctx->store->cm != NULL
                                             && ctx->current_cert != NULL) {
        return wolfSSL_CertManagerVerifyBuffer(ctx->store->cm,
                    ctx->current_cert->derCert.buffer,
                    ctx->current_cert->derCert.length,
                    SSL_FILETYPE_ASN1);
    }
    return SSL_FATAL_ERROR;
}


WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_lastUpdate(WOLFSSL_X509_CRL* crl)
{
    (void)crl;
    return 0;
}


WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_nextUpdate(WOLFSSL_X509_CRL* crl)
{
    (void)crl;
    return 0;
}



WOLFSSL_EVP_PKEY* wolfSSL_X509_get_pubkey(WOLFSSL_X509* x509)
{
    WOLFSSL_EVP_PKEY* key = NULL;
    if (x509 != NULL) {
        key = (WOLFSSL_EVP_PKEY*)XMALLOC(
                    sizeof(WOLFSSL_EVP_PKEY), NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        if (key != NULL) {
            key->type = x509->pubKeyOID;
            key->save_type = 0;
            key->pkey.ptr = (char*)XMALLOC(
                        x509->pubKey.length, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
            if (key->pkey.ptr == NULL) {
                XFREE(key, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
                return NULL;
            }
            XMEMCPY(key->pkey.ptr,
                                  x509->pubKey.buffer, x509->pubKey.length);
            key->pkey_sz = x509->pubKey.length;
            #ifdef HAVE_ECC
                key->pkey_curve = (int)x509->pkCurveOID;
            #endif /* HAVE_ECC */
        }
    }
    return key;
}


int wolfSSL_X509_CRL_verify(WOLFSSL_X509_CRL* crl, WOLFSSL_EVP_PKEY* key)
{
    (void)crl;
    (void)key;
    return 0;
}


void wolfSSL_X509_STORE_CTX_set_error(WOLFSSL_X509_STORE_CTX* ctx, int err)
{
    (void)ctx;
    (void)err;
}


void wolfSSL_X509_OBJECT_free_contents(WOLFSSL_X509_OBJECT* obj)
{
    (void)obj;
}


void wolfSSL_EVP_PKEY_free(WOLFSSL_EVP_PKEY* key)
{
    if (key != NULL) {
        if (key->pkey.ptr != NULL)
            XFREE(key->pkey.ptr, NULL, 0);
        XFREE(key, NULL, 0);
    }
}


int wolfSSL_X509_cmp_current_time(const WOLFSSL_ASN1_TIME* asnTime)
{
    (void)asnTime;
    return 0;
}


int wolfSSL_sk_X509_REVOKED_num(WOLFSSL_X509_REVOKED* revoked)
{
    (void)revoked;
    return 0;
}



WOLFSSL_X509_REVOKED* wolfSSL_X509_CRL_get_REVOKED(WOLFSSL_X509_CRL* crl)
{
    (void)crl;
    return 0;
}


WOLFSSL_X509_REVOKED* wolfSSL_sk_X509_REVOKED_value(
                                    WOLFSSL_X509_REVOKED* revoked, int value)
{
    (void)revoked;
    (void)value;
    return 0;
}



WOLFSSL_ASN1_INTEGER* wolfSSL_X509_get_serialNumber(WOLFSSL_X509* x509)
{
    (void)x509;
    return 0;
}


int wolfSSL_ASN1_TIME_print(WOLFSSL_BIO* bio, const WOLFSSL_ASN1_TIME* asnTime)
{
    (void)bio;
    (void)asnTime;
    return 0;
}



int wolfSSL_ASN1_INTEGER_cmp(const WOLFSSL_ASN1_INTEGER* a,
                            const WOLFSSL_ASN1_INTEGER* b)
{
    (void)a;
    (void)b;
    return 0;
}


long wolfSSL_ASN1_INTEGER_get(const WOLFSSL_ASN1_INTEGER* i)
{
    (void)i;
    return 0;
}



void* wolfSSL_X509_STORE_CTX_get_ex_data(WOLFSSL_X509_STORE_CTX* ctx, int idx)
{
#ifdef FORTRESS
    if (ctx != NULL && idx == 0)
        return ctx->ex_data;
#else
    (void)ctx;
    (void)idx;
#endif
    return 0;
}


int wolfSSL_get_ex_data_X509_STORE_CTX_idx(void)
{
    return 0;
}


void* wolfSSL_get_ex_data(const WOLFSSL* ssl, int idx)
{
#ifdef FORTRESS
    if (ssl != NULL && idx < MAX_EX_DATA)
        return ssl->ex_data[idx];
#else
    (void)ssl;
    (void)idx;
#endif
    return 0;
}


void wolfSSL_CTX_set_info_callback(WOLFSSL_CTX* ctx, void (*f)(void))
{
    (void)ctx;
    (void)f;
}



char* wolfSSL_alert_type_string_long(int alertID)
{
    (void)alertID;
    return 0;
}


char* wolfSSL_alert_desc_string_long(int alertID)
{
    (void)alertID;
    return 0;
}


char* wolfSSL_state_string_long(WOLFSSL* ssl)
{
    (void)ssl;
    return 0;
}


int wolfSSL_PEM_def_callback(char* name, int num, int w, void* key)
{
    (void)name;
    (void)num;
    (void)w;
    (void)key;
    return 0;
}


long wolfSSL_CTX_sess_accept(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}


long wolfSSL_CTX_sess_connect(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}


long wolfSSL_CTX_sess_accept_good(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}


long wolfSSL_CTX_sess_connect_good(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}


long wolfSSL_CTX_sess_accept_renegotiate(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}


long wolfSSL_CTX_sess_connect_renegotiate(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}


long wolfSSL_CTX_sess_hits(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}


long wolfSSL_CTX_sess_cb_hits(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}


long wolfSSL_CTX_sess_cache_full(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}


long wolfSSL_CTX_sess_misses(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}


long wolfSSL_CTX_sess_timeouts(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}


long wolfSSL_CTX_sess_number(WOLFSSL_CTX* ctx)
{
    (void)ctx;
    return 0;
}

#ifndef NO_DES3

void wolfSSL_DES_set_key_unchecked(WOLFSSL_const_DES_cblock* myDes,
                                               WOLFSSL_DES_key_schedule* key)
{
    (void)myDes;
    (void)key;
}


void wolfSSL_DES_set_odd_parity(WOLFSSL_DES_cblock* myDes)
{
    (void)myDes;
}


void wolfSSL_DES_ecb_encrypt(WOLFSSL_DES_cblock* desa,
             WOLFSSL_DES_cblock* desb, WOLFSSL_DES_key_schedule* key, int len)
{
    (void)desa;
    (void)desb;
    (void)key;
    (void)len;
}

#endif /* NO_DES3 */

int wolfSSL_BIO_printf(WOLFSSL_BIO* bio, const char* format, ...)
{
    (void)bio;
    (void)format;
    return 0;
}


int wolfSSL_ASN1_UTCTIME_print(WOLFSSL_BIO* bio, const WOLFSSL_ASN1_UTCTIME* a)
{
    (void)bio;
    (void)a;
    return 0;
}


int  wolfSSL_sk_num(WOLFSSL_X509_REVOKED* rev)
{
    (void)rev;
    return 0;
}


void* wolfSSL_sk_value(WOLFSSL_X509_REVOKED* rev, int i)
{
    (void)rev;
    (void)i;
    return 0;
}


/* stunnel 4.28 needs */
void* wolfSSL_CTX_get_ex_data(const WOLFSSL_CTX* ctx, int d)
{
    (void)ctx;
    (void)d;
    return 0;
}


int wolfSSL_CTX_set_ex_data(WOLFSSL_CTX* ctx, int d, void* p)
{
    (void)ctx;
    (void)d;
    (void)p;
    return SSL_SUCCESS;
}


void wolfSSL_CTX_sess_set_get_cb(WOLFSSL_CTX* ctx,
                    WOLFSSL_SESSION*(*f)(WOLFSSL*, unsigned char*, int, int*))
{
    (void)ctx;
    (void)f;
}


void wolfSSL_CTX_sess_set_new_cb(WOLFSSL_CTX* ctx,
                             int (*f)(WOLFSSL*, WOLFSSL_SESSION*))
{
    (void)ctx;
    (void)f;
}


void wolfSSL_CTX_sess_set_remove_cb(WOLFSSL_CTX* ctx, void (*f)(WOLFSSL_CTX*,
                                                        WOLFSSL_SESSION*))
{
    (void)ctx;
    (void)f;
}


int wolfSSL_i2d_SSL_SESSION(WOLFSSL_SESSION* sess, unsigned char** p)
{
    (void)sess;
    (void)p;
    return sizeof(WOLFSSL_SESSION);
}


WOLFSSL_SESSION* wolfSSL_d2i_SSL_SESSION(WOLFSSL_SESSION** sess,
                                const unsigned char** p, long i)
{
    (void)p;
    (void)i;
    if (sess)
        return *sess;
    return NULL;
}


long wolfSSL_SESSION_get_timeout(const WOLFSSL_SESSION* sess)
{
	WOLFSSL_ENTER();
    return sess->timeout;
}


long wolfSSL_SESSION_get_time(const WOLFSSL_SESSION* sess)
{
	WOLFSSL_ENTER();
    return sess->bornOn;
}


int wolfSSL_CTX_get_ex_new_index(long idx, void* arg, void* a, void* b,
                                void* c)
{
    (void)idx;
    (void)arg;
    (void)a;
    (void)b;
    (void)c;
    return 0;
}

#endif /* OPENSSL_EXTRA */


#ifdef KEEP_PEER_CERT
char*  wolfSSL_X509_get_subjectCN(WOLFSSL_X509* x509)
{
    if (x509 == NULL)
        return NULL;

    return x509->subjectCN;
}
#endif /* KEEP_PEER_CERT */



#ifdef SESSION_CERTS
/* Get peer's certificate chain */
WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl)
{
    WOLFSSL_ENTER();
    if (ssl)
        return &ssl->session.chain;

    return 0;
}


/* Get peer's certificate chain total count */
int wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN* chain)
{
    WOLFSSL_ENTER();
    if (chain)
        return chain->count;

    return 0;
}


/* Get peer's ASN.1 DER ceritifcate at index (idx) length in bytes */
int wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN* chain, int idx)
{
    WOLFSSL_ENTER();
    if (chain)
        return chain->certs[idx].length;

    return 0;
}


/* Get peer's ASN.1 DER ceritifcate at index (idx) */
byte* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN* chain, int idx)
{
    WOLFSSL_ENTER();
    if (chain)
        return chain->certs[idx].buffer;

    return 0;
}


/* Get peer's wolfSSL X509 ceritifcate at index (idx) */
WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN* chain, int idx)
{
    int          ret;
    WOLFSSL_X509* x509 = NULL;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endif

    WOLFSSL_ENTER();
    if (chain != NULL) {
    #ifdef WOLFSSL_SMALL_STACK
        cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (cert != NULL)
    #endif
        {
            InitDecodedCert(cert, chain->certs[idx].buffer,
                                  chain->certs[idx].length, NULL);

            if ((ret = ParseCertRelative(cert, CERT_TYPE, 0, NULL)) != 0)
                WOLFSSL_MSG("Failed to parse cert");
            else {
                x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
                                                             DYNAMIC_TYPE_X509);
                if (x509 == NULL) {
                    WOLFSSL_MSG("Failed alloc X509");
                }
                else {
                    InitX509(x509, 1);

                    if ((ret = CopyDecodedToX509(x509, cert)) != 0) {
                        WOLFSSL_MSG("Failed to copy decoded");
                        XFREE(x509, NULL, DYNAMIC_TYPE_X509);
                        x509 = NULL;
                    }
                }
            }

            FreeDecodedCert(cert);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
    }

    return x509;
}


/* Get peer's PEM ceritifcate at index (idx), output to buffer if inLen big
   enough else return error (-1), output length is in *outLen
   SSL_SUCCESS on ok */
int  wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN* chain, int idx,
                               unsigned char* buf, int inLen, int* outLen)
{
    const char header[] = "-----BEGIN CERTIFICATE-----\n";
    const char footer[] = "-----END CERTIFICATE-----\n";

    int headerLen = sizeof(header) - 1;
    int footerLen = sizeof(footer) - 1;
    int i;
    int err;

    WOLFSSL_ENTER();
    if (!chain || !outLen || !buf)
        return BAD_FUNC_ARG;

    /* don't even try if inLen too short */
    if (inLen < headerLen + footerLen + chain->certs[idx].length)
        return BAD_FUNC_ARG;

    /* header */
    XMEMCPY(buf, header, headerLen);
    i = headerLen;

    /* body */
    *outLen = inLen;  /* input to Base64_Encode */
    if ( (err = Base64_Encode(chain->certs[idx].buffer,
                       chain->certs[idx].length, buf + i, (word32*)outLen)) < 0)
        return err;
    i += *outLen;

    /* footer */
    if ( (i + footerLen) > inLen)
        return BAD_FUNC_ARG;
    XMEMCPY(buf + i, footer, footerLen);
    *outLen += headerLen + footerLen;

    return SSL_SUCCESS;
}


/* get session ID */
const byte* wolfSSL_get_sessionID(const WOLFSSL_SESSION* session)
{
    WOLFSSL_ENTER();
    if (session)
        return session->sessionID;

    return NULL;
}


#endif /* SESSION_CERTS */

#ifdef HAVE_FUZZER
void wolfSSL_SetFuzzerCb(WOLFSSL* ssl, CallbackFuzzer cbf, void* fCtx)
{
    if (ssl) {
        ssl->fuzzerCb  = cbf;
        ssl->fuzzerCtx = fCtx;
    }
}
#endif

#ifndef NO_CERTS
#ifdef  HAVE_PK_CALLBACKS

#ifdef HAVE_ECC

void  wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX* ctx, CallbackEccSign cb)
{
    if (ctx)
        ctx->EccSignCb = cb;
}


void  wolfSSL_SetEccSignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->EccSignCtx = ctx;
}


void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->EccSignCtx;

    return NULL;
}


void  wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX* ctx, CallbackEccVerify cb)
{
    if (ctx)
        ctx->EccVerifyCb = cb;
}


void  wolfSSL_SetEccVerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->EccVerifyCtx = ctx;
}


void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->EccVerifyCtx;

    return NULL;
}

#endif /* HAVE_ECC */

#ifndef NO_RSA

void  wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX* ctx, CallbackRsaSign cb)
{
    if (ctx)
        ctx->RsaSignCb = cb;
}


void  wolfSSL_SetRsaSignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->RsaSignCtx = ctx;
}


void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->RsaSignCtx;

    return NULL;
}


void  wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb)
{
    if (ctx)
        ctx->RsaVerifyCb = cb;
}


void  wolfSSL_SetRsaVerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->RsaVerifyCtx = ctx;
}


void* wolfSSL_GetRsaVerifyCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->RsaVerifyCtx;

    return NULL;
}

void  wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX* ctx, CallbackRsaEnc cb)
{
    if (ctx)
        ctx->RsaEncCb = cb;
}


void  wolfSSL_SetRsaEncCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->RsaEncCtx = ctx;
}


void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->RsaEncCtx;

    return NULL;
}

void  wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX* ctx, CallbackRsaDec cb)
{
    if (ctx)
        ctx->RsaDecCb = cb;
}


void  wolfSSL_SetRsaDecCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->RsaDecCtx = ctx;
}


void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->RsaDecCtx;

    return NULL;
}


#endif /* NO_RSA */

#endif /* HAVE_PK_CALLBACKS */
#endif /* NO_CERTS */


#ifdef WOLFSSL_HAVE_WOLFSCEP
    /* Used by autoconf to see if wolfSCEP is available */
    void wolfSSL_wolfSCEP(void) {}
#endif


#ifdef WOLFSSL_HAVE_CERT_SERVICE
    /* Used by autoconf to see if cert service is available */
    void wolfSSL_cert_service(void) {}
#endif

