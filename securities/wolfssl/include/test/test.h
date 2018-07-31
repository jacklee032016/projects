/* test.h */

#ifndef wolfSSL_TEST_H
#define wolfSSL_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/logging.h>

#include "cmnDebug.h"

#ifdef ATOMIC_USER
    #include <wolfssl/wolfcrypt/aes.h>
    #include <wolfssl/wolfcrypt/arc4.h>
    #include <wolfssl/wolfcrypt/hmac.h>
#endif

#ifdef HAVE_PK_CALLBACKS
    #include <wolfssl/wolfcrypt/asn.h>
    #ifdef HAVE_ECC
        #include <wolfssl/wolfcrypt/ecc.h>
    #endif /* HAVE_ECC */
#endif /*HAVE_PK_CALLBACKS */



#ifdef HAVE_CAVIUM
    #include "cavium_sysdep.h"
    #include "cavium_common.h"
    #include "cavium_ioctl.h"
#endif





   

void InitTcpReady(tcp_ready*);
void FreeTcpReady(tcp_ready*);
void wait_tcp_ready(func_args*);

typedef THREAD_RETURN WOLFSSL_THREAD THREAD_FUNC(void*);

void start_thread(THREAD_FUNC, func_args*, THREAD_TYPE*);
void join_thread(THREAD_TYPE);




#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)

static INLINE int PasswordCallBack(char* passwd, int sz, int rw, void* userdata)
{
    (void)rw;
    (void)userdata;
    strncpy(passwd, "yassl123", sz);
    return 8;
}

#endif


#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)

static INLINE void ShowX509(WOLFSSL_X509* x509, const char* hdr)
{
    char* altName;
    char* issuer  = wolfSSL_X509_NAME_oneline( wolfSSL_X509_get_issuer_name(x509), 0, 0);
    char* subject = wolfSSL_X509_NAME_oneline( wolfSSL_X509_get_subject_name(x509), 0, 0);
    byte  serial[32];
    int   ret;
    int   sz = sizeof(serial);
        
    printf("%s\n issuer : %s\n subject: %s\n", hdr, issuer, subject);

    while ( (altName = wolfSSL_X509_get_next_altname(x509)) != NULL)
        printf(" altname = %s\n", altName);

    ret = wolfSSL_X509_get_serial_number(x509, serial, &sz);
    if (ret == SSL_SUCCESS) {
        int  i;
        int  strLen;
        char serialMsg[80];

        /* testsuite has multiple threads writing to stdout, get output
           message ready to write once */
        strLen = sprintf(serialMsg, " serial number");
        for (i = 0; i < sz; i++)
            sprintf(serialMsg + strLen + (i*3), ":%02x ", serial[i]);
        printf("%s\n", serialMsg);
    }

    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
    XFREE(issuer,  0, DYNAMIC_TYPE_OPENSSL);
}

#endif /* KEEP_PEER_CERT || SESSION_CERTS */




#if defined(NO_FILESYSTEM) && !defined(NO_CERTS)

    enum {
        WOLFSSL_CA   = 1,
        WOLFSSL_CERT = 2,
        WOLFSSL_KEY  = 3
    };

    static INLINE void load_buffer(WOLFSSL_CTX* ctx, const char* fname, int type)
    {
        /* test buffer load */
        long  sz = 0;
        byte  buff[10000];
        FILE* file = fopen(fname, "rb");

        if (!file)
            err_sys("can't open file for buffer load "
                    "Please run from wolfSSL home directory if not");
        fseek(file, 0, SEEK_END);
        sz = ftell(file);
        rewind(file);
        fread(buff, sizeof(buff), 1, file);
  
        if (type == WOLFSSL_CA) {
            if (wolfSSL_CTX_load_verify_buffer(ctx, buff, sz, SSL_FILETYPE_PEM)
                                              != SSL_SUCCESS)
                err_sys("can't load buffer ca file");
        }
        else if (type == WOLFSSL_CERT) {
            if (wolfSSL_CTX_use_certificate_buffer(ctx, buff, sz,
                        SSL_FILETYPE_PEM) != SSL_SUCCESS)
                err_sys("can't load buffer cert file");
        }
        else if (type == WOLFSSL_KEY) {
            if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, buff, sz,
                        SSL_FILETYPE_PEM) != SSL_SUCCESS)
                err_sys("can't load buffer key file");
        }
    }

#endif /* NO_FILESYSTEM */

#ifdef VERIFY_CALLBACK

static INLINE int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)preverify;
    char buffer[WOLFSSL_MAX_ERROR_SZ];

#ifdef OPENSSL_EXTRA
    WOLFSSL_X509* peer;
#endif

    printf("In verification callback, error = %d, %s\n", store->error,
                                 wolfSSL_ERR_error_string(store->error, buffer));
#ifdef OPENSSL_EXTRA
    peer = store->current_cert;
    if (peer) {
        char* issuer  = wolfSSL_X509_NAME_oneline( wolfSSL_X509_get_issuer_name(peer), 0, 0);
        char* subject = wolfSSL_X509_NAME_oneline( wolfSSL_X509_get_subject_name(peer), 0, 0);
        printf("peer's cert info:\n issuer : %s\n subject: %s\n", issuer, subject);
        XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
        XFREE(issuer,  0, DYNAMIC_TYPE_OPENSSL);
    }
    else
        printf("peer has no cert!\n");
#endif
    printf("Subject's domain name is %s\n", store->domain);

    printf("Allowing to continue anyway (shouldn't do this, EVER!!!)\n");
    return 1;
}

#endif /* VERIFY_CALLBACK */



#ifdef HAVE_CRL

static INLINE void CRL_CallBack(const char* url)
{
    printf("CRL callback url = %s\n", url);
}

#endif

#ifndef NO_DH
static INLINE void SetDH(WOLFSSL* ssl)
{
    /* dh1024 p */
    static unsigned char p[] =
    {
        0xE6, 0x96, 0x9D, 0x3D, 0x49, 0x5B, 0xE3, 0x2C, 0x7C, 0xF1, 0x80, 0xC3,
        0xBD, 0xD4, 0x79, 0x8E, 0x91, 0xB7, 0x81, 0x82, 0x51, 0xBB, 0x05, 0x5E,
        0x2A, 0x20, 0x64, 0x90, 0x4A, 0x79, 0xA7, 0x70, 0xFA, 0x15, 0xA2, 0x59,
        0xCB, 0xD5, 0x23, 0xA6, 0xA6, 0xEF, 0x09, 0xC4, 0x30, 0x48, 0xD5, 0xA2,
        0x2F, 0x97, 0x1F, 0x3C, 0x20, 0x12, 0x9B, 0x48, 0x00, 0x0E, 0x6E, 0xDD,
        0x06, 0x1C, 0xBC, 0x05, 0x3E, 0x37, 0x1D, 0x79, 0x4E, 0x53, 0x27, 0xDF,
        0x61, 0x1E, 0xBB, 0xBE, 0x1B, 0xAC, 0x9B, 0x5C, 0x60, 0x44, 0xCF, 0x02,
        0x3D, 0x76, 0xE0, 0x5E, 0xEA, 0x9B, 0xAD, 0x99, 0x1B, 0x13, 0xA6, 0x3C,
        0x97, 0x4E, 0x9E, 0xF1, 0x83, 0x9E, 0xB5, 0xDB, 0x12, 0x51, 0x36, 0xF7,
        0x26, 0x2E, 0x56, 0xA8, 0x87, 0x15, 0x38, 0xDF, 0xD8, 0x23, 0xC6, 0x50,
        0x50, 0x85, 0xE2, 0x1F, 0x0D, 0xD5, 0xC8, 0x6B,
    };

    /* dh1024 g */
    static unsigned char g[] =
    {
      0x02,
    };

    wolfSSL_SetTmpDH(ssl, p, sizeof(p), g, sizeof(g));
}

static INLINE void SetDHCtx(WOLFSSL_CTX* ctx)
{
    /* dh1024 p */
    static unsigned char p[] =
    {
        0xE6, 0x96, 0x9D, 0x3D, 0x49, 0x5B, 0xE3, 0x2C, 0x7C, 0xF1, 0x80, 0xC3,
        0xBD, 0xD4, 0x79, 0x8E, 0x91, 0xB7, 0x81, 0x82, 0x51, 0xBB, 0x05, 0x5E,
        0x2A, 0x20, 0x64, 0x90, 0x4A, 0x79, 0xA7, 0x70, 0xFA, 0x15, 0xA2, 0x59,
        0xCB, 0xD5, 0x23, 0xA6, 0xA6, 0xEF, 0x09, 0xC4, 0x30, 0x48, 0xD5, 0xA2,
        0x2F, 0x97, 0x1F, 0x3C, 0x20, 0x12, 0x9B, 0x48, 0x00, 0x0E, 0x6E, 0xDD,
        0x06, 0x1C, 0xBC, 0x05, 0x3E, 0x37, 0x1D, 0x79, 0x4E, 0x53, 0x27, 0xDF,
        0x61, 0x1E, 0xBB, 0xBE, 0x1B, 0xAC, 0x9B, 0x5C, 0x60, 0x44, 0xCF, 0x02,
        0x3D, 0x76, 0xE0, 0x5E, 0xEA, 0x9B, 0xAD, 0x99, 0x1B, 0x13, 0xA6, 0x3C,
        0x97, 0x4E, 0x9E, 0xF1, 0x83, 0x9E, 0xB5, 0xDB, 0x12, 0x51, 0x36, 0xF7,
        0x26, 0x2E, 0x56, 0xA8, 0x87, 0x15, 0x38, 0xDF, 0xD8, 0x23, 0xC6, 0x50,
        0x50, 0x85, 0xE2, 0x1F, 0x0D, 0xD5, 0xC8, 0x6B,
    };

    /* dh1024 g */
    static unsigned char g[] =
    {
      0x02,
    };

    wolfSSL_CTX_SetTmpDH(ctx, p, sizeof(p), g, sizeof(g));
}
#endif /* NO_DH */

#ifndef NO_CERTS

static INLINE void CaCb(unsigned char* der, int sz, int type)
{
    (void)der;
    printf("Got CA cache add callback, derSz = %d, type = %d\n", sz, type);
}

#endif /* !NO_CERTS */

#ifdef HAVE_CAVIUM

static INLINE int OpenNitroxDevice(int dma_mode,int dev_id)
{
   Csp1CoreAssignment core_assign;
   Uint32             device;

   if (CspInitialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
      return -1;
   if (Csp1GetDevType(&device))
      return -1;
   if (device != NPX_DEVICE) {
      if (ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID], IOCTL_CSP1_GET_CORE_ASSIGNMENT,
                (Uint32 *)&core_assign)!= 0)
         return -1;
   }
   CspShutdown(CAVIUM_DEV_ID);

   return CspInitialize(dma_mode, dev_id);
}

#endif /* HAVE_CAVIUM */





#ifdef HAVE_STACK_SIZE

typedef THREAD_RETURN WOLFSSL_THREAD (*thread_func)(void* args);


static INLINE void StackSizeCheck(func_args* args, thread_func tf)
{
    int            ret, i, used;
    unsigned char* myStack;
    int            stackSize = 1024*128;
    pthread_attr_t myAttr;
    pthread_t      threadId;

#ifdef PTHREAD_STACK_MIN
    if (stackSize < PTHREAD_STACK_MIN)
        stackSize = PTHREAD_STACK_MIN;
#endif

    ret = posix_memalign((void**)&myStack, sysconf(_SC_PAGESIZE), stackSize);
    if (ret != 0) 
        err_sys("posix_memalign failed\n");        

    memset(myStack, 0x01, stackSize);

    ret = pthread_attr_init(&myAttr);
    if (ret != 0)
        err_sys("attr_init failed");

    ret = pthread_attr_setstack(&myAttr, myStack, stackSize);
    if (ret != 0)
        err_sys("attr_setstackaddr failed");

    ret = pthread_create(&threadId, &myAttr, tf, args);
    if (ret != 0) {
        perror("pthread_create failed");
        exit(EXIT_FAILURE);
    }

    ret = pthread_join(threadId, NULL);
    if (ret != 0)
        err_sys("pthread_join failed");

    for (i = 0; i < stackSize; i++) {
        if (myStack[i] != 0x01) {
            break;
        }
    }

    used = stackSize - i;
    printf("stack used = %d\n", used);
}


#endif /* HAVE_STACK_SIZE */



#ifdef ATOMIC_USER

/* Atomic Encrypt Context example */
typedef struct AtomicEncCtx {
    int  keySetup;           /* have we done key setup yet */
    Aes  aes;                /* for aes example */
} AtomicEncCtx;


/* Atomic Decrypt Context example */
typedef struct AtomicDecCtx {
    int  keySetup;           /* have we done key setup yet */
    Aes  aes;                /* for aes example */
} AtomicDecCtx;


static INLINE int myMacEncryptCb(WOLFSSL* ssl, unsigned char* macOut, 
       const unsigned char* macIn, unsigned int macInSz, int macContent, 
       int macVerify, unsigned char* encOut, const unsigned char* encIn,
       unsigned int encSz, void* ctx)
{
    int  ret;
    Hmac hmac;
    byte myInner[WOLFSSL_TLS_HMAC_INNER_SZ];
    AtomicEncCtx* encCtx = (AtomicEncCtx*)ctx;
    const char* tlsStr = "TLS";

    /* example supports (d)tls aes */
    if (wolfSSL_GetBulkCipher(ssl) != wolfssl_aes) {
        printf("myMacEncryptCb not using AES\n");
        return -1;
    }

    if (strstr(wolfSSL_get_version(ssl), tlsStr) == NULL) {
        printf("myMacEncryptCb not using (D)TLS\n");
        return -1;
    }

    /* hmac, not needed if aead mode */
    wolfSSL_SetTlsHmacInner(ssl, myInner, macInSz, macContent, macVerify);

    ret = wc_HmacSetKey(&hmac, wolfSSL_GetHmacType(ssl),
               wolfSSL_GetMacSecret(ssl, macVerify), wolfSSL_GetHmacSize(ssl));
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, myInner, sizeof(myInner));
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, macIn, macInSz);
    if (ret != 0)
        return ret;
    ret = wc_HmacFinal(&hmac, macOut);
    if (ret != 0)
        return ret;


    /* encrypt setup on first time */
    if (encCtx->keySetup == 0) {
        int   keyLen = wolfSSL_GetKeySize(ssl);
        const byte* key;
        const byte* iv;

        if (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END) {
            key = wolfSSL_GetClientWriteKey(ssl);
            iv  = wolfSSL_GetClientWriteIV(ssl);
        }
        else {
            key = wolfSSL_GetServerWriteKey(ssl);
            iv  = wolfSSL_GetServerWriteIV(ssl);
        }

        ret = wc_AesSetKey(&encCtx->aes, key, keyLen, iv, AES_ENCRYPTION);
        if (ret != 0) {
            printf("AesSetKey failed in myMacEncryptCb\n");
            return ret;
        }
        encCtx->keySetup = 1;
    }

    /* encrypt */
    return wc_AesCbcEncrypt(&encCtx->aes, encOut, encIn, encSz);
}


static INLINE int myDecryptVerifyCb(WOLFSSL* ssl, 
       unsigned char* decOut, const unsigned char* decIn,
       unsigned int decSz, int macContent, int macVerify,
       unsigned int* padSz, void* ctx)
{
    AtomicDecCtx* decCtx = (AtomicDecCtx*)ctx;
    int ret      = 0;
    int macInSz  = 0;
    int ivExtra  = 0;
    int digestSz = wolfSSL_GetHmacSize(ssl);
    unsigned int pad     = 0;
    unsigned int padByte = 0;
    Hmac hmac;
    byte myInner[WOLFSSL_TLS_HMAC_INNER_SZ];
    byte verify[MAX_DIGEST_SIZE];
    const char* tlsStr = "TLS";

    /* example supports (d)tls aes */
    if (wolfSSL_GetBulkCipher(ssl) != wolfssl_aes) {
        printf("myMacEncryptCb not using AES\n");
        return -1;
    }

    if (strstr(wolfSSL_get_version(ssl), tlsStr) == NULL) {
        printf("myMacEncryptCb not using (D)TLS\n");
        return -1;
    }

    /*decrypt */
    if (decCtx->keySetup == 0) {
        int   keyLen = wolfSSL_GetKeySize(ssl);
        const byte* key;
        const byte* iv;

        /* decrypt is from other side (peer) */
        if (wolfSSL_GetSide(ssl) == WOLFSSL_SERVER_END) {
            key = wolfSSL_GetClientWriteKey(ssl);
            iv  = wolfSSL_GetClientWriteIV(ssl);
        }
        else {
            key = wolfSSL_GetServerWriteKey(ssl);
            iv  = wolfSSL_GetServerWriteIV(ssl);
        }

        ret = wc_AesSetKey(&decCtx->aes, key, keyLen, iv, AES_DECRYPTION);
        if (ret != 0) {
            printf("AesSetKey failed in myDecryptVerifyCb\n");
            return ret;
        }
        decCtx->keySetup = 1;
    }

    /* decrypt */
    ret = wc_AesCbcDecrypt(&decCtx->aes, decOut, decIn, decSz);

    if (wolfSSL_GetCipherType(ssl) == WOLFSSL_AEAD_TYPE) {
        *padSz = wolfSSL_GetAeadMacSize(ssl);
        return 0; /* hmac, not needed if aead mode */
    }

    if (wolfSSL_GetCipherType(ssl) == WOLFSSL_BLOCK_TYPE) {
        pad     = *(decOut + decSz - 1);
        padByte = 1;
        if (wolfSSL_IsTLSv1_1(ssl))
            ivExtra = wolfSSL_GetCipherBlockSize(ssl);
    }

    *padSz  = wolfSSL_GetHmacSize(ssl) + pad + padByte;
    macInSz = decSz - ivExtra - digestSz - pad - padByte;

    wolfSSL_SetTlsHmacInner(ssl, myInner, macInSz, macContent, macVerify);

    ret = wc_HmacSetKey(&hmac, wolfSSL_GetHmacType(ssl),
               wolfSSL_GetMacSecret(ssl, macVerify), digestSz);
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, myInner, sizeof(myInner));
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, decOut + ivExtra, macInSz);
    if (ret != 0)
        return ret;
    ret = wc_HmacFinal(&hmac, verify);
    if (ret != 0)
        return ret;

    if (memcmp(verify, decOut + decSz - digestSz - pad - padByte,
               digestSz) != 0) {
        printf("myDecryptVerify verify failed\n");
        return -1;
    }

    return ret;
}


static INLINE void SetupAtomicUser(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    AtomicEncCtx* encCtx;
    AtomicDecCtx* decCtx;

    encCtx = (AtomicEncCtx*)malloc(sizeof(AtomicEncCtx));
    if (encCtx == NULL)
        err_sys("AtomicEncCtx malloc failed");
    memset(encCtx, 0, sizeof(AtomicEncCtx));

    decCtx = (AtomicDecCtx*)malloc(sizeof(AtomicDecCtx));
    if (decCtx == NULL) {
        free(encCtx);
        err_sys("AtomicDecCtx malloc failed");
    }
    memset(decCtx, 0, sizeof(AtomicDecCtx));

    wolfSSL_CTX_SetMacEncryptCb(ctx, myMacEncryptCb);
    wolfSSL_SetMacEncryptCtx(ssl, encCtx);

    wolfSSL_CTX_SetDecryptVerifyCb(ctx, myDecryptVerifyCb);
    wolfSSL_SetDecryptVerifyCtx(ssl, decCtx);
}


static INLINE void FreeAtomicUser(WOLFSSL* ssl)
{
    AtomicEncCtx* encCtx = (AtomicEncCtx*)wolfSSL_GetMacEncryptCtx(ssl);
    AtomicDecCtx* decCtx = (AtomicDecCtx*)wolfSSL_GetDecryptVerifyCtx(ssl);

    free(decCtx);
    free(encCtx);
}

#endif /* ATOMIC_USER */


#ifdef HAVE_PK_CALLBACKS

#ifdef HAVE_ECC

static INLINE int myEccSign(WOLFSSL* ssl, const byte* in, word32 inSz,
        byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx)
{
    RNG     rng;
    int     ret;
    word32  idx = 0;
    ecc_key myKey;

    (void)ssl;
    (void)ctx;

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    wc_ecc_init(&myKey);
    
    ret = wc_EccPrivateKeyDecode(key, &idx, &myKey, keySz);    
    if (ret == 0)
        ret = wc_ecc_sign_hash(in, inSz, out, outSz, &rng, &myKey);
    wc_ecc_free(&myKey);
    wc_FreeRng(&rng);

    return ret;
}


static INLINE int myEccVerify(WOLFSSL* ssl, const byte* sig, word32 sigSz,
        const byte* hash, word32 hashSz, const byte* key, word32 keySz,
        int* result, void* ctx)
{
    int     ret;
    ecc_key myKey;

    (void)ssl;
    (void)ctx;

    wc_ecc_init(&myKey);
    
    ret = wc_ecc_import_x963(key, keySz, &myKey);
    if (ret == 0)
        ret = wc_ecc_verify_hash(sig, sigSz, hash, hashSz, result, &myKey);
    wc_ecc_free(&myKey);

    return ret;
}

#endif /* HAVE_ECC */

#ifndef NO_RSA

static INLINE int myRsaSign(WOLFSSL* ssl, const byte* in, word32 inSz,
        byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx)
{
    RNG     rng;
    int     ret;
    word32  idx = 0;
    RsaKey  myKey;

    (void)ssl;
    (void)ctx;

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    wc_InitRsaKey(&myKey, NULL);
    
    ret = wc_RsaPrivateKeyDecode(key, &idx, &myKey, keySz);    
    if (ret == 0)
        ret = wc_RsaSSL_Sign(in, inSz, out, *outSz, &myKey, &rng);
    if (ret > 0) {  /* save and convert to 0 success */
        *outSz = ret;
        ret = 0;
    }
    wc_FreeRsaKey(&myKey);
    wc_FreeRng(&rng);

    return ret;
}


static INLINE int myRsaVerify(WOLFSSL* ssl, byte* sig, word32 sigSz,
        byte** out,
        const byte* key, word32 keySz,
        void* ctx)
{
    int     ret;
    word32  idx = 0;
    RsaKey  myKey;

    (void)ssl;
    (void)ctx;

    wc_InitRsaKey(&myKey, NULL);

    ret = wc_RsaPublicKeyDecode(key, &idx, &myKey, keySz);
    if (ret == 0)
        ret = wc_RsaSSL_VerifyInline(sig, sigSz, out, &myKey);
    wc_FreeRsaKey(&myKey);

    return ret;
}


static INLINE int myRsaEnc(WOLFSSL* ssl, const byte* in, word32 inSz,
                           byte* out, word32* outSz, const byte* key,
                           word32 keySz, void* ctx)
{
    int     ret;
    word32  idx = 0;
    RsaKey  myKey;
    RNG     rng;

    (void)ssl;
    (void)ctx;

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    wc_InitRsaKey(&myKey, NULL);
    
    ret = wc_RsaPublicKeyDecode(key, &idx, &myKey, keySz);
    if (ret == 0) {
        ret = wc_RsaPublicEncrypt(in, inSz, out, *outSz, &myKey, &rng);
        if (ret > 0) {
            *outSz = ret;
            ret = 0;  /* reset to success */
        }
    }
    wc_FreeRsaKey(&myKey);
    wc_FreeRng(&rng);

    return ret;
}

static INLINE int myRsaDec(WOLFSSL* ssl, byte* in, word32 inSz,
                           byte** out,
                           const byte* key, word32 keySz, void* ctx)
{
    int     ret;
    word32  idx = 0;
    RsaKey  myKey;

    (void)ssl;
    (void)ctx;

    wc_InitRsaKey(&myKey, NULL);

    ret = wc_RsaPrivateKeyDecode(key, &idx, &myKey, keySz);
    if (ret == 0) {
        ret = wc_RsaPrivateDecryptInline(in, inSz, out, &myKey);
    }
    wc_FreeRsaKey(&myKey);

    return ret;
}

#endif /* NO_RSA */

static INLINE void SetupPkCallbacks(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    (void)ctx;
    (void)ssl;

    #ifdef HAVE_ECC
        wolfSSL_CTX_SetEccSignCb(ctx, myEccSign);
        wolfSSL_CTX_SetEccVerifyCb(ctx, myEccVerify);
    #endif /* HAVE_ECC */
    #ifndef NO_RSA 
        wolfSSL_CTX_SetRsaSignCb(ctx, myRsaSign);
        wolfSSL_CTX_SetRsaVerifyCb(ctx, myRsaVerify);
        wolfSSL_CTX_SetRsaEncCb(ctx, myRsaEnc);
        wolfSSL_CTX_SetRsaDecCb(ctx, myRsaDec);
    #endif /* NO_RSA */
}

#endif /* HAVE_PK_CALLBACKS */





#if defined(__hpux__) || defined(__MINGW32__) || defined (WOLFSSL_TIRTOS) \
                      || defined(_MSC_VER)

/* HP/UX doesn't have strsep, needed by test/suites.c */
static INLINE char* strsep(char **stringp, const char *delim)
{
    char* start;
    char* end;

    start = *stringp;
    if (start == NULL)
        return NULL;

    if ((end = strpbrk(start, delim))) {
        *end++ = '\0';
        *stringp = end;
    } else {
        *stringp = NULL;
    }

    return start;
}

#endif /* __hpux__ and others */

/* Create unique filename, len is length of tempfn name, assuming
   len does not include null terminating character,
   num is number of characters in tempfn name to randomize */
static INLINE const char* mymktemp(char *tempfn, int len, int num)
{
    int x, size;
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz";
    RNG rng;
    byte out;

    if (tempfn == NULL || len < 1 || num < 1 || len <= num) {
        printf("Bad input\n");
        return NULL;
    }

    size = len - 1;

    if (wc_InitRng(&rng) != 0) {
        printf("InitRng failed\n");
        return NULL;
    }

    for (x = size; x > size - num; x--) {
        if (wc_RNG_GenerateBlock(&rng,(byte*)&out, sizeof(out)) != 0) {
            printf("RNG_GenerateBlock failed\n");
            return NULL;
        }
        tempfn[x] = alphanum[out % (sizeof(alphanum) - 1)];
    }
    tempfn[len] = '\0';

    wc_FreeRng(&rng);

    return tempfn;
}



#if defined(HAVE_SESSION_TICKET) && defined(HAVE_CHACHA) && defined(HAVE_POLY1305)

    #include <wolfssl/wolfcrypt/chacha20_poly1305.h>

    typedef struct key_ctx {
        byte name[WOLFSSL_TICKET_NAME_SZ];     /* name for this context */
        byte key[16];                          /* cipher key */
    } key_ctx;

    static key_ctx myKey_ctx;
    static RNG rng;

    static INLINE int TicketInit(void)
    {
        int ret = wc_InitRng(&rng);
        if (ret != 0) return ret;

        ret = wc_RNG_GenerateBlock(&rng, myKey_ctx.key, sizeof(myKey_ctx.key));
        if (ret != 0) return ret;

        ret = wc_RNG_GenerateBlock(&rng, myKey_ctx.name,sizeof(myKey_ctx.name));
        if (ret != 0) return ret;

        return 0;
    }

    static INLINE void TicketCleanup(void)
    {
        wc_FreeRng(&rng);
    }

    static INLINE int myTicketEncCb(WOLFSSL* ssl,
                             byte key_name[WOLFSSL_TICKET_NAME_SZ],
                             byte iv[WOLFSSL_TICKET_IV_SZ],
                             byte mac[WOLFSSL_TICKET_MAC_SZ],
                             int enc, byte* ticket, int inLen, int* outLen,
                             void* userCtx)
    {
        (void)ssl;
        (void)userCtx;

        int ret;
        word16 sLen = htons(inLen);
        byte aad[WOLFSSL_TICKET_NAME_SZ + WOLFSSL_TICKET_IV_SZ + 2];
        int  aadSz = WOLFSSL_TICKET_NAME_SZ + WOLFSSL_TICKET_IV_SZ + 2;
        byte* tmp = aad;

        if (enc) {
            XMEMCPY(key_name, myKey_ctx.name, WOLFSSL_TICKET_NAME_SZ);

            ret = wc_RNG_GenerateBlock(&rng, iv, WOLFSSL_TICKET_IV_SZ);
            if (ret != 0) return WOLFSSL_TICKET_RET_REJECT;

            /* build aad from key name, iv, and length */
            XMEMCPY(tmp, key_name, WOLFSSL_TICKET_NAME_SZ);
            tmp += WOLFSSL_TICKET_NAME_SZ;
            XMEMCPY(tmp, iv, WOLFSSL_TICKET_IV_SZ);
            tmp += WOLFSSL_TICKET_IV_SZ;
            XMEMCPY(tmp, &sLen, 2);

            ret = wc_ChaCha20Poly1305_Encrypt(myKey_ctx.key, iv,
                                              aad, aadSz,
                                              ticket, inLen,
                                              ticket,
                                              mac);
            if (ret != 0) return WOLFSSL_TICKET_RET_REJECT;
            *outLen = inLen;  /* no padding in this mode */
        } else {
            /* decrypt */

            /* see if we know this key */
            if (XMEMCMP(key_name, myKey_ctx.name, WOLFSSL_TICKET_NAME_SZ) != 0){
                printf("client presented unknown ticket key name ");
                return WOLFSSL_TICKET_RET_FATAL;
            }

            /* build aad from key name, iv, and length */
            XMEMCPY(tmp, key_name, WOLFSSL_TICKET_NAME_SZ);
            tmp += WOLFSSL_TICKET_NAME_SZ;
            XMEMCPY(tmp, iv, WOLFSSL_TICKET_IV_SZ);
            tmp += WOLFSSL_TICKET_IV_SZ;
            XMEMCPY(tmp, &sLen, 2);

            ret = wc_ChaCha20Poly1305_Decrypt(myKey_ctx.key, iv,
                                              aad, aadSz,
                                              ticket, inLen,
                                              mac,
                                              ticket);
            if (ret != 0) return WOLFSSL_TICKET_RET_REJECT;
            *outLen = inLen;  /* no padding in this mode */
        }

        return WOLFSSL_TICKET_RET_OK;
    }

#endif  /* HAVE_SESSION_TICKET && CHACHA20 && POLY1305 */

#endif /* wolfSSL_TEST_H */
