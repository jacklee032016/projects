
/*
* Callbacks in internal modules of SSL: Wolf SSL Internal Callbacks
*/


#define WOLFSSL_TICKET_NAME_SZ 16
#define WOLFSSL_TICKET_IV_SZ   16
#define WOLFSSL_TICKET_MAC_SZ  32

/* User Atomic Record Layer CallBacks */
typedef int (*CallbackMacEncrypt)(struct	WOLFSSL* ssl, unsigned char* macOut,
       const unsigned char* macIn, unsigned int macInSz, int macContent,
       int macVerify, unsigned char* encOut, const unsigned char* encIn,
       unsigned int encSz, void* ctx);

/* I/O callbacks */
typedef int (*CallbackIORecv)(struct	WOLFSSL *ssl, char *buf, int sz, void *ctx);
typedef int (*CallbackIOSend)(struct	WOLFSSL *ssl, char *buf, int sz, void *ctx);

typedef int (*CallbackFuzzer)(struct	WOLFSSL* ssl, const unsigned char* buf, int sz,int type, void* fuzzCtx);

#ifndef PSK_TYPES_DEFINED
    typedef unsigned int (*psk_client_callback)(struct	WOLFSSL*, const char*, char*,unsigned int, unsigned char*, unsigned int);
    typedef unsigned int (*psk_server_callback)(struct	WOLFSSL*, const char*, unsigned char*, unsigned int);
#endif /* PSK_TYPES_DEFINED */

typedef int (*VerifyCallback)(int, struct	WOLFSSL_X509_STORE_CTX*);
typedef int (*pem_password_cb)(char*, int, int, void*);
typedef int (*SessionSecretCb)(struct	WOLFSSL* ssl,  void* secret, int* secretSz, void* ctx);

typedef int (*CallbackGenCookie)(struct	WOLFSSL* ssl, unsigned char* buf, int sz,
                                 void* ctx);

typedef int (*SessionTicketEncCb)(struct	WOLFSSL*,
                                 unsigned char key_name[WOLFSSL_TICKET_NAME_SZ],
                                 unsigned char iv[WOLFSSL_TICKET_IV_SZ],
                                 unsigned char mac[WOLFSSL_TICKET_MAC_SZ],
                                 int enc, unsigned char*, int, int*, void*);

typedef int (*CallbackDecryptVerify)(struct	WOLFSSL* ssl,
       unsigned char* decOut, const unsigned char* decIn,
       unsigned int decSz, int content, int verify, unsigned int* padSz,
       void* ctx);

/* Public Key Callback support */
typedef int (*CallbackEccSign)(struct	WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
typedef int (*CallbackEccVerify)(struct	WOLFSSL* ssl,
       const unsigned char* sig, unsigned int sigSz,
       const unsigned char* hash, unsigned int hashSz,
       const unsigned char* keyDer, unsigned int keySz,
       int* result, void* ctx);
typedef int (*CallbackRsaSign)(struct	WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
typedef int (*CallbackRsaVerify)(struct	WOLFSSL* ssl,
       unsigned char* sig, unsigned int sigSz,
       unsigned char** out,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
typedef int (*CallbackRsaEnc)(struct	WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
typedef int (*CallbackRsaDec)(struct	WOLFSSL* ssl,
       unsigned char* in, unsigned int inSz,
       unsigned char** out,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);

typedef int (*HandShakeDoneCb)(struct	WOLFSSL*, void*);


typedef int (*hmacfp) (struct	WOLFSSL*, byte*, const byte*, word32, int, int);



