
#include "cmnSsl.h"

#ifdef OPENSSL_EXTRA

    unsigned long wolfSSLeay(void)
    {
        return SSLEAY_VERSION_NUMBER;
    }


    const char* wolfSSLeay_version(int type)
    {
        static const char* version = "SSLeay wolfSSL compatibility";
        (void)type;
        return version;
    }


#ifndef NO_MD5
    void wolfSSL_MD5_Init(WOLFSSL_MD5_CTX* md5)
    {
        typedef char md5_test[sizeof(MD5_CTX) >= sizeof(Md5) ? 1 : -1];
        (void)sizeof(md5_test);

	WOLFSSL_ENTER();
        wc_InitMd5((Md5*)md5);
    }


    void wolfSSL_MD5_Update(WOLFSSL_MD5_CTX* md5, const void* input,
                           unsigned long sz)
    {
	WOLFSSL_ENTER();
        wc_Md5Update((Md5*)md5, (const byte*)input, (word32)sz);
    }


    void wolfSSL_MD5_Final(byte* input, WOLFSSL_MD5_CTX* md5)
    {
	WOLFSSL_ENTER();
        wc_Md5Final((Md5*)md5, input);
    }
#endif /* NO_MD5 */


#ifndef NO_SHA
    void wolfSSL_SHA_Init(WOLFSSL_SHA_CTX* sha)
    {
        typedef char sha_test[sizeof(SHA_CTX) >= sizeof(Sha) ? 1 : -1];
        (void)sizeof(sha_test);

	WOLFSSL_ENTER();
        wc_InitSha((Sha*)sha);  /* OpenSSL compat, no ret */
    }


    void wolfSSL_SHA_Update(WOLFSSL_SHA_CTX* sha, const void* input,
                           unsigned long sz)
    {
	WOLFSSL_ENTER();
        wc_ShaUpdate((Sha*)sha, (const byte*)input, (word32)sz);
    }


    void wolfSSL_SHA_Final(byte* input, WOLFSSL_SHA_CTX* sha)
    {
	WOLFSSL_ENTER();
        wc_ShaFinal((Sha*)sha, input);
    }


    void wolfSSL_SHA1_Init(WOLFSSL_SHA_CTX* sha)
    {
	WOLFSSL_ENTER();
        SHA_Init(sha);
    }


    void wolfSSL_SHA1_Update(WOLFSSL_SHA_CTX* sha, const void* input,
                            unsigned long sz)
    {
	WOLFSSL_ENTER();
        SHA_Update(sha, input, sz);
    }


    void wolfSSL_SHA1_Final(byte* input, WOLFSSL_SHA_CTX* sha)
    {
	WOLFSSL_ENTER();
        SHA_Final(input, sha);
    }
#endif /* NO_SHA */


    void wolfSSL_SHA256_Init(WOLFSSL_SHA256_CTX* sha256)
    {
        typedef char sha_test[sizeof(SHA256_CTX) >= sizeof(Sha256) ? 1 : -1];
        (void)sizeof(sha_test);

	WOLFSSL_ENTER();
        wc_InitSha256((Sha256*)sha256);  /* OpenSSL compat, no error */
    }


    void wolfSSL_SHA256_Update(WOLFSSL_SHA256_CTX* sha, const void* input,
                              unsigned long sz)
    {
	WOLFSSL_ENTER();
        wc_Sha256Update((Sha256*)sha, (const byte*)input, (word32)sz);
        /* OpenSSL compat, no error */
    }


    void wolfSSL_SHA256_Final(byte* input, WOLFSSL_SHA256_CTX* sha)
    {
	WOLFSSL_ENTER();
        wc_Sha256Final((Sha256*)sha, input);
        /* OpenSSL compat, no error */
    }


    #ifdef WOLFSSL_SHA384

    void wolfSSL_SHA384_Init(WOLFSSL_SHA384_CTX* sha)
    {
        typedef char sha_test[sizeof(SHA384_CTX) >= sizeof(Sha384) ? 1 : -1];
        (void)sizeof(sha_test);

        wc_InitSha384((Sha384*)sha);   /* OpenSSL compat, no error */
    }


    void wolfSSL_SHA384_Update(WOLFSSL_SHA384_CTX* sha, const void* input,
                           unsigned long sz)
    {
        wc_Sha384Update((Sha384*)sha, (const byte*)input, (word32)sz);
        /* OpenSSL compat, no error */
    }


    void wolfSSL_SHA384_Final(byte* input, WOLFSSL_SHA384_CTX* sha)
    {
        wc_Sha384Final((Sha384*)sha, input);
        /* OpenSSL compat, no error */
    }

    #endif /* WOLFSSL_SHA384 */


   #ifdef WOLFSSL_SHA512

    void wolfSSL_SHA512_Init(WOLFSSL_SHA512_CTX* sha)
    {
        typedef char sha_test[sizeof(SHA512_CTX) >= sizeof(Sha512) ? 1 : -1];
        (void)sizeof(sha_test);

        wc_InitSha512((Sha512*)sha);  /* OpenSSL compat, no error */
    }


    void wolfSSL_SHA512_Update(WOLFSSL_SHA512_CTX* sha, const void* input,
                           unsigned long sz)
    {
        wc_Sha512Update((Sha512*)sha, (const byte*)input, (word32)sz);
        /* OpenSSL compat, no error */
    }


    void wolfSSL_SHA512_Final(byte* input, WOLFSSL_SHA512_CTX* sha)
    {
        wc_Sha512Final((Sha512*)sha, input);
        /* OpenSSL compat, no error */
    }

    #endif /* WOLFSSL_SHA512 */


    #ifndef NO_MD5

    const WOLFSSL_EVP_MD* wolfSSL_EVP_md5(void)
    {
        static const char* type = "MD5";
        return type;
    }

    #endif /* NO_MD5 */


#ifndef NO_SHA
    const WOLFSSL_EVP_MD* wolfSSL_EVP_sha1(void)
    {
        static const char* type = "SHA";
        return type;
    }
#endif /* NO_SHA */


    const WOLFSSL_EVP_MD* wolfSSL_EVP_sha256(void)
    {
        static const char* type = "SHA256";
        return type;
    }

    #ifdef WOLFSSL_SHA384

    const WOLFSSL_EVP_MD* wolfSSL_EVP_sha384(void)
    {
        static const char* type = "SHA384";
        return type;
    }

    #endif /* WOLFSSL_SHA384 */

    #ifdef WOLFSSL_SHA512

    const WOLFSSL_EVP_MD* wolfSSL_EVP_sha512(void)
    {
        static const char* type = "SHA512";
        return type;
    }

    #endif /* WOLFSSL_SHA512 */


    void wolfSSL_EVP_MD_CTX_init(WOLFSSL_EVP_MD_CTX* ctx)
    {
	WOLFSSL_ENTER();
        (void)ctx;
        /* do nothing */
    }


    const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_cbc(void)
    {
        static const char* type = "AES128-CBC";
	WOLFSSL_ENTER();
        return type;
    }


    const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_cbc(void)
    {
        static const char* type = "AES192-CBC";
	WOLFSSL_ENTER();
        return type;
    }


    const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_cbc(void)
    {
        static const char* type = "AES256-CBC";
	WOLFSSL_ENTER();
        return type;
    }


    const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_ctr(void)
    {
        static const char* type = "AES128-CTR";
	WOLFSSL_ENTER();
        return type;
    }


    const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_ctr(void)
    {
        static const char* type = "AES192-CTR";
	WOLFSSL_ENTER();
        return type;
    }


    const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_ctr(void)
    {
        static const char* type = "AES256-CTR";
	WOLFSSL_ENTER();
        return type;
    }


    const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_cbc(void)
    {
        static const char* type = "DES-CBC";
	WOLFSSL_ENTER();
        return type;
    }


    const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_ede3_cbc(void)
    {
        static const char* type = "DES-EDE3-CBC";
	WOLFSSL_ENTER();
        return type;
    }


    const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_rc4(void)
    {
        static const char* type = "ARC4";
	WOLFSSL_ENTER();
        return type;
    }


    const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_enc_null(void)
    {
        static const char* type = "NULL";
	WOLFSSL_ENTER();
        return type;
    }


    int wolfSSL_EVP_MD_CTX_cleanup(WOLFSSL_EVP_MD_CTX* ctx)
    {
	WOLFSSL_ENTER();
        (void)ctx;
        return 0;
    }



    void wolfSSL_EVP_CIPHER_CTX_init(WOLFSSL_EVP_CIPHER_CTX* ctx)
    {
	WOLFSSL_ENTER();
        if (ctx) {
            ctx->cipherType = 0xff;   /* no init */
            ctx->keyLen     = 0;
            ctx->enc        = 1;      /* start in encrypt mode */
        }
    }


    /* SSL_SUCCESS on ok */
    int wolfSSL_EVP_CIPHER_CTX_cleanup(WOLFSSL_EVP_CIPHER_CTX* ctx)
    {
	WOLFSSL_ENTER();
        if (ctx) {
            ctx->cipherType = 0xff;  /* no more init */
            ctx->keyLen     = 0;
        }

        return SSL_SUCCESS;
    }


    /* SSL_SUCCESS on ok */
    int  wolfSSL_EVP_CipherInit(WOLFSSL_EVP_CIPHER_CTX* ctx,
                               const WOLFSSL_EVP_CIPHER* type, byte* key,
                               byte* iv, int enc)
    {
#if defined(NO_AES) && defined(NO_DES3)
        (void)iv;
        (void)enc;
#else
        int ret = 0;
#endif

	WOLFSSL_ENTER();
        if (ctx == NULL) {
            WOLFSSL_MSG("no ctx");
            return 0;   /* failure */
        }

        if (type == NULL && ctx->cipherType == 0xff) {
            WOLFSSL_MSG("no type set");
            return 0;   /* failure */
        }

#ifndef NO_AES
        if (ctx->cipherType == AES_128_CBC_TYPE || (type &&
                                       XSTRNCMP(type, "AES128-CBC", 10) == 0)) {
            WOLFSSL_MSG("AES-128-CBC");
            ctx->cipherType = AES_128_CBC_TYPE;
            ctx->keyLen     = 16;
            if (enc == 0 || enc == 1)
                ctx->enc = enc ? 1 : 0;
            if (key) {
                ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                                ctx->enc ? AES_ENCRYPTION : AES_DECRYPTION);
                if (ret != 0)
                    return ret;
            }
            if (iv && key == NULL) {
                ret = wc_AesSetIV(&ctx->cipher.aes, iv);
                if (ret != 0)
                    return ret;
            }
        }
        else if (ctx->cipherType == AES_192_CBC_TYPE || (type &&
                                       XSTRNCMP(type, "AES192-CBC", 10) == 0)) {
            WOLFSSL_MSG("AES-192-CBC");
            ctx->cipherType = AES_192_CBC_TYPE;
            ctx->keyLen     = 24;
            if (enc == 0 || enc == 1)
                ctx->enc = enc ? 1 : 0;
            if (key) {
                ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                                ctx->enc ? AES_ENCRYPTION : AES_DECRYPTION);
                if (ret != 0)
                    return ret;
            }
            if (iv && key == NULL) {
                ret = wc_AesSetIV(&ctx->cipher.aes, iv);
                if (ret != 0)
                    return ret;
            }
        }
        else if (ctx->cipherType == AES_256_CBC_TYPE || (type &&
                                       XSTRNCMP(type, "AES256-CBC", 10) == 0)) {
            WOLFSSL_MSG("AES-256-CBC");
            ctx->cipherType = AES_256_CBC_TYPE;
            ctx->keyLen     = 32;
            if (enc == 0 || enc == 1)
                ctx->enc = enc ? 1 : 0;
            if (key) {
                ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                                ctx->enc ? AES_ENCRYPTION : AES_DECRYPTION);
                if (ret != 0)
                    return ret;
            }
            if (iv && key == NULL) {
                ret = wc_AesSetIV(&ctx->cipher.aes, iv);
                if (ret != 0)
                    return ret;
            }
        }
#ifdef WOLFSSL_AES_COUNTER
        else if (ctx->cipherType == AES_128_CTR_TYPE || (type &&
                                       XSTRNCMP(type, "AES128-CTR", 10) == 0)) {
            WOLFSSL_MSG("AES-128-CTR");
            ctx->cipherType = AES_128_CTR_TYPE;
            ctx->keyLen     = 16;
            if (enc == 0 || enc == 1)
                ctx->enc = enc ? 1 : 0;
            if (key) {
                ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                                AES_ENCRYPTION);
                if (ret != 0)
                    return ret;
            }
            if (iv && key == NULL) {
                ret = wc_AesSetIV(&ctx->cipher.aes, iv);
                if (ret != 0)
                    return ret;
            }
        }
        else if (ctx->cipherType == AES_192_CTR_TYPE || (type &&
                                       XSTRNCMP(type, "AES192-CTR", 10) == 0)) {
            WOLFSSL_MSG("AES-192-CTR");
            ctx->cipherType = AES_192_CTR_TYPE;
            ctx->keyLen     = 24;
            if (enc == 0 || enc == 1)
                ctx->enc = enc ? 1 : 0;
            if (key) {
                ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                                AES_ENCRYPTION);
                if (ret != 0)
                    return ret;
            }
            if (iv && key == NULL) {
                ret = wc_AesSetIV(&ctx->cipher.aes, iv);
                if (ret != 0)
                    return ret;
            }
        }
        else if (ctx->cipherType == AES_256_CTR_TYPE || (type &&
                                       XSTRNCMP(type, "AES256-CTR", 10) == 0)) {
            WOLFSSL_MSG("AES-256-CTR");
            ctx->cipherType = AES_256_CTR_TYPE;
            ctx->keyLen     = 32;
            if (enc == 0 || enc == 1)
                ctx->enc = enc ? 1 : 0;
            if (key) {
                ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                                AES_ENCRYPTION);
                if (ret != 0)
                    return ret;
            }
            if (iv && key == NULL) {
                ret = wc_AesSetIV(&ctx->cipher.aes, iv);
                if (ret != 0)
                    return ret;
            }
        }
#endif /* WOLFSSL_AES_CTR */
#endif /* NO_AES */

#ifndef NO_DES3
        else if (ctx->cipherType == DES_CBC_TYPE || (type &&
                                       XSTRNCMP(type, "DES-CBC", 7) == 0)) {
            WOLFSSL_MSG("DES-CBC");
            ctx->cipherType = DES_CBC_TYPE;
            ctx->keyLen     = 8;
            if (enc == 0 || enc == 1)
                ctx->enc = enc ? 1 : 0;
            if (key) {
                ret = wc_Des_SetKey(&ctx->cipher.des, key, iv,
                          ctx->enc ? DES_ENCRYPTION : DES_DECRYPTION);
                if (ret != 0)
                    return ret;
            }

            if (iv && key == NULL)
                wc_Des_SetIV(&ctx->cipher.des, iv);
        }
        else if (ctx->cipherType == DES_EDE3_CBC_TYPE || (type &&
                                     XSTRNCMP(type, "DES-EDE3-CBC", 11) == 0)) {
            WOLFSSL_MSG("DES-EDE3-CBC");
            ctx->cipherType = DES_EDE3_CBC_TYPE;
            ctx->keyLen     = 24;
            if (enc == 0 || enc == 1)
                ctx->enc = enc ? 1 : 0;
            if (key) {
                ret = wc_Des3_SetKey(&ctx->cipher.des3, key, iv,
                          ctx->enc ? DES_ENCRYPTION : DES_DECRYPTION);
                if (ret != 0)
                    return ret;
            }

            if (iv && key == NULL) {
                ret = wc_Des3_SetIV(&ctx->cipher.des3, iv);
                if (ret != 0)
                    return ret;
            }
        }
#endif /* NO_DES3 */
#ifndef NO_RC4
        else if (ctx->cipherType == ARC4_TYPE || (type &&
                                     XSTRNCMP(type, "ARC4", 4) == 0)) {
            WOLFSSL_MSG("ARC4");
            ctx->cipherType = ARC4_TYPE;
            if (ctx->keyLen == 0)  /* user may have already set */
                ctx->keyLen = 16;  /* default to 128 */
            if (key)
                wc_Arc4SetKey(&ctx->cipher.arc4, key, ctx->keyLen);
        }
#endif /* NO_RC4 */
        else if (ctx->cipherType == NULL_CIPHER_TYPE || (type &&
                                     XSTRNCMP(type, "NULL", 4) == 0)) {
            WOLFSSL_MSG("NULL cipher");
            ctx->cipherType = NULL_CIPHER_TYPE;
            ctx->keyLen = 0;
        }
        else
            return 0;   /* failure */


        return SSL_SUCCESS;
    }


    /* SSL_SUCCESS on ok */
    int wolfSSL_EVP_CIPHER_CTX_key_length(WOLFSSL_EVP_CIPHER_CTX* ctx)
    {
	WOLFSSL_ENTER();
        if (ctx)
            return ctx->keyLen;

        return 0;   /* failure */
    }


    /* SSL_SUCCESS on ok */
    int wolfSSL_EVP_CIPHER_CTX_set_key_length(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                             int keylen)
    {
	WOLFSSL_ENTER();
        if (ctx)
            ctx->keyLen = keylen;
        else
            return 0;  /* failure */

        return SSL_SUCCESS;
    }


    /* SSL_SUCCESS on ok */
    int wolfSSL_EVP_Cipher(WOLFSSL_EVP_CIPHER_CTX* ctx, byte* dst, byte* src,
                          word32 len)
    {
        int ret = 0;
	WOLFSSL_ENTER();

        if (ctx == NULL || dst == NULL || src == NULL) {
            WOLFSSL_MSG("Bad function argument");
            return 0;  /* failure */
        }

        if (ctx->cipherType == 0xff) {
            WOLFSSL_MSG("no init");
            return 0;  /* failure */
        }

        switch (ctx->cipherType) {

#ifndef NO_AES
            case AES_128_CBC_TYPE :
            case AES_192_CBC_TYPE :
            case AES_256_CBC_TYPE :
                WOLFSSL_MSG("AES CBC");
                if (ctx->enc)
                    ret = wc_AesCbcEncrypt(&ctx->cipher.aes, dst, src, len);
                else
                    ret = wc_AesCbcDecrypt(&ctx->cipher.aes, dst, src, len);
                break;

#ifdef WOLFSSL_AES_COUNTER
            case AES_128_CTR_TYPE :
            case AES_192_CTR_TYPE :
            case AES_256_CTR_TYPE :
                    WOLFSSL_MSG("AES CTR");
                    wc_AesCtrEncrypt(&ctx->cipher.aes, dst, src, len);
                break;
#endif
#endif /* NO_AES */

#ifndef NO_DES3
            case DES_CBC_TYPE :
                if (ctx->enc)
                    wc_Des_CbcEncrypt(&ctx->cipher.des, dst, src, len);
                else
                    wc_Des_CbcDecrypt(&ctx->cipher.des, dst, src, len);
                break;

            case DES_EDE3_CBC_TYPE :
                if (ctx->enc)
                    ret = wc_Des3_CbcEncrypt(&ctx->cipher.des3, dst, src, len);
                else
                    ret = wc_Des3_CbcDecrypt(&ctx->cipher.des3, dst, src, len);
                break;
#endif

#ifndef NO_RC4
            case ARC4_TYPE :
                wc_Arc4Process(&ctx->cipher.arc4, dst, src, len);
                break;
#endif

            case NULL_CIPHER_TYPE :
                XMEMCPY(dst, src, len);
                break;

            default: {
                WOLFSSL_MSG("bad type");
                return 0;  /* failure */
            }
        }

        if (ret != 0) {
            WOLFSSL_MSG("wolfSSL_EVP_Cipher failure");
            return 0;  /* failuer */
        }

        WOLFSSL_MSG("wolfSSL_EVP_Cipher success");
        return SSL_SUCCESS;  /* success */
    }


    /* store for external read of iv, SSL_SUCCESS on success */
    int  wolfSSL_StoreExternalIV(WOLFSSL_EVP_CIPHER_CTX* ctx)
    {
	WOLFSSL_ENTER();

        if (ctx == NULL) {
            WOLFSSL_MSG("Bad function argument");
            return SSL_FATAL_ERROR;
        }

        switch (ctx->cipherType) {

#ifndef NO_AES
            case AES_128_CBC_TYPE :
            case AES_192_CBC_TYPE :
            case AES_256_CBC_TYPE :
                WOLFSSL_MSG("AES CBC");
                memcpy(ctx->iv, &ctx->cipher.aes.reg, AES_BLOCK_SIZE);
                break;

#ifdef WOLFSSL_AES_COUNTER
            case AES_128_CTR_TYPE :
            case AES_192_CTR_TYPE :
            case AES_256_CTR_TYPE :
                WOLFSSL_MSG("AES CTR");
                memcpy(ctx->iv, &ctx->cipher.aes.reg, AES_BLOCK_SIZE);
                break;
#endif /* WOLFSSL_AES_COUNTER */

#endif /* NO_AES */

#ifndef NO_DES3
            case DES_CBC_TYPE :
                WOLFSSL_MSG("DES CBC");
                memcpy(ctx->iv, &ctx->cipher.des.reg, DES_BLOCK_SIZE);
                break;

            case DES_EDE3_CBC_TYPE :
                WOLFSSL_MSG("DES EDE3 CBC");
                memcpy(ctx->iv, &ctx->cipher.des3.reg, DES_BLOCK_SIZE);
                break;
#endif

            case ARC4_TYPE :
                WOLFSSL_MSG("ARC4");
                break;

            case NULL_CIPHER_TYPE :
                WOLFSSL_MSG("NULL");
                break;

            default: {
                WOLFSSL_MSG("bad type");
                return SSL_FATAL_ERROR;
            }
        }
        return SSL_SUCCESS;
    }


    /* set internal IV from external, SSL_SUCCESS on success */
    int  wolfSSL_SetInternalIV(WOLFSSL_EVP_CIPHER_CTX* ctx)
    {

	WOLFSSL_ENTER();

        if (ctx == NULL) {
            WOLFSSL_MSG("Bad function argument");
            return SSL_FATAL_ERROR;
        }

        switch (ctx->cipherType) {

#ifndef NO_AES
            case AES_128_CBC_TYPE :
            case AES_192_CBC_TYPE :
            case AES_256_CBC_TYPE :
                WOLFSSL_MSG("AES CBC");
                memcpy(&ctx->cipher.aes.reg, ctx->iv, AES_BLOCK_SIZE);
                break;

#ifdef WOLFSSL_AES_COUNTER
            case AES_128_CTR_TYPE :
            case AES_192_CTR_TYPE :
            case AES_256_CTR_TYPE :
                WOLFSSL_MSG("AES CTR");
                memcpy(&ctx->cipher.aes.reg, ctx->iv, AES_BLOCK_SIZE);
                break;
#endif

#endif /* NO_AES */

#ifndef NO_DES3
            case DES_CBC_TYPE :
                WOLFSSL_MSG("DES CBC");
                memcpy(&ctx->cipher.des.reg, ctx->iv, DES_BLOCK_SIZE);
                break;

            case DES_EDE3_CBC_TYPE :
                WOLFSSL_MSG("DES EDE3 CBC");
                memcpy(&ctx->cipher.des3.reg, ctx->iv, DES_BLOCK_SIZE);
                break;
#endif

            case ARC4_TYPE :
                WOLFSSL_MSG("ARC4");
                break;

            case NULL_CIPHER_TYPE :
                WOLFSSL_MSG("NULL");
                break;

            default: {
                WOLFSSL_MSG("bad type");
                return SSL_FATAL_ERROR;
            }
        }
        return SSL_SUCCESS;
    }


    /* SSL_SUCCESS on ok */
    int wolfSSL_EVP_DigestInit(WOLFSSL_EVP_MD_CTX* ctx, const WOLFSSL_EVP_MD* type)
    {
	WOLFSSL_ENTER();
        if (XSTRNCMP(type, "SHA256", 6) == 0) {
             ctx->macType = SHA256;
             wolfSSL_SHA256_Init((SHA256_CTX*)&ctx->hash);
        }
    #ifdef WOLFSSL_SHA384
        else if (XSTRNCMP(type, "SHA384", 6) == 0) {
             ctx->macType = SHA384;
             wolfSSL_SHA384_Init((SHA384_CTX*)&ctx->hash);
        }
    #endif
    #ifdef WOLFSSL_SHA512
        else if (XSTRNCMP(type, "SHA512", 6) == 0) {
             ctx->macType = SHA512;
             wolfSSL_SHA512_Init((SHA512_CTX*)&ctx->hash);
        }
    #endif
    #ifndef NO_MD5
        else if (XSTRNCMP(type, "MD5", 3) == 0) {
            ctx->macType = MD5;
            wolfSSL_MD5_Init((MD5_CTX*)&ctx->hash);
        }
    #endif
    #ifndef NO_SHA
        /* has to be last since would pick or 256, 384, or 512 too */
        else if (XSTRNCMP(type, "SHA", 3) == 0) {
             ctx->macType = SHA;
             wolfSSL_SHA_Init((SHA_CTX*)&ctx->hash);
        }
    #endif /* NO_SHA */
        else
             return BAD_FUNC_ARG;

        return SSL_SUCCESS;
    }


    /* SSL_SUCCESS on ok */
    int wolfSSL_EVP_DigestUpdate(WOLFSSL_EVP_MD_CTX* ctx, const void* data,
                                unsigned long sz)
    {
	WOLFSSL_ENTER();

        switch (ctx->macType) {
#ifndef NO_MD5
            case MD5:
                wolfSSL_MD5_Update((MD5_CTX*)&ctx->hash, data,
                                  (unsigned long)sz);
                break;
#endif
#ifndef NO_SHA
            case SHA:
                wolfSSL_SHA_Update((SHA_CTX*)&ctx->hash, data,
                                  (unsigned long)sz);
                break;
#endif
#ifndef NO_SHA256
            case SHA256:
                wolfSSL_SHA256_Update((SHA256_CTX*)&ctx->hash, data,
                                     (unsigned long)sz);
                break;
#endif
#ifdef WOLFSSL_SHA384
            case SHA384:
                wolfSSL_SHA384_Update((SHA384_CTX*)&ctx->hash, data,
                                     (unsigned long)sz);
                break;
#endif
#ifdef WOLFSSL_SHA512
            case SHA512:
                wolfSSL_SHA512_Update((SHA512_CTX*)&ctx->hash, data,
                                     (unsigned long)sz);
                break;
#endif
            default:
                return BAD_FUNC_ARG;
        }

        return SSL_SUCCESS;
    }


    /* SSL_SUCCESS on ok */
    int wolfSSL_EVP_DigestFinal(WOLFSSL_EVP_MD_CTX* ctx, unsigned char* md,
                               unsigned int* s)
    {
	WOLFSSL_ENTER();
        switch (ctx->macType) {
#ifndef NO_MD5
            case MD5:
                wolfSSL_MD5_Final(md, (MD5_CTX*)&ctx->hash);
                if (s) *s = MD5_DIGEST_SIZE;
                break;
#endif
#ifndef NO_SHA
            case SHA:
                wolfSSL_SHA_Final(md, (SHA_CTX*)&ctx->hash);
                if (s) *s = SHA_DIGEST_SIZE;
                break;
#endif
#ifndef NO_SHA256
            case SHA256:
                wolfSSL_SHA256_Final(md, (SHA256_CTX*)&ctx->hash);
                if (s) *s = SHA256_DIGEST_SIZE;
                break;
#endif
#ifdef WOLFSSL_SHA384
            case SHA384:
                wolfSSL_SHA384_Final(md, (SHA384_CTX*)&ctx->hash);
                if (s) *s = SHA384_DIGEST_SIZE;
                break;
#endif
#ifdef WOLFSSL_SHA512
            case SHA512:
                wolfSSL_SHA512_Final(md, (SHA512_CTX*)&ctx->hash);
                if (s) *s = SHA512_DIGEST_SIZE;
                break;
#endif
            default:
                return BAD_FUNC_ARG;
        }

        return SSL_SUCCESS;
    }


    /* SSL_SUCCESS on ok */
    int wolfSSL_EVP_DigestFinal_ex(WOLFSSL_EVP_MD_CTX* ctx, unsigned char* md,
                                  unsigned int* s)
    {
	WOLFSSL_ENTER();
        return EVP_DigestFinal(ctx, md, s);
    }


    unsigned char* wolfSSL_HMAC(const WOLFSSL_EVP_MD* evp_md, const void* key,
                               int key_len, const unsigned char* d, int n,
                               unsigned char* md, unsigned int* md_len)
    {
        int type;
        unsigned char* ret = NULL;
#ifdef WOLFSSL_SMALL_STACK
        Hmac* hmac = NULL;
#else
        Hmac  hmac[1];
#endif

	WOLFSSL_ENTER();
        if (!md)
            return NULL;  /* no static buffer support */

        if (XSTRNCMP(evp_md, "MD5", 3) == 0)
            type = MD5;
        else if (XSTRNCMP(evp_md, "SHA", 3) == 0)
            type = SHA;
        else
            return NULL;

    #ifdef WOLFSSL_SMALL_STACK
        hmac = (Hmac*)XMALLOC(sizeof(Hmac), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (hmac == NULL)
            return NULL;
    #endif

        if (wc_HmacSetKey(hmac, type, (const byte*)key, key_len) == 0)
            if (wc_HmacUpdate(hmac, d, n) == 0)
                if (wc_HmacFinal(hmac, md) == 0) {
                    if (md_len)
                        *md_len = (type == MD5) ? (int)MD5_DIGEST_SIZE
                                                : (int)SHA_DIGEST_SIZE;
                    ret = md;
                }

    #ifdef WOLFSSL_SMALL_STACK
        XFREE(hmac, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif

        return ret;
    }

    void wolfSSL_ERR_clear_error(void)
    {
        /* TODO: */
    }


    int wolfSSL_RAND_status(void)
    {
        return SSL_SUCCESS;  /* wolfCrypt provides enough seed internally */
    }



    void wolfSSL_RAND_add(const void* add, int len, double entropy)
    {
        (void)add;
        (void)len;
        (void)entropy;

        /* wolfSSL seeds/adds internally, use explicit RNG if you want
           to take control */
    }


#ifndef NO_DES3
    /* SSL_SUCCESS on ok */
    int wolfSSL_DES_key_sched(WOLFSSL_const_DES_cblock* key,
                             WOLFSSL_DES_key_schedule* schedule)
    {
	WOLFSSL_ENTER();
        XMEMCPY(schedule, key, sizeof(const_DES_cblock));
        return SSL_SUCCESS;
    }


    void wolfSSL_DES_cbc_encrypt(const unsigned char* input,
                     unsigned char* output, long length,
                     WOLFSSL_DES_key_schedule* schedule, WOLFSSL_DES_cblock* ivec,
                     int enc)
    {
        Des myDes;

	WOLFSSL_ENTER();

        /* OpenSSL compat, no ret */
        wc_Des_SetKey(&myDes, (const byte*)schedule, (const byte*)ivec, !enc);

        if (enc)
            wc_Des_CbcEncrypt(&myDes, output, input, (word32)length);
        else
            wc_Des_CbcDecrypt(&myDes, output, input, (word32)length);
    }


    /* correctly sets ivec for next call */
    void wolfSSL_DES_ncbc_encrypt(const unsigned char* input,
                     unsigned char* output, long length,
                     WOLFSSL_DES_key_schedule* schedule, WOLFSSL_DES_cblock* ivec,
                     int enc)
    {
        Des myDes;

	WOLFSSL_ENTER();

        /* OpenSSL compat, no ret */
        wc_Des_SetKey(&myDes, (const byte*)schedule, (const byte*)ivec, !enc);

        if (enc)
            wc_Des_CbcEncrypt(&myDes, output, input, (word32)length);
        else
            wc_Des_CbcDecrypt(&myDes, output, input, (word32)length);

        XMEMCPY(ivec, output + length - sizeof(DES_cblock), sizeof(DES_cblock));
    }

#endif /* NO_DES3 */


    void wolfSSL_ERR_free_strings(void)
    {
        /* handled internally */
    }


    void wolfSSL_ERR_remove_state(unsigned long state)
    {
        /* TODO: GetErrors().Remove(); */
        (void)state;
    }


    void wolfSSL_EVP_cleanup(void)
    {
        /* nothing to do here */
    }


    void wolfSSL_cleanup_all_ex_data(void)
    {
        /* nothing to do here */
    }


    int wolfSSL_clear(WOLFSSL* ssl)
    {
        (void)ssl;
        /* TODO: GetErrors().Remove(); */
        return SSL_SUCCESS;
    }


    long wolfSSL_SSL_SESSION_set_timeout(WOLFSSL_SESSION* ses, long t)
    {
        word32 tmptime;
        if (!ses || t < 0)
            return BAD_FUNC_ARG;

        tmptime = t & 0xFFFFFFFF;

        ses->timeout = tmptime;

        return SSL_SUCCESS;
    }


    long wolfSSL_CTX_set_mode(WOLFSSL_CTX* ctx, long mode)
    {
        /* SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER is wolfSSL default mode */

	WOLFSSL_ENTER();
        if (mode == SSL_MODE_ENABLE_PARTIAL_WRITE)
            ctx->partialWrite = 1;

        return mode;
    }


    long wolfSSL_SSL_get_mode(WOLFSSL* ssl)
    {
        /* TODO: */
        (void)ssl;
        return 0;
    }


    long wolfSSL_CTX_get_mode(WOLFSSL_CTX* ctx)
    {
        /* TODO: */
        (void)ctx;
        return 0;
    }


    void wolfSSL_CTX_set_default_read_ahead(WOLFSSL_CTX* ctx, int m)
    {
        /* TODO: maybe? */
        (void)ctx;
        (void)m;
    }


    int wolfSSL_CTX_set_session_id_context(WOLFSSL_CTX* ctx,
                                       const unsigned char* sid_ctx,
                                       unsigned int sid_ctx_len)
    {
        /* No application specific context needed for wolfSSL */
        (void)ctx;
        (void)sid_ctx;
        (void)sid_ctx_len;
        return SSL_SUCCESS;
    }


    long wolfSSL_CTX_sess_get_cache_size(WOLFSSL_CTX* ctx)
    {
        /* TODO: maybe? */
        (void)ctx;
        return (~0);
    }

    unsigned long wolfSSL_ERR_get_error_line_data(const char** file, int* line,
                                          const char** data, int *flags)
    {
        /* Not implemented */
        (void)file;
        (void)line;
        (void)data;
        (void)flags;
        return 0;
    }

#endif /* OPENSSL_EXTRA */


