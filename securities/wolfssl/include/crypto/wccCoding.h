/* coding.h
 */


#ifndef __WCC_CODING_H__
#define	__WCC_CODING_H__

#include <wccTypes.h>

#ifdef __cplusplus
    extern "C" {
#endif


WOLFSSL_API int Base64_Decode(const byte* in, word32 inLen, byte* out, word32* outLen);

#if defined(OPENSSL_EXTRA) || defined(SESSION_CERTS) || defined(WOLFSSL_KEY_GEN)                         || defined(WOLFSSL_CERT_GEN) || defined(HAVE_WEBSERVER)
    #ifndef WOLFSSL_BASE64_ENCODE
        #define WOLFSSL_BASE64_ENCODE
    #endif
#endif


#ifdef WOLFSSL_BASE64_ENCODE
    /* encode isn't */
    WOLFSSL_API int Base64_Encode(const byte* in, word32 inLen, byte* out,
                                  word32* outLen);
    WOLFSSL_API int Base64_EncodeEsc(const byte* in, word32 inLen, byte* out, word32* outLen);
#endif

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || defined(HAVE_FIPS)
    WOLFSSL_API int Base16_Decode(const byte* in, word32 inLen, byte* out, word32* outLen);
#endif


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_CODING_H */

