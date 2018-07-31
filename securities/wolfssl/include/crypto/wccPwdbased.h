/* pwdbased.h
 */

#ifndef __WCC_PWDBASED_H__
#define __WCC_PWDBASED_H__

#include <wccTypes.h>

#ifndef NO_PWDBASED

#ifndef NO_MD5
    #include <wchMd5.h>       /* for hash type */
#endif

#include <wchSha.h>

#ifdef __cplusplus
    extern "C" {
#endif

/*
 * hashType renamed to typeH to avoid shadowing global declation here:
 * wolfssl/wolfcrypt/asn.h line 173 in enum Oid_Types
 */
WOLFSSL_API int wc_PBKDF1(byte* output, const byte* passwd, int pLen,
                      const byte* salt, int sLen, int iterations, int kLen,
                      int typeH);
WOLFSSL_API int wc_PBKDF2(byte* output, const byte* passwd, int pLen,
                      const byte* salt, int sLen, int iterations, int kLen,
                      int typeH);
WOLFSSL_API int wc_PKCS12_PBKDF(byte* output, const byte* passwd, int pLen,
                            const byte* salt, int sLen, int iterations,
                            int kLen, int typeH, int purpose);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_PWDBASED */
#endif /* WOLF_CRYPT_PWDBASED_H */
