/* misc.h
 */


#ifndef __WCC_MISC_H__
#define __WCC_MISC_H__


#include <wccTypes.h>


#ifdef __cplusplus
    extern "C" {
#endif


#ifdef NO_INLINE
WOLFSSL_LOCAL word32 rotlFixed(word32, word32);
WOLFSSL_LOCAL word32 rotrFixed(word32, word32);

WOLFSSL_LOCAL word32 ByteReverseWord32(word32);
WOLFSSL_LOCAL void   ByteReverseWords(word32*, const word32*, word32);

WOLFSSL_LOCAL void XorWords(wolfssl_word*, const wolfssl_word*, word32);
WOLFSSL_LOCAL void xorbuf(void*, const void*, word32);

WOLFSSL_LOCAL void ForceZero(const void*, word32);

WOLFSSL_LOCAL int ConstantCompare(const byte*, const byte*, int);

#ifdef WORD64_AVAILABLE
WOLFSSL_LOCAL word64 rotlFixed64(word64, word64);
WOLFSSL_LOCAL word64 rotrFixed64(word64, word64);

WOLFSSL_LOCAL word64 ByteReverseWord64(word64);
WOLFSSL_LOCAL void   ByteReverseWords64(word64*, const word64*, word32);
#endif /* WORD64_AVAILABLE */

#endif /* NO_INLINE */


#ifdef __cplusplus
    }   /* extern "C" */
#endif


#endif /* WOLF_CRYPT_MISC_H */

