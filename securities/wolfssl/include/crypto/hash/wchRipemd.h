/* ripemd.h
 */

#ifndef __WCH_RIPEMD_H__
#define __WCH_RIPEMD_H__

#include <wccTypes.h>

#ifdef WOLFSSL_RIPEMD

#ifdef __cplusplus
    extern "C" {
#endif


/* in bytes */
enum {
    RIPEMD             =  3,    /* hash type unique */
    RIPEMD_BLOCK_SIZE  = 64,
    RIPEMD_DIGEST_SIZE = 20,
    RIPEMD_PAD_SIZE    = 56
};


/* RipeMd 160 digest */
typedef struct RipeMd {
    word32  buffLen;   /* in bytes          */
    word32  loLen;     /* length in bytes   */
    word32  hiLen;     /* length in bytes   */
    word32  digest[RIPEMD_DIGEST_SIZE / sizeof(word32)];
    word32  buffer[RIPEMD_BLOCK_SIZE  / sizeof(word32)];
} RipeMd;


WOLFSSL_API void wc_InitRipeMd(RipeMd*);
WOLFSSL_API void wc_RipeMdUpdate(RipeMd*, const byte*, word32);
WOLFSSL_API void wc_RipeMdFinal(RipeMd*, byte*);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_RIPEMD */
#endif /* WOLF_CRYPT_RIPEMD_H */
