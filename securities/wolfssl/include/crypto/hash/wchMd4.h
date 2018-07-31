/* md4.h
 */

#ifndef __WCH_MD4_H__
#define __WCH_MD4_H__

#include <wccTypes.h>

#ifndef NO_MD4

#ifdef __cplusplus
    extern "C" {
#endif

/* in bytes */
enum {
    MD4_BLOCK_SIZE  = 64,
    MD4_DIGEST_SIZE = 16,
    MD4_PAD_SIZE    = 56
};


/* MD4 digest */
typedef struct Md4 {
	word32  buffLen;   /* in bytes          */
	word32  loLen;     /* length in bytes   */
	word32  hiLen;     /* length in bytes   */
	word32  digest[MD4_DIGEST_SIZE / sizeof(word32)];
	word32  buffer[MD4_BLOCK_SIZE  / sizeof(word32)];
} Md4;


WOLFSSL_API void wc_InitMd4(Md4*);
WOLFSSL_API void wc_Md4Update(Md4*, const byte*, word32);
WOLFSSL_API void wc_Md4Final(Md4*, byte*);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_MD4 */
#endif /* WOLF_CRYPT_MD4_H */

