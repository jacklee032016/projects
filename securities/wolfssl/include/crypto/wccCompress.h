/* compress.h
 */

#ifndef __WCC_COMPRESS_H__
#define __WCC_COMPRESS_H__

#include <wccTypes.h>

#ifdef HAVE_LIBZ

#ifdef __cplusplus
    extern "C" {
#endif


#define COMPRESS_FIXED 1


WOLFSSL_API int wc_Compress(byte*, word32, const byte*, word32, word32);
WOLFSSL_API int wc_DeCompress(byte*, word32, const byte*, word32);


#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* HAVE_LIBZ */
#endif /* WOLF_CRYPT_COMPRESS_H */

