/* hc128.h
 */

#ifndef __WCS_HC128_H__
#define __WCS_HC128_H__

#include <wccTypes.h>

#ifndef NO_HC128

#ifdef __cplusplus
    extern "C" {
#endif

enum {
	HC128_ENC_TYPE    =  6    /* cipher unique type */
};

/* HC-128 stream cipher */
typedef struct HC128 {
    word32 T[1024];             /* P[i] = T[i];  Q[i] = T[1024 + i ]; */
    word32 X[16];
    word32 Y[16];
    word32 counter1024;         /* counter1024 = i mod 1024 at the ith step */
    word32 key[8];
    word32 iv[8];
} HC128;


WOLFSSL_API int wc_Hc128_Process(HC128*, byte*, const byte*, word32);
WOLFSSL_API int wc_Hc128_SetKey(HC128*, const byte* key, const byte* iv);


#ifdef __cplusplus
    }
#endif

#endif /* HAVE_HC128 */
#endif

