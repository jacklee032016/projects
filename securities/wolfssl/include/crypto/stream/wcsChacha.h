/* chacha.h
 */

#ifndef __WCS_CHACHA_H__
#define __WCS_CHACHA_H__

#include <wccTypes.h>

#ifdef HAVE_CHACHA

#ifdef __cplusplus
    extern "C" {
#endif

enum {
	CHACHA_ENC_TYPE = 7     /* cipher unique type */
};

typedef struct ChaCha {
    word32 X[16];           /* state of cipher */
} ChaCha;

/**
  * IV(nonce) changes with each record
  * counter is for what value the block counter should start ... usually 0
  */
WOLFSSL_API int wc_Chacha_SetIV(ChaCha* ctx, const byte* inIv, word32 counter);

WOLFSSL_API int wc_Chacha_Process(ChaCha* ctx, byte* cipher, const byte* plain, word32 msglen);
WOLFSSL_API int wc_Chacha_SetKey(ChaCha* ctx, const byte* key, word32 keySz);

#ifdef __cplusplus
    }
#endif

#endif /* HAVE_CHACHA */
#endif

