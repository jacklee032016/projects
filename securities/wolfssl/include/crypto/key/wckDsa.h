/* dsa.h
 */

#ifndef __WCK_DSA_H__
#define __WCK_DSA_H__

#include "cmnWcc.h"

#ifndef NO_DSA


#ifdef __cplusplus
    extern "C" {
#endif


typedef enum {
	DSA_KEY_TYPE_PUBLIC   = 0,
	DSA_KEY_TYPE_PRIVATE  = 1
}DSA_KEY_TYPE_T;

/* DSA */
typedef struct DsaKey {
	mp_int p, q, g, y, x;
	DSA_KEY_TYPE_T	type;                               /* public or private */
} DsaKey;


WOLFSSL_API void wc_InitDsaKey(DsaKey* key);
WOLFSSL_API void wc_FreeDsaKey(DsaKey* key);

WOLFSSL_API int wc_DsaSign(const byte* digest, byte* out, DsaKey* key, RNG* rng);
WOLFSSL_API int wc_DsaVerify(const byte* digest, const byte* sig, DsaKey* key, int* answer);

int DsaPrivateKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key, word32 inSz);
int DsaPublicKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key, word32 inSz);

#ifdef __cplusplus
    }
#endif

#endif /* NO_DSA */
#endif

