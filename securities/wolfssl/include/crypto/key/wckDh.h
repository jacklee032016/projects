/* dh.h
 */

#ifndef __WCK_DH_H__
#define __WCK_DH_H__

#include "cmnWcc.h"

#ifndef NO_DH


#ifdef __cplusplus
    extern "C" {
#endif


/* Diffie-Hellman Key */
typedef struct DhKey {
    mp_int p, g;                            /* group parameters  */
} DhKey;


WOLFSSL_API void wc_InitDhKey(DhKey* key);
WOLFSSL_API void wc_FreeDhKey(DhKey* key);

/* public/private pair of this key */
WOLFSSL_API int wc_DhGenerateKeyPair(DhKey* key, RNG* rng, byte* priv, word32* privSz, byte* pub, word32* pubSz);
/* create shared secret from local private key and received public key */
WOLFSSL_API int wc_DhAgree(DhKey* key, byte* agree, word32* agreeSz,
                       const byte* priv, word32 privSz, const byte* otherPub,
                       word32 pubSz);

WOLFSSL_API int wc_DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key, word32);
WOLFSSL_API int wc_DhSetKey(DhKey* key, const byte* p, word32 pSz, const byte* g, word32 gSz);
WOLFSSL_API int wc_DhParamsLoad(const byte* input, word32 inSz, byte* p, word32* pInOutSz, byte* g, word32* gInOutSz);


#ifdef __cplusplus
    }
#endif

#endif /* NO_DH */
#endif

