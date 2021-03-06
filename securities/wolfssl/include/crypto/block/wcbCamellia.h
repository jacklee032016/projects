/* camellia.h ver 1.2.0
 *
 * Copyright (c) 2006,2007
 * NTT (Nippon Telegraph and Telephone Corporation) . All rights reserved.
 *
 */

/* camellia.h
 */

#ifndef __WCB_CAMELLIA_H__
#define __WCB_CAMELLIA_H__

#include <wccTypes.h>

#ifdef HAVE_CAMELLIA

#ifdef __cplusplus
    extern "C" {
#endif

enum {
    CAMELLIA_BLOCK_SIZE = 16
};

#define CAMELLIA_TABLE_BYTE_LEN		272
#define CAMELLIA_TABLE_WORD_LEN		(CAMELLIA_TABLE_BYTE_LEN / sizeof(word32))

typedef word32 KEY_TABLE_TYPE[CAMELLIA_TABLE_WORD_LEN];

typedef struct Camellia {
    word32 keySz;
    KEY_TABLE_TYPE key;
    word32 reg[CAMELLIA_BLOCK_SIZE / sizeof(word32)]; /* for CBC mode */
    word32 tmp[CAMELLIA_BLOCK_SIZE / sizeof(word32)]; /* for CBC mode */
} Camellia;


WOLFSSL_API int  wc_CamelliaSetKey(Camellia* cam, const byte* key, word32 len, const byte* iv);
WOLFSSL_API int  wc_CamelliaSetIV(Camellia* cam, const byte* iv);
WOLFSSL_API void wc_CamelliaEncryptDirect(Camellia* cam, byte* out, const byte* in);
WOLFSSL_API void wc_CamelliaDecryptDirect(Camellia* cam, byte* out, const byte* in);
WOLFSSL_API void wc_CamelliaCbcEncrypt(Camellia* cam, byte* out, const byte* in, word32 sz);
WOLFSSL_API void wc_CamelliaCbcDecrypt(Camellia* cam, byte* out, const byte* in, word32 sz);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_CAMELLIA */
#endif /* WOLF_CRYPT_CAMELLIA_H */

