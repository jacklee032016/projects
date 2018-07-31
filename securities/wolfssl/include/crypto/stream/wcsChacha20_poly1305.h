/* chacha20_poly1305.h
 */

#ifndef __WCS_CHACHA20_POLY1305_H__
#define __WCS_CHACHA20_POLY1305_H__

#include <wccTypes.h>

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)

#ifdef __cplusplus
    extern "C" {
#endif

#define CHACHA20_POLY1305_AEAD_KEYSIZE      32
#define CHACHA20_POLY1305_AEAD_IV_SIZE      12
#define CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE 16

enum {
    CHACHA20_POLY_1305_ENC_TYPE = 8    /* cipher unique type */
};

    /*
     * The IV for this implementation is 96 bits to give the most flexibility.
     *
     * Some protocols may have unique per-invocation inputs that are not
     * 96-bit in length. For example, IPsec may specify a 64-bit nonce. In
     * such a case, it is up to the protocol document to define how to
     * transform the protocol nonce into a 96-bit nonce, for example by
     * concatenating a constant value.
     */

WOLFSSL_API
int wc_ChaCha20Poly1305_Encrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, const word32 inAADLen,
                const byte* inPlaintext, const word32 inPlaintextLen,
                byte* outCiphertext,
                byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]);

WOLFSSL_API
int wc_ChaCha20Poly1305_Decrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, const word32 inAADLen,
                const byte* inCiphertext, const word32 inCiphertextLen,
                const byte inAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
                byte* outPlaintext);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_CHACHA && HAVE_POLY1305 */
#endif /* WOLF_CRYPT_CHACHA20_POLY1305_H */
