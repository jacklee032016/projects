/**
 *  Camellia block cipher
 */
#ifndef MBEDTLS_CAMELLIA_H
#define MBEDTLS_CAMELLIA_H

#include "mbed.h"

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_CAMELLIA_ENCRYPT     1
#define MBEDTLS_CAMELLIA_DECRYPT     0

#define MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH           -0x0024  /**< Invalid key length. */
#define MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH         -0x0026  /**< Invalid data input length. */

#if !defined(MBEDTLS_CAMELLIA_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           CAMELLIA context structure
 */
typedef struct
{
    int nr;                     /*!<  number of rounds  */
    uint32_t rk[68];            /*!<  CAMELLIA round keys    */
}
mbedtls_camellia_context;

/**
 *           Initialize CAMELLIA context
 *
 * \param ctx      CAMELLIA context to be initialized
 */
void mbedtls_camellia_init( mbedtls_camellia_context *ctx );

/**
 *           Clear CAMELLIA context
 *
 * \param ctx      CAMELLIA context to be cleared
 */
void mbedtls_camellia_free( mbedtls_camellia_context *ctx );

/**
 *           CAMELLIA key schedule (encryption)
 *
 * \param ctx      CAMELLIA context to be initialized
 * \param key      encryption key
 * \param keybits  must be 128, 192 or 256
 *
 * \return         0 if successful, or MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH
 */
int mbedtls_camellia_setkey_enc( mbedtls_camellia_context *ctx, const unsigned char *key,
                         unsigned int keybits );

/**
 *           CAMELLIA key schedule (decryption)
 *
 * \param ctx      CAMELLIA context to be initialized
 * \param key      decryption key
 * \param keybits  must be 128, 192 or 256
 *
 * \return         0 if successful, or MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH
 */
int mbedtls_camellia_setkey_dec( mbedtls_camellia_context *ctx, const unsigned char *key,
                         unsigned int keybits );

/**
 *           CAMELLIA-ECB block encryption/decryption
 *
 * \param ctx      CAMELLIA context
 * \param mode     MBEDTLS_CAMELLIA_ENCRYPT or MBEDTLS_CAMELLIA_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if successful
 */
int mbedtls_camellia_crypt_ecb( mbedtls_camellia_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] );

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/**
 *           CAMELLIA-CBC buffer encryption/decryption
 *                 Length should be a multiple of the block
 *                 size (16 bytes)
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      CAMELLIA context
 * \param mode     MBEDTLS_CAMELLIA_ENCRYPT or MBEDTLS_CAMELLIA_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or
 *                 MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH
 */
int mbedtls_camellia_crypt_cbc( mbedtls_camellia_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/**
 *           CAMELLIA-CFB128 buffer encryption/decryption
 *
 * Note: Due to the nature of CFB you should use the same key schedule for
 * both encryption and decryption. So a context initialized with
 * mbedtls_camellia_setkey_enc() for both MBEDTLS_CAMELLIA_ENCRYPT and CAMELLIE_DECRYPT.
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      CAMELLIA context
 * \param mode     MBEDTLS_CAMELLIA_ENCRYPT or MBEDTLS_CAMELLIA_DECRYPT
 * \param length   length of the input data
 * \param iv_off   offset in IV (updated after use)
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or
 *                 MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH
 */
int mbedtls_camellia_crypt_cfb128( mbedtls_camellia_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/**
 *                CAMELLIA-CTR buffer encryption/decryption
 *
 * Warning: You have to keep the maximum use of your counter in mind!
 *
 * Note: Due to the nature of CTR you should use the same key schedule for
 * both encryption and decryption. So a context initialized with
 * mbedtls_camellia_setkey_enc() for both MBEDTLS_CAMELLIA_ENCRYPT and MBEDTLS_CAMELLIA_DECRYPT.
 *
 * \param ctx           CAMELLIA context
 * \param length        The length of the data
 * \param nc_off        The offset in the current stream_block (for resuming
 *                      within current cipher stream). The offset pointer to
 *                      should be 0 at the start of a stream.
 * \param nonce_counter The 128-bit nonce and counter.
 * \param stream_block  The saved stream-block for resuming. Is overwritten
 *                      by the function.
 * \param input         The input data stream
 * \param output        The output data stream
 *
 * \return         0 if successful
 */
int mbedtls_camellia_crypt_ctr( mbedtls_camellia_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_CAMELLIA_ALT */
#include "camellia_alt.h"
#endif /* MBEDTLS_CAMELLIA_ALT */


#endif /* camellia.h */
