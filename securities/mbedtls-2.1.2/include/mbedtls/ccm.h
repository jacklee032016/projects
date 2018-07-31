/**
 *  Counter with CBC-MAC (CCM) for 128-bit block ciphers
 */
#ifndef MBEDTLS_CCM_H
#define MBEDTLS_CCM_H

#include "cipher.h"

#define MBEDTLS_ERR_CCM_BAD_INPUT      -0x000D /**< Bad input parameters to function. */
#define MBEDTLS_ERR_CCM_AUTH_FAILED    -0x000F /**< Authenticated decryption failed. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           CCM context structure
 */
typedef struct {
    mbedtls_cipher_context_t cipher_ctx;    /*!< cipher context used */
}
mbedtls_ccm_context;

/**
 *            Initialize CCM context (just makes references valid)
 *                  Makes the context ready for mbedtls_ccm_setkey() or
 *                  mbedtls_ccm_free().
 *
 * \param ctx       CCM context to initialize
 */
void mbedtls_ccm_init( mbedtls_ccm_context *ctx );

/**
 *            CCM initialization (encryption and decryption)
 *
 * \param ctx       CCM context to be initialized
 * \param cipher    cipher to use (a 128-bit block cipher)
 * \param key       encryption key
 * \param keybits   key size in bits (must be acceptable by the cipher)
 *
 * \return          0 if successful, or a cipher specific error code
 */
int mbedtls_ccm_setkey( mbedtls_ccm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits );

/**
 *            Free a CCM context and underlying cipher sub-context
 *
 * \param ctx       CCM context to free
 */
void mbedtls_ccm_free( mbedtls_ccm_context *ctx );

/**
 *            CCM buffer encryption
 *
 * \param ctx       CCM context
 * \param length    length of the input data in bytes
 * \param iv        nonce (initialization vector)
 * \param iv_len    length of IV in bytes
 *                  must be 2, 3, 4, 5, 6, 7 or 8
 * \param add       additional data
 * \param add_len   length of additional data in bytes
 *                  must be less than 2^16 - 2^8
 * \param input     buffer holding the input data
 * \param output    buffer for holding the output data
 *                  must be at least 'length' bytes wide
 * \param tag       buffer for holding the tag
 * \param tag_len   length of the tag to generate in bytes
 *                  must be 4, 6, 8, 10, 14 or 16
 *
 * \note            The tag is written to a separate buffer. To get the tag
 *                  concatenated with the output as in the CCM spec, use
 *                  tag = output + length and make sure the output buffer is
 *                  at least length + tag_len wide.
 *
 * \return          0 if successful
 */
int mbedtls_ccm_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len );

/**
 *            CCM buffer authenticated decryption
 *
 * \param ctx       CCM context
 * \param length    length of the input data
 * \param iv        initialization vector
 * \param iv_len    length of IV
 * \param add       additional data
 * \param add_len   length of additional data
 * \param input     buffer holding the input data
 * \param output    buffer for holding the output data
 * \param tag       buffer holding the tag
 * \param tag_len   length of the tag
 *
 * \return         0 if successful and authenticated,
 *                 MBEDTLS_ERR_CCM_AUTH_FAILED if tag does not match
 */
int mbedtls_ccm_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CCM_H */
