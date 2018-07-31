/**
 *  SHA-224 and SHA-256 cryptographic hash function
 */
#ifndef MBEDTLS_SHA256_H
#define MBEDTLS_SHA256_H

#include "mbed.h"

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_SHA256_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           SHA-256 context structure
 */
typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[8];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
    int is224;                  /*!< 0 => SHA-256, else SHA-224 */
}
mbedtls_sha256_context;

/**
 *           Initialize SHA-256 context
 *
 * \param ctx      SHA-256 context to be initialized
 */
void mbedtls_sha256_init( mbedtls_sha256_context *ctx );

/**
 *           Clear SHA-256 context
 *
 * \param ctx      SHA-256 context to be cleared
 */
void mbedtls_sha256_free( mbedtls_sha256_context *ctx );

/**
 *           Clone (the state of) a SHA-256 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_sha256_clone( mbedtls_sha256_context *dst,
                           const mbedtls_sha256_context *src );

/**
 *           SHA-256 context setup
 *
 * \param ctx      context to be initialized
 * \param is224    0 = use SHA256, 1 = use SHA224
 */
void mbedtls_sha256_starts( mbedtls_sha256_context *ctx, int is224 );

/**
 *           SHA-256 process buffer
 *
 * \param ctx      SHA-256 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void mbedtls_sha256_update( mbedtls_sha256_context *ctx, const unsigned char *input,
                    size_t ilen );

/**
 *           SHA-256 final digest
 *
 * \param ctx      SHA-256 context
 * \param output   SHA-224/256 checksum result
 */
void mbedtls_sha256_finish( mbedtls_sha256_context *ctx, unsigned char output[32] );

/* Internal use */
void mbedtls_sha256_process( mbedtls_sha256_context *ctx, const unsigned char data[64] );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_SHA256_ALT */
#include "sha256_alt.h"
#endif /* MBEDTLS_SHA256_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           Output = SHA-256( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SHA-224/256 checksum result
 * \param is224    0 = use SHA256, 1 = use SHA224
 */
void mbedtls_sha256( const unsigned char *input, size_t ilen,
           unsigned char output[32], int is224 );


#ifdef __cplusplus
}
#endif

#endif /* mbedtls_sha256.h */
