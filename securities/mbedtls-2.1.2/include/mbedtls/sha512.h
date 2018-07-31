/**
 * \file mbedtls_sha512.h
 */
#ifndef MBEDTLS_SHA512_H
#define MBEDTLS_SHA512_H

#include "mbed.h"

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_SHA512_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           SHA-512 context structure
 */
typedef struct
{
    uint64_t total[2];          /*!< number of bytes processed  */
    uint64_t state[8];          /*!< intermediate digest state  */
    unsigned char buffer[128];  /*!< data block being processed */
    int is384;                  /*!< 0 => SHA-512, else SHA-384 */
}mbedtls_sha512_context;

/**
 *           Initialize SHA-512 context
 *
 * \param ctx      SHA-512 context to be initialized
 */
void mbedtls_sha512_init( mbedtls_sha512_context *ctx );

/**
 *           Clear SHA-512 context
 *
 * \param ctx      SHA-512 context to be cleared
 */
void mbedtls_sha512_free( mbedtls_sha512_context *ctx );

/**
 *           Clone (the state of) a SHA-512 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_sha512_clone( mbedtls_sha512_context *dst,
                           const mbedtls_sha512_context *src );

/**
 *           SHA-512 context setup
 *
 * \param ctx      context to be initialized
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
void mbedtls_sha512_starts( mbedtls_sha512_context *ctx, int is384 );

/**
 *           SHA-512 process buffer
 *
 * \param ctx      SHA-512 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void mbedtls_sha512_update( mbedtls_sha512_context *ctx, const unsigned char *input,
                    size_t ilen );

/**
 *           SHA-512 final digest
 *
 * \param ctx      SHA-512 context
 * \param output   SHA-384/512 checksum result
 */
void mbedtls_sha512_finish( mbedtls_sha512_context *ctx, unsigned char output[64] );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_SHA512_ALT */
#include "sha512_alt.h"
#endif /* MBEDTLS_SHA512_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           Output = SHA-512( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SHA-384/512 checksum result
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
void mbedtls_sha512( const unsigned char *input, size_t ilen,
             unsigned char output[64], int is384 );


/* Internal use */
void mbedtls_sha512_process( mbedtls_sha512_context *ctx, const unsigned char data[128] );

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_sha512.h */
