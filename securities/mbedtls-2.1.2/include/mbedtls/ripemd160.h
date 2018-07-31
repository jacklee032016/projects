/**
 *  RIPE MD-160 message digest
 */
#ifndef MBEDTLS_RIPEMD160_H
#define MBEDTLS_RIPEMD160_H

#include "mbed.h"

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_RIPEMD160_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           RIPEMD-160 context structure
 */
typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[5];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}mbedtls_ripemd160_context;

/* Initialize RIPEMD-160 context
 */
void mbedtls_ripemd160_init( mbedtls_ripemd160_context *ctx );

void mbedtls_ripemd160_free( mbedtls_ripemd160_context *ctx );

/**
 *           Clone (the state of) an RIPEMD-160 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_ripemd160_clone( mbedtls_ripemd160_context *dst,
                        const mbedtls_ripemd160_context *src );

/**
 *           RIPEMD-160 context setup
 *
 * \param ctx      context to be initialized
 */
void mbedtls_ripemd160_starts( mbedtls_ripemd160_context *ctx );

/**
 *           RIPEMD-160 process buffer
 *
 * \param ctx      RIPEMD-160 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void mbedtls_ripemd160_update( mbedtls_ripemd160_context *ctx,
                       const unsigned char *input, size_t ilen );

/**
 *           RIPEMD-160 final digest
 *
 * \param ctx      RIPEMD-160 context
 * \param output   RIPEMD-160 checksum result
 */
void mbedtls_ripemd160_finish( mbedtls_ripemd160_context *ctx, unsigned char output[20] );

/* Internal use */
void mbedtls_ripemd160_process( mbedtls_ripemd160_context *ctx, const unsigned char data[64] );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_RIPEMD160_ALT */
#include "ripemd160.h"
#endif /* MBEDTLS_RIPEMD160_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           Output = RIPEMD-160( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   RIPEMD-160 checksum result
 */
void mbedtls_ripemd160( const unsigned char *input, size_t ilen,
                unsigned char output[20] );


#ifdef __cplusplus
}
#endif

#endif /* mbedtls_ripemd160.h */
