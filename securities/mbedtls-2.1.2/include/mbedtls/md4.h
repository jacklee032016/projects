/**
 *  MD4 message digest algorithm (hash function)
 */
#ifndef MBEDTLS_MD4_H
#define MBEDTLS_MD4_H

#include "mbed.h"

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_MD4_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           MD4 context structure
 */
typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[4];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}
mbedtls_md4_context;

/**
 *           Initialize MD4 context
 *
 * \param ctx      MD4 context to be initialized
 */
void mbedtls_md4_init( mbedtls_md4_context *ctx );

/**
 *           Clear MD4 context
 *
 * \param ctx      MD4 context to be cleared
 */
void mbedtls_md4_free( mbedtls_md4_context *ctx );

/**
 *           Clone (the state of) an MD4 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_md4_clone( mbedtls_md4_context *dst,
                        const mbedtls_md4_context *src );

/**
 *           MD4 context setup
 *
 * \param ctx      context to be initialized
 */
void mbedtls_md4_starts( mbedtls_md4_context *ctx );

/**
 *           MD4 process buffer
 *
 * \param ctx      MD4 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void mbedtls_md4_update( mbedtls_md4_context *ctx, const unsigned char *input, size_t ilen );

/**
 *           MD4 final digest
 *
 * \param ctx      MD4 context
 * \param output   MD4 checksum result
 */
void mbedtls_md4_finish( mbedtls_md4_context *ctx, unsigned char output[16] );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_MD4_ALT */
#include "md4_alt.h"
#endif /* MBEDTLS_MD4_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           Output = MD4( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   MD4 checksum result
 */
void mbedtls_md4( const unsigned char *input, size_t ilen, unsigned char output[16] );


/* Internal use */
void mbedtls_md4_process( mbedtls_md4_context *ctx, const unsigned char data[64] );

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_md4.h */
