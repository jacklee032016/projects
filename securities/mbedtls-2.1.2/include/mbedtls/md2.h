/**
 *  MD2 message digest algorithm (hash function)
 */
#ifndef MBEDTLS_MD2_H
#define MBEDTLS_MD2_H

#include "mbed.h"

#include <stddef.h>

#if !defined(MBEDTLS_MD2_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           MD2 context structure
 */
typedef struct
{
    unsigned char cksum[16];    /*!< checksum of the data block */
    unsigned char state[48];    /*!< intermediate digest state  */
    unsigned char buffer[16];   /*!< data block being processed */
    size_t left;                /*!< amount of data in buffer   */
}
mbedtls_md2_context;

/**
 *           Initialize MD2 context
 *
 * \param ctx      MD2 context to be initialized
 */
void mbedtls_md2_init( mbedtls_md2_context *ctx );

/**
 *           Clear MD2 context
 *
 * \param ctx      MD2 context to be cleared
 */
void mbedtls_md2_free( mbedtls_md2_context *ctx );

/**
 *           Clone (the state of) an MD2 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_md2_clone( mbedtls_md2_context *dst,
                        const mbedtls_md2_context *src );

/**
 *           MD2 context setup
 *
 * \param ctx      context to be initialized
 */
void mbedtls_md2_starts( mbedtls_md2_context *ctx );

/**
 *           MD2 process buffer
 *
 * \param ctx      MD2 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void mbedtls_md2_update( mbedtls_md2_context *ctx, const unsigned char *input, size_t ilen );

/**
 *           MD2 final digest
 *
 * \param ctx      MD2 context
 * \param output   MD2 checksum result
 */
void mbedtls_md2_finish( mbedtls_md2_context *ctx, unsigned char output[16] );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_MD2_ALT */
#include "md2_alt.h"
#endif /* MBEDTLS_MD2_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           Output = MD2( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   MD2 checksum result
 */
void mbedtls_md2( const unsigned char *input, size_t ilen, unsigned char output[16] );


/* Internal use */
void mbedtls_md2_process( mbedtls_md2_context *ctx );

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_md2.h */
