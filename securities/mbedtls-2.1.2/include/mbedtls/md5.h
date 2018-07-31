/**
 *  MD5 message digest algorithm (hash function)
 */
#ifndef MBEDTLS_MD5_H
#define MBEDTLS_MD5_H

#include "mbed.h"

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_MD5_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           MD5 context structure
 */
typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[4];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}
mbedtls_md5_context;

/**
 *           Initialize MD5 context
 *
 * \param ctx      MD5 context to be initialized
 */
void mbedtls_md5_init( mbedtls_md5_context *ctx );

/**
 *           Clear MD5 context
 *
 * \param ctx      MD5 context to be cleared
 */
void mbedtls_md5_free( mbedtls_md5_context *ctx );

/**
 *           Clone (the state of) an MD5 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_md5_clone( mbedtls_md5_context *dst,
                        const mbedtls_md5_context *src );

/**
 *           MD5 context setup
 *
 * \param ctx      context to be initialized
 */
void mbedtls_md5_starts( mbedtls_md5_context *ctx );

/**
 *           MD5 process buffer
 *
 * \param ctx      MD5 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void mbedtls_md5_update( mbedtls_md5_context *ctx, const unsigned char *input, size_t ilen );

/**
 *           MD5 final digest
 *
 * \param ctx      MD5 context
 * \param output   MD5 checksum result
 */
void mbedtls_md5_finish( mbedtls_md5_context *ctx, unsigned char output[16] );

/* Internal use */
void mbedtls_md5_process( mbedtls_md5_context *ctx, const unsigned char data[64] );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_MD5_ALT */
#include "md5_alt.h"
#endif /* MBEDTLS_MD5_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           Output = MD5( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   MD5 checksum result
 */
void mbedtls_md5( const unsigned char *input, size_t ilen, unsigned char output[16] );


#ifdef __cplusplus
}
#endif

#endif /* mbedtls_md5.h */
