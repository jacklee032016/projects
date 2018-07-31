/**
 *  The ARCFOUR stream cipher
 */
#ifndef MBEDTLS_ARC4_H
#define MBEDTLS_ARC4_H

#include "mbed.h"

#include <stddef.h>

#if !defined(MBEDTLS_ARC4_ALT)
// Regular implementation

#ifdef __cplusplus
extern "C" {
#endif

/* ARC4 context structure */
typedef struct
{
	int x;				/*!< permutation index */
	int y;				/*!< permutation index */
	unsigned char m[256];	/*!< permutation table */
}mbedtls_arc4_context;


/*  Initialize ARC4 context */
void mbedtls_arc4_init( mbedtls_arc4_context *ctx );

/* Clear ARC4 context */
void mbedtls_arc4_free( mbedtls_arc4_context *ctx );

/* ARC4 key schedule
 * \param key      the secret key
 * \param keylen   length of the key, in bytes
 */
void mbedtls_arc4_setup( mbedtls_arc4_context *ctx, const unsigned char *key,unsigned int keylen );

/**
 *           ARC4 cipher function
 *
 * \param ctx      ARC4 context
 * \param length   length of the input data
 * \param input    buffer holding the input data
 * \param output   buffer for the output data
 *
 * \return         0 if successful
 */
int mbedtls_arc4_crypt( mbedtls_arc4_context *ctx, size_t length, const unsigned char *input,unsigned char *output );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_ARC4_ALT */
#include "arc4_alt.h"
#endif /* MBEDTLS_ARC4_ALT */


#endif

