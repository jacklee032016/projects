/**
 *  HAVEGE: HArdware Volatile Entropy Gathering and Expansion
 */
#ifndef MBEDTLS_HAVEGE_H
#define MBEDTLS_HAVEGE_H

#include <stddef.h>

#define MBEDTLS_HAVEGE_COLLECT_SIZE 1024

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           HAVEGE state structure
 */
typedef struct
{
    int PT1, PT2, offset[2];
    int pool[MBEDTLS_HAVEGE_COLLECT_SIZE];
    int WALK[8192];
}mbedtls_havege_state;

/**
 *           HAVEGE initialization
 *
 * \param hs       HAVEGE state to be initialized
 */
void mbedtls_havege_init( mbedtls_havege_state *hs );

/**
 *           Clear HAVEGE state
 *
 * \param hs       HAVEGE state to be cleared
 */
void mbedtls_havege_free( mbedtls_havege_state *hs );

/**
 *           HAVEGE rand function
 *
 * \param p_rng    A HAVEGE state
 * \param output   Buffer to fill
 * \param len      Length of buffer
 *
 * \return         0
 */
int mbedtls_havege_random( void *p_rng, unsigned char *output, size_t len );

#ifdef __cplusplus
}
#endif

#endif

