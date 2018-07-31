/**
 *  DTLS cookie callbacks implementation
 */
#ifndef MBEDTLS_SSL_COOKIE_H
#define MBEDTLS_SSL_COOKIE_H

#include "ssl.h"

#if defined(MBEDTLS_THREADING_C)
#include "threading.h"
#endif

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */
#ifndef MBEDTLS_SSL_COOKIE_TIMEOUT
#define MBEDTLS_SSL_COOKIE_TIMEOUT     60 /**< Default expiration delay of DTLS cookies, in seconds if HAVE_TIME, or in number of cookies issued */
#endif

/* \} name SECTION: Module settings */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *           Context for the default cookie functions.
 */
typedef struct
{
    mbedtls_md_context_t    hmac_ctx;   /*!< context for the HMAC portion   */
#if !defined(MBEDTLS_HAVE_TIME)
    unsigned long   serial;     /*!< serial number for expiration   */
#endif
    unsigned long   timeout;    /*!< timeout delay, in seconds if HAVE_TIME,
                                     or in number of tickets issued */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex;
#endif
} mbedtls_ssl_cookie_ctx;

/**
 *           Initialize cookie context
 */
void mbedtls_ssl_cookie_init( mbedtls_ssl_cookie_ctx *ctx );

/**
 *           Setup cookie context (generate keys)
 */
int mbedtls_ssl_cookie_setup( mbedtls_ssl_cookie_ctx *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

/**
 *           Set expiration delay for cookies
 *                 (Default MBEDTLS_SSL_COOKIE_TIMEOUT)
 *
 * \param ctx      Cookie contex
 * \param delay    Delay, in seconds if HAVE_TIME, or in number of cookies
 *                 issued in the meantime.
 *                 0 to disable expiration (NOT recommended)
 */
void mbedtls_ssl_cookie_set_timeout( mbedtls_ssl_cookie_ctx *ctx, unsigned long delay );

/**
 *           Free cookie context
 */
void mbedtls_ssl_cookie_free( mbedtls_ssl_cookie_ctx *ctx );

/**
 *           Generate cookie, see \c mbedtls_ssl_cookie_write_t
 */
mbedtls_ssl_cookie_write_t mbedtls_ssl_cookie_write;

/**
 *           Verify cookie, see \c mbedtls_ssl_cookie_write_t
 */
mbedtls_ssl_cookie_check_t mbedtls_ssl_cookie_check;

#ifdef __cplusplus
}
#endif

#endif /* ssl_cookie.h */
