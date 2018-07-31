
#ifndef	__M_BED_H__
#define	__M_BED_H__

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif



#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free

#include <stdio.h>
#define mbedtls_exit       exit
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#endif

#include <string.h>

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

#define	MD_OUT_LENGTH_MD5			16
#define	MD_OUT_LENGTH_RIPEMD		20
#define	MD_OUT_LENGTH_SHA1			20
#define	MD_OUT_LENGTH_SHA256		32
#define	MD_OUT_LENGTH_SHA512		64

#define	MD_DATA_LENGTH_MD5			64
#define	MD_DATA_LENGTH_RIPEMD		64
#define	MD_DATA_LENGTH_SHA1			64
#define	MD_DATA_LENGTH_SHA256		64
#define	MD_DATA_LENGTH_SHA512		128


#endif

