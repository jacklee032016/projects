
#include "mbed.h"

#include "tests.h"


#if defined(MBEDTLS_X509_USE_C)

#include "mbedtls/x509_crt.h"
#include "mbedtls/certs.h"

/*
 * Checkup routine
 */
int mbedtls_x509_self_test( int verbose )
{
#if defined(MBEDTLS_CERTS_C) && defined(MBEDTLS_SHA1_C)
    int ret;
    uint32_t flags;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;

    if( verbose != 0 )
        mbedtls_printf( "  X.509 certificate load: " );

    mbedtls_x509_crt_init( &clicert );

    ret = mbedtls_x509_crt_parse( &clicert, (const unsigned char *) mbedtls_test_cli_crt,
                           mbedtls_test_cli_crt_len );
    if( ret != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( ret );
    }

    mbedtls_x509_crt_init( &cacert );

    ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) mbedtls_test_ca_crt,
                          mbedtls_test_ca_crt_len );
    if( ret != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( ret );
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  X.509 signature verify: ");

    ret = mbedtls_x509_crt_verify( &clicert, &cacert, NULL, NULL, &flags, NULL, NULL );
    if( ret != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( ret );
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n\n");

    mbedtls_x509_crt_free( &cacert  );
    mbedtls_x509_crt_free( &clicert );

    return( 0 );
#else
    ((void) verbose);
    return( 0 );
#endif /* MBEDTLS_CERTS_C && MBEDTLS_SHA1_C */
}

#endif /* MBEDTLS_X509_USE_C */

