/**
 *   Use and generate multiple entropies calls into a file
 */

#include "mbed.h"

#if defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_FS_IO)
#include "mbedtls/entropy.h"

#include <stdio.h>
#endif

#if !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_FS_IO)
int main( void )
{
    mbedtls_printf("MBEDTLS_ENTROPY_C and/or MBEDTLS_FS_IO not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int i, k, ret;
    mbedtls_entropy_context entropy;
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];

    if( argc < 2 )
    {
        mbedtls_fprintf( stderr, "usage: %s <output filename>\n", argv[0] );
        return( 1 );
    }

    if( ( f = fopen( argv[1], "wb+" ) ) == NULL )
    {
        mbedtls_printf( "failed to open '%s' for writing.\n", argv[1] );
        return( 1 );
    }

    mbedtls_entropy_init( &entropy );

    for( i = 0, k = 768; i < k; i++ )
    {
        ret = mbedtls_entropy_func( &entropy, buf, sizeof( buf ) );
        if( ret != 0 )
        {
            mbedtls_printf("failed!\n");
            goto cleanup;
        }

        fwrite( buf, 1, sizeof( buf ), f );

        mbedtls_printf( "Generating %ldkb of data in file '%s'... %04.1f" \
                "%% done\r", (long)(sizeof(buf) * k / 1024), argv[1], (100 * (float) (i + 1)) / k );
        fflush( stdout );
    }

    ret = 0;

cleanup:
    mbedtls_printf( "\n" );

    fclose( f );
    mbedtls_entropy_free( &entropy );

    return( ret );
}
#endif

