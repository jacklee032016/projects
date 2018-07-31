/*
 *  Classic "Hello, world" demonstration program
 */

#include "mbed.h"

#if defined(MBEDTLS_MD5_C)
#include "mbedtls/md5.h"
#endif

#if !defined(MBEDTLS_MD5_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_MD5_C not defined.\n");
    return( 0 );
}
#else
int main( void )
{
    int i;
    unsigned char digest[16];
    char str[] = "Hello, world!";

    mbedtls_printf( "\n  MD5('%s') = ", str );

    mbedtls_md5( (unsigned char *) str, 13, digest );

    for( i = 0; i < 16; i++ )
        mbedtls_printf( "%02x", digest[i] );

    mbedtls_printf( "\n\n" );

#if defined(_WIN32)
    mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( 0 );
}
#endif

