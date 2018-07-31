/*
 *  Translate error code to error string
 */

#include "mbed.h"

#if defined(MBEDTLS_ERROR_C) || defined(MBEDTLS_ERROR_STRERROR_DUMMY)
#include "mbedtls/error.h"
#endif

#define USAGE \
    "\n usage: strerror <errorcode>\n" \
    "\n where <errorcode> can be a decimal or hexadecimal (starts with 0x or -0x)\n"

#if !defined(MBEDTLS_ERROR_C) && !defined(MBEDTLS_ERROR_STRERROR_DUMMY)
int main( void )
{
    mbedtls_printf("MBEDTLS_ERROR_C and/or MBEDTLS_ERROR_STRERROR_DUMMY not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    long int val;
    char *end = argv[1];

    if( argc != 2 )
    {
        mbedtls_printf( USAGE );
        return( 0 );
    }

    val = strtol( argv[1], &end, 10 );
    if( *end != '\0' )
    {
        val = strtol( argv[1], &end, 16 );
        if( *end != '\0' )
        {
            mbedtls_printf( USAGE );
            return( 0 );
        }
    }
    if( val > 0 )
        val = -val;

    if( val != 0 )
    {
        char error_buf[200];
        mbedtls_strerror( val, error_buf, 200 );
        mbedtls_printf("Last error was: -0x%04x - %s\n\n", (int) -val, error_buf );
    }

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( val );
}
#endif /* MBEDTLS_ERROR_C */
