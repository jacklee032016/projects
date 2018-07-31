/*
 *  RSA simple decryption program
 */

#include "mbed.h"

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_RSA_C) && \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_RSA_C) ||  \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_FS_IO and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int ret, c;
    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char result[1024];
    unsigned char buf[512];
    const char *pers = "rsa_decrypt";
    ((void) argv);

    memset(result, 0, sizeof( result ) );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    ret = 1;

    if( argc != 1 )
    {
        mbedtls_printf( "usage: rsa_decrypt\n" );

#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif

        goto exit;
    }

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( "\n  . Reading private key from rsa_priv.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_priv.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not open rsa_priv.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    if( ( ret = mbedtls_mpi_read_file( &rsa.N , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.E , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.D , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.P , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.Q , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.DP, 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.DQ, 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.QP, 16, f ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n\n", ret );
        goto exit;
    }

    rsa.len = ( mbedtls_mpi_bitlen( &rsa.N ) + 7 ) >> 3;

    fclose( f );

    /*
     * Extract the RSA encrypted value from the text file
     */
    ret = 1;

    if( ( f = fopen( "result-enc.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( "\n  ! Could not open %s\n\n", "result-enc.txt" );
        goto exit;
    }

    i = 0;

    while( fscanf( f, "%02X", &c ) > 0 &&
           i < (int) sizeof( buf ) )
        buf[i++] = (unsigned char) c;

    fclose( f );

    if( i != rsa.len )
    {
        mbedtls_printf( "\n  ! Invalid RSA signature format\n\n" );
        goto exit;
    }

    /*
     * Decrypt the encrypted RSA data and print the result.
     */
    mbedtls_printf( "\n  . Decrypting the encrypted data" );
    fflush( stdout );

    if( ( ret = mbedtls_rsa_pkcs1_decrypt( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
                                   MBEDTLS_RSA_PRIVATE, &i, buf, result,
                                   1024 ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( "\n  . OK\n\n" );

    mbedtls_printf( "The decrypted result is: '%s'\n\n", result );

    ret = 0;

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_RSA_C && MBEDTLS_FS_IO */
