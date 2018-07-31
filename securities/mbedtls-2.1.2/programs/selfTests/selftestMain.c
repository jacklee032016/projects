/*
 *  Self-test demonstration program
 */

#include "mbed.h"

#include "tests.h"

static int test_snprintf( size_t n, const char ref_buf[10], int ref_ret )
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    ret = mbedtls_snprintf( buf, n, "%s", "123" );
    if( ret < 0 || (size_t) ret >= n )
        ret = -1;

    if( strncmp( ref_buf, buf, sizeof( buf ) ) != 0 ||ref_ret != ret ||
        memcmp( buf + n, ref + n, sizeof( buf ) - n ) != 0 )
    {
        return( 1 );
    }

    return( 0 );
}

static int run_test_snprintf( void )
{
    return( test_snprintf( 0, "xxxxxxxxx",  -1 ) != 0 ||
            test_snprintf( 1, "",           -1 ) != 0 ||
            test_snprintf( 2, "1",          -1 ) != 0 ||
            test_snprintf( 3, "12",         -1 ) != 0 ||
            test_snprintf( 4, "123",         3 ) != 0 ||
            test_snprintf( 5, "123",         3 ) != 0 );
}

int main( int argc, char *argv[] )
{
    int ret = 0, v;
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    unsigned char buf[1000000];
#endif
    void *pointer;

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset( &pointer, 0, sizeof( void * ) );
    if( pointer != NULL )
    {
        mbedtls_printf( "all-bits-zero is not a NULL pointer\n" );
        return( 1 );
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if( run_test_snprintf() != 0 )
    {
        mbedtls_printf( "the snprintf implementation is broken\n" );
        return( 0 );
    }

    if( argc == 2 && strcmp( argv[1], "-quiet" ) == 0 )
        v = 0;
    else
    {
        v = 1;
        mbedtls_printf( "\n" );
    }

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_init( buf, sizeof(buf) );
#endif



#if defined(MBEDTLS_TIMING_C)
    if( ( ret = mbedtls_timing_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_BASE64_C)
    if( ( ret = mbedtls_base64_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_BIGNUM_C)
    if( ( ret = mbedtls_mpi_self_test( v ) ) != 0 )
        return( ret );
#endif


#if defined(MBEDTLS_ENTROPY_C)
    if( ( ret = mbedtls_entropy_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_CTR_DRBG_C)
    if( ( ret = mbedtls_ctr_drbg_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_HMAC_DRBG_C)
    if( ( ret = mbedtls_hmac_drbg_self_test( v ) ) != 0 )
        return( ret );
#endif



#if defined(MBEDTLS_MD2_C)
    if( ( ret = mbedtls_md2_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_MD4_C)
    if( ( ret = mbedtls_md4_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_MD5_C)
    if( ( ret = mbedtls_md5_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_RIPEMD160_C)
    if( ( ret = mbedtls_ripemd160_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_SHA1_C)
    if( ( ret = mbedtls_sha1_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_SHA256_C)
    if( ( ret = mbedtls_sha256_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_SHA512_C)
    if( ( ret = mbedtls_sha512_self_test( v ) ) != 0 )
        return( ret );
#endif


#if defined(MBEDTLS_ARC4_C)
    if( ( ret = mbedtls_arc4_self_test( v ) ) != 0 )
        return( ret );
#endif


#if defined(MBEDTLS_DES_C)
    if( ( ret = mbedtls_des_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_AES_C)
    if( ( ret = mbedtls_aes_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_CAMELLIA_C)
    if( ( ret = mbedtls_camellia_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_XTEA_C)
    if( ( ret = mbedtls_xtea_self_test( v ) ) != 0 )
        return( ret );
#endif

#if defined(MBEDTLS_GCM_C) && defined(MBEDTLS_AES_C)
    if( ( ret = mbedtls_gcm_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_CCM_C) && defined(MBEDTLS_AES_C)
    if( ( ret = mbedtls_ccm_self_test( v ) ) != 0 )
        return( ret );
#endif
#if defined(MBEDTLS_ECP_C)
    if( ( ret = mbedtls_ecp_self_test( v ) ) != 0 )
        return( ret );
#endif



#if defined(MBEDTLS_DHM_C)
    if( ( ret = mbedtls_dhm_self_test( v ) ) != 0 )
        return( ret );
#endif

#if defined(MBEDTLS_RSA_C)
    if( ( ret = mbedtls_rsa_self_test( v ) ) != 0 )
        return( ret );
#endif

#if defined(MBEDTLS_PKCS5_C)
    if( ( ret = mbedtls_pkcs5_self_test( v ) ) != 0 )
        return( ret );
#endif

#if defined(MBEDTLS_X509_USE_C)
    if( ( ret = mbedtls_x509_self_test( v ) ) != 0 )
        return( ret );
#endif

    if( v != 0 )
    {
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && defined(MBEDTLS_MEMORY_DEBUG)
        mbedtls_memory_buffer_alloc_status();
#endif
    }

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_free();

    if( ( ret = mbedtls_memory_buffer_alloc_self_test( v ) ) != 0 )
        return( ret );
#endif

    if( v != 0 )
    {
        mbedtls_printf( "  [ All tests passed ]\n\n" );
#if defined(_WIN32)
        mbedtls_printf( "  Press Enter to exit this program.\n" );
        fflush( stdout ); getchar();
#endif
    }

    return( ret );
}
