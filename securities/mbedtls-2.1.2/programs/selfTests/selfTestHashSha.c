
#include "mbed.h"

#include "tests.h"


#if defined(MBEDTLS_SHA1_C)
/*
 * FIPS-180-1 test vectors
 */
static const unsigned char sha1_test_buf[3][57] =
{
    { "abc" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" },
    { "" }
};

static const int sha1_test_buflen[3] =
{
    3, 56, 1000
};

static const unsigned char sha1_test_sum[3][20] =
{
    { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
      0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D },
    { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
      0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1 },
    { 0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
      0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F }
};

/*
 * Checkup routine
 */
int mbedtls_sha1_self_test( int verbose )
{
    int i, j, buflen, ret = 0;
    unsigned char buf[1024];
    unsigned char sha1sum[20];
    mbedtls_sha1_context ctx;

    mbedtls_sha1_init( &ctx );

    /*
     * SHA-1
     */
    for( i = 0; i < 3; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  SHA-1 test #%d: ", i + 1 );

        mbedtls_sha1_starts( &ctx );

        if( i == 2 )
        {
            memset( buf, 'a', buflen = 1000 );

            for( j = 0; j < 1000; j++ )
                mbedtls_sha1_update( &ctx, buf, buflen );
        }
        else
            mbedtls_sha1_update( &ctx, sha1_test_buf[i], sha1_test_buflen[i] );

        mbedtls_sha1_finish( &ctx, sha1sum );

        if( memcmp( sha1sum, sha1_test_sum[i], 20 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

exit:
    mbedtls_sha1_free( &ctx );

    return( ret );
}

#endif /* MBEDTLS_SHA1_C */

#if defined(MBEDTLS_SHA256_C)
/*
 * FIPS-180-2 test vectors
 */
static const unsigned char sha256_test_buf[3][57] =
{
    { "abc" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" },
    { "" }
};

static const int sha256_test_buflen[3] =
{
    3, 56, 1000
};

static const unsigned char sha256_test_sum[6][32] =
{
    /*
     * SHA-224 test vectors
     */
    { 0x23, 0x09, 0x7D, 0x22, 0x34, 0x05, 0xD8, 0x22,
      0x86, 0x42, 0xA4, 0x77, 0xBD, 0xA2, 0x55, 0xB3,
      0x2A, 0xAD, 0xBC, 0xE4, 0xBD, 0xA0, 0xB3, 0xF7,
      0xE3, 0x6C, 0x9D, 0xA7 },
    { 0x75, 0x38, 0x8B, 0x16, 0x51, 0x27, 0x76, 0xCC,
      0x5D, 0xBA, 0x5D, 0xA1, 0xFD, 0x89, 0x01, 0x50,
      0xB0, 0xC6, 0x45, 0x5C, 0xB4, 0xF5, 0x8B, 0x19,
      0x52, 0x52, 0x25, 0x25 },
    { 0x20, 0x79, 0x46, 0x55, 0x98, 0x0C, 0x91, 0xD8,
      0xBB, 0xB4, 0xC1, 0xEA, 0x97, 0x61, 0x8A, 0x4B,
      0xF0, 0x3F, 0x42, 0x58, 0x19, 0x48, 0xB2, 0xEE,
      0x4E, 0xE7, 0xAD, 0x67 },

    /*
     * SHA-256 test vectors
     */
    { 0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
      0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
      0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
      0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD },
    { 0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
      0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
      0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
      0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1 },
    { 0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92,
      0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7, 0x3E, 0x67,
      0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E,
      0x04, 0x6D, 0x39, 0xCC, 0xC7, 0x11, 0x2C, 0xD0 }
};

/*
 * Checkup routine
 */
int mbedtls_sha256_self_test( int verbose )
{
    int i, j, k, buflen, ret = 0;
    unsigned char buf[1024];
    unsigned char sha256sum[32];
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init( &ctx );

    for( i = 0; i < 6; i++ )
    {
        j = i % 3;
        k = i < 3;

        if( verbose != 0 )
            mbedtls_printf( "  SHA-%d test #%d: ", 256 - k * 32, j + 1 );

        mbedtls_sha256_starts( &ctx, k );

        if( j == 2 )
        {
            memset( buf, 'a', buflen = 1000 );

            for( j = 0; j < 1000; j++ )
                mbedtls_sha256_update( &ctx, buf, buflen );
        }
        else
            mbedtls_sha256_update( &ctx, sha256_test_buf[j],
                                 sha256_test_buflen[j] );

        mbedtls_sha256_finish( &ctx, sha256sum );

        if( memcmp( sha256sum, sha256_test_sum[i], 32 - k * 4 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

exit:
    mbedtls_sha256_free( &ctx );

    return( ret );
}

#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)

/*
 * FIPS-180-2 test vectors
 */
static const unsigned char sha512_test_buf[3][113] =
{
    { "abc" },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
      "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" },
    { "" }
};

static const int sha512_test_buflen[3] =
{
    3, 112, 1000
};

static const unsigned char sha512_test_sum[6][64] =
{
    /*
     * SHA-384 test vectors
     */
    { 0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B,
      0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
      0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
      0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
      0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
      0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7 },
    { 0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8,
      0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD, 0x1B, 0x47,
      0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2,
      0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0, 0xF7, 0x12,
      0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9,
      0x66, 0xC3, 0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39 },
    { 0x9D, 0x0E, 0x18, 0x09, 0x71, 0x64, 0x74, 0xCB,
      0x08, 0x6E, 0x83, 0x4E, 0x31, 0x0A, 0x4A, 0x1C,
      0xED, 0x14, 0x9E, 0x9C, 0x00, 0xF2, 0x48, 0x52,
      0x79, 0x72, 0xCE, 0xC5, 0x70, 0x4C, 0x2A, 0x5B,
      0x07, 0xB8, 0xB3, 0xDC, 0x38, 0xEC, 0xC4, 0xEB,
      0xAE, 0x97, 0xDD, 0xD8, 0x7F, 0x3D, 0x89, 0x85 },

    /*
     * SHA-512 test vectors
     */
    { 0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
      0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
      0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
      0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
      0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
      0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
      0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
      0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F },
    { 0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA,
      0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
      0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1,
      0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
      0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4,
      0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
      0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
      0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09 },
    { 0xE7, 0x18, 0x48, 0x3D, 0x0C, 0xE7, 0x69, 0x64,
      0x4E, 0x2E, 0x42, 0xC7, 0xBC, 0x15, 0xB4, 0x63,
      0x8E, 0x1F, 0x98, 0xB1, 0x3B, 0x20, 0x44, 0x28,
      0x56, 0x32, 0xA8, 0x03, 0xAF, 0xA9, 0x73, 0xEB,
      0xDE, 0x0F, 0xF2, 0x44, 0x87, 0x7E, 0xA6, 0x0A,
      0x4C, 0xB0, 0x43, 0x2C, 0xE5, 0x77, 0xC3, 0x1B,
      0xEB, 0x00, 0x9C, 0x5C, 0x2C, 0x49, 0xAA, 0x2E,
      0x4E, 0xAD, 0xB2, 0x17, 0xAD, 0x8C, 0xC0, 0x9B }
};

/*
 * Checkup routine
 */
int mbedtls_sha512_self_test( int verbose )
{
    int i, j, k, buflen, ret = 0;
    unsigned char buf[1024];
    unsigned char sha512sum[64];
    mbedtls_sha512_context ctx;

    mbedtls_sha512_init( &ctx );

    for( i = 0; i < 6; i++ )
    {
        j = i % 3;
        k = i < 3;

        if( verbose != 0 )
            mbedtls_printf( "  SHA-%d test #%d: ", 512 - k * 128, j + 1 );

        mbedtls_sha512_starts( &ctx, k );

        if( j == 2 )
        {
            memset( buf, 'a', buflen = 1000 );

            for( j = 0; j < 1000; j++ )
                mbedtls_sha512_update( &ctx, buf, buflen );
        }
        else
            mbedtls_sha512_update( &ctx, sha512_test_buf[j],
                                 sha512_test_buflen[j] );

        mbedtls_sha512_finish( &ctx, sha512sum );

        if( memcmp( sha512sum, sha512_test_sum[i], 64 - k * 16 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

exit:
    mbedtls_sha512_free( &ctx );

    return( ret );
}

#endif /* MBEDTLS_SHA512_C */

