
#include "mbed.h"

#include "tests.h"



#if defined(MBEDTLS_TIMING_C)

/*
 * Busy-waits for the given number of milliseconds.
 * Used for testing mbedtls_timing_hardclock.
 */
static void busy_msleep( unsigned long msec )
{
    struct mbedtls_timing_hr_time hires;
    unsigned long i = 0; /* for busy-waiting */
    volatile unsigned long j; /* to prevent optimisation */

    (void) mbedtls_timing_get_timer( &hires, 1 );

    while( mbedtls_timing_get_timer( &hires, 0 ) < msec )
        i++;

    j = i;
    (void) j;
}

#define FAIL    do                      \
{                                       \
    if( verbose != 0 )                  \
        mbedtls_printf( "failed\n" );   \
                                        \
    return( 1 );                        \
} while( 0 )

/*
 * Checkup routine
 *
 * Warning: this is work in progress, some tests may not be reliable enough
 * yet! False positives may happen.
 */
int mbedtls_timing_self_test( int verbose )
{
    unsigned long cycles, ratio;
    unsigned long millisecs, secs;
    int hardfail;
    struct mbedtls_timing_hr_time hires;
    uint32_t a, b;
    mbedtls_timing_delay_context ctx;

    if( verbose != 0 )
        mbedtls_printf( "  TIMING tests note: will take some time!\n" );

    if( verbose != 0 )
        mbedtls_printf( "  TIMING test #1 (set_alarm / get_timer): " );

	for( secs = 1; secs <= 3; secs++ )
	{
		(void) mbedtls_timing_get_timer( &hires, 1 );

		mbedtls_set_alarm( (int) secs );
		while( !mbedtls_timing_alarmed )
			;

		millisecs = mbedtls_timing_get_timer( &hires, 0 );

		/* For some reason on Windows it looks like alarm has an extra delay
		* (maybe related to creating a new thread). Allow some room here. */
		if( millisecs < 800 * secs || millisecs > 1200 * secs + 300 )
		{
			if( verbose != 0 )
				mbedtls_printf( "failed: real delay is %d\n",millisecs );

			return( 1 );
		}
	}
	if( verbose != 0 )
		mbedtls_printf( "passed\n" );


    if( verbose != 0 )
        mbedtls_printf( "  TIMING test #2 (set/get_delay        ): " );

    for( a = 200; a <= 400; a += 200 )
    {
        for( b = 200; b <= 400; b += 200 )
        {
            mbedtls_timing_set_delay( &ctx, a, a + b );

            busy_msleep( a - a / 8 );
            if( mbedtls_timing_get_delay( &ctx ) != 0 )
                FAIL;

            busy_msleep( a / 4 );
            if( mbedtls_timing_get_delay( &ctx ) != 1 )
                FAIL;

            busy_msleep( b - a / 8 - b / 8 );
            if( mbedtls_timing_get_delay( &ctx ) != 1 )
                FAIL;

            busy_msleep( b / 4 );
            if( mbedtls_timing_get_delay( &ctx ) != 2 )
                FAIL;
        }
    }

    mbedtls_timing_set_delay( &ctx, 0, 0 );
    busy_msleep( 200 );
    if( mbedtls_timing_get_delay( &ctx ) != -1 )
        FAIL;

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );


    if( verbose != 0 )
        mbedtls_printf( "  TIMING test #3 (hardclock / get_timer): " );

    /*
     * Allow one failure for possible counter wrapping.
     * On a 4Ghz 32-bit machine the cycle counter wraps about once per second;
     * since the whole test is about 10ms, it shouldn't happen twice in a row.
     */
    hardfail = 0;

hard_test:
    if( hardfail > 1 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed (ignored)\n" );

        goto hard_test_done;
    }

    /* Get a reference ratio cycles/ms */
    millisecs = 1;
    cycles = mbedtls_timing_hardclock();
    busy_msleep( millisecs );
    cycles = mbedtls_timing_hardclock() - cycles;
    ratio = cycles / millisecs;

    /* Check that the ratio is mostly constant */
    for( millisecs = 2; millisecs <= 4; millisecs++ )
    {
        cycles = mbedtls_timing_hardclock();
        busy_msleep( millisecs );
        cycles = mbedtls_timing_hardclock() - cycles;

        /* Allow variation up to 20% */
        if( cycles / millisecs < ratio - ratio / 5 ||
            cycles / millisecs > ratio + ratio / 5 )
        {
            hardfail++;
            goto hard_test;
        }
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

hard_test_done:

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( 0 );
}
#endif /* #if defined(MBEDTLS_TIMING_C) */

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
static int check_pointer( void *p )
{
    if( p == NULL )
        return( -1 );

    if( (size_t) p % MBEDTLS_MEMORY_ALIGN_MULTIPLE != 0 )
        return( -1 );

    return( 0 );
}

static int check_all_free( )
{
    if(
#if defined(MBEDTLS_MEMORY_DEBUG)
        heap.total_used != 0 ||
#endif
        heap.first != heap.first_free ||
        (void *) heap.first != (void *) heap.buf )
    {
        return( -1 );
    }

    return( 0 );
}

#define TEST_ASSERT( condition )            \
    if( ! (condition) )                     \
    {                                       \
        if( verbose != 0 )                  \
            mbedtls_printf( "failed\n" );  \
                                            \
        ret = 1;                            \
        goto cleanup;                       \
    }

int mbedtls_memory_buffer_alloc_self_test( int verbose )
{
    unsigned char buf[1024];
    unsigned char *p, *q, *r, *end;
    int ret = 0;

    if( verbose != 0 )
        mbedtls_printf( "  MBA test #1 (basic alloc-free cycle): " );

    mbedtls_memory_buffer_alloc_init( buf, sizeof( buf ) );

    p = mbedtls_calloc( 1, 1 );
    q = mbedtls_calloc( 1, 128 );
    r = mbedtls_calloc( 1, 16 );

    TEST_ASSERT( check_pointer( p ) == 0 &&
                 check_pointer( q ) == 0 &&
                 check_pointer( r ) == 0 );

    mbedtls_free( r );
    mbedtls_free( q );
    mbedtls_free( p );

    TEST_ASSERT( check_all_free( ) == 0 );

    /* Memorize end to compare with the next test */
    end = heap.buf + heap.len;

    mbedtls_memory_buffer_alloc_free( );

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    if( verbose != 0 )
        mbedtls_printf( "  MBA test #2 (buf not aligned): " );

    mbedtls_memory_buffer_alloc_init( buf + 1, sizeof( buf ) - 1 );

    TEST_ASSERT( heap.buf + heap.len == end );

    p = mbedtls_calloc( 1, 1 );
    q = mbedtls_calloc( 1, 128 );
    r = mbedtls_calloc( 1, 16 );

    TEST_ASSERT( check_pointer( p ) == 0 &&
                 check_pointer( q ) == 0 &&
                 check_pointer( r ) == 0 );

    mbedtls_free( r );
    mbedtls_free( q );
    mbedtls_free( p );

    TEST_ASSERT( check_all_free( ) == 0 );

    mbedtls_memory_buffer_alloc_free( );

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    if( verbose != 0 )
        mbedtls_printf( "  MBA test #3 (full): " );

    mbedtls_memory_buffer_alloc_init( buf, sizeof( buf ) );

    p = mbedtls_calloc( 1, sizeof( buf ) - sizeof( memory_header ) );

    TEST_ASSERT( check_pointer( p ) == 0 );
    TEST_ASSERT( mbedtls_calloc( 1, 1 ) == NULL );

    mbedtls_free( p );

    p = mbedtls_calloc( 1, sizeof( buf ) - 2 * sizeof( memory_header ) - 16 );
    q = mbedtls_calloc( 1, 16 );

    TEST_ASSERT( check_pointer( p ) == 0 && check_pointer( q ) == 0 );
    TEST_ASSERT( mbedtls_calloc( 1, 1 ) == NULL );

    mbedtls_free( q );

    TEST_ASSERT( mbedtls_calloc( 1, 17 ) == NULL );

    mbedtls_free( p );

    TEST_ASSERT( check_all_free( ) == 0 );

    mbedtls_memory_buffer_alloc_free( );

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

cleanup:
    mbedtls_memory_buffer_alloc_free( );

    return( ret );
}
#endif /* MBEDTLS_MEMORY_BUFFER_ALLOC_C */


