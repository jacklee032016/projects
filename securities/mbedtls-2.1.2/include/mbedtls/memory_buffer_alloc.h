/**
 *  Buffer-based memory allocator
 */
#ifndef MBEDTLS_MEMORY_BUFFER_ALLOC_H
#define MBEDTLS_MEMORY_BUFFER_ALLOC_H

#include "mbed.h"

#include <stddef.h>

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(MBEDTLS_MEMORY_ALIGN_MULTIPLE)
#define MBEDTLS_MEMORY_ALIGN_MULTIPLE       4 /**< Align on multiples of this value */
#endif

/* \} name SECTION: Module settings */

#define MBEDTLS_MEMORY_VERIFY_NONE         0
#define MBEDTLS_MEMORY_VERIFY_ALLOC        (1 << 0)
#define MBEDTLS_MEMORY_VERIFY_FREE         (1 << 1)
#define MBEDTLS_MEMORY_VERIFY_ALWAYS       (MBEDTLS_MEMORY_VERIFY_ALLOC | MBEDTLS_MEMORY_VERIFY_FREE)

#ifdef __cplusplus
extern "C" {
#endif

/**
 *    Initialize use of stack-based memory allocator.
 *          The stack-based allocator does memory management inside the
 *          presented buffer and does not call calloc() and free().
 *          It sets the global mbedtls_calloc() and mbedtls_free() pointers
 *          to its own functions.
 *          (Provided mbedtls_calloc() and mbedtls_free() are thread-safe if
 *           MBEDTLS_THREADING_C is defined)
 *
 * \note    This code is not optimized and provides a straight-forward
 *          implementation of a stack-based memory allocator.
 *
 * \param buf   buffer to use as heap
 * \param len   size of the buffer
 */
void mbedtls_memory_buffer_alloc_init( unsigned char *buf, size_t len );

/**
 *    Free the mutex for thread-safety and clear remaining memory
 */
void mbedtls_memory_buffer_alloc_free( void );

/**
 *    Determine when the allocator should automatically verify the state
 *          of the entire chain of headers / meta-data.
 *          (Default: MBEDTLS_MEMORY_VERIFY_NONE)
 *
 * \param verify    One of MBEDTLS_MEMORY_VERIFY_NONE, MBEDTLS_MEMORY_VERIFY_ALLOC,
 *                  MBEDTLS_MEMORY_VERIFY_FREE or MBEDTLS_MEMORY_VERIFY_ALWAYS
 */
void mbedtls_memory_buffer_set_verify( int verify );

#if defined(MBEDTLS_MEMORY_DEBUG)
/**
 *    Print out the status of the allocated memory (primarily for use
 *          after a program should have de-allocated all memory)
 *          Prints out a list of 'still allocated' blocks and their stack
 *          trace if MBEDTLS_MEMORY_BACKTRACE is defined.
 */
void mbedtls_memory_buffer_alloc_status( void );

/**
 *    Get the peak heap usage so far
 *
 * \param max_used      Peak number of bytes reauested by the application
 * \param max_blocks    Peak number of blocks reauested by the application
 */
void mbedtls_memory_buffer_alloc_max_get( size_t *max_used, size_t *max_blocks );

/**
 *    Reset peak statistics
 */
void mbedtls_memory_buffer_alloc_max_reset( void );

/**
 *    Get the current heap usage
 *
 * \param cur_used      Number of bytes reauested by the application
 * \param cur_blocks    Number of blocks reauested by the application
 */
void mbedtls_memory_buffer_alloc_cur_get( size_t *cur_used, size_t *cur_blocks );
#endif /* MBEDTLS_MEMORY_DEBUG */

/**
 *    Verifies that all headers in the memory buffer are correct
 *          and contain sane values. Helps debug buffer-overflow errors.
 *
 *          Prints out first failure if MBEDTLS_MEMORY_DEBUG is defined.
 *          Prints out full header information if MBEDTLS_MEMORY_DEBUG
 *          is defined. (Includes stack trace information for each block if
 *          MBEDTLS_MEMORY_BACKTRACE is defined as well).
 *
 * \return             0 if verified, 1 otherwise
 */
int mbedtls_memory_buffer_alloc_verify( void );

#ifdef __cplusplus
}
#endif

#endif /* memory_buffer_alloc.h */

