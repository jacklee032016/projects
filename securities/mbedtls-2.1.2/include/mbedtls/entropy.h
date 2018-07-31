/**
 *  Entropy accumulator implementation
 */
#ifndef MBEDTLS_ENTROPY_H
#define MBEDTLS_ENTROPY_H

#include "mbed.h"

#include <stddef.h>

#if defined(MBEDTLS_SHA512_C) && !defined(MBEDTLS_ENTROPY_FORCE_SHA256)
#include "sha512.h"
#define MBEDTLS_ENTROPY_SHA512_ACCUMULATOR
#else
#if defined(MBEDTLS_SHA256_C)
#define MBEDTLS_ENTROPY_SHA256_ACCUMULATOR
#include "sha256.h"
#endif
#endif

#if defined(MBEDTLS_THREADING_C)
#include "threading.h"
#endif

#if defined(MBEDTLS_HAVEGE_C)
#include "havege.h"
#endif

#define MBEDTLS_ERR_ENTROPY_SOURCE_FAILED                 -0x003C  /**< Critical entropy source failure. */
#define MBEDTLS_ERR_ENTROPY_MAX_SOURCES                   -0x003E  /**< No more sources can be added. */
#define MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED            -0x0040  /**< No sources have been added to poll. */
#define MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE              -0x003D  /**< No strong sources have been added to poll. */
#define MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR                 -0x003F  /**< Read/write error in file. */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(MBEDTLS_ENTROPY_MAX_SOURCES)
#define MBEDTLS_ENTROPY_MAX_SOURCES     20      /**< Maximum number of sources supported */
#endif

#if !defined(MBEDTLS_ENTROPY_MAX_GATHER)
#define MBEDTLS_ENTROPY_MAX_GATHER      128     /**< Maximum amount requested from entropy sources */
#endif

/* \} name SECTION: Module settings */

#if defined(MBEDTLS_ENTROPY_SHA512_ACCUMULATOR)
#define MBEDTLS_ENTROPY_BLOCK_SIZE      64      /**< Block size of entropy accumulator (SHA-512) */
#else
#define MBEDTLS_ENTROPY_BLOCK_SIZE      32      /**< Block size of entropy accumulator (SHA-256) */
#endif

#define MBEDTLS_ENTROPY_MAX_SEED_SIZE   1024    /**< Maximum size of seed we read from seed file */
#define MBEDTLS_ENTROPY_SOURCE_MANUAL   MBEDTLS_ENTROPY_MAX_SOURCES

#define MBEDTLS_ENTROPY_SOURCE_STRONG   1       /**< Entropy source is strong   */
#define MBEDTLS_ENTROPY_SOURCE_WEAK     0       /**< Entropy source is weak     */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *            Entropy poll callback pointer
 *
 * \param data      Callback-specific data pointer
 * \param output    Data to fill
 * \param len       Maximum size to provide
 * \param olen      The actual amount of bytes put into the buffer (Can be 0)
 *
 * \return          0 if no critical failures occurred,
 *                  MBEDTLS_ERR_ENTROPY_SOURCE_FAILED otherwise
 */
typedef int (*mbedtls_entropy_f_source_ptr)(void *data, unsigned char *output, size_t len, size_t *olen);

/* Entropy source state */
typedef struct
{
	mbedtls_entropy_f_source_ptr    f_source;   /**< The entropy source callback */
	void 		*p_source;   /**< The callback data pointer */
	size_t		size;       /**< Amount received in bytes */
	size_t		threshold;  /**< Minimum bytes required before release */
	int		strong;     /**< Is the source strong? */
}mbedtls_entropy_source_state;

/**
 *            Entropy context structure
 */
typedef struct
{
#if defined(MBEDTLS_ENTROPY_SHA512_ACCUMULATOR)
	mbedtls_sha512_context  accumulator;
#else
	mbedtls_sha256_context  accumulator;
#endif
	int             source_count;
	mbedtls_entropy_source_state    source[MBEDTLS_ENTROPY_MAX_SOURCES];
#if defined(MBEDTLS_HAVEGE_C)
	mbedtls_havege_state    havege_data;
#endif
#if defined(MBEDTLS_THREADING_C)
	mbedtls_threading_mutex_t mutex;    /*!< mutex                  */
#endif
}mbedtls_entropy_context;


void mbedtls_entropy_init( mbedtls_entropy_context *ctx );

void mbedtls_entropy_free( mbedtls_entropy_context *ctx );

/**
 *            Adds an entropy source to poll
 *                  (Thread-safe if MBEDTLS_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param f_source  Entropy function
 * \param p_source  Function data
 * \param threshold Minimum required from source before entropy is released
 *                  ( with mbedtls_entropy_func() ) (in bytes)
 * \param strong    MBEDTLS_ENTROPY_SOURCE_STRONG or
 *                  MBEDTSL_ENTROPY_SOURCE_WEAK.
 *                  At least one strong source needs to be added.
 *                  Weaker sources (such as the cycle counter) can be used as
 *                  a complement.
 *
 * \return          0 if successful or MBEDTLS_ERR_ENTROPY_MAX_SOURCES
 */
int mbedtls_entropy_add_source( mbedtls_entropy_context *ctx,
                        mbedtls_entropy_f_source_ptr f_source, void *p_source,
                        size_t threshold, int strong );

/**
 *            Trigger an extra gather poll for the accumulator
 *                  (Thread-safe if MBEDTLS_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 *
 * \return          0 if successful, or MBEDTLS_ERR_ENTROPY_SOURCE_FAILED
 */
int mbedtls_entropy_gather( mbedtls_entropy_context *ctx );

/**
 *            Retrieve entropy from the accumulator
 *                  (Maximum length: MBEDTLS_ENTROPY_BLOCK_SIZE)
 *                  (Thread-safe if MBEDTLS_THREADING_C is enabled)
 *
 * \param data      Entropy context
 * \param output    Buffer to fill
 * \param len       Number of bytes desired, must be at most MBEDTLS_ENTROPY_BLOCK_SIZE
 *
 * \return          0 if successful, or MBEDTLS_ERR_ENTROPY_SOURCE_FAILED
 */
int mbedtls_entropy_func( void *data, unsigned char *output, size_t len );

/**
 *            Add data to the accumulator manually
 *                  (Thread-safe if MBEDTLS_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param data      Data to add
 * \param len       Length of data
 *
 * \return          0 if successful
 */
int mbedtls_entropy_update_manual( mbedtls_entropy_context *ctx,
                           const unsigned char *data, size_t len );

#if defined(MBEDTLS_FS_IO)
/**
 *                Write a seed file
 *
 * \param ctx           Entropy context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR on file error, or
 *                      MBEDTLS_ERR_ENTROPY_SOURCE_FAILED
 */
int mbedtls_entropy_write_seed_file( mbedtls_entropy_context *ctx, const char *path );

/**
 *                Read and update a seed file. Seed is added to this
 *                      instance. No more than MBEDTLS_ENTROPY_MAX_SEED_SIZE bytes are
 *                      read from the seed file. The rest is ignored.
 *
 * \param ctx           Entropy context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR on file error,
 *                      MBEDTLS_ERR_ENTROPY_SOURCE_FAILED
 */
int mbedtls_entropy_update_seed_file( mbedtls_entropy_context *ctx, const char *path );
#endif /* MBEDTLS_FS_IO */


#ifdef __cplusplus
}
#endif

#endif

