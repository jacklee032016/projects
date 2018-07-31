/* random.h
 */


#ifndef __WCC_RANDOM_H__
#define __WCC_RANDOM_H__

#include <wccTypes.h>

#ifdef HAVE_FIPS
/* for fips @wc_fips */
#include <cyassl/ctaocrypt/random.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef HAVE_FIPS /* avoid redefining structs and macros */
#if defined(HAVE_HASHDRBG) || defined(NO_RC4)
    #ifdef NO_SHA256
        #error "Hash DRBG requires SHA-256."
    #endif /* NO_SHA256 */

    #include <wchSha256.h>
#else /* HAVE_HASHDRBG || NO_RC4 */
    #include <wcsArc4.h>
#endif /* HAVE_HASHDRBG || NO_RC4 */

#if defined(USE_WINDOWS_API)
    #if defined(_WIN64)
        typedef unsigned __int64	ProviderHandle;
        /* type HCRYPTPROV, avoid #include <windows.h> */
    #else
        typedef unsigned long		ProviderHandle;
    #endif
#endif


/* OS specific seeder */
typedef struct OS_Seed {
#if defined(USE_WINDOWS_API)
	ProviderHandle handle;
#else
	int fd;
#endif
} OS_Seed;


#if defined(WOLFSSL_MDK_ARM)
#undef RNG
#define RNG wolfSSL_RNG   /* for avoiding name conflict in "stm32f2xx.h" */
#endif


#if defined(HAVE_HASHDRBG) || defined(NO_RC4)


#define DRBG_SEED_LEN (440/8)


struct DRBG; /* Private DRBG state */


/* Hash-based Deterministic Random Bit Generator */
typedef struct RNG {
    struct DRBG* drbg;
    OS_Seed seed;
    byte status;
} RNG;


#else /* HAVE_HASHDRBG || NO_RC4 */


#define WOLFSSL_RNG_CAVIUM_MAGIC 0xBEEF0004

/* secure Random Number Generator */


typedef struct RNG {
    OS_Seed seed;
    Arc4    cipher;
#ifdef HAVE_CAVIUM
    int    devId;           /* nitrox device id */
    word32 magic;           /* using cavium magic */
#endif
} RNG;


#endif /* HAVE_HASH_DRBG || NO_RC4 */

#endif /* HAVE_FIPS */

WOLFSSL_LOCAL int wc_GenerateSeed(OS_Seed* os, byte* seed, word32 sz);

#if defined(HAVE_HASHDRBG) || defined(NO_RC4)

#ifdef HAVE_CAVIUM
    WOLFSSL_API int  wc_InitRngCavium(RNG*, int);
#endif

#endif /* HAVE_HASH_DRBG || NO_RC4 */


WOLFSSL_API int  wc_InitRng(RNG*);
WOLFSSL_API int  wc_RNG_GenerateBlock(RNG*, byte*, word32 sz);
WOLFSSL_API int  wc_RNG_GenerateByte(RNG*, byte*);
WOLFSSL_API int  wc_FreeRng(RNG*);


#if defined(HAVE_HASHDRBG) || defined(NO_RC4)
    WOLFSSL_API int wc_RNG_HealthTest(int reseed,
                                        const byte* entropyA, word32 entropyASz,
                                        const byte* entropyB, word32 entropyBSz,
                                        byte* output, word32 outputSz);
#endif /* HAVE_HASHDRBG || NO_RC4 */

#ifdef __cplusplus
    }
#endif

#endif

