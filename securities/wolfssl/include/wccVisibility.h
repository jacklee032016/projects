/* visibility.h
 *
 */

/* Visibility control macros */

#ifndef __WCC_VISIBILITY_H__
#define __WCC_VISIBILITY_H__


/* for compatibility and so that fips is using same name of macro @wc_fips */
#ifdef HAVE_FIPS
    #include <cyassl/ctaocrypt/visibility.h>
    #define WOLFSSL_API   CYASSL_API
	#define WOLFSSL_LOCAL CYASSL_LOCAL
#else

/* WOLFSSL_API is used for the public API symbols.
        It either imports or exports (or does nothing for static builds)

   WOLFSSL_LOCAL is used for non-API symbols (private).
*/

#if defined(BUILDING_WOLFSSL)
    #if defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
        #define WOLFSSL_API   __attribute__ ((visibility("default")))
        #define WOLFSSL_LOCAL __attribute__ ((visibility("hidden")))
    #elif defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)
        #define WOLFSSL_API   __global
        #define WOLFSSL_LOCAL __hidden
    #elif defined(_MSC_VER)
        #ifdef WOLFSSL_DLL
            #define WOLFSSL_API __declspec(dllexport)
        #else
            #define WOLFSSL_API
        #endif
        #define WOLFSSL_LOCAL
    #else
        #define WOLFSSL_API
        #define WOLFSSL_LOCAL
    #endif /* HAVE_VISIBILITY */
#else /* BUILDING_WOLFSSL */
    #if defined(_MSC_VER)
        #ifdef WOLFSSL_DLL
            #define WOLFSSL_API __declspec(dllimport)
        #else
            #define WOLFSSL_API
        #endif
        #define WOLFSSL_LOCAL
    #else
        #define WOLFSSL_API
        #define WOLFSSL_LOCAL
    #endif
#endif /* BUILDING_WOLFSSL */

#endif /* HAVE_FIPS */
#endif /* WOLF_CRYPT_VISIBILITY_H */

