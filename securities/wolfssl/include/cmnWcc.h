/*
* Encapsulation of all wold common crypto logics
*/

#ifndef		__COMMON_CRYPTO_H__
#define		__COMMON_CRYPTO_H__

#ifdef	MINGW
	#define	SNPRINTF		snprintf
#else
//	#define	SNPRINTF		_snprintf
//	#define	SNPRINTF		_snprintf_s
#define	SNPRINTF(msg, size, format,...) \
	_snprintf(msg, size, format, ##__VA_ARGS__)
	
#define	GETS(msg)	\
			fgets(msg, sizeof(msg), stdin)
#endif

#if 1
#define	DEBUG_MSG( format ,...) \
	{char msg[512]; \
	SNPRINTF(msg, sizeof(msg), format, __VA_ARGS__ ); \
	printf(msg);}

#define	TRACE()		printf(__FILE__ " "__FUNCTION__"() : %d line\n", __LINE__ )

//	WOLFSSL_MSG(msg);} 
#else
	SNPRINTF(msg, sizeof(msg), format, ##__VA_ARGS__ ); \
#define	DEBUG_MSG( format ,...) \
	{char msg[512]; va_list args; \
  		va_start(args, format);	\
	SNPRINTF(msg, sizeof(msg), format, args); \
	printf(msg); \
	OutputDebugString(msg);} 

#define	TRACE()

#endif

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wccSettings.h>
#include <wccTypes.h>

#include <wccError.h>
#include <wccLogging.h>


#ifdef NO_INLINE
    #include <wccMisc.h>
#else
    #include <src/crypto/wccMisc.c>
#endif

#include <wccCoding.h>
#include <wccInteger.h>
#include <wccRandom.h>
#include <wccPwdbased.h>

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable: 4996)
#endif


#if defined(__GNUC__)
    #define WOLFSSL_PACK __attribute__ ((packed))
#else
    #define WOLFSSL_PACK
#endif


#endif

