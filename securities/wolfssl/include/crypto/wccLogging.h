/* logging.h
 *
 */

/* submitted by eof */


#ifndef __WCC_LOGGING_H__
#define __WCC_LOGGING_H__

#include <wccTypes.h>

#ifdef __cplusplus
    extern "C" {
#endif


enum  CYA_Log_Levels {
    ERROR_LOG = 0,
    INFO_LOG,
    ENTER_LOG,
    LEAVE_LOG,
    OTHER_LOG
};

typedef void (*wolfSSL_Logging_cb)(const int logLevel, const char *const logMessage);
WOLFSSL_API int wolfSSL_SetLoggingCb(wolfSSL_Logging_cb log_function);

#ifdef DEBUG_WOLFSSL

	#define	WOLFSSL_ENTER()	\
		WOLFSSL_MSG( "wolfSSL Entering " __FUNCTION__ );

	#define	WOLFSSL_LEAVE( ret)	\
	{ char buffer[80];  sprintf(buffer, "wolfSSL Leaving " __FUNCTION__ ", return %d ", ret); \
		WOLFSSL_MSG( buffer); }
		
	#define	WOLFSSL_LEAVE_2()	\
		WOLFSSL_MSG( "wolfSSL Leaving " __FUNCTION__ );
		

#else /* DEBUG_WOLFSSL   */

//    #define WOLFSSL_ENTER(m)
    #define WOLFSSL_ENTER()
    #define WOLFSSL_LEAVE(m, r)

    #define WOLFSSL_ERROR(e)
    #define WOLFSSL_MSG(m)

#endif /* DEBUG_WOLFSSL  */

void WOLFSSL_ERROR(int);
void WOLFSSL_MSG(const char* msg);
void wolfSslDebug(char *format, ...);


#ifdef __cplusplus
}
#endif

#endif 


