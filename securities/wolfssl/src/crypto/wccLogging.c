/* logging.c
 */

#include "cmnWcc.h"


#ifdef DEBUG_WOLFSSL
/* Set these to default values initially. */
static wolfSSL_Logging_cb log_function = 0;
static int loggingEnabled = 0;
#endif /* DEBUG_WOLFSSL */

int wolfSSL_Debugging_ON(void)
{
#ifdef DEBUG_WOLFSSL
	loggingEnabled = 1;
	return 0;
#else
	return NOT_COMPILED_IN;
#endif
}


void wolfSSL_Debugging_OFF(void)
{
#ifdef DEBUG_WOLFSSL
	loggingEnabled = 0;
#endif
}


int wolfSSL_SetLoggingCb(wolfSSL_Logging_cb f)
{
#ifdef DEBUG_WOLFSSL
	int res = 0;

	if (f)
		log_function = f;
	else
		res = BAD_FUNC_ARG;

	return res;
#else
	(void)f;
	return NOT_COMPILED_IN;
#endif
}




#ifdef DEBUG_WOLFSSL

#ifdef FREESCALE_MQX
    #include <fio.h>
#else
    #include <stdio.h>   /* for default printf stuff */
#endif

#ifdef THREADX
    int dc_log_printf(char*, ...);
#endif

static void wolfssl_log(const int logLevel, const char *const logMessage)
{
	if (log_function)
		log_function(logLevel, logMessage);
	else {
		if (loggingEnabled) {
#ifdef THREADX
			dc_log_printf("%s\n", logMessage);
#elif defined(MICRIUM)
#if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
			NetSecure_TraceOut((CPU_CHAR *)logMessage);
#endif
#elif defined(WOLFSSL_MDK_ARM)
			fflush(stdout) ;
			printf("%s\n", logMessage);
			fflush(stdout) ;
#else
			fprintf(stderr, "%s\n", logMessage);
#endif
		}
	}
}


void WOLFSSL_MSG(const char* msg)
{
	if (loggingEnabled)
		wolfssl_log(INFO_LOG , msg);
}

#if 0
void WOLFSSL_ENTER(const char* msg)
{
	if (loggingEnabled)
	{
		char buffer[80];
		sprintf(buffer, "wolfSSL Entering %s", msg);
		wolfssl_log(ENTER_LOG , buffer);
	}
}

void WOLFSSL_LEAVE(const char* msg, int ret)
{
    if (loggingEnabled) {
        char buffer[80];
        sprintf(buffer, "wolfSSL Leaving %s, return %d", msg, ret);
        wolfssl_log(LEAVE_LOG , buffer);
    }
}
#endif


void WOLFSSL_ERROR(int error)
{
	if (loggingEnabled) {
		char buffer[80];
		sprintf(buffer, "wolfSSL error occured, error = %d", error);
		wolfssl_log(ERROR_LOG , buffer);
	}
}

void wolfSslDebug(char *format, ...)
{
	static char debugStr[1024];
#if 1
	va_list marker;

	va_start( marker, format );     /* Initialize variable arguments. */
	memset(debugStr, 0, sizeof(debugStr));

	/* vsprintf : param of va_list; sprintf : param of varied params such as 'format ...' */
	vsprintf(debugStr, format, marker);
	
	va_end( marker);
#else
	SNPRINTF(debugStr, sizeof(debugStr), format, __VA_ARGS__ );
#endif
	printf(debugStr );
}

#endif  /* DEBUG_WOLFSSL */

