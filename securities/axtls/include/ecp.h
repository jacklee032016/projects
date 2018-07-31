
#ifndef	__ECP_H__
#define	__ECP_H__

/*
 * The testing of the crypto and ssl stuff goes here. Keeps the individual code
 * modules from being uncluttered with test code.
 */

#include "tls.h"

#define DEFAULT_CERT		CERT_HOME_DIR"axTLS.x509_512.cer"
#define DEFAULT_KEY			CERT_HOME_DIR"axTLS.key_512"     
//#define DEFAULT_SVR_OPTION      SSL_DISPLAY_BYTES|SSL_DISPLAY_STATES
#define DEFAULT_SVR_OPTION      0
//#define DEFAULT_CLNT_OPTION      SSL_DISPLAY_BYTES|SSL_DISPLAY_STATES
#define DEFAULT_CLNT_OPTION     0

/* hack to remove gcc warning */
#define SYSTEM(A)           if (system(A) < 0) printf("system call error\n");

extern	int	g_port;

/* the format of output of Hash/crypto operation is binary number, so it is not associated with the represent of hex digit, 
such as the difference of 0xAA or 0xaa, */
#define	BINARYC_COMPARE(dest, src, size, name )	\
        if (memcmp((dest), (src), (size))){		\
		printf("\tError: %s failed\n", name);		\
        	printf(#dest" is :\n");axDebugDump(dest, size); printf(#src" is :\n");axDebugDump(src, size); goto end;} \
		else{printf("\t\t%s passed\n", name);}
		
//        	printf(#src" is :\n");axDebugDump(src, size); \

#define	TEST_RESULT(res, func)	\
	{if((res)!=0){ printf(#func " failed\n");goto cleanup;}\
	else{printf(#func " passed\n");TTY_FLUSH();} }


#define	TEST_WITH_ARGUMENT(func, value, ret)	\
		printf(#func " is testing.....\n"); TEST_RESULT( (ret)=((func)(value)), func )
        	
#define	TEST_NO_ARGUMENT(func, ret)	\
        	printf(#func " is testing.....\n"); TEST_RESULT( (ret)=((func)()), func )


int testCrypto(void);

#define	TEST_CERT_DIR			"samples\\certs\\"

#define	VALIDATE_CERT_DIR		"data\\certs\\public\\"

#endif

