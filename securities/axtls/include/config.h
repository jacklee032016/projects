/*
* create this file from source code and win32Config. Zhijie Li Nov.12.2015
*/
#ifndef	__CONFIG_H__
#define	__CONFIG_H__

#define	CONFIG_SSL_FULL_MODE


/*****     SSL library          ********/
#define	CONFIG_SSL_CTX_MUTEXING
#define	CONFIG_SSL_HAS_PEM
#define	CONFIG_DEBUG

#define	CERT_KEY		"1024"
#define	CERT_NAME		"ecpServer"

/***  defined by myself ****/
#define	CERT_HOME_DIR								"data\\certs\\tests\\"

#define	CONFIG_SSL_PRIVATE_KEY_PASSWORD		"abcd"
#define	CONFIG_SSL_PRIVATE_KEY_LOCATION			CERT_HOME_DIR CERT_NAME"."CERT_KEY".key.pem"
#if 0
#define	CONFIG_SSL_GENERATE_X509_CERT
#define	CONFIG_WIN32_USE_CRYPTO_LIB
#else
//#define	CONFIG_SSL_X509_CERT_LOCATION			CERT_HOME_DIR CERT_NAME"."CERT_KEY".cer"
#define	CONFIG_SSL_X509_CERT_LOCATION			CERT_HOME_DIR CERT_NAME"."CERT_KEY".x509.pem"
#endif

#define	CONFIG_SSL_MAX_CERTS			12

#define	CONFIG_SSL_EXPIRY_TIME		24
#define	CONFIG_X509_MAX_CA_CERTS	4

/*
CONFIG_SSL_USE_DEFAULT_KEY=y
*/




#define	CONFIG_SSL_X509_COMMON_NAME				"Zhijie"
#define	CONFIG_SSL_X509_ORGANIZATION_NAME			"Office"
#define	CONFIG_SSL_X509_ORGANIZATION_UNIT_NAME	"tech"


/*****     HTTP Server          ********/
#define	CONFIG_HTTP_PORT								80
#define	CONFIG_HTTP_HTTPS_PORT						443
#define	CONFIG_HTTP_SESSION_CACHE_SIZE				5

#define	CONFIG_HTTP_WEBROOT							"www"	/* root directory of www service */
#define	CONFIG_HTTP_TIMEOUT							300

#define	CONFIG_HTTP_DIRECTORIES

#define	CONFIG_HTTP_VERBOSE


#define	TRACE()		printf(__FILE__"."__FUNCTION__"()--Line %d\n", __LINE__)

#ifdef  _DEBUG
#define DISPLAY_BYTES(ssl, data, size, format, ...)	\
	{if (IS_SET_SSL_FLAG(SSL_DISPLAY_BYTES)) { \
		if(data!=NULL){print_blob(data, size, format, ##__VA_ARGS__);} }}

#define	AX_DEBUG( format ,...) \
			{char str[10240];  \
				SPRINTF(str, sizeof(str), format, ##__VA_ARGS__); axPrintf(str); }
/*
			{char str[10240]; SPRINTF(str, sizeof(str), __FILE__"|%s[%d] --", __FUNCTION__, __LINE__); \
				SPRINTF(str+strlen(str), sizeof(str)-strlen(str), format, ##__VA_ARGS__); axPrintf(str); }
*/
#define	AX_LOG 		axPrintf

//#warning		"build with DEBUG info" format, ##__VA_ARGS__
#else
#define DISPLAY_BYTES(A,B,C,D,...)

#define	AX_DEBUG			
#define	AX_LOG				printf
#endif

	

#if 1
#define BE64_2_HOST(bigEndian)   \
    ( ( (uint64_t) (bigEndian)[0] << 56 )       \
        | ( (uint64_t) (bigEndian)[1] << 48 )       \
        | ( (uint64_t) (bigEndian)[2] << 40 )       \
        | ( (uint64_t) (bigEndian)[3] << 32 )       \
        | ( (uint64_t) (bigEndian)[4] << 24 )       \
        | ( (uint64_t) (bigEndian)[5] << 16 )       \
        | ( (uint64_t) (bigEndian)[6] <<  8 )       \
        | ( (uint64_t) (bigEndian)[7]       )
        
#else
#define BE64_2_HOST(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 56 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 48 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 40 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 32 );       \
    (b)[(i) + 4] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 5] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 6] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 7] = (unsigned char) ( (n)       );       \
}
#endif

#ifdef	WIN32
#define	SPRINTF(dest, size, ...)		sprintf_s((dest), (size), ##__VA_ARGS__)

#define	SNPRINTF(dest, size, ...)		_snprintf_s(dest, size,  _TRUNCATE, ##__VA_ARGS__)
#define	STRCPY(dest, size, src)		strcpy_s((dest), (size), (src) )
#else
#define	SPRINTF(dest, size, ...)		sprintf((dest),##__VA_ARGS__)

#define	SNPRINTF(dest, size,...)		snprintf((dest), (size), ##__VA_ARGS__)
#define	STRCPY(dest, size, src)		strcpy((dest), (src) )
#endif

#endif

