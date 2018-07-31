/*
* Commnd Header for SSL/TLS/DTLS library, based on crypto library
*/

#ifndef	__CMN_SSL_H__
#define	__CMN_SSL_H__


#include "cmnCrypto.h"

#ifdef HAVE_ERRNO_H
    #include <errno.h>
#endif

typedef byte word24[3];

/* used by ssl.c too */
static INLINE void c32to24(word32 in, word24 out)
{
    out[0] = (in >> 16) & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] =  in & 0xff;
}

/* convert 32 bit integer to opaque */
static INLINE void c32toa(word32 u32, byte* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
}


#ifdef WOLFSSL_DTLS

static INLINE void c32to48(word32 in, byte out[6])
{
    out[0] = 0;
    out[1] = 0;
    out[2] = (in >> 24) & 0xff;
    out[3] = (in >> 16) & 0xff;
    out[4] = (in >>  8) & 0xff;
    out[5] =  in & 0xff;
}

#endif /* WOLFSSL_DTLS */


/* convert 16 bit integer to opaque */
static INLINE void c16toa(word16 u16, byte* c)
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] =  u16 & 0xff;
}

/* convert a 24 bit integer into a 32 bit one */
static INLINE void c24to32(const word24 u24, word32* u32)
{
    *u32 = (u24[0] << 16) | (u24[1] << 8) | u24[2];
}


/* convert opaque to 16 bit integer */
static INLINE void ato16(const byte* c, word16* u16)
{
    *u16 = (word16) ((c[0] << 8) | (c[1]));
}


#if defined(WOLFSSL_DTLS) || defined(HAVE_SESSION_TICKET)

/* convert opaque to 32 bit integer */
static INLINE void ato32(const byte* c, word32* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}

#endif /* WOLFSSL_DTLS */

#if !defined(NO_CERTS) || !defined(NO_SESSION_CACHE)

/* Make a work from the front of random hash */
static INLINE word32 MakeWordFromHash(const byte* hashID)
{
	return (hashID[0] << 24) | (hashID[1] << 16) | (hashID[2] <<  8) |hashID[3];
}

#endif /* !NO_CERTS || !NO_SESSION_CACHE */


#ifndef TRUE
    #define TRUE  1
#endif
#ifndef FALSE
    #define FALSE 0
#endif

#ifdef _MSC_VER
    /* disable for while(0) cases at the .c level for now */
    #pragma warning(disable:4127)
#endif

#if defined(WOLFSSL_CALLBACKS) && !defined(LARGE_STATIC_BUFFERS)
    #error \
WOLFSSL_CALLBACKS needs LARGE_STATIC_BUFFERS, please add LARGE_STATIC_BUFFERS
#endif

#if defined(HAVE_SECURE_RENEGOTIATION) && defined(HAVE_RENEGOTIATION_INDICATION)
    #error Cannot use both secure-renegotiation and renegotiation-indication
#endif



typedef enum {
    doProcessInit = 0,
#ifndef NO_WOLFSSL_SERVER
    runProcessOldClientHello,
#endif
    getRecordLayerHeader,
    getData,
    runProcessingOneMessage
} processReply;

#include <wcmHmac.h>

#include <wscError.h>
#include <wscCrl.h>
#include <wssCallbacks.h>
#include <wsiCallbacks.h>
#include <wssSsl.h>
#include <wssProtocols.h>
#include <wsiInternal.h>
#include <wssSslApis.h>
#include <wsiApis.h>



extern	volatile int initRefCount;
extern	wolfSSL_Mutex count_mutex;   /* init ref count mutex */
extern	wolfSSL_Mutex session_mutex;   /* SessionCache mutex */


#endif

