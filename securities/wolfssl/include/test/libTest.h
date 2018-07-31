
#ifndef __LIB_TEST_H__
#define __LIB_TEST_H__

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#include "cmnSsl.h"

#pragma once

/************* dependent on OS ******************************/
#ifdef USE_WINDOWS_API 
    #include <winsock2.h>
    #include <process.h>
    #ifdef TEST_IPV6            /* don't require newer SDK for IPV4 */
        #include <ws2tcpip.h>
        #include <wspiapi.h>
    #endif
    #define SOCKET_T		SOCKET
//    #define SNPRINTF		_snprintf
#elif defined(WOLFSSL_MDK_ARM)
    #include <string.h>
#elif defined(WOLFSSL_TIRTOS)
    #include <string.h>
    #include <netdb.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <ti/sysbios/knl/Task.h>
    struct hostent {
    	char *h_name; /* official name of host */
    	char **h_aliases; /* alias list */
    	int h_addrtype; /* host address type */
    	int h_length; /* length of address */
    	char **h_addr_list; /* list of addresses from name server */
    };
    #define SOCKET_T int
#else
    #include <string.h>
    #include <sys/types.h>
#ifndef WOLFSSL_LEANPSK
    #include <unistd.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <pthread.h>
    #include <fcntl.h>
    #ifdef TEST_IPV6
        #include <netdb.h>
    #endif
#endif
    #define SOCKET_T int
    #ifndef SO_NOSIGPIPE
        #include <signal.h>  /* ignore SIGPIPE */
    #endif
//    #define SNPRINTF snprintf
#endif /* USE_WINDOWS_API */



#ifdef TEST_IPV6
    typedef struct sockaddr_in6 SOCKADDR_IN_T;
    #define AF_INET_V    AF_INET6
#else
    typedef struct sockaddr_in  SOCKADDR_IN_T;
    #define AF_INET_V    AF_INET
#endif

#ifdef USE_WINDOWS_API 
    #define CloseSocket(s) closesocket(s)
    #define StartTCP() { WSADATA wsd; WSAStartup(0x0002, &wsd); }
#elif defined(WOLFSSL_MDK_ARM)
    #define CloseSocket(s) closesocket(s)
    #define StartTCP() 
#else
    #define CloseSocket(s) close(s)
    #define StartTCP() 
#endif


#if defined(__MACH__) || defined(USE_WINDOWS_API)
    #ifndef _SOCKLEN_T
        typedef int socklen_t;
    #endif
#endif


#ifdef SINGLE_THREADED
	typedef unsigned int  THREAD_RETURN;
	typedef void*         THREAD_TYPE;
	#define WOLFSSL_THREAD
#else
	#if defined(_POSIX_THREADS) && !defined(__MINGW32__)
		typedef void*         THREAD_RETURN;
		typedef pthread_t     THREAD_TYPE;
		#define WOLFSSL_THREAD
		#define INFINITE -1
		#define WAIT_OBJECT_0 0L
	#elif defined(WOLFSSL_MDK_ARM)
		typedef unsigned int  THREAD_RETURN;
		typedef int           THREAD_TYPE;
		#define WOLFSSL_THREAD
	#elif defined(WOLFSSL_TIRTOS)
		typedef void          THREAD_RETURN;
		typedef Task_Handle   THREAD_TYPE;
		#define WOLFSSL_THREAD
	#else
		/* default, in Windows test environment */
		typedef unsigned int	THREAD_RETURN;
		typedef intptr_t		THREAD_TYPE;
		#define WOLFSSL_THREAD __stdcall
	#endif
#endif



#if defined(WOLFSSL_MDK_ARM)
        #include <stdio.h>
        #include <string.h>

        #if defined(WOLFSSL_MDK5)
            #include "cmsis_os.h"
            #include "rl_fs.h" 
            #include "rl_net.h" 
        #else
            #include "rtl.h"
        #endif

        #include "wolfssl_MDK_ARM.h"
#endif

#if !defined(WOLFSSL_TRACK_MEMORY) && !defined(NO_MAIN_DRIVER)
    /* in case memory tracker wants stats */
    #define WOLFSSL_TRACK_MEMORY
#endif



#ifdef _MSC_VER
    /* disable conversion warning */
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable:4244 4996)
#endif


/* error for network connection */
enum {
	TEST_SELECT_FAIL,
	TEST_TIMEOUT,
	TEST_RECV_READY,
	TEST_ERROR_READY
};

#define SERVER_DEFAULT_VERSION			3
#define SERVER_DTLS_DEFAULT_VERSION		(-2)
#define SERVER_INVALID_VERSION				(-99)

#define CLIENT_DEFAULT_VERSION			3
#define CLIENT_DTLS_DEFAULT_VERSION		(-2)
#define CLIENT_INVALID_VERSION				(-99)

#if !defined(NO_FILESYSTEM) && defined(WOLFSSL_MAX_STRENGTH)
#define DEFAULT_MIN_DHKEY_BITS			2048
#else
#define DEFAULT_MIN_DHKEY_BITS			1024
#endif

/* error code for usage */
#define MY_EX_USAGE 2

typedef struct tcp_ready
{
	word16 ready;              /* predicate */
	word16 port;
#if defined(_POSIX_THREADS) && !defined(__MINGW32__)
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
#endif
} tcp_ready;    


/* General big buffer size for many tests. */ 
#define FOURK_BUF 4096


typedef struct testVector
{
	const char	*input;
	const char	*output;
	size_t		inLen;
	size_t		outLen;
} testVector;


#define	TEST_FUNCTION(funtion, name, ret )	\
	{printf(#name" test ===========\n" ); \
	if ( (ret = (funtion)()) != 0)		\
        {return err_sys("==========="#name"      test failed!\n\n" );} \
    else	\
	{printf("===========" #name"      test passed!\n\n"); } }

#define chSTR(x)		#x



typedef WOLFSSL_METHOD* (*method_provider)(void);
typedef void (*ctx_callback)(WOLFSSL_CTX* ctx);
typedef void (*ssl_callback)(WOLFSSL* ssl);

typedef struct callback_functions
{
	method_provider	method;
	ctx_callback		ctx_ready;
	ssl_callback		ssl_ready;
	ssl_callback		on_result;
} callback_functions;


typedef struct func_args
{
	int				argc;
	char				** argv;
	int				return_code;
	
	tcp_ready		*signal;
	callback_functions	*callbacks;
} func_args;

/* HPUX doesn't use socklent_t for third parameter to accept, unless
   _XOPEN_SOURCE_EXTENDED is defined */
#if !defined(__hpux__) && !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_IAR_ARM)
    typedef socklen_t* ACCEPT_THIRD_T;
#else
    #if defined _XOPEN_SOURCE_EXTENDED
        typedef socklen_t* ACCEPT_THIRD_T;
    #else
        typedef int*       ACCEPT_THIRD_T;
    #endif
#endif

#ifndef MAX_PATH
    #define MAX_PATH 256
#endif


/* all certs relative to wolfSSL home directory now */
#define caCert     "./certs/ca-cert.pem"
#define eccCert    "./certs/server-ecc.pem"
#define eccKey     "./certs/ecc-key.pem"
#define svrCert    "./certs/server-cert.pem"
#define svrKey     "./certs/server-key.pem"
#define cliCert    "./certs/client-cert.pem"
#define cliKey     "./certs/client-key.pem"
#define ntruCert   "./certs/ntru-cert.pem"
#define ntruKey    "./certs/ntru-key.raw"
#define dhParam    "./certs/dh2048.pem"
#define cliEccKey  "./certs/ecc-client-key.pem"
#define cliEccCert "./certs/client-ecc-cert.pem"
#define crlPemDir  "./certs/crl"

extern int   myoptind;
extern char* myoptarg;
extern const char* const wolfSSLIP;
extern const word16  wolfSSLPort;


void build_addr(SOCKADDR_IN_T* addr, const char* peer, word16 port, int udp);
void tcp_socket(SOCKET_T* sockfd, int udp);
void tcp_connect(SOCKET_T* sockfd, const char* ip, word16 port, int udp);
void udp_connect(SOCKET_T* sockfd, void* addr, int addrSz);
int tcp_select(SOCKET_T socketfd, int to_sec);
void tcp_listen(SOCKET_T* sockfd, word16* port, int useAnyAddr, int udp);
int udp_read_connect(SOCKET_T sockfd);
int udp_read_connect(SOCKET_T sockfd);
void tcp_accept(SOCKET_T* sockfd, SOCKET_T* clientfd,
                              func_args* args, word16 port, int useAnyAddr,
                              int udp, int ready_file);
void tcp_set_nonblocking(SOCKET_T* sockfd);


int mygetopt(int argc, char** argv, const char* optstring);
void err_sys(const char* fmt, ...);

double current_time();



unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len);
unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
        unsigned char* key, unsigned int key_max_len);


void InitMemoryTracker(void);
void ShowMemoryTracker(void);

void StackTrap(void);

int myDateCb(int preverify, WOLFSSL_X509_STORE_CTX* store);
void showPeer(WOLFSSL* ssl);


void ChangeDirBack(int x);
int CurrentDir(const char* str);


#endif

