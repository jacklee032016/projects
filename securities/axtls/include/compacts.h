
/**
 * Some stuff to minimise the differences between windows and linux/unix
 */

#ifndef __COMPACTS_H__
#define __COMPACTS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#if defined(WIN32)
#include "windows.h"	/*lzj */
typedef UINT8 uint8_t;
typedef INT8 int8_t;
typedef UINT16 uint16_t;
typedef INT16 int16_t;
typedef UINT32 uint32_t;
typedef INT32 int32_t;
typedef UINT64 uint64_t;
typedef INT64 int64_t;
#define	__attribute__(packed)	
#else   /* Not Win32 */

#ifdef CONFIG_PLATFORM_SOLARIS
#include <inttypes.h>
#else
#include <stdint.h>
#include <endian.h>
#endif /* Not Solaris */
#endif

#if defined(WIN32)
#define STDCALL                 __stdcall
#if defined(_DLL) || defined (TLS_SHARED)
#define	EXP_FUNC	__declspec(dllexport) //	__stdcall
#else
#define	EXP_FUNC	__declspec(dllimport) //	__stdcall
#endif
#else
#define STDCALL
#define EXP_FUNC
#endif

#if defined(_WIN32_WCE)
#undef WIN32
#define WIN32
#endif

#ifdef WIN32

/* Windows CE stuff */
#if defined(_WIN32_WCE)
#include <basetsd.h>
#define abort()                 exit(1)
#else
#include <io.h>
#include <process.h>
#include <sys/timeb.h>
#include <fcntl.h>
#endif      /* _WIN32_WCE */

#include <winsock.h>
#include <direct.h>
#undef getpid
#undef open
#undef close
#undef sleep
#undef gettimeofday
#undef dup2
#undef unlink

#define SOCKET_READ(A,B,C)      recv(A,B,C,0)
#define SOCKET_WRITE(A,B,C)     send(A,B,C,0)
#define SOCKET_CLOSE(A)         closesocket(A)
#define srandom(A)              srand(A)
#define random()                rand()
#define getpid()                _getpid()
#define snprintf                _snprintf
#define open(A,B)               _open(A,B)
#define dup2(A,B)               _dup2(A,B)
#define unlink(A)               _unlink(A)
#define close(A)                _close(A)
#define read(A,B,C)             _read(A,B,C)
#define write(A,B,C)            _write(A,B,C)
#define sleep(A)                Sleep(A*1000)
#define usleep(A)               Sleep(A/1000)
#define strdup(A)               _strdup(A)
#define chroot(A)               _chdir(A)
#define chdir(A)                _chdir(A)
#define alloca(A)               _alloca(A)
#ifndef lseek
#define lseek(A,B,C)            _lseek(A,B,C)
#endif

/* This fix gets around a problem where a win32 application on a cygwin xterm
   doesn't display regular output (until a certain buffer limit) - but it works
   fine under a normal DOS window. This is a hack to get around the issue - 
   see http://www.khngai.com/emacs/tty.php  */
#define TTY_FLUSH()             if (!_isatty(_fileno(stdout))) fflush(stdout);

/*
 * automatically build some library dependencies.
 */
#pragma comment(lib, "WS2_32.lib")
#pragma comment(lib, "AdvAPI32.lib")

typedef int socklen_t;

EXP_FUNC void STDCALL gettimeofday(struct timeval* t,void* timezone);
EXP_FUNC int STDCALL strcasecmp(const char *s1, const char *s2);
EXP_FUNC int STDCALL getdomainname(char *buf, int buf_size);

#ifndef be64toh
#define be64toh(x) 	axBe64ToHost(x)
#endif


#else   /* Not Win32 */

#include <unistd.h>
#include <pwd.h>
#include <netdb.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>

#define SOCKET_READ(A,B,C)      read(A,B,C)
#define SOCKET_WRITE(A,B,C)     write(A,B,C)
#define SOCKET_CLOSE(A)         if (A >= 0) close(A)
#define TTY_FLUSH()

#ifndef be64toh
#define be64toh(x) __be64_to_cpu(x)
#endif

#endif  /* Not Win32 */

/* some functions to mutate the way these work */
#define malloc(A)       ax_malloc(A)
#ifndef realloc
#define realloc(A,B)    ax_realloc(A,B)
#endif
#define calloc(A,B)     ax_calloc(A,B)

EXP_FUNC void * STDCALL ax_malloc(size_t s);
EXP_FUNC void * STDCALL ax_realloc(void *y, size_t s);
EXP_FUNC void * STDCALL ax_calloc(size_t n, size_t s);
EXP_FUNC int STDCALL ax_open(const char *pathname, int flags); 

#ifdef CONFIG_PLATFORM_LINUX
void exit_now(const char *format, ...) __attribute((noreturn));
#else
void exit_now(const char *format, ...);
#endif

/* Mutexing definitions */
#if defined(CONFIG_SSL_CTX_MUTEXING)
#if defined(WIN32)
#define SSL_CTX_MUTEX_TYPE          HANDLE
#define SSL_CTX_MUTEX_INIT(A)       A=CreateMutex(0, FALSE, 0)
#define SSL_CTX_MUTEX_DESTROY(A)    CloseHandle(A)
#define SSL_CTX_LOCK(A)             WaitForSingleObject(A, INFINITE)
#define SSL_CTX_UNLOCK(A)           ReleaseMutex(A)
#else 
#include <pthread.h>
#define SSL_CTX_MUTEX_TYPE          pthread_mutex_t
#define SSL_CTX_MUTEX_INIT(A)       pthread_mutex_init(&A, NULL)
#define SSL_CTX_MUTEX_DESTROY(A)    pthread_mutex_destroy(&A)
#define SSL_CTX_LOCK(A)             pthread_mutex_lock(&A)
#define SSL_CTX_UNLOCK(A)           pthread_mutex_unlock(&A)
#endif
#else   /* no mutexing */
#define SSL_CTX_MUTEX_INIT(A)
#define SSL_CTX_MUTEX_DESTROY(A)
#define SSL_CTX_LOCK(A)
#define SSL_CTX_UNLOCK(A)
#endif


typedef void (STDCALL *THREAD_FUNC_T)(void *data);


/* a char into a hex number */
#define	CHAR_2_NUM(chr) \
		( (chr) <='9')? (chr-'0'):( (chr)<'a')? (chr-'A'+10):(chr-'a'+10)
		
//		int num = (data[i] <= '9') ? (data[i] - '0') : (data[i] - 'A' + 10);

#define	LITTLE_2_BIG(littleValue) \
		((((littleValue) & 0xff000000) >> 24)|(((littleValue) & 0x00ff0000) >> 8) \
		|(((littleValue) & 0x0000ff00) << 8)| (((littleValue) & 0x000000ff)<<24))

// \
//		
	

#ifdef __cplusplus
}
#endif

#endif

