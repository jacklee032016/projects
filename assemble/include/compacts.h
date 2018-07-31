#ifndef	__COMPACTS_H__
#define	__COMPACTS_H__

 #if defined(__GNUC__) 
#include <unistd.h>
typedef unsigned int			uint32_t;
typedef signed long long		int64_t;
typedef unsigned long long		uint64_t;
		  
typedef	uint64_t				U64;

#define CPUID(func,ax,bx,cx,dx)\
__asm__ __volatile__ ("cpuid":\
 "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));


#define	RDTSC(dwTimerLo, dwTimerHi) \
	asm volatile("rdtsc" \
		:"=a"(dwTimerLo),"=d"(dwTimerHi) /*output*/ \
		:	/*input list */	\
		:"%eax", "%edx");	/* clobber list */


#else 
#if defined(_MSC_VER)
#include <intrin.h>
typedef	unsigned __int64		U64;

/* intinsic functions are functions from compiler, not from library such as C 
* https://msdn.microsoft.com/en-us/library/26td21ds.aspx
*/
#pragma intrinsic(__rdtsc)

#define	RDTSC(dwTimerLo, dwTimerHi) \
	__asm{rdtsc	\
		mov dwTimerLo, eax	\
		mov dwTimerHi, edx}

#endif
#endif


#endif

