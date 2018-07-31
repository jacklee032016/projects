
#include "hdAsm.h"

U64 cpuInfoRdtsc( void )
{
 #if defined(__GNUC__) 
	uint64_t ull;
	uint32_t lower = 0, upper = 0;

	asm volatile ("rdtsc": "=a" (lower), "=d" (upper));

	ull = ((uint64_t) upper << 32) + lower;
#else 
#if defined(_MSC_VER)
	unsigned __int64 ull;
	unsigned int lower = 0, upper =0;
	__asm
	{
		rdtsc
		mov dword ptr ull, eax
		mov dword ptr ull+4, edx
		mov dword ptr lower, eax
		mov dword ptr upper, edx
	}
	ull = ((unsigned __int64) upper << 32) + lower;
#endif
#endif
	
	return ull;
}

unsigned char *cpuId(void)
{
	static int done = 0;
	static unsigned int c = 0, b =0, d= 0;
	static unsigned char str[13];
	memset(str, 0, sizeof(str));

	if( ! done )
	{
#if defined (__GNUC__)
#if 1
		asm( "movl  $1, %%eax   \n\t"
		"cpuid             \n\t"
		: "=c" (c)
		:
		: "eax", "ebx", "edx" );
#else
		c = Check_CPU_support_AES();
#endif
#else 
#if defined (_MSC_VER)
		__asm{
			XOR eax, eax
			cpuid
			mov dword ptr c, ecx
			mov dword ptr b, ebx
			mov dword ptr d, edx
		}
#endif
#endif
		done = 1;
	}

	memcpy(str, (unsigned char *)&b, 4);
	memcpy(str+4, (unsigned char *)&d, 4);
	memcpy(str+8, (unsigned char *)&c, 4);
	return str;
}

/* Check the CPUID bit for the availability of the Intel SHA Extensions */
int check_for_intel_sha_extensions()
{
	int a, b, c, d;

	/* Look for CPUID.7.0.EBX[29] 
	* EAX = 7, ECX = 0 */
	a = 7;
	c = 0;

	asm volatile ("cpuid"
	             :"=a"(a), "=b"(b), "=c"(c), "=d"(d)
	             :"a"(a), "c"(c)
	            );

	/* SHA feature bit is EBX[29] */
	return ((b >> 29) & 1);
}


