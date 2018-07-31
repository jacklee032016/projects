
// processor: x86, x64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hdAsm.h"

 #if defined(__GNUC__) 


int Check_CPU_support_AES()
{
	unsigned int a,b,c,d;
	CPUID(1, a,b,c,d);
	return c;
}

#endif


int aesniSupport( )
{
	static int done = 0;
	static unsigned int c = 0, b =0, d= 0;
	unsigned char str[13];
	memset(str, 0, sizeof(str));

	if( ! done )
	{
#if defined (__GNUC__)
#if 1
		asm volatile( "movl  $1, %%eax   \n\t"
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
;			XOR eax, eax
			mov	eax,	1	
			cpuid
			mov dword ptr c, ecx
		}
#endif
#endif
		done = 1;
	}

	return( ( c & 0x2000000 ) != 0 );
}



int main()
{
	U64 i =0,j=0;
	char	*str = NULL;
	char		cpuInfo[20];
	int 	a = 1, b=2, c= 3;
	
#if defined(_MSC_VER)
//	i = __rdtsc();
#endif
	memset(cpuInfo, 0, 20);

	j = cpuInfoRdtsc();
	printf("%I64d (%I64d) ticks\n", i, j);


	printf("set Parameter to assembly...\n");
	setParamsValues(a, b, c);

	printf("set Parameter Pointer to assembly...\n");
	setParamsPointers( &a, &b,  &c);
	printf("After modified:%d\t%d\t%d\n", a, b, c);

	printf("CPU ID \t:%s\n", cpuId());
//	printf("Frequency \t:%d (%f)\n", CalculateCPUSpeed(), ProcSpeedCalc());
	printf("Integer\t:%d\n", getInt());
	printf("String\t:'%s'\n", getString());
	
	printf("CPU ID String\t:\n");
	str = cpuString(cpuInfo);
	printf("\t:%s(%s)\n", str, cpuInfo );
	printf("CPU Brand:%s\n", cpuBrand());
	printf("AES Support \t:%s\n", (aesniSupport()==0)? "No":"Yes");

	if (0 == check_for_intel_sha_extensions()) {
		printf("Intel SHA Extensions are not enabled on this processor\n");
		return 1;
	}
	else
		printf("Intel SHA Extensions Enabled!\n");
	
	printf("Stack String\t:'%s'\n", getStackString() );


	return 0;
}

