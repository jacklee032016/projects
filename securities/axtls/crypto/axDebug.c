
#include "compacts.h"

EXP_FUNC void	STDCALL axDebugDump(void *buf, int size)
{
	int i, j;
	unsigned char	*b = (unsigned char *)buf;

	for(i=0; i< size/16; i++)
	{		
		for(j=0;j<16;j++)
		{
//			printf("0x%02x ", b[i*16+j]);
			printf("%02x ", b[i*16+j]);
		}

		printf("\n");
	}
	
	for(i=(i-1)*16+j; i <size; i++)
		printf("%02x ", b[i]);
	printf("\n");
	
}

EXP_FUNC uint64_t STDCALL axBe64ToHost(uint64_t be)
{
	uint64_t ret = 0;
	uint64_t value = be;
	unsigned char	*buf = (unsigned char *)&value;

	ret = (((uint64_t)buf[0])<< 56) | (( (uint64_t)buf[1]) << 48)
	        |( ( (uint64_t)buf[2]) << 40)  | (( (uint64_t)buf[3]) << 32)
	        |( ( (uint64_t)buf[4]) << 24) | (( (uint64_t)buf[5]) << 16) 
	        |( ( (uint64_t)buf[6]) <<  8)   | ( (uint64_t)buf[7]);

	return ret;
}

/* varied arguments, so the "_" is not appended into the function name output of VC */
EXP_FUNC void STDCALL axPrintf(const char *format,...)
{
	static char debugStr[10240];
#if 1
	va_list marker;
	va_start( marker, format );

	/* Initialize variable arguments. */
	memset(debugStr, 0, sizeof(debugStr));

	/* vsprintf : param of va_list; sprintf : param of varied params such as 'format ...' */
	vsprintf(debugStr, format, marker);
	va_end( marker);
#else
	SNPRINTF(debugStr, sizeof(debugStr), format, __VA_ARGS__ );
#endif
	printf(debugStr);

}


