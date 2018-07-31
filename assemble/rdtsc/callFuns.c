
#include <stdio.h>

char format[] = "\t\tTest \"%s\"!\n";
char world[] = "Hello world";

int main( void )
{
	printf("test....\n");
#if 0	
	__asm
	{
		mov  eax, offset world
		push eax
		mov  eax, offset format
		push eax

		call printf
		
		//clean up the stack so that main can exit cleanly
		//use the unused register ebx to do the cleanup
//    		add     esp, 4
//		pop  ebx
		pop  ebx
		pop  ebx
	}
#endif	
	printf("End!\n");

	return 0;
}

