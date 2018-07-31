#ifndef __TIMER_H__
#define __TIMER_H__

#pragma warning (push)
#pragma warning (disable : 4035)	// disable no return value warning

__forceinline  int GetPentiumTimer()
{
	__asm
	{
		xor   eax,eax	          // VC won't realize that eax is modified w/out this
								  //   instruction to modify the val.
								  //   Problem shows up in release mode builds
;		_emit 0x0F		          // Pentium high-freq counter to edx;eax
;		_emit 0x31		          // only care about low 32 bits in eax

		rdtsc
		xor   edx,edx	          // so VC gets that edx is modified
	}
}

#pragma warning (pop)

#endif