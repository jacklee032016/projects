[bits 32]
[CPU intelnop]


align 16
global _do_rdtsc
_do_rdtsc:

	rdtsc
	ret
