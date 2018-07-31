.section .data

info : .ascii "L2 Cache Size : %u KB\nLine size : %u bytes\n"
.asciz "Associativity : %02xh\n"
err : .asciz "Feature unsupported.\n"

.section .text

.global _main
#.type _main,@function
.align 32
_main:
	pushl	%ebp
	movl	%esp,	%ebp
	pushl	%ebx
	
	movl	$0x80000000,	%eax
	cpuid
	
	cmpl	$0x80000006,	%eax
	jl	error
	
	movl	$0x80000006,	%eax
	cpuid
	
	movl	%ecx,	%eax
	
	movl	%eax,	%edx
	andl	$0xff,	%edx	# lowest 8 bits, cache line size
	
	movl	%eax,	%ecx
	shrl	$12,	%ecx
	andl	$0xf,	%ecx	# bit 12~15, L2 Associativity field
	
	movl	%eax,	%esi
	shrl	$16,	%esi
	andl	$0xffff,%esi	# bit 16~31, cache size 1k unit
	
	movl	$info,	%edi

	pushl	%ecx
	pushl	%edx
	pushl	%esi
	pushl	%edi
//	xorb	%al,	%al
	call	_printf
//	addl	$16,	%ebp
	popl	%edi
	popl	%esi
	popl	%edx
	popl	%ecx
	
	jmp end
	
.align 16
error:
	movl	$err,	%edi
//	xorb	%al,	%al
	pushl	%edi
	call	_printf
	popl	%edi

.align 16
end:
	popl	%ebx
	movl	%ebp,	%esp
	popl	%ebp
	xorl	%eax,	%eax
	
	ret

