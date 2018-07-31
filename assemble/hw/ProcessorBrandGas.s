
.section .data

s0 : .asciz "Processor Brand String: %.48s\n"
err : .asciz "Feature unsupported.\n"

.section .text

.global _main
#.type _main,@function
.align 32
_main:
	pushl	%ebp
	movl	%esp,	%ebp
	subl	$48,	%esp
	pushl	%ebx
	
	movl	$0x80000000,	%eax
	cpuid
	
	cmpl	$0x80000004,	%eax
	jl	error
	
	movl	$0x80000002,	%esi
	movl	%esp,	%edi

.align 16
get_brand:
	movl	%esi,	%eax
	cpuid
	
	movl	%eax,	(%edi)
	movl	%ebx,	4(%edi)
	movl	%ecx,	8(%edi)
	movl	%edx,	12(%edi)
	
	addl	$1,	%esi
	addl	$16,	%edi
	cmpl	$0x80000004,	%esi
	jle	get_brand

print_brand:
	movl	$s0,	%edi
	movl	%esp,	%esi
;	xorb	%al,	%al
	pushl	%esi
	pushl	%edi
	call	_printf
	popl	%edi
	popl	%esi
	
	jmp	end

.align 16
error:
	movl	$err,	%edi
;	xorb	%al,	%al
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

