
.section .data


ss1 : .asciz "Processor Brand String: %.48s\n"
err : .asciz "Feature unsupported.\n"
status : .asciz "Running...\n"

.section .text

	.global _cpuBrand
//.type _cpuBrand,@function
.align 32
_cpuBrand:
	pushl	%ebp
	movl	%esp,	%ebp
	subl	$48,	%esp
//	pushl	%ebx
	

	pushl	$status
	call	_printf
	popl	%eax

	movl	$0x80000000,	%eax
	cpuid
	
	cmpl	$0x80000004,	%eax
	jl	error
	
	movl	$0x80000002,	%esi
	movl	%esp,	%edi

.align 16
get_brand:
	movl	%esi,	%eax
//	xorl	%eax,	%eax
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
//	pushl	$status
	pushl	%esp
	pushl	$ss1
	call	_printf
	popl	%ebx
	popl	%ebx
	
	jmp	end

.align 16
error:
	push	$err
//	xorb	%al,	%al
	call	_printf
	popl	%eax

.align 16
end:
	movl	%esp,	%eax
	popl	%ebx
	movl	%ebp,	%esp
	popl	%ebp

	ret

