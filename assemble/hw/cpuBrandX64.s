
.section .data

.set WIN64,1

s0 : .asciz "Processor Brand String: %s\n"
err : .asciz "Feature unsupported.\n"
status : .asciz "Running...\n"

.section .text

.global main
//.type main,@function
.align 32
main:
	pushq	%rbp
	movq	%rsp,	%rbp
	subq	$16,	%rsp
	pushq	%rbx
	

	movq	$status,	%rcx
	call	printf

	movl	$0x80000000,	%eax
	cpuid
	
	cmpl	$0x80000004,	%eax
	jl	error
	
	movl	$0x80000002,	%esi
	movq	%rsp,	%rdi

.align 16
get_brand:
	movl	%esi,	%eax
//	xorl	%eax,	%eax
	cpuid
	
	movl	%eax,	(%edi)
	movl	%ebx,	4(%edi)
	movl	%ecx,	8(%edi)
	movl	%edx,	12(%edi)
	
//	addl	$1,	%esi
//	addq	$16,	%rdi
//	cmpl	$0x80000004,	%esi
//	jle	get_brand

print_brand:
//	movq	$status,	%rdx
	movq	%rsp,	%rdx
	movq	$s0,	%rcx
	xorb	%al,	%al
	call	printf
	
	jmp	end

.align 16
error:
	movq	$err,	%rcx
	xorb	%al,	%al
	call	printf

.align 16
end:
	popq	%rbx
	movq	%rbp,	%rsp
	popq	%rbp
	xorl	%eax,	%eax

	movl	$10, %eax
	ret

