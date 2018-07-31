.section .data
s0:	.asciz	"Largest basic function number supported: %i\n"
s1: 	.asciz	"Vendor ID: %.12s\n"

.text
	.align	32
	.global _main
#  .intel_syntax

_main:
	pushl	%ebp
        pushl   %ebx
	movl	%esp,%ebp
	subl	$16,%esp

	xorl	%eax,%eax
	cpuid

	movl	%ebx,0(%esp)
	movl	%edx,4(%esp)
	movl	%ecx,8(%esp)

	pushl	%eax
	pushl	$s0
	call	_printf
	popl	%eax
	popl	%eax

//	movq	$s1,%edi
//	movq	%esp,%esi
//	xorb	%al,%al
	push	%esp
	pushl	$s1
	call	_printf
	popl	%eax
	popl	%eax
	


	movl	%ebp, %esp
	popl	%ebx
	popl	%ebp
	
	mov $34,    %eax; 
	ret
  
