# used to test the differece between YASM and GAS

.section .data
s0:	.asciz	"String returned by assmebly"

# stringLen: .byte .-s0   #	all compiling OK, but no right result
 # for YASM, when link, it complaints that no externel symbol of stringLen found
 # for GAS, it is all OK
 .set stringLen, .-s0 

.section .text

	.global	_main
	.align 32

# test accessing the variable in stack after function has been returned
# It is testfied that stack varible can not be used as return value, even it is OK in some cases
_main:
	pushl	%ebp
	movl	%esp,	%ebp
	
	subl	$stringLen,	%esp	# alocate variable in stack
	movl	$stringLen,	%ecx	# length: counter register
	movl	%esp,	%edi
	movl	$s0,	%esi
	cld		# clear direction flags
	rep movsb	# rep : replicate string operation prefix

	push	%esp
	call	_printf
	pop	%eax
	
	movl	(%esp),	%eax	# return value
	
	movl	%ebp,	%esp
	popl	%ebp
	ret

