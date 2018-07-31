.section .data
s0:	.asciz	"String returned by assmebly"

.if	0
stringLen: .byte .   #	.byte 1	# symbol defination
#	.set	stringLen, $endS0-$s0 # set the value of symbol
#	.equ stringLen, 20 #endS0-s0	# set value to a symbol
#	.equ stringLen,.-.data
.else
 	.set	stringLen, .-s0 	# no symbol is defined, and stringLen in code is replaced by its value
# 	.equ	stringLen, 20	# no symbol is defined, and stringLen in code is replaced by its value
# 	stringLen = 20		# stringLen as a symbol, which is not replaced in code segment
.endif
# s1:	.asciz	


.text
	.align	32

// comment char ';' can not used after statement
	.global _cpuString	# 1: declared as global, so it can be called by others
	.global _getInt
	.global _getString
	.global	_getStackString

# test accessing the variable in stack after function has been returned
# It is testfied that stack varible can not be used as return value, even it is OK in some cases
_getStackString:
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


# a string pointer is passed as argument, so string are written to this pointer which allocated by caller
_cpuString:
	pushl	%esp
	pushl	%ebx
	pushl	%edx
	pushl	%ecx

//	subl	$16,%esp

	xorl	%eax,	%eax
	cpuid

	movl	4(%esp),	%eax
	movl	%ebx, 		0(%eax)
	movl	%edx, 		4(%eax)
	movl	%ecx, 		8(%eax)

//	movl	(%eax),		%eax

	popl		%ecx
	popl		%edx
	popl		%ebx
	popl		%esp
	
	ret	# 2: statement of ret is mandatory for a procedure


# return data of values type by eax
  _getInt:
	pushl	%ebp
	pushl	%esp

	movl	$34, %eax
	
	popl		%esp
	popl		%ebp
	
	ret

# return a pointer which is allocated by callee	
  _getString:
	pushl	%ebp
	pushl	%esp

	movl	$s0, %eax
	
	popl		%esp
	popl		%ebp
	
	ret


