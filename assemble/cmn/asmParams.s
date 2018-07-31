.section .data
format_str:	.asciz	"\t%d\n"


.text
	.align	32

	.global _setParamsValues

	.global _setParamsPointers
	

// used to test parameters of value type transfered from C/C++
_setParamsValues:
	# caller is responsible for stack operations of parameters, so no push at begin of callee

	# first argument at (%esp)+4; and (%esp) is new top of stacl
	pushl	4(%esp)		# value at 4(%esp) is send as righted parameter of printf
	pushl	$format_str
	call	_printf
	popl	%eax
	popl	%eax

	# second argument
	movl	8(%esp),	%eax	# value at (%esp)+8 is send to eax
	pushl	%eax		
	pushl	$format_str
	call	_printf
	popl	%eax
	popl	%eax

	# third argument
	pushl	12(%esp)
	pushl	$format_str
	call	_printf
	popl	%eax
	popl	%eax


// display a immediate number 
	push	$4
	pushl	$format_str
	call	_printf
	popl	%eax
	popl	%eax

	ret


// used to set parameters value of pointer type transfered from C/C++
_setParamsPointers:
	# caller is responsible for stack operations of parameters, so no push at begin of callee

	movl	8(%esp),	%edx	# address of (%esp)+8 is second argument
	pushl	(%edx)			# second argument is an address, so in-direct address
	pushl	$format_str
	call	_printf
	popl	%ecx
	popl	%ecx

	# second argument
	movl	8(%esp),	%edx	# address of (%esp)+8 is second argument
	movl	(%edx),	%eax	
	addl	$10,	%eax
	movl	%eax,	(%edx)

	ret

