.section .data
A:	.byte	12
D:	.asciz  "Test String %s"
E:	.asciz	"Hello"
	
.section .text
	.global _main
#  .intel_syntax

/*
; NASM syntax #$12 
section .text
	global _main
*/
_main:
#	mov	(D), %eax
	pushl	$E	# second argument
	pushl	$D	# first argument
#	xor	al,al
	call	_printf
	popl	%eax
	popl	%eax
	
	mov $34,    %eax; 
	ret
  
