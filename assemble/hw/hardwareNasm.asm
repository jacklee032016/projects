    extern  _printf

section .data
	s0 	DB	"Largest basic function number supported: %i\n", 0
	s1	DB	"Vendor ID: %.12s\n", 0


section	.text
	global	_main

;	.align	32
_main:
	push	ebp
        push   	ebx
	mov	ebp, esp
	sub	esp, 16

	xor	eax,eax
	cpuid

	mov	[esp], ebx
	mov	[esp+4], edx
	mov	[esp+8], ecx

	mov	eax,s0
	push	esp
	push	eax
	call	_printf
	pop	eax
	pop	eax
	
	mov	eax,s1
	push	esp
	push	eax
	call	_printf
	pop	eax
	pop	eax

	mov	ebp, esp
	pop	ebx
	pop	ebp
	
;	add     esp, 4
	
	ret

