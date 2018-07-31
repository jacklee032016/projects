    .file "func.s"
    .arch generic64
    .code64

.bss
	flt_one:    .tfloat 0x0
	.align 16
	.equ BSS_SIZE,.-.bss

.data
	oka:	.long 0xAABBCCDD
	    .word 0xEEFF
	    .quad 0x0011223344556677
    .global as_pi80
as_pi80:
    .tfloat  0f3.14159265358979323846
    .align 16
    .size as_pi80,.-as_pi80

.text
   .align 16
bss_start:
   .long .bss
bss_size:
   .long BSS_SIZE
data_start:
   .long .data
text_start:
   .long .text
   .global _start
   .type _start,@function
_start:
    nop
    fwait
    fldpi
    mov oka,%rax
    mov .bss,%rax
    mov .text,%rax
    ret
    nop
    nop
    .size _start,.-_start
    .end
    
