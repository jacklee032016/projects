    .file "func.s"
    .align 16
    .bss
noinit:
    .tfloat
    .align 16
    .size noinit, .-noinit
    .data
    .global as_pi80
as_pi80:
    .tfloat  0f3.14159265358979323846
    .align 16
    .size as_pi80,.-as_pi80
as_sqrt2:
    .tfloat  0f1.41421356237309504880
    .align 16
co_sqrt2:
    .tfloat 0f0
    .align 16
   .text
   .global get_pi80
   .type get_pi80,@function
get_pi80:
    fwait
    fld1
    fld1
    faddp %st,%st(1)
    fsqrt
    fstpt co_sqrt2
    fldpi
    ret
    .size get_pi80,.-get_pi80
