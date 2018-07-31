	.file "generic.s"
# the bss section is usually first
# uninitialized variables
	.bss
	.equ START_NUM 3096 # define a constant, no allocation
	.comm z:4,4 # define symbol z, 4 bytes, aligned on 4 boundry, and global.
a:	.long         # define symbol a to be a long, but not initialized

# the data section is next
# initialized variables
	.data
x:	.byte 128 # one byte (char), initialize to 128
y:	.long 2,4,6 # three longs, initialized to 2,4,6 respectively.
          #  the symbol y only addresses the first definition (2).

msg:	.ascii "Hello" # sequential initialized bytes
msg1:	.asciz "Hello, World" # string of initialized bytes
                           # zero terminated, so +1 in size.
	.global w    # declare w to be a global declared in another source file
                     # (because it is not declared within this source file)
                     # technically not necessary, but prevents a redefinition
                     # of a global w within the source file.
# The text section contains the code, and is
# usually the entry point. The default entry symbol is usually _start
	.text
_start:
	nop
	ret
# No more assembly past .end
	.end