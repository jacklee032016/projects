.file "iftest1.s"

.section .data

.if CHINESE

//.equ CN,1 #equ Cn,"您好！"会出错，还不认字符串也不能认浮点数形式

CN_say: .string "您好，欢迎您"

//.set US,1
.else
CN_say: .string "Hello,Welcome to you !"

.endif


.text

.global _main

_main:
	pushl %ebp

	movl %esp,%ebp

	andl $-16,%esp

	subl $32,%esp


	movl $CN_say,(%esp)

	call _printf

	leave
	ret

# as iftest1.s -o iftest1.o -gstabs
# ld -o iftest1.exe iftest1.o -Lf:/perqu/cframIde/minGW/lib –lcrtdll

