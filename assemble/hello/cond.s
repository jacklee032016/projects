.file "iftest1.s"

.section .data

.if CHINESE

//.equ CN,1 #equ Cn,"���ã�"������������ַ���Ҳ�����ϸ�������ʽ

CN_say: .string "���ã���ӭ��"

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
# ld -o iftest1.exe iftest1.o -Lf:/perqu/cframIde/minGW/lib �Clcrtdll

