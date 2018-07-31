AS=as
DEBUGFLAGS=-g
ASFLAGS=-O0 -Wa,-a
CC=gcc
CFLAGS=-O0 -fverbose-asm
CPP=$(CC) -E
CPPFLAGS=
LDFLAGS=-Wl,--oformat=binary -nostdlib -nodefaultlibs -Wl,-M -Ttext 0x7000 -Tdata 0x8000 -Tbss 0x9000
RM=rm
OBJDUMP=objdump
HEXDUMP=hexdump

all:exmpl

exmpl:func.o
	${CC} ${LDFLAGS} -o $@ $^ > exmpl_lst.txt

%.o:%.s
	${CC} ${ASFLAGS} -c -o $@ $^

dump-%:%
	${HEXDUMP} -e '1/4 "%x\n"' -n 16 $<
	${OBJDUMP} -D -m i386:x86-64 -b binary  --start-address=0x10 --stop-address=0x3F $< | more

clean:
	${RM} -f *.o *~ main.s *.i exmpl exmpl_lst.txt

