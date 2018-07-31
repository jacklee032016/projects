AS=as
ASFLAGS=-g -O0 -Wa,-a
CC=gcc
CFLAGS=-g -O0 -fverbose-asm
CPP=$(CC) -E
CPPFLAGS=
LDFLAGS=
RM=rm
OBJDUMP=objdump
READELF=readelf
GDB=gdb

all:exmpl

exmpl:main.o func.o
	$(CC) $(LDFLAGS) -o $@ $^

main.i:main.c
main.s:main.i
main.o:main.s

%.i:%.c
	$(CPP) $(CPPFLAGS) -o $@ $^

%.s:%.i
	$(CC) -S $(CFLAGS) -o $@ $^

%.o:%.s
	$(CC) $(ASFLAGS) -c -o $@ $^

dump-%:%
	$(OBJDUMP) -t -S -l -d $< | more

elf-%:%
	$(READELF) -a $<

debug:exmpl
	$(GDB) $<

clean:
	$(RM) -f *.o *~ main.s *.i exmpl

.PRECIOUS: %.i %.s
.SECONDARY: %.i %.s
.SUFFIIXES:
.PHONEY:dump-% elf-% debug clean
