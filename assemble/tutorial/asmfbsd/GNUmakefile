# MBR flags: 0x80 -- try packet interface (also known as EDD or LBA)
BOOT_MBR_FLAGS?=	0x80

ORG=	0x600

CPPFLAGS=
ASFLAGS=-Wa,--defsym -Wa,"FLAGS=${BOOT_MBR_FLAGS}" -Wa,-a
LDFLAGS=-e start -Ttext ${ORG} -Wl,-N,-S,--oformat,binary -nostdlib -nodefaultlibs
CC=gcc
CPP=${CC} -E
OBJDUMP=objdump
HEXDUMP=hexdump

all:mbr

mbr:mbr.o
	$(CC) $(LDFLAGS) -o $@ $^

%.s:%.sx
	${CPP} ${CPPFLAGS} -o $@ $^

%.o:%.s
	${CC} -c ${ASFLAGS} -o $@ $^ > mbr.list.txt

diss: mbr
	${OBJDUMP} -D -b binary -mi8086 --show-raw-insn --stop-address=0xB8 $<
	${HEXDUMP} -C -n 261 -s 0xB9  $<
	${HEXDUMP} -C -s 0x1fe -n 2 $<

clean:
	rm -f *.o *~ mbr mbr.list.txt

.SUFFIXES:
