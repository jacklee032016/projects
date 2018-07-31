
gcc testRdtsc.c -o test.exe

as helloWorld.asm -o hello.o

ld hello.o -o hello.exe

./test.exe
./hello.exe

gcc -c hello.asm -o hello.o && ld hello.o && ./a.out
