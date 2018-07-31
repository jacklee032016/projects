
ASM=h

../yasm.exe -fwin32 h.asm 
gcc -v h.obj -o h2.exe
./h2.exe
