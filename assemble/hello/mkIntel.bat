..\yasm.exe -f win32 helloIntel.s
link helloIntel.obj libcmt.lib
helloIntel.exe
echo $?

