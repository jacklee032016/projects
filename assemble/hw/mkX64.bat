set ASM=cpuBrandX64
del %ASM%.exe
del %ASM%.obj
yasm.exe -f x64 -p gas -D WIN64 -l %ASM%.list %ASM%.s
link /subsystem:console /LARGEADDRESSAWARE:NO %ASM%.obj libcmt.lib 
%ASM%.exe
echo return code is :  %ERRORLEVEL%

