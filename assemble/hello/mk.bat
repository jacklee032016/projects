
set ASM=testSymbol

del %ASM%.exe
del %ASM%.obj
rem 
yasm.exe -f win32 -p gas -D CHINESE=1 -l %ASM%.list %ASM%.s
link /subsystem:console %ASM%.obj libcmt.lib 
%ASM%.exe
echo return code is :  %ERRORLEVEL%
