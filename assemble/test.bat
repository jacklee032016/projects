
@echo off
rem ..\yasm.exe -fwin32 h.asm 
rem link /PDBSTRIPPED:as.pdb /MANIFEST:NO h.obj libcmt.lib

WIN7_DEBUG\first.exe
echo return code is : %ERRORLEVEL%

