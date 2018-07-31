# This file is from SDK_HOME/include/Win32.Mak

# Syntax
#
# Build Rules Quick Start
#
#  ---------------------------------------------------------------------------
#   To build:         |  Compiler Options      | Linker options (pick one
#                     |                        | line. con = console,
#                     |                        | gui = GUI, ole = GUI OLE)
#  ---------------------------------------------------------------------------
#  Single threaded    | cdebug cflags cvars    | ldebug guilflags guilibs
#  app with static    |                        | ldebug conlflags conlibs
#  CRT                |                        | ldebug guilflags olelibs
#  ---------------------------------------------------------------------------
#  Multithreaded app  | cdebug cflags cvarsmt  | ldebug guilflags guilibsmt
#  with static CRT    |                        | ldebug conlflags conlibsmt
#                     |                        | ldebug guilflags olelibsmt
#  ---------------------------------------------------------------------------
#  Single or multi-   | cdebug cflags cvarsdll | ldebug guilflags guilibsdll
#  threaded app with  |                        | ldebug conlflags conlibsdll
#  DLL version of CRT |                        | ldebug guilflags olelibsdll
#  (MSVCRT.DLL)       |                        |
#  ---------------------------------------------------------------------------
#  DLL with static    | cdebug cflags cvarsmt  | ldebug dlllflags guilibsmt
#  CRT*               |                        | ldebug dlllflags conlibsmt
#                     |                        | ldebug dlllflags olelibsmt
#  ---------------------------------------------------------------------------
#  DLL with DLL       | cdebug cflags cvarsdll | ldebug dlllflags guilibsdll
#  version of CRT     |                        | ldebug dlllflags conlibsdll
#  (MSVCRT.DLL)       |                        | ldebug dlllflags olelibsdll
#  ---------------------------------------------------------------------------
#
#  * Always make DLLs multithreaded because a DLL has no way to know whether
#    the calling application has multiple threads, and has no way to prevent
#    multithreaded apps from loading it.
#
#  To specify an Intel x86 build that defaults to stdcall, add scall to the
#  list of compiler options.
#
# =========================================================================


# command in nmake: begin with !
# !IF ( "$(CPU)" == "X86" ) || ( "$(CPU)" == "x86" )
# CPU = i386
# !ENDIF # CPU == X86


#
# Common compiler flags:
#   -c   - compile without linking
#   -W3  - Set warning level to level 3    (-W4 for 64-bit compilations)
#   -Zi  - generate debugging information
#   -Od  - disable all optimizations
#   -Ox  - use maximum optimizations
#   -Zd  - generate only public symbols and line numbers for debugging
#   -GS  - enable security checks
#
# i386 specific compiler flags:
#   -Gz  - stdcall   (only if scall is added to makefile's compiler build rules)
#
# -------------------------------------------------------------------------




# system command execute  
# !IF "$(OS)" == "Windows_NT"
# CLEANUP=if exist $(OUTDIR)/$(NULL) rd /s /q $(OUTDIR)
# !ELSE
# CLEANUP=deltree /y $(OUTDIR)
# !ENDIF

# mutiple lines message defined as following
# VC6MSG=This sample only compiles with Microsoft Visual C++ 6.0. \
#       To compile this run vcvars32.bat for Visual C++ 6.0, and setenv.bat in $(MSSDK).


# message when build
# !ifndef Proj
# !     ERROR Component name (Proj) has not been defined.
# !endif


.SUFFIXES: .c .Cpp .Cxx .Obj .Def .Lib .Dll .Exe .Idl .h .Mc .Rc .Res .Exp .Bin .Hpj .Ini .Pdb .Trg .Ocx .Tlb .Res .Srl .Odl

# C Targets
.c{$(ObjDir)\}.Obj:
    $(MkDest)
!if "$(LOG)"=="YES"
    @echo $(CC) $(CL) $(crtflags) $(cDefines) $< $(LogCmd)
!endif
    $(CC) $(CL) $(crtflags) $(cDefines) $< $(LogCmd)

# C++ Targets
.cpp{$(ObjDir)\}.Obj:
    $(MkDest)
!if "$(LOG)"=="YES"
    @echo $(CC) $(CL) $(crtflags) $(cDefines) $< $(LogCmd)
!endif
    $(CC) $(CL) $(crtflags) $(cDefines) $< $(LogCmd)

# C++ Targets
.cxx{$(ObjDir)\}.obj:
    $(MkDest)
!if "$(LOG)"=="YES"
    @echo $(CC) $(CL) $(crtflags) $(cDefines) $< $(LogCmd)
!endif
    $(CC) $(CL) $(crtflags) $(cDefines) $< $(LogCmd)

# Resource Targets from .RC files
{$(ResDir)\}.Rc{$(ObjDir)\}.Res:
    $(MkDest)
!if "$(LOG)"=="YES"
    @echo $(RC) $(RFLAGS) $(ResDir)\$(@B).rc $(LogCmd)
!endif
    $(RC) $(RFLAGS) $(ResDir)\$(@B).rc $(LogCmd)

# Resource Targets from .MC files
.Mc{$(ObjDir)\}.Res:
    $(MkDest)
!if "$(LOG)"=="YES"
    @echo $(MC) $(MFLAGS) $< $(LogCmd)
!endif
    $(MC) $(MFLAGS) $< $(LogCmd)
!if "$(LOG)"=="YES"
    @echo $(RC) $(MRFLAGS) -fo$@ "$(ObjDir)\$(@B).rc" $(LogCmd)
!endif
    $(RC) $(MRFLAGS) -fo$@ "$(ObjDir)\$(@B).rc" $(LogCmd)

# Import Libraries
.Def{$(ObjDir)\}.Lib:
!if "$(LOG)"=="YES"
    @echo $(IMPLIB) -NOLOGO -MACHINE:$(CPU) -DEF:$(@B).DEF -OUT:$@ $(LogCmd)
!endif
    $(IMPLIB) -NOLOGO -MACHINE:$(CPU) -DEF:$(@B).DEF -OUT:$@ $(LogCmd)
    set copycmd=/Y
    xcopy "$@" "$(LibDir)\" $(LogCmd)

.Def{$(ObjDir)\}.Exp:
!if "$(LOG)"=="YES"
    @echo $(IMPLIB) -NOLOGO -MACHINE:$(CPU) -DEF:$(@B).DEF -OUT:"$(@R).Lib" $(LogCmd)
!endif
    $(IMPLIB) -NOLOGO -MACHINE:$(CPU) -DEF:$(@B).DEF -OUT:"$(@R).Lib" $(LogCmd)

# Static Libraries
{$(ObjDir)\}.Obj{$(ObjDir)\}.Lib:
!if "$(LOG)"=="YES"
    @echo $(LIBU) $(LIBFLAGS)  $** $(LogCmd)
!endif
    $(LIBU) $(LIBFLAGS) $** $(LogCmd)
!ifdef USE_EXCHANGE
!if "$(LOG)"=="YES"
    @echo xcopy "$(@R).Lib" "$(LibDir)" $(LogCmd)
!endif
    set copycmd=/Y
    -xcopy "$(@R).Lib" "$(LibDir)\" $(LogCmd)
!endif # USE_EXCHANGE

# DLLs
{$(ObjDir)\}.Obj{$(ObjDir)\}.Dll:
    @echo $** > "$(ObjDir)\objfiles.lst"
    @echo $(LinkLibs) > "$(ObjDir)\libfiles.lst"
!if "$(LOG)"=="YES"
    @echo   $(LINK) $(LFLAGS) $(DLLFLAGS) $(linkflags) "@$(ObjDir)\objfiles.lst" "@$(ObjDir)\libfiles.lst" $(LogCmd)
!endif
    $(LINK) $(LFLAGS) $(DLLFLAGS) $(linkflags) "@$(ObjDir)\objfiles.lst" "@$(ObjDir)\libfiles.lst" $(LogCmd)
!ifdef USE_EXCHANGE
!if "$(LOG)"=="YES"
    @echo xcopy "$(@R).Lib" "$(LibDir)" $(LogCmd)
!endif
    set copycmd=/Y
    -xcopy "$(@R).Lib" "$(LibDir)\" $(LogCmd)
!endif # USE_EXCHANGE

# OCXs
{$(ObjDir)\}.obj{$(ObjDir)\}.Ocx:
    @echo $** > "$(ObjDir)\objfiles.lst"
    @echo $(LinkLibs) > "$(ObjDir)\libfiles.lst"
!if "$(LOG)"=="YES"
    @echo   $(LINK) $(LFLAGS) $(DLLFLAGS) $(linkflags) "@$(ObjDir)\objfiles.lst" "@$(ObjDir)\libfiles.lst" $(LogCmd)
!endif
    $(LINK) $(LFLAGS) $(DLLFLAGS) $(linkflags) "@$(ObjDir)\objfiles.lst" "@$(ObjDir)\libfiles.lst" $(LogCmd)
!ifdef USE_EXCHANGE
!if "$(LOG)"=="YES"
    @echo xcopy "$(@R).Lib" "$(LibDir)" $(LogCmd)
!endif
    set copycmd=/Y
    -xcopy "$(@R).Lib" "$(LibDir)\" $(LogCmd)
!endif # USE_EXCHANGE

# BINs
{$(ObjDir)\}.Obj{$(ObjDir)\}.Bin:
    @echo $(LinkLibs) > "$(ObjDir)\libfiles.lst"
!if "$(LOG)"=="YES"
    @echo $(LINK) $(LFLAGS) $(linkflags) $** "@$(ObjDir)\libfiles.lst" $(LogCmd)
!endif
    $(LINK) $(LFLAGS) $(linkflags) $** "@$(ObjDir)\libfiles.lst" $(LogCmd)

# EXEs
{$(ObjDir)\}.Obj{$(ObjDir)\}.Exe:
    @echo $** > "$(ObjDir)\objfiles.lst"
    @echo $(LinkLibs) > "$(ObjDir)\libfiles.lst"
!if "$(LOG)"=="YES"
    @echo $(LINK) $(LFLAGS) $(linkflags) "@$(ObjDir)\objfiles.lst" "@$(ObjDir)\libfiles.lst" $(LogCmd)
!endif
    $(LINK) $(LFLAGS) $(linkflags) "@$(ObjDir)\objfiles.lst" "@$(ObjDir)\libfiles.lst" $(LogCmd)

# Helpfiles
.Hpj{$(ObjDir)\}.Hlp:
    $(MkDest)
!if "$(LOG)"=="YES"
    @echo  $(HC) $(HFLAGS) $(@B).Hpj
!endif
    $(HC) $(HFLAGS) $(@B).Hpj
!if "$(LOG)"=="YES"
    @echo   xcopy "$(@F)" "$(ObjDir)"
!endif
    set copycmd=/Y
    -xcopy "$(@F)" "$(ObjDir)" $(LogCmd)

# TRGs
{$(ObjDir)\}.Exe{$(ObjDir)\}.Trg:
	$(MkDest)
!if "$(LOG)"=="YES"
     @echo $? /RegServer "$(ObjDir)\regsvr32.Trg" $(LogCmd)
!endif
     @-$? /RegServer $(LogCmd)
     echo regsvr32 exec. time > "$(ObjDir)\regsvr32.Trg" $(LogCmd)

{$(ObjDir)\}.Dll{$(ObjDir)\}.Trg:
	$(MkDest)
!if "$(LOG)"=="YES"
     @echo regsvr32 /s $? regsvr32.trg 
!endif
     @-regsvr32 /s $? $(LogCmd)
     echo regsvr32 exec. time > "$(ObjDir)\regsvr32.Trg"

# .Hs
.Idl{$(ObjDir)\}.H:
    $(MkDest)
!if "$(LOG)"=="YES"
     @echo $(MIDL) /Oicf /out "$(ObjDir)" $** $(LogCmd)
!endif
     $(MIDL) /Oicf /out "$(ObjDir)" $** $(LogCmd)

# .Tlbs
.Odl{$(ObjDir)\}.Tlb:
	$(MkDest)
!if "$(LOG)"=="YES"
    @echo $(MIDL) /nologo /out "$(ObjDir)" $** $(LogCmd)
!endif
    $(MIDL) /nologo /out "$(ObjDir)" $** $(LogCmd)


#---------------------------------------------
# List Output Files
#---------------------------------------------
ListDir:
    dir "$(ObjDir)"

#---------------------------------------------
# Display Output Listing File
#---------------------------------------------
!ifndef ERRVIEW
ERRVIEW=start notepad.Exe
!endif

ListOut:
    $(ERRVIEW) "$(ObjDir)\$(Proj).out"

#---------------------------------------------
# Delete Output Listing File
#---------------------------------------------
DelOut:
    del "$(ObjDir)\$(Proj).out"

#---------------------------------------------
# Clean Output Directories
#---------------------------------------------
clean:
 $(MkDest)
!if "$(OS)" == "Windows_NT"
 -del /q "$(ObjDir)\*.Obj" \
         "$(ObjDir)\*.out" \
         "$(ObjDir)\*.h"   \
         "$(ObjDir)\*.dbg" \
         "$(ObjDir)\*.Lib" \
         "$(ObjDir)\*.Exe" \
         "$(ObjDir)\*.Dll" \
         "$(ObjDir)\*.Map" \
         "$(ObjDir)\*.Res" \
         "$(ObjDir)\*.rc"  \
         "$(ObjDir)\*.bin" \
         "$(ObjDir)\*.lst" \
         "$(ObjDir)\*.blt" \
         "$(ObjDir)\*.hlp" \
         "$(ObjDir)\*.trg" \
         "$(ObjDir)\*.srl" \
         "$(ObjDir)\*.ini" \
         "$(ObjDir)\*.tlb" \
         "$(ObjDir)\*.pdb" \
         "$(ObjDir)\*.exp" >NUL 2>NUL
!else  # Win95 doesn't support "2>" on command line, multiple files on a Del command, or /q
 -erase  "$(ObjDir)\*.Obj" >NUL
 -erase  "$(ObjDir)\*.out" >NUL
 -erase  "$(ObjDir)\*.h"   >NUL
 -erase  "$(ObjDir)\*.dbg" >NUL
 -erase  "$(ObjDir)\*.Lib" >NUL
 -erase  "$(ObjDir)\*.Exe" >NUL
 -erase  "$(ObjDir)\*.Dll" >NUL
 -erase  "$(ObjDir)\*.Map" >NUL
 -erase  "$(ObjDir)\*.Res" >NUL
 -erase  "$(ObjDir)\*.rc"  >NUL
 -erase  "$(ObjDir)\*.bin" >NUL
 -erase  "$(ObjDir)\*.lst" >NUL
 -erase  "$(ObjDir)\*.blt" >NUL
 -erase  "$(ObjDir)\*.hlp" >NUL
 -erase  "$(ObjDir)\*.trg" >NUL
 -erase  "$(ObjDir)\*.srl" >NUL
 -erase  "$(ObjDir)\*.ini" >NUL
 -erase  "$(ObjDir)\*.pdb" >NUL
 -erase  "$(ObjDir)\*.exp" >NUL
 -erase  "$(ObjDir)\*.tlb" >NUL
 -erase  "$(ObjDir)\*.c"   >NUL
 -erase  "$(ObjDir)\*.trg" >NUL
!endif  # OS == Windows_NT
!endif      # BASEMAKE_INCLUDED


MkWWWDest=@for %d in ($(WWWROOT)\SDK $(WWWROOT)\SDK\$(Proj) $(WWWSCRIPTS)\SDK) do @$(COMSPEC) /c if not exist %d md %d

{$(ObjDir)\}.obj{$(ObjDir)\}.exe:
    @echo $**  > $(ObjDir)\objfiles.lst
    @echo $(LinkLibs) > $(ObjDir)\libfiles.lst
!if "$(LOG)"=="YES"
    @echo $(LINK) $(LFLAGS) $(linkflags) @$(ObjDir)\objfiles.lst @$(ObjDir)\libfiles.lst $(LogCmd)
!endif
    $(LINK) $(LFLAGS) $(linkflags) @$(ObjDir)\objfiles.lst @$(ObjDir)\libfiles.lst $(LogCmd)

{$(ObjDir)}.Dll{$(WWWSCRIPTS)\SDK}.Dll:
 $(MkWWWDest)
 !copy $? $(WWWSCRIPTS)\SDK


