# NMAKE.include

MAKEEXE = nmake
IMPLIB  = lib
CC      = cl
LIBU    = lib
LINK    = link
RC      = rc
MC      = mc
HC      = start /wait hcrtf


hcvars = -xn

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

# cdebug = -Gh -Ox -DNDEBUG

#cdebug = $(cdebug) -I./include 

conlflags = $(lflags) -subsystem:console,$(EXEVER)
guilflags = $(lflags) -subsystem:windows,$(EXEVER)
dlllflags = $(lflags) -entry:_DllMainCRTStartup$(DLLENTRY) -dll


# basic subsystem specific libraries, less the C Run-Time
baselibs    = kernel32.lib $(optlibs) $(winsocklibs) advapi32.lib
winlibs     = $(baselibs) user32.lib gdi32.lib comdlg32.lib winspool.lib

# for Windows applications that use the C Run-Time libraries
conlibs     = $(baselibs)
guilibs     = $(winlibs)

# for OLE applications
olelibs     = ole32.lib uuid.lib oleaut32.lib $(guilibs)


rcflags = $(rcflags) /Iinclude /D_SECURE_NO_WARNINGS /D_CRT_SECURE_NO_WARNINGS
cflags = $(cflags) /Iinclude 
# /D_CRT_SECURE_NO_WARNINGS  /DUNICODE /D_UNICODE /DUNICODE /D_UNICODE 


OBJDIR=$(OUTDIR)\$(SRC_DIR)

# all command and macro can not be indented 
!IF "$(TARGET_TYPE)" == "CUI"
LINK_FALGS=$(conlflags)
LINK_LIBS=$(conlibs)
!ELSE
!IF "$(TARGET_TYPE)" == "GUI"
LINK_FALGS=$(guiflags)
LINK_LIBS=$(guilibs)
!ELSE # DLL
LINK_FALGS=$(dlllflags)
LINK_LIBS=$(guilibsdll)
!ENDIF
!ENDIF


#inferencal rule:
# 1: defination with directory
# 2: only target of object is defined when using these rules
#{tests}.c{$(OBJDIR)}.obj:
#    $(cc) $(cflags) $(cdebug) $(cvars) /Fo"$(OBJDIR)\\" /Fd"$(OBJDIR)\\" /Fd"$(OBJDIR)\\" $**

#!if "$(LOG)"=="YES"
#    @echo $(CC) $(CL) $(crtflags) $(cDefines) $< $(LogCmd)
#!endif

# Second, the suffix rule
# C++ Targets
{$(SRC_DIR)}.cpp{$(OBJDIR)}.obj:
    $(cc) $(cflags) $(cdebug) /Fo"$(OBJDIR)\\" /Fd"$(OBJDIR)\\" /Fd"$(OBJDIR)\\" $**
    
{$(SRC_DIR)}.c{$(OBJDIR)}.obj:
    $(cc) $(cflags) $(cdebug) /Fo"$(OBJDIR)\\" /Fd"$(OBJDIR)\\" /Fd"$(OBJDIR)\\" $**


#$(OUTDIR)\$(EXE_NAME).res: $(EXE_NAME).rc $(EXE_NAME).ico
#    $(rc) $(rcflags) $(rcvars) /fo $(OUTDIR)\$(EXE_NAME).res $(EXE_NAME).rc
    
{$(SRC_DIR)}.rc{$(OBJDIR)}.res:
    $(rc) $(rcflags) $(rcvars) /fo $(OBJDIR)\$(EXE_NAME).res $**

cflags=$(cflags) /D_DEBUG /MTd 
