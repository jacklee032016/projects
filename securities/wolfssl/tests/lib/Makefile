# Nmake macros for building Windows 32-Bit apps

!include <win32.mak>

# TARGET_TYPE=DLL

!include MakePre.mak
QUIET=N

# cdebug=$(cdebug) /D_DEBUG_TO_FILE 

DLL_NAME=libTest


# with the suffix rule, the object can be made from C or CPP source file
OBJS= \
    $(OBJDIR)\libTestNetwork.obj   \
    $(OBJDIR)\libTestUtils.obj   \
    $(OBJDIR)\libTestPsk.obj   \
    $(OBJDIR)\libTestTrack.obj   \


DEST=$(OUTDIR)\$(DLL_NAME).lib

# cvarsdll is only used for DLL, dll not dependent on CmnHdr.h
# UNICODE and _UNICODE must be defined both 
cflags=$(cflags) $(cvarsdll)

all: $(OBJDIR)  $(DEST)

$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)

# def file is not used
# /DEF:$(SRC_DIR)\dllMain.def

$(DEST): $(OBJS) 
    $(link) -lib -out:$@ $(OBJS) 


# $(link) $(linkdebug) $(dlllflags) -out:$@   $(OBJS) $(guilibsdll)
#!if "$(QUIET)"=="N"
#    dumpbin /exports $@
#!endif    

#    mt -manifest $(OUTDIR)\Select.dll.manifest -outputresource:$(OUTDIR)\Select.dll;2


clean:
        $(CLEANUP)
