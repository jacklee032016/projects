# 

!include <Win32.Mak>

TARGET_TYPE=CUI
#GUI

#EXE_NAME=test
EXE_NAME=testCryptoHashMd

# First, the object should be build
OBJS= \
    $(OBJDIR)\$(EXE_NAME).obj    \
    $(OBJDIR)\testCryptoHashSha.obj    \
    $(OBJDIR)\testCryptoHashHMac.obj    \
    $(OBJDIR)\testCryptoBlocks.obj    \
    $(OBJDIR)\testCryptoStreams.obj    \
    $(OBJDIR)\testCryptoPublicKey.obj    \
    $(OBJDIR)\testCryptoMisc.obj    \

!if "$(TARGET_TYPE)" == "GUI"
RESES= \
    $(OBJDIR)\$(EXE_NAME).res    
!else
RESES= 
!endif


DEST=$(OUTDIR)\$(EXE_NAME).exe

# Second, Suffix and rules
!include MakePre.mak
    

# Third, the target dependences
all: $(OBJDIR) $(OBJS) $(DEST) $(OUTDIR)\testCryptoHashSha.exe $(OUTDIR)\testCryptoHashHMac.exe $(OUTDIR)\testCryptoBlocks.exe \
			$(OUTDIR)\testCryptoStreams.exe $(OUTDIR)\testCryptoPublicKey.exe $(OUTDIR)\testCryptoMisc.exe

$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)

# $@ : full name of current target
# $** : the names of all the dependent files $(LINK_LIBS)
$(DEST): $(RESES) $(OBJDIR)\$(EXE_NAME).obj 
	$(link) /out:$@ $(IMLIBS) $** advapi32.lib
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    

$(OUTDIR)\testCryptoHashSha.exe:$(OBJDIR)\testCryptoHashSha.obj
	$(link) /out:$@ $(IMLIBS) $** advapi32.lib

$(OUTDIR)\testCryptoHashHMac.exe:$(OBJDIR)\testCryptoHashHMac.obj
	$(link) /out:$@ $(IMLIBS) $** advapi32.lib

$(OUTDIR)\testCryptoBlocks.exe:$(OBJDIR)\testCryptoBlocks.obj
	$(link) /out:$@ $(IMLIBS) $** advapi32.lib

$(OUTDIR)\testCryptoStreams.exe:$(OBJDIR)\testCryptoStreams.obj
	$(link) /out:$@ $(IMLIBS) $** advapi32.lib

$(OUTDIR)\testCryptoPublicKey.exe:$(OBJDIR)\testCryptoPublicKey.obj
	$(link) /out:$@ $(IMLIBS) $** advapi32.lib Ws2_32.lib

$(OUTDIR)\testCryptoMisc.exe:$(OBJDIR)\testCryptoMisc.obj
	$(link) /out:$@ $(IMLIBS) $** advapi32.lib

#	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $** $(OUTDIR)\.lib advapi32.lib

clean:
        $(CLEANUP)
