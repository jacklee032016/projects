# 

!include <Win32.Mak>

TARGET_TYPE=CUI
#GUI

EXE_NAME=echoclient

# First, the object should be build
OBJS= \
    $(OBJDIR)\$(EXE_NAME).obj    \


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
all: $(OBJDIR) $(OBJS) $(DEST) 

$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)

# $@ : full name of current target
# $** : the names of all the dependent files $(LINK_LIBS)
$(DEST): $(RESES)  $(OBJS)
	$(link) /out:$@ $(IMLIBS) $** advapi32.lib Ws2_32.lib
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    


#	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $** $(OUTDIR)\.lib advapi32.lib

clean:
        $(CLEANUP)
