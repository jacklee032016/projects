# 

!include <Win32.Mak>

TARGET_TYPE=GUI

EXE_NAME=Savant

# First, the object should be build
OBJS= \
    $(OBJDIR)\savant.obj    \
    $(OBJDIR)\authenticate.obj    \
    $(OBJDIR)\cgi.obj    \
    $(OBJDIR)\headers.obj    \
    $(OBJDIR)\dirList.obj    \
    $(OBJDIR)\imageMapNcsa.obj    \
    $(OBJDIR)\isapi.obj    \
    $(OBJDIR)\logging.obj    \
    $(OBJDIR)\mime.obj    \
    $(OBJDIR)\request.obj    \
    $(OBJDIR)\response.obj    \
    $(OBJDIR)\serverConfig.obj    \
    $(OBJDIR)\uri.obj    \
    $(OBJDIR)\utilsDate.obj    \
    $(OBJDIR)\utilsSocket.obj    \
    $(OBJDIR)\utilsString.obj    \
    $(OBJDIR)\wincgi.obj    \
    $(OBJDIR)\httpService.obj    \
  


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
all: $(OBJDIR)  $(DEST)

$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)


LIBS = kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib \
		ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib comctl32.lib 


$(DEST): $(OBJS) $(RESES)
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $** $(LINK_LIBS) $(LIBS)
	
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    


#	gdi32.lib 


clean:
        $(CLEANUP)

