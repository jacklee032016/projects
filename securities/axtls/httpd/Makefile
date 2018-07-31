# 



TARGET_TYPE=CUI

#/D "CARES_BUILDING_LIBRARY" 
!IF "$(DLL_SUPPORT)"=="YES"
!ELSE
cflags=$(cflags) /D "CARES_STATICLIB"
!ENDIF


EXE_NAME=ecpws


ODD = \

  
OBJS = \
    $(OBJDIR)\axhttpd.obj    \
    $(OBJDIR)\proc.obj    \
    $(OBJDIR)\tdate_parse.obj    \
    $(OBJDIR)\htpasswd.obj    \
		

!if "$(TARGET_TYPE)" == "GUI"
RESES= \
    $(OBJDIR)\$(EXE_NAME).res    
!else
RESES= 
!endif


!include MakePre.mak


DEST= $(OUTDIR)\axhttpd.exe  $(OUTDIR)\htpasswd.exe 


# Third, the target dependences
all:$(OBJDIR) $(OBJS) $(DEST) 


$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)


LIBS =$(LIB_CRYPTO).lib $(LIB_TLS).lib wsock32.lib  advapi32.lib 
#user32.lib  $(linkdebug) -subsystem:console 

ODD_LIB = kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib \
		ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib 

$(OUTDIR)\axhttpd.exe: $(OBJDIR)\axhttpd.obj $(OBJDIR)\proc.obj $(OBJDIR)\tdate_parse.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\htpasswd.exe: $(OBJDIR)\htpasswd.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 


	
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    


#	gdi32.lib 


clean:
        $(CLEANUP)

