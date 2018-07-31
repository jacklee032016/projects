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
    $(OBJDIR)\cert_app.obj    \
    $(OBJDIR)\crl_app.obj    \
    $(OBJDIR)\cert_req.obj    \
    $(OBJDIR)\cert_write.obj    \
    $(OBJDIR)\req_app.obj    \
		
		

!if "$(TARGET_TYPE)" == "GUI"
RESES= \
    $(OBJDIR)\$(EXE_NAME).res    
!else
RESES= 
!endif


!include MakePre.mak


DEST=$(OUTDIR)\cert_app.exe $(OUTDIR)\crl_app.exe $(OUTDIR)\cert_req.exe \
			$(OUTDIR)\cert_write.exe $(OUTDIR)\req_app.exe 


# Third, the target dependences
all:$(OBJDIR) $(OBJS) $(DEST) 


$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)


LIBS =$(LIB_CRYPTO).lib $(LIB_X509).lib $(LIB_TLS).lib wsock32.lib  advapi32.lib 
#user32.lib  $(linkdebug) -subsystem:console 


$(OUTDIR)\cert_app.exe: $(OBJDIR)\cert_app.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\crl_app.exe: $(OBJDIR)\crl_app.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\cert_req.exe: $(OBJDIR)\cert_req.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\cert_write.exe: $(OBJDIR)\cert_write.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\req_app.exe: $(OBJDIR)\req_app.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 


	
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    


#	gdi32.lib 


clean:
        $(CLEANUP)

