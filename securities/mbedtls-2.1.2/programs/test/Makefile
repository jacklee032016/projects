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
    $(OBJDIR)\benchmark.obj    \
    $(OBJDIR)\ssl_cert_test.obj    \
    $(OBJDIR)\udp_proxy.obj    \
		

!if "$(TARGET_TYPE)" == "GUI"
RESES= \
    $(OBJDIR)\$(EXE_NAME).res    
!else
RESES= 
!endif


!include MakePre.mak


DEST=$(OUTDIR)\benchmark.exe $(OUTDIR)\ssl_cert_test.exe \
			$(OUTDIR)\udp_proxy.exe


# Third, the target dependences
all:$(OBJDIR) $(OBJS) $(DEST) 


$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)


LIBS =$(LIB_CRYPTO).lib $(LIB_X509).lib $(LIB_TLS).lib wsock32.lib  advapi32.lib 
#user32.lib  $(linkdebug) -subsystem:console 


$(OUTDIR)\benchmark.exe: $(OBJDIR)\benchmark.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\ssl_cert_test.exe: $(OBJDIR)\ssl_cert_test.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\udp_proxy.exe: $(OBJDIR)\udp_proxy.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

	
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    


#	gdi32.lib 


clean:
        $(CLEANUP)

