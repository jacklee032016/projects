# 



TARGET_TYPE=CUI

#/D "CARES_BUILDING_LIBRARY" 
!IF "$(DLL_SUPPORT)"=="YES"
!ELSE
cflags=$(cflags) /D "CARES_STATICLIB"
!ENDIF


EXE_NAME=ecpws


ODD = \
    $(OBJDIR)\ssl_pthread_server.obj    \

  
OBJS = \
    $(OBJDIR)\dtls_client.obj    \
    $(OBJDIR)\dtls_server.obj    \
    $(OBJDIR)\mini_client.obj    \
    $(OBJDIR)\ssl_client1.obj    \
    $(OBJDIR)\ssl_client2.obj    \
    $(OBJDIR)\ssl_fork_server.obj    \
    $(OBJDIR)\ssl_mail_client.obj    \
    $(OBJDIR)\ssl_server.obj    \
    $(OBJDIR)\ssl_server2.obj    \
		


!if "$(TARGET_TYPE)" == "GUI"
RESES= \
    $(OBJDIR)\$(EXE_NAME).res    
!else
RESES= 
!endif


!include MakePre.mak


DEST=$(OUTDIR)\dtls_client.exe $(OUTDIR)\dtls_server.exe $(OUTDIR)\mini_client.exe \
			$(OUTDIR)\ssl_client1.exe $(OUTDIR)\ssl_client2.exe \
			$(OUTDIR)\ssl_fork_server.exe $(OUTDIR)\ssl_mail_client.exe $(OUTDIR)\ssl_server.exe \
			$(OUTDIR)\ssl_server2.exe 
			
#$(OUTDIR)\ssl_pthread_server.exe 



# Third, the target dependences
all:$(OBJDIR) $(OBJS) $(DEST) 


$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)


LIBS =$(LIB_CRYPTO).lib $(LIB_X509).lib $(LIB_TLS).lib wsock32.lib  advapi32.lib 
#user32.lib  $(linkdebug) -subsystem:console 


$(OUTDIR)\dtls_server.exe: $(OBJDIR)\dtls_server.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\dtls_client.exe: $(OBJDIR)\dtls_client.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\mini_client.exe: $(OBJDIR)\mini_client.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\ssl_client1.exe: $(OBJDIR)\ssl_client1.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\ssl_client2.exe: $(OBJDIR)\ssl_client2.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\ssl_fork_server.exe: $(OBJDIR)\ssl_fork_server.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\ssl_mail_client.exe: $(OBJDIR)\ssl_mail_client.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\ssl_server.exe: $(OBJDIR)\ssl_server.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\ssl_server2.exe: $(OBJDIR)\ssl_server2.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\req_app.exe: $(OBJDIR)\req_app.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 



	
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    


#	gdi32.lib 


clean:
        $(CLEANUP)

