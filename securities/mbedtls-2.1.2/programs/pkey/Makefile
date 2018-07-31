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
    $(OBJDIR)\dh_client.obj    \
    $(OBJDIR)\dh_genprime.obj    \
    $(OBJDIR)\dh_server.obj    \
    $(OBJDIR)\ecdsa.obj    \
    $(OBJDIR)\gen_key.obj    \
    $(OBJDIR)\key_app.obj    \
    $(OBJDIR)\key_app_writer.obj    \
    $(OBJDIR)\mpi_demo.obj    \
    $(OBJDIR)\pk_decrypt.obj    \
    $(OBJDIR)\pk_encrypt.obj    \
    $(OBJDIR)\pk_sign.obj    \
    $(OBJDIR)\pk_verify.obj    \
    $(OBJDIR)\rsa_genkey.obj    \
    $(OBJDIR)\rsa_decrypt.obj    \
    $(OBJDIR)\rsa_encrypt.obj    \
    $(OBJDIR)\rsa_sign.obj    \
    $(OBJDIR)\rsa_verify.obj    \
    $(OBJDIR)\rsa_sign_pss.obj    \
    $(OBJDIR)\rsa_verify_pss.obj    \
		
		

!if "$(TARGET_TYPE)" == "GUI"
RESES= \
    $(OBJDIR)\$(EXE_NAME).res    
!else
RESES= 
!endif


!include MakePre.mak


DEST=$(OUTDIR)\dh_client.exe $(OUTDIR)\dh_genprime.exe $(OUTDIR)\dh_server.exe \
			$(OUTDIR)\ecdsa.exe $(OUTDIR)\gen_key.exe $(OUTDIR)\key_app.exe \
			$(OUTDIR)\key_app_writer.exe $(OUTDIR)\mpi_demo.exe $(OUTDIR)\pk_decrypt.exe \
			$(OUTDIR)\pk_encrypt.exe $(OUTDIR)\pk_sign.exe $(OUTDIR)\pk_verify.exe \
			$(OUTDIR)\rsa_genkey.exe $(OUTDIR)\rsa_decrypt.exe $(OUTDIR)\rsa_encrypt.exe \
			$(OUTDIR)\rsa_sign.exe $(OUTDIR)\rsa_verify.exe $(OUTDIR)\rsa_sign_pss.exe \
			$(OUTDIR)\rsa_verify_pss.exe 

# Third, the target dependences
all:$(OBJDIR) $(OBJS) $(DEST) 


$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)


LIBS =$(LIB_CRYPTO).lib  $(LIB_TLS).lib wsock32.lib  advapi32.lib 
#user32.lib  $(linkdebug) -subsystem:console 


$(OUTDIR)\dh_client.exe: $(OBJDIR)\dh_client.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\dh_genprime.exe: $(OBJDIR)\dh_genprime.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\dh_server.exe: $(OBJDIR)\dh_server.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\ecdsa.exe: $(OBJDIR)\ecdsa.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\gen_key.exe: $(OBJDIR)\gen_key.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\key_app.exe: $(OBJDIR)\key_app.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\key_app_writer.exe: $(OBJDIR)\key_app_writer.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\mpi_demo.exe: $(OBJDIR)\mpi_demo.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\pk_decrypt.exe: $(OBJDIR)\pk_decrypt.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\pk_encrypt.exe: $(OBJDIR)\pk_encrypt.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\pk_sign.exe: $(OBJDIR)\pk_sign.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\pk_verify.exe: $(OBJDIR)\pk_verify.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\rsa_genkey.exe: $(OBJDIR)\rsa_genkey.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\rsa_decrypt.exe: $(OBJDIR)\rsa_decrypt.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\rsa_encrypt.exe: $(OBJDIR)\rsa_encrypt.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\rsa_sign.exe: $(OBJDIR)\rsa_sign.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\rsa_verify.exe: $(OBJDIR)\rsa_verify.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\rsa_sign_pss.exe: $(OBJDIR)\rsa_sign_pss.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\rsa_verify_pss.exe: $(OBJDIR)\rsa_verify_pss.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS)


	
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    


#	gdi32.lib 


clean:
        $(CLEANUP)

