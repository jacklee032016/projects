# 


TARGET_TYPE=CUI


EXE_NAME=ecpws


ODD = \
    $(OBJDIR)\ssltest.obj    \
    $(OBJDIR)\sslTestClient.obj    \
    $(OBJDIR)\ssltestServer.obj    \

  
OBJS = \
    $(OBJDIR)\testBigIntBenchmark.obj    \
    $(OBJDIR)\testCrypto.obj    \
    $(OBJDIR)\testCerts.obj    \
    $(OBJDIR)\testTls.obj    \
		

!if "$(TARGET_TYPE)" == "GUI"
RESES= \
    $(OBJDIR)\$(EXE_NAME).res    
!else
RESES= 
!endif


!include MakePre.mak


DEST= $(OUTDIR)\testBigIntBenchmark.exe $(OUTDIR)\testCrypto.exe  $(OUTDIR)\testCerts.exe  $(OUTDIR)\testTls.exe


# Third, the target dependences
all:$(OBJDIR) $(OBJS) $(DEST) 


$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)


LIBS =$(LIB_CRYPTO).lib $(LIB_TLS).lib wsock32.lib  advapi32.lib 
#user32.lib  $(linkdebug) -subsystem:console 

ODD_LIB = kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib \
		ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib 

#$(OUTDIR)\ssltest.exe: $(OBJDIR)\ssltest.obj $(OBJDIR)\ssltestClient.obj $(OBJDIR)\ssltestServer.obj $(OBJDIR)\ssltestCrypto.obj
#	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\testBigIntBenchmark.exe: $(OBJDIR)\testBigIntBenchmark.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\testCrypto.exe: $(OBJDIR)\testCrypto.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\testCerts.exe: $(OBJDIR)\testCerts.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\testTls.exe: $(OBJDIR)\testTls.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 


	
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    


#	gdi32.lib 


clean:
        $(CLEANUP)

