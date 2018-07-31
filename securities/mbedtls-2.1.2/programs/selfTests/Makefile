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
    $(OBJDIR)\selftestMain.obj    \
    $(OBJDIR)\selftestBasis.obj    \
    $(OBJDIR)\selftestSys.obj    \
    $(OBJDIR)\selftestHashMd.obj    \
    $(OBJDIR)\selftestHashSha.obj    \
    $(OBJDIR)\selftestBlock.obj    \
    $(OBJDIR)\selftestPublicKey.obj    \
    $(OBJDIR)\selftestX509.obj    \
    $(OBJDIR)\selftestRandom.obj    \
    $(OBJDIR)\selftestCipher.obj    \
    $(OBJDIR)\selftestCipherGcm.obj    \
		

!if "$(TARGET_TYPE)" == "GUI"
RESES= \
    $(OBJDIR)\$(EXE_NAME).res    
!else
RESES= 
!endif


!include MakePre.mak


DEST=$(OUTDIR)\selftest.exe \



# Third, the target dependences
all:$(OBJDIR) $(OBJS) $(DEST) 


$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)


LIBS =$(LIB_CRYPTO).lib $(LIB_X509).lib $(LIB_TLS).lib wsock32.lib  advapi32.lib 
#user32.lib  $(linkdebug) -subsystem:console 


$(OUTDIR)\selftest.exe: $(OBJS)
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

	
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    


#	gdi32.lib 


clean:
        $(CLEANUP)

