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
    $(OBJDIR)\gen_entropy.obj    \
    $(OBJDIR)\gen_random_havege.obj    \
    $(OBJDIR)\gen_random_ctr_drbg.obj    \
		
		

!if "$(TARGET_TYPE)" == "GUI"
RESES= \
    $(OBJDIR)\$(EXE_NAME).res    
!else
RESES= 
!endif


!include MakePre.mak


DEST=$(OUTDIR)\gen_entropy.exe $(OUTDIR)\gen_random_havege.exe $(OUTDIR)\gen_random_ctr_drbg.exe


# Third, the target dependences
all:$(OBJDIR) $(OBJS) $(DEST) 


$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)


LIBS =$(LIB_CRYPTO).lib wsock32.lib  advapi32.lib 
#user32.lib  $(linkdebug) -subsystem:console 


$(OUTDIR)\gen_entropy.exe: $(OBJDIR)\gen_entropy.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\gen_random_havege.exe: $(OBJDIR)\gen_random_havege.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 

$(OUTDIR)\gen_random_ctr_drbg.exe: $(OBJDIR)\gen_random_ctr_drbg.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 


	
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    


#	gdi32.lib 


clean:
        $(CLEANUP)

