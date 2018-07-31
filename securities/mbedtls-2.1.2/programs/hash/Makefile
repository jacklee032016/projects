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
    $(OBJDIR)\generic_sum.obj    \
    $(OBJDIR)\hello.obj    \
		
		

!if "$(TARGET_TYPE)" == "GUI"
RESES= \
    $(OBJDIR)\$(EXE_NAME).res    
!else
RESES= 
!endif


!include MakePre.mak


DEST=$(OUTDIR)\generic_sum.exe $(OUTDIR)\hello.exe 


# Third, the target dependences
all:$(OBJDIR) $(OBJS) $(DEST) 


$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)


LIBS =$(LIB_CRYPTO).lib wsock32.lib  advapi32.lib 
#user32.lib  $(linkdebug) -subsystem:console 


$(OUTDIR)\generic_sum.exe: $(OBJDIR)\generic_sum.obj
	$(link) $(linkdebug) $(LINK_FLAGS) -out:$@ $**  $(LINK_LIBS) $(LIBS)

$(OUTDIR)\hello.exe: $(OBJDIR)\hello.obj
	$(link) $(LINK_FLAGS) -out:$@ $** $(LIBS) 


	
!if "$(QUIET)"=="N"
    dumpbin /imports $@
!endif    


#	gdi32.lib 


clean:
        $(CLEANUP)

