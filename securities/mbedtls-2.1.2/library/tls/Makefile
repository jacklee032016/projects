# Nmake macros for building Windows 32-Bit apps


cflags=$(cflags) /D_DEBUG_TO_FILE /D "CARES_BUILDING_LIBRARY" 

!IF "$(DLL_SUPPORT)"=="YES"
TARGET_TYPE=DLL
!ELSE
cflags=$(cflags) /D "CARES_STATICLIB"
!ENDIF


QUIET=N

cdebug=$(cdebug) /D_DEBUG_TO_FILE /D "CARES_BUILDING_LIBRARY"  
# /D "CARES_STATICLIB"
#

DLL_NAME=$(LIB_TLS)



# with the suffix rule, the object can be made from C or CPP source file
OBJS= \
    $(OBJDIR)\debug.obj   \
    $(OBJDIR)\net.obj   \
    $(OBJDIR)\ssl_cache.obj   \
    $(OBJDIR)\ssl_ciphersuites.obj   \
    $(OBJDIR)\ssl_cli.obj   \
    $(OBJDIR)\ssl_cookie.obj   \
    $(OBJDIR)\ssl_srv.obj   \
    $(OBJDIR)\ssl_ticket.obj   \
    $(OBJDIR)\ssl_tls.obj   \



!if "$(TARGET_TYPE)"=="DLL"
DEST=$(DLL_NAME).dll
# RESES=$(OBJDIR)\cares.res
!else
DEST=$(DLL_NAME).lib
!endif    


!include MakePre.mak
            
    


# cvarsdll is only used for DLL, dll not dependent on CmnHdr.h
# UNICODE and _UNICODE must be defined both 
cflags=$(cflags) 

all: $(OBJDIR)  $(DEST)

$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)
    


# def file is not used
# /DEF:$(SRC_DIR)\dllMain.def 

#$(DEST): $(OBJS) 


$(DEST): $(OBJS) $(RESES)
!if "$(TARGET_TYPE)"=="DLL"
    $(link) $(dlllflags) -out:$@ $** $(conlibsdll)
!if "$(QUIET)"=="N"
    dumpbin /exports $@
!endif    
!else
    $(link) -lib -out:$@ $** 
!endif    


#    mt -manifest $(OUTDIR)\Select.dll.manifest -outputresource:$(OUTDIR)\Select.dll;2


clean:
        $(CLEANUP)
