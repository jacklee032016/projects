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

DLL_NAME=$(LIB_X509)



# with the suffix rule, the object can be made from C or CPP source file
OBJS= \
    $(OBJDIR)\certs.obj   \
    $(OBJDIR)\pkcs11.obj   \
    $(OBJDIR)\x509.obj   \
    $(OBJDIR)\x509_create.obj   \
    $(OBJDIR)\x509_crl.obj   \
    $(OBJDIR)\x509_crt.obj   \
    $(OBJDIR)\x509_csr.obj   \
    $(OBJDIR)\x509write_crt.obj   \
    $(OBJDIR)\x509write_csr.obj   \



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
