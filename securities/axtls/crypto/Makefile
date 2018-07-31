# Nmake macros for building Windows 32-Bit apps


!IF "$(DLL_SUPPORT)"=="YES"
TARGET_TYPE=DLL
cflags=$(cflags) /DCRYPTO_SHARED
!ELSE
cflags=$(cflags) 
!ENDIF


QUIET=N

DLL_NAME=$(LIB_CRYPTO)

# with the suffix rule, the object can be made from C or CPP source file
OBJS= \
    $(OBJDIR)\os_port.obj   \
    $(OBJDIR)\crypto_misc.obj   \
    $(OBJDIR)\aes.obj   \
    $(OBJDIR)\bigint.obj   \
    $(OBJDIR)\hmac.obj   \
    $(OBJDIR)\md5.obj   \
    $(OBJDIR)\rc4.obj   \
    $(OBJDIR)\rsa.obj   \
    $(OBJDIR)\sha1.obj   \
    $(OBJDIR)\sha256.obj   \
    $(OBJDIR)\sha384.obj   \
    $(OBJDIR)\sha512.obj   \
    $(OBJDIR)\axDebug.obj   \



!if "$(TARGET_TYPE)"=="DLL"
DEST=$(DLL_NAME).dll
# RESES=$(OBJDIR)\cares.res
!else
DEST=$(DLL_NAME).lib
!endif    


!include MakePre.mak
            

# cvarsdll is only used for DLL, dll not dependent on CmnHdr.h
# UNICODE and _UNICODE must be defined both 

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
