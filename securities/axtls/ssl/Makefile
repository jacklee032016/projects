# Nmake macros for building Windows 32-Bit apps

!IF "$(DLL_SUPPORT)"=="YES"
TARGET_TYPE=DLL
!ELSE
cflags=$(cflags) 
!ENDIF


QUIET=N


DLL_NAME=$(LIB_TLS)


# with the suffix rule, the object can be made from C or CPP source file
OBJS= \
    $(OBJDIR)\asn1.obj   \
    $(OBJDIR)\gen_cert.obj   \
    $(OBJDIR)\loader.obj   \
    $(OBJDIR)\openssl.obj   \
    $(OBJDIR)\p12.obj   \
    $(OBJDIR)\x509.obj   \
    $(OBJDIR)\tls1.obj   \
    $(OBJDIR)\tls1Server.obj   \
    $(OBJDIR)\tls1Client.obj   \
    $(OBJDIR)\tlsCrypto.obj   \
    $(OBJDIR)\tlsRxSend.obj   \
    $(OBJDIR)\tlsProtocol.obj   \
    $(OBJDIR)\tlsUtils.obj   \
    $(OBJDIR)\net.obj   \


!if "$(TARGET_TYPE)"=="DLL"
DEST=$(DLL_NAME).dll
# RESES=$(OBJDIR)\cares.res
!else
DEST=$(DLL_NAME).lib
!endif    


!include MakePre.mak
            

# cvarsdll is only used for DLL, dll not dependent on CmnHdr.h
# UNICODE and _UNICODE must be defined both 
cflags=$(cflags) /Icrypto

all: $(OBJDIR)  $(DEST)

$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)
    


# def file is not used
# /DEF:$(SRC_DIR)\dllMain.def 

#$(DEST): $(OBJS) 


$(DEST): $(OBJS) $(RESES)
!if "$(TARGET_TYPE)"=="DLL"
    $(link) $(dlllflags) -out:$@ $** $(LIB_CRYPTO).lib $(conlibsdll)
!if "$(QUIET)"=="N"
    dumpbin /exports $@
!endif    
!else
    $(link) -lib -out:$@ $** 
!endif    


#    mt -manifest $(OUTDIR)\Select.dll.manifest -outputresource:$(OUTDIR)\Select.dll;2


clean:
        $(CLEANUP)
