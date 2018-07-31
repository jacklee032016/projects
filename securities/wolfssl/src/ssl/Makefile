# Nmake macros for building Windows 32-Bit apps

!include <win32.mak>

TARGET_TYPE=DLL

!include MakePre.mak
QUIET=N

# cdebug=$(cdebug) /D_DEBUG_TO_FILE 

DLL_NAME=libSsl


BASIC_OBJS_DIR=$(OBJDIR)\basic
CERT_OBJS_DIR=$(OBJDIR)\cert

CLIENT_OBJS_DIR=$(OBJDIR)\client
SERVER_OBJS_DIR=$(OBJDIR)\server


# with the suffix rule, the object can be made from C or CPP source file
OBJS= \
       $(OBJDIR)/wscCrl.obj \
       $(OBJDIR)/wscIo.obj \
       $(OBJDIR)/wscOcsp.obj \
       $(OBJDIR)/wscKeys.obj \
       $(OBJDIR)/wscKeySetCipherSpecs.obj \
       $(OBJDIR)/wscTls.obj	\
       $(OBJDIR)/wscSniffer.obj \
       $(OBJDIR)/wsiInternal.obj \
       $(OBJDIR)/wsiBuildMsg.obj \
       $(OBJDIR)/wsiCipherSuites.obj \
       $(OBJDIR)/wsiDoCertificate.obj \
       $(OBJDIR)/wsiDoHandShakeMsg.obj \
       $(OBJDIR)/wsiInit.obj \
       $(OBJDIR)/wsiReceive.obj \
       $(OBJDIR)/wsiSend.obj \
       $(OBJDIR)/wsiServerKeyExchange.obj \
       $(OBJDIR)/wsiUtils.obj \
       $(OBJDIR)/wssSsl.obj \
       $(OBJDIR)/wssCA.obj \
       $(OBJDIR)/wssCert.obj \
       $(OBJDIR)/wssCipher.obj \
       $(OBJDIR)/wssExtra.obj \
       $(OBJDIR)/wssInit.obj \
       $(OBJDIR)/wssMethod.obj \
       $(OBJDIR)/wssOpenSsl.obj \
       $(OBJDIR)/wssProtocolHandlers.obj \

 
# not used
#     $(OBJDIR)\wccCompress.obj   \

    
CERT_OBJS= \
    $(CERT_OBJS_DIR)\wssCertLoad.obj   \


BASIC_OBJS= \
    $(BASIC_OBJS_DIR)\wssErrors.obj   \

CLIENT_OBJS= \
    $(CLIENT_OBJS_DIR)\wsiClientSend.obj   \

SERVER_OBJS= \
		$(SERVER_OBJS_DIR)/wsiServerSend.obj \
             

#if BUILD_OCSP
#$(SSL_OBJS) = $(SSL_OBJS) $(SSL_OBJS_DIR)/ocsp.obj
#endif

#if BUILD_CRL
#$(SSL_OBJS) += $(SSL_OBJS_DIR)/crl.obj
#endif

#if BUILD_SNIFFER
#$(SSL_OBJS) += $(SSL_OBJS_DIR)/sniffer.obj
#endif


{$(SRC_DIR)\cert\}.c{$(CERT_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(CERT_OBJS_DIR)\\" /Fd"$(CERT_OBJS_DIR)\\" /Fd"$(CERT_OBJS_DIR)\\" $**

{$(SRC_DIR)\basic\}.c{$(BASIC_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(BASIC_OBJS_DIR)\\" /Fd"$(BASIC_OBJS_DIR)\\" /Fd"$(BASIC_OBJS_DIR)\\" $**

{$(SRC_DIR)\client\}.c{$(CLIENT_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(CLIENT_OBJS_DIR)\\" /Fd"$(CLIENT_OBJS_DIR)\\" /Fd"$(CLIENT_OBJS_DIR)\\" $**

{$(SRC_DIR)\server\}.c{$(SERVER_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(SERVER_OBJS_DIR)\\" /Fd"$(SERVER_OBJS_DIR)\\" /Fd"$(SERVER_OBJS_DIR)\\" $**



DEST=$(OUTDIR)\$(DLL_NAME).lib

# cvarsdll is only used for DLL, dll not dependent on CmnHdr.h
# UNICODE and _UNICODE must be defined both 
cflags=$(cflags) $(cvarsdll)

all: $(OBJDIR) $(CERT_OBJS_DIR) $(BASIC_OBJS_DIR) $(CLIENT_OBJS_DIR) $(SERVER_OBJS_DIR) $(DEST)

$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)
    

$(CERT_OBJS_DIR) :    
    if not exist "$(CERT_OBJS_DIR)/$(NULL)" mkdir $(CERT_OBJS_DIR)

$(BASIC_OBJS_DIR) :    
    if not exist "$(BASIC_OBJS_DIR)/$(NULL)" mkdir $(BASIC_OBJS_DIR)

$(CLIENT_OBJS_DIR) :    
    if not exist "$(CLIENT_OBJS_DIR)/$(NULL)" mkdir $(CLIENT_OBJS_DIR)

$(SERVER_OBJS_DIR) :    
    if not exist "$(SERVER_OBJS_DIR)/$(NULL)" mkdir $(SERVER_OBJS_DIR)


# def file is not used
# /DEF:$(SRC_DIR)\dllMain.def 

#   
$(DEST): $(OBJS) $(CERT_OBJS) $(BASIC_OBJS) $(CLIENT_OBJS) $(SERVER_OBJS)
    $(link) -lib -out:$@ $(OBJS) $(CERT_OBJS) $(BASIC_OBJS) $(CLIENT_OBJS) $(SERVER_OBJS)
    

# $(link) $(linkdebug) $(dlllflags) -out:$@   $(OBJS) $(guilibsdll)
#!if "$(QUIET)"=="N"
#    dumpbin /exports $@
#!endif    

#    mt -manifest $(OUTDIR)\Select.dll.manifest -outputresource:$(OUTDIR)\Select.dll;2


clean:
        $(CLEANUP)
