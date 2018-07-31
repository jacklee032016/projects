# Nmake macros for building Windows 32-Bit apps

!include <win32.mak>

TARGET_TYPE=DLL

!include MakePre.mak
QUIET=N

# cdebug=$(cdebug) /D_DEBUG_TO_FILE 

DLL_NAME=libCertificate


ASN_OBJS_DIR			=$(OBJDIR)\asn
ENCODE_OBJS_DIR	=$(OBJDIR)\encode
DECODE_OBJS_DIR	=$(OBJDIR)\decode
PKCS7_OBJS_DIR		=$(OBJDIR)pkcs7


# with the suffix rule, the object can be made from C or CPP source file
OBJS= \
    $(OBJDIR)\certCodeSignature.obj   \

ASN_OBJS=	\
    $(ASN_OBJS_DIR)\certAsn.obj   \
    $(ASN_OBJS_DIR)\certAsnSetGet.obj   \
    $(ASN_OBJS_DIR)\certAsnTime.obj   \
    

ENCODE_OBJS= \
	$(ENCODE_OBJS_DIR)/certEncodeUtils.obj	\
	$(ENCODE_OBJS_DIR)/certEncodeMakeCert.obj	\
	$(ENCODE_OBJS_DIR)/certEncodeKey2Cert.obj	\
	$(ENCODE_OBJS_DIR)/certEncodeKey2Der.obj	\
	$(ENCODE_OBJS_DIR)/certEncodeKey2Request.obj	\


DECODE_OBJS= \
	$(DECODE_OBJS_DIR)/certDecodeCertExtension.obj	\
	$(DECODE_OBJS_DIR)/certDecodeCertsGet.obj	\
	$(DECODE_OBJS_DIR)/certDecodeCerts.obj	\
	$(DECODE_OBJS_DIR)/certDecodeKeys.obj		\
	$(DECODE_OBJS_DIR)/certDecodePem2Der.obj	\
	$(DECODE_OBJS_DIR)/certDecodeCrl.obj	\


PKCS7_OBJS= \
    $(PKCS7_OBJS_DIR)\certPkcs7.obj   \
    $(PKCS7_OBJS_DIR)\certPkcs7EnvelopeData.obj   \
    $(PKCS7_OBJS_DIR)\certPkcs7SignedData.obj   \



#if	WOLFSSL_CERT_REQ
#endif

            
    
{$(SRC_DIR)\asn\}.c{$(ASN_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(ASN_OBJS_DIR)\\" /Fd"$(ASN_OBJS_DIR)\\" /Fd"$(ASN_OBJS_DIR)\\" $**

{$(SRC_DIR)\encode\}.c{$(ENCODE_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(ENCODE_OBJS_DIR)\\" /Fd"$(ENCODE_OBJS_DIR)\\" /Fd"$(ENCODE_OBJS_DIR)\\" $**

{$(SRC_DIR)\decode\}.c{$(DECODE_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(DECODE_OBJS_DIR)\\" /Fd"$(DECODE_OBJS_DIR)\\" /Fd"$(DECODE_OBJS_DIR)\\" $**


{$(SRC_DIR)\pkcs7\}.c{$(PKCS7_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(PKCS7_OBJS_DIR)\\" /Fd"$(PKCS7_OBJS_DIR)\\" /Fd"$(PKCS7_OBJS_DIR)\\" $**



DEST=$(OUTDIR)\$(DLL_NAME).lib

# cvarsdll is only used for DLL, dll not dependent on CmnHdr.h
# UNICODE and _UNICODE must be defined both 
cflags=$(cflags) $(cvarsdll)

all: $(OBJDIR) $(ASN_OBJS_DIR) $(ENCODE_OBJS_DIR) $(DECODE_OBJS_DIR) $(PKCS7_OBJS_DIR) $(DEST)

$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)
    
$(ASN_OBJS_DIR) :    
    if not exist "$(ASN_OBJS_DIR)/$(NULL)" mkdir $(ASN_OBJS_DIR)

$(ENCODE_OBJS_DIR) :    
    if not exist "$(ENCODE_OBJS_DIR)/$(NULL)" mkdir $(ENCODE_OBJS_DIR)

$(DECODE_OBJS_DIR) :    
    if not exist "$(DECODE_OBJS_DIR)/$(NULL)" mkdir $(DECODE_OBJS_DIR)

$(PKCS7_OBJS_DIR) :    
    if not exist "$(PKCS7_OBJS_DIR)/$(NULL)" mkdir $(PKCS7_OBJS_DIR)


# def file is not used
# /DEF:$(SRC_DIR)\dllMain.def 

#   
$(DEST): $(OBJS) $(ASN_OBJS) $(ENCODE_OBJS) $(DECODE_OBJS) $(PKCS7_OBJS) 
    $(link) -lib -out:$@ $(OBJS) $(ASN_OBJS) $(ENCODE_OBJS)  $(DECODE_OBJS) $(PKCS7_OBJS) 
    

# $(link) $(linkdebug) $(dlllflags) -out:$@   $(OBJS) $(guilibsdll)
#!if "$(QUIET)"=="N"
#    dumpbin /exports $@
#!endif    

#    mt -manifest $(OUTDIR)\Select.dll.manifest -outputresource:$(OUTDIR)\Select.dll;2


clean:
        $(CLEANUP)
