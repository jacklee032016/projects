# Nmake macros for building Windows 32-Bit apps

!include <win32.mak>

TARGET_TYPE=DLL

!include MakePre.mak
QUIET=N

# cdebug=$(cdebug) /D_DEBUG_TO_FILE 

DLL_NAME=cyacrypt

HASH_OBJS_DIR=$(OBJDIR)\hash
KEYHASH_OBJS_DIR=$(OBJDIR)\keyedHash
BLOCK_OBJS_DIR=$(OBJDIR)\block
STREAM_OBJS_DIR=$(OBJDIR)\stream
KEYCIPHER_OBJS_DIR=$(OBJDIR)\keyCipher

SSL_OBJS_DIR=$(OBJDIR)\ssl


HASH_OBJS= \
    $(HASH_OBJS_DIR)\md2.obj   \
    $(HASH_OBJS_DIR)\md4.obj   \
    $(HASH_OBJS_DIR)\md5.obj   \
    $(HASH_OBJS_DIR)\sha.obj   \
    $(HASH_OBJS_DIR)\sha256.obj   \
    $(HASH_OBJS_DIR)\sha512.obj   \
    $(HASH_OBJS_DIR)\ripemd.obj   \
    $(HASH_OBJS_DIR)\blake2b.obj   \

KEY_HASH_OBJS= \
    $(KEYHASH_OBJS_DIR)\hmac.obj   \
    $(KEYHASH_OBJS_DIR)\poly1305.obj   \
    
BLOCK_OBJS= \
    $(BLOCK_OBJS_DIR)\aes.obj   \
    $(BLOCK_OBJS_DIR)\des3.obj   \
    $(BLOCK_OBJS_DIR)\camellia.obj   \

STREAM_OBJS= \
    $(STREAM_OBJS_DIR)\arc4.obj   \
    $(STREAM_OBJS_DIR)\rabbit.obj   \
    $(STREAM_OBJS_DIR)\hc128.obj   \
    $(STREAM_OBJS_DIR)\chacha.obj   \
    $(STREAM_OBJS_DIR)\chacha20_poly1305.obj   \

KEYCIPHER_OBJS= \
    $(KEYCIPHER_OBJS_DIR)\dh.obj   \
    $(KEYCIPHER_OBJS_DIR)\dsa.obj   \
    $(KEYCIPHER_OBJS_DIR)\rsa.obj   \
    $(KEYCIPHER_OBJS_DIR)\pkcs7.obj   \
    

# SSL embeded here
SSL_OBJS= \
               $(SSL_OBJS_DIR)/io.obj \
               $(SSL_OBJS_DIR)/tls.obj	\
               $(SSL_OBJS_DIR)/ocsp.obj \
               $(SSL_OBJS_DIR)/crl.obj \
               $(SSL_OBJS_DIR)/sniffer.obj \
               $(SSL_OBJS_DIR)/keys.obj \
               $(SSL_OBJS_DIR)/keySetCipherSpecs.obj \
               $(SSL_OBJS_DIR)/internal.obj \
               $(SSL_OBJS_DIR)/interBuildMsg.obj \
               $(SSL_OBJS_DIR)/interCipherSuites.obj \
               $(SSL_OBJS_DIR)/interClient.obj \
               $(SSL_OBJS_DIR)/interDoCertificate.obj \
               $(SSL_OBJS_DIR)/interDoHandShakeMsg.obj \
               $(SSL_OBJS_DIR)/interInit.obj \
               $(SSL_OBJS_DIR)/interProcessReply.obj \
               $(SSL_OBJS_DIR)/interSend.obj \
               $(SSL_OBJS_DIR)/interServer.obj \
               $(SSL_OBJS_DIR)/interServerKeyExchange.obj \
               $(SSL_OBJS_DIR)/interUtils.obj \
               $(SSL_OBJS_DIR)/ssl.obj \
               $(SSL_OBJS_DIR)/sslCA.obj \
               $(SSL_OBJS_DIR)/sslCert.obj \
               $(SSL_OBJS_DIR)/sslCipher.obj \
               $(SSL_OBJS_DIR)/sslExtra.obj \
               $(SSL_OBJS_DIR)/sslInit.obj \
               $(SSL_OBJS_DIR)/sslMethod.obj \
               $(SSL_OBJS_DIR)/sslOpenSsl.obj \
               $(SSL_OBJS_DIR)/sslProtocolHandlers.obj \
               

#if BUILD_OCSP
#$(SSL_OBJS) = $(SSL_OBJS) $(SSL_OBJS_DIR)/ocsp.obj
#endif

#if BUILD_CRL
#$(SSL_OBJS) += $(SSL_OBJS_DIR)/crl.obj
#endif

#if BUILD_SNIFFER
#$(SSL_OBJS) += $(SSL_OBJS_DIR)/sniffer.obj
#endif


    
{$(SRC_DIR)\hash\}.c{$(HASH_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(HASH_OBJS_DIR)\\" /Fd"$(HASH_OBJS_DIR)\\" /Fd"$(HASH_OBJS_DIR)\\" $**

{$(SRC_DIR)\keyedHash\}.c{$(KEYHASH_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(KEYHASH_OBJS_DIR)\\" /Fd"$(KEYHASH_OBJS_DIR)\\" /Fd"$(KEYHASH_OBJS_DIR)\\" $**

{$(SRC_DIR)\block\}.c{$(BLOCK_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(BLOCK_OBJS_DIR)\\" /Fd"$(BLOCK_OBJS_DIR)\\" /Fd"$(BLOCK_OBJS_DIR)\\" $**

{$(SRC_DIR)\stream\}.c{$(STREAM_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(STREAM_OBJS_DIR)\\" /Fd"$(STREAM_OBJS_DIR)\\" /Fd"$(STREAM_OBJS_DIR)\\" $**

{$(SRC_DIR)\keyCipher\}.c{$(KEYCIPHER_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(KEYCIPHER_OBJS_DIR)\\" /Fd"$(KEYCIPHER_OBJS_DIR)\\" /Fd"$(KEYCIPHER_OBJS_DIR)\\" $**

{$(SRC_DIR)\ssl\}.c{$(SSL_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(SSL_OBJS_DIR)\\" /Fd"$(SSL_OBJS_DIR)\\" /Fd"$(SSL_OBJS_DIR)\\" $**



# with the suffix rule, the object can be made from C or CPP source file
OBJS= \
    $(OBJDIR)\asn.obj   \
    $(OBJDIR)\asnKey2Der.obj   \
    $(OBJDIR)\asnKey2Cert.obj   \
    $(OBJDIR)\asnKey2Request.obj   \
    $(OBJDIR)\asnParseCerts.obj   \
    $(OBJDIR)\asnParseKeys.obj   \
    $(OBJDIR)\asnSetGet.obj   \
    $(OBJDIR)\asnTime.obj   \
    $(OBJDIR)\coding.obj   \
    $(OBJDIR)\ecc.obj   \
    $(OBJDIR)\error.obj   \
    $(OBJDIR)\hash.obj   \
    $(OBJDIR)\integer.obj   \
    $(OBJDIR)\logging.obj   \
    $(OBJDIR)\memory.obj   \
    $(OBJDIR)\pwdbased.obj   \
    $(OBJDIR)\random.obj   \
    $(OBJDIR)\wc_port.obj   \
    

DEST=$(OUTDIR)\$(DLL_NAME).lib

# cvarsdll is only used for DLL, dll not dependent on CmnHdr.h
# UNICODE and _UNICODE must be defined both 
cflags=$(cflags) $(cvarsdll)

all: $(OBJDIR) $(HASH_OBJS_DIR) $(KEYHASH_OBJS_DIR) $(BLOCK_OBJS_DIR) $(STREAM_OBJS_DIR) $(KEYCIPHER_OBJS_DIR) $(SSL_OBJS_DIR)  $(DEST)

$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)
    
$(HASH_OBJS_DIR) :    
    if not exist "$(HASH_OBJS_DIR)/$(NULL)" mkdir $(HASH_OBJS_DIR)

$(KEYHASH_OBJS_DIR) :    
    if not exist "$(KEYHASH_OBJS_DIR)/$(NULL)" mkdir $(KEYHASH_OBJS_DIR)

$(BLOCK_OBJS_DIR) :    
    if not exist "$(BLOCK_OBJS_DIR)/$(NULL)" mkdir $(BLOCK_OBJS_DIR)

$(STREAM_OBJS_DIR) :    
    if not exist "$(STREAM_OBJS_DIR)/$(NULL)" mkdir $(STREAM_OBJS_DIR)

$(KEYCIPHER_OBJS_DIR) :    
    if not exist "$(KEYCIPHER_OBJS_DIR)/$(NULL)" mkdir $(KEYCIPHER_OBJS_DIR)

$(SSL_OBJS_DIR) :    
    if not exist "$(SSL_OBJS_DIR)/$(NULL)" mkdir $(SSL_OBJS_DIR)


# def file is not used
# /DEF:$(SRC_DIR)\dllMain.def 

$(DEST): $(OBJS) $(HASH_OBJS) $(KEY_HASH_OBJS) $(BLOCK_OBJS) $(STREAM_OBJS) $(KEYCIPHER_OBJS)  $(SSL_OBJS)
    $(link) -lib -out:$@ $(OBJS) $(HASH_OBJS) $(KEY_HASH_OBJS) $(BLOCK_OBJS) $(STREAM_OBJS) $(KEYCIPHER_OBJS) $(SSL_OBJS)


# $(link) $(linkdebug) $(dlllflags) -out:$@   $(OBJS) $(guilibsdll)
#!if "$(QUIET)"=="N"
#    dumpbin /exports $@
#!endif    

#    mt -manifest $(OUTDIR)\Select.dll.manifest -outputresource:$(OUTDIR)\Select.dll;2


clean:
        $(CLEANUP)
