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

DLL_NAME=$(LIB_CRYPTO)


RANDOM_OBJS_DIR		=$(OBJDIR)\random
HASH_OBJS_DIR		=$(OBJDIR)\hash
CIPHER_OBJS_DIR		=$(OBJDIR)\cipher
BLOCK_OBJS_DIR		=$(OBJDIR)\cipher\block
STREAM_OBJS_DIR	=$(OBJDIR)\cipher\stream
KEY_OBJS_DIR			=$(OBJDIR)\publicKey


RANDOM_OBJS=	\
	    $(RANDOM_OBJS_DIR)\entropy.obj   \
	    $(RANDOM_OBJS_DIR)\entropy_poll.obj   \
	    $(RANDOM_OBJS_DIR)\havege.obj   \
	    $(RANDOM_OBJS_DIR)\ctr_drbg.obj   \
	    $(RANDOM_OBJS_DIR)\hmac_drbg.obj   \


HASH_OBJS=	\
    $(HASH_OBJS_DIR)\md.obj   \
    $(HASH_OBJS_DIR)\md2.obj   \
    $(HASH_OBJS_DIR)\md4.obj   \
    $(HASH_OBJS_DIR)\md5.obj   \
    $(HASH_OBJS_DIR)\md_wrap.obj   \
    $(HASH_OBJS_DIR)\ripemd160.obj   \
    $(HASH_OBJS_DIR)\sha1.obj   \
    $(HASH_OBJS_DIR)\sha256.obj   \
    $(HASH_OBJS_DIR)\sha512.obj   \
   

BLOCK_OBJS= \
	$(BLOCK_OBJS_DIR)/aes.obj	\
	$(BLOCK_OBJS_DIR)/aesni.obj	\
	$(BLOCK_OBJS_DIR)/camellia.obj	\
	$(BLOCK_OBJS_DIR)/des.obj	\
	$(BLOCK_OBJS_DIR)/blowfish.obj	\
	$(BLOCK_OBJS_DIR)/xtea.obj	\


STREAM_OBJS= \
	$(STREAM_OBJS_DIR)/arc4.obj	\

CIPHER_OBJS= \
	    $(CIPHER_OBJS_DIR)\ccm.obj   \
	    $(CIPHER_OBJS_DIR)\cipher.obj   \
	    $(CIPHER_OBJS_DIR)\cipher_wrap.obj   \
	    $(CIPHER_OBJS_DIR)\gcm.obj   \
	    $(BLOCK_OBJS)		\
	    $(STREAM_OBJS)		\


KEY_OBJS= \
	    $(KEY_OBJS_DIR)\dhm.obj   \
	    $(KEY_OBJS_DIR)\ecdh.obj   \
	    $(KEY_OBJS_DIR)\ecdsa.obj   \
	    $(KEY_OBJS_DIR)\rsa.obj   \
	    $(KEY_OBJS_DIR)\pem.obj   \
	    $(KEY_OBJS_DIR)\pk.obj   \
	    $(KEY_OBJS_DIR)\pk_wrap.obj   \
	    $(KEY_OBJS_DIR)\pkcs12.obj   \
	    $(KEY_OBJS_DIR)\pkcs5.obj   \
	    $(KEY_OBJS_DIR)\pkparse.obj   \
	    $(KEY_OBJS_DIR)\pkwrite.obj   \
	    $(KEY_OBJS_DIR)\ecp.obj   \
	    $(KEY_OBJS_DIR)\ecp_curves.obj   \


OBJS= \
	    $(OBJDIR)\asn1parse.obj   \
	    $(OBJDIR)\asn1write.obj   \
	    $(OBJDIR)\base64.obj   \
	    $(OBJDIR)\bignum.obj   \
	    $(OBJDIR)\error.obj   \
	    $(OBJDIR)\memory_buffer_alloc.obj   \
	    $(OBJDIR)\oid.obj   \
	    $(OBJDIR)\padlock.obj   \
	    $(OBJDIR)\platform.obj   \
	    $(OBJDIR)\threading.obj   \
	    $(OBJDIR)\timing.obj   \
	    $(OBJDIR)\version.obj   \
	    $(OBJDIR)\version_features.obj   \
	    $(RANDOM_OBJS)		\
	    $(HASH_OBJS)		\
	    $(CIPHER_OBJS)		\
	    $(KEY_OBJS)		\


!if "$(TARGET_TYPE)"=="DLL"
DEST=$(DLL_NAME).dll
# RESES=$(OBJDIR)\cares.res
!else
DEST=$(DLL_NAME).lib
!endif    


!include MakePre.mak
            
    
{$(SRC_DIR)\random\}.c{$(RANDOM_OBJS_DIR)\}.obj:
    $(cc) $(cflags)  /Fo"$(RANDOM_OBJS_DIR)\\" /Fd"$(RANDOM_OBJS_DIR)\\" $**

{$(SRC_DIR)\hash\}.c{$(HASH_OBJS_DIR)\}.obj:
    $(cc) $(cflags)  /Fo"$(HASH_OBJS_DIR)\\" /Fd"$(HASH_OBJS_DIR)\\" $**

{$(SRC_DIR)\cipher\block\}.c{$(BLOCK_OBJS_DIR)\}.obj:
    $(cc) $(cflags)  /Fo"$(BLOCK_OBJS_DIR)\\" /Fd"$(BLOCK_OBJS_DIR)\\"  $**

{$(SRC_DIR)\cipher\stream\}.c{$(STREAM_OBJS_DIR)\}.obj:
    $(cc) $(cflags) /Fo"$(STREAM_OBJS_DIR)\\" /Fd"$(STREAM_OBJS_DIR)\\" $**

{$(SRC_DIR)\cipher\}.c{$(CIPHER_OBJS_DIR)\}.obj:
    $(cc) $(cflags) /Fo"$(CIPHER_OBJS_DIR)\\" /Fd"$(CIPHER_OBJS_DIR)\\" $**


{$(SRC_DIR)\publicKey\}.c{$(KEY_OBJS_DIR)\}.obj:
    $(cc) $(cflags) /Fo"$(KEY_OBJS_DIR)\\" /Fd"$(KEY_OBJS_DIR)\\" $**



# cvarsdll is only used for DLL, dll not dependent on CmnHdr.h
# UNICODE and _UNICODE must be defined both 
cflags=$(cflags) 

all: $(OBJDIR) $(RANDOM_OBJS_DIR) $(HASH_OBJS_DIR) $(BLOCK_OBJS_DIR) $(CIPHER_OBJS_DIR) $(STREAM_OBJS_DIR) $(KEY_OBJS_DIR) $(DEST)

$(OBJDIR) :
    if not exist "$(OBJDIR)/$(NULL)" mkdir $(OBJDIR)
    
$(RANDOM_OBJS_DIR) :    
    if not exist "$(RANDOM_OBJS_DIR)/$(NULL)" mkdir $(RANDOM_OBJS_DIR)

$(HASH_OBJS_DIR) :    
    if not exist "$(HASH_OBJS_DIR)/$(NULL)" mkdir $(HASH_OBJS_DIR)

$(CIPHER_OBJS_DIR) :    
    if not exist "$(CIPHER_OBJS_DIR)/$(NULL)" mkdir $(CIPHER_OBJS_DIR)

$(BLOCK_OBJS_DIR) :    
    if not exist "$(BLOCK_OBJS_DIR)/$(NULL)" mkdir $(BLOCK_OBJS_DIR)

$(STREAM_OBJS_DIR) :    
    if not exist "$(STREAM_OBJS_DIR)/$(NULL)" mkdir $(STREAM_OBJS_DIR)

$(KEY_OBJS_DIR) :    
    if not exist "$(KEY_OBJS_DIR)/$(NULL)" mkdir $(KEY_OBJS_DIR)


# def file is not used
# /DEF:$(SRC_DIR)\dllMain.def 

#   $(linkdebug)  msvcrt.lib 
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
