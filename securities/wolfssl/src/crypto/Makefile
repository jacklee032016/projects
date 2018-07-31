# Nmake macros for building Windows 32-Bit apps

!include <win32.mak>

TARGET_TYPE=DLL

!include MakePre.mak
QUIET=N

# cdebug=$(cdebug) /D_DEBUG_TO_FILE 

DLL_NAME=libCrypto

HASH_OBJS_DIR=$(OBJDIR)\hash
KEYHASH_OBJS_DIR=$(OBJDIR)\mac
BLOCK_OBJS_DIR=$(OBJDIR)\block
STREAM_OBJS_DIR=$(OBJDIR)\stream
KEYCIPHER_OBJS_DIR=$(OBJDIR)\key


# with the suffix rule, the object can be made from C or CPP source file
OBJS= \
    $(OBJDIR)\wccCoding.obj   \
    $(OBJDIR)\wccError.obj   \
    $(OBJDIR)\wccLogging.obj   \
    $(OBJDIR)\wccInteger.obj   \
    $(OBJDIR)\wccMemory.obj   \
    $(OBJDIR)\wccPort.obj   \
    $(OBJDIR)\wccRandom.obj   \
    $(OBJDIR)\wccPwdbased.obj   \

# not used
#     $(OBJDIR)\wccCompress.obj   \


HASH_OBJS= \
    $(HASH_OBJS_DIR)\wchMd2.obj   \
    $(HASH_OBJS_DIR)\wchMd4.obj   \
    $(HASH_OBJS_DIR)\wchMd5.obj   \
    $(HASH_OBJS_DIR)\wchSha.obj   \
    $(HASH_OBJS_DIR)\wchSha256.obj   \
    $(HASH_OBJS_DIR)\wchSha512.obj   \
    $(HASH_OBJS_DIR)\wchRipemd.obj   \
    $(HASH_OBJS_DIR)\wchBlake2b.obj   \
    $(HASH_OBJS_DIR)\wchHash.obj   \

KEY_HASH_OBJS= \
    $(KEYHASH_OBJS_DIR)\wcmHmac.obj   \
    $(KEYHASH_OBJS_DIR)\wcmPoly1305.obj   \
    
BLOCK_OBJS= \
    $(BLOCK_OBJS_DIR)\wcbAes.obj   \
    $(BLOCK_OBJS_DIR)\wcbDes3.obj   \
    $(BLOCK_OBJS_DIR)\wcbCamellia.obj   \

STREAM_OBJS= \
    $(STREAM_OBJS_DIR)\wcsArc4.obj   \
    $(STREAM_OBJS_DIR)\wcsRabbit.obj   \
    $(STREAM_OBJS_DIR)\wcsHc128.obj   \
    $(STREAM_OBJS_DIR)\wcsChacha.obj   \
    $(STREAM_OBJS_DIR)\wcsChacha20_poly1305.obj   \

KEYCIPHER_OBJS= \
    $(KEYCIPHER_OBJS_DIR)\wckDh.obj   \
    $(KEYCIPHER_OBJS_DIR)\wckDsa.obj   \
    $(KEYCIPHER_OBJS_DIR)\wckRsa.obj   \
    $(KEYCIPHER_OBJS_DIR)\wckEcc.obj   \
    
              
    
{$(SRC_DIR)\hash\}.c{$(HASH_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(HASH_OBJS_DIR)\\" /Fd"$(HASH_OBJS_DIR)\\" /Fd"$(HASH_OBJS_DIR)\\" $**

{$(SRC_DIR)\mac\}.c{$(KEYHASH_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(KEYHASH_OBJS_DIR)\\" /Fd"$(KEYHASH_OBJS_DIR)\\" /Fd"$(KEYHASH_OBJS_DIR)\\" $**

{$(SRC_DIR)\block\}.c{$(BLOCK_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(BLOCK_OBJS_DIR)\\" /Fd"$(BLOCK_OBJS_DIR)\\" /Fd"$(BLOCK_OBJS_DIR)\\" $**

{$(SRC_DIR)\stream\}.c{$(STREAM_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(STREAM_OBJS_DIR)\\" /Fd"$(STREAM_OBJS_DIR)\\" /Fd"$(STREAM_OBJS_DIR)\\" $**

{$(SRC_DIR)\key\}.c{$(KEYCIPHER_OBJS_DIR)\}.obj:
    $(cc) $(ccflags) $(cdebug) /Fo"$(KEYCIPHER_OBJS_DIR)\\" /Fd"$(KEYCIPHER_OBJS_DIR)\\" /Fd"$(KEYCIPHER_OBJS_DIR)\\" $**



DEST=$(OUTDIR)\$(DLL_NAME).lib

# cvarsdll is only used for DLL, dll not dependent on CmnHdr.h
# UNICODE and _UNICODE must be defined both 
cflags=$(cflags) $(cvarsdll)

all: $(OBJDIR) $(HASH_OBJS_DIR) $(KEYHASH_OBJS_DIR) $(BLOCK_OBJS_DIR) $(STREAM_OBJS_DIR) $(KEYCIPHER_OBJS_DIR) \
			$(ASN_OBJS_DIR) $(SSL_OBJS_DIR)  $(DEST)

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


# def file is not used
# /DEF:$(SRC_DIR)\dllMain.def 

#   
$(DEST): $(OBJS) $(HASH_OBJS) $(KEY_HASH_OBJS) $(BLOCK_OBJS) $(STREAM_OBJS)	$(KEYCIPHER_OBJS)
    $(link) -lib -out:$@ $(OBJS) $(HASH_OBJS) $(KEY_HASH_OBJS) $(BLOCK_OBJS) $(STREAM_OBJS) $(KEYCIPHER_OBJS) 
    

# $(link) $(linkdebug) $(dlllflags) -out:$@   $(OBJS) $(guilibsdll)
#!if "$(QUIET)"=="N"
#    dumpbin /exports $@
#!endif    

#    mt -manifest $(OUTDIR)\Select.dll.manifest -outputresource:$(OUTDIR)\Select.dll;2


clean:
        $(CLEANUP)
