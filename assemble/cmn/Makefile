# Makefile 
# $Id$

# build as statistic library
IS_STATIC=
# yes
include $(TOP_DIR)/Makefile.pre

CODE_SUBDIRS := .


SRC += \
		hdUtils.c \
		cpuInfo.c \
		
ASM_SRC += \
		cpuString.s \
		cpuBrand.s \
		asmParams.s \


#		doRdtsc.s \



CFLAGS +=$(C_CFLAGS_1)

LOCAL_CLEAN:=clear

LOCAL_ALL:

$(LOCAL_CLEAN):
	
TARGET_LIB:=libHwUtils

# LOCAL_TEST:=


include $(TOP_DIR)/Makefile.post

	
install: all
	$(COPY) $(TOP_DIR)/src/include/* $(RELEASE_HOME)/include
	$(COPY) $(LIB_DIR)/* $(RELEASE_HOME)/lib
	$(COPY) $(BIN_DIR)/* $(RELEASE_HOME)/bin

#	$(RM) $(TARGET_LIB_DEF)
cleanLocal:
	$(RM) $(OBJ_DIR)
	$(RM) $(BIN_DIR)
	$(RM) $(LIB_DIR)
	