# Makefile 
# $Id$

include $(TOP_DIR)/Makefile.pre

# build as statistic library
IS_STATIC=yes

CODE_SUBDIRS := .

ASM_SRC += \
		hardwareGas.s    \
    ProcessorBrandGas.s    \
    extL2CacheGas.s    \
			
ODD =\
    $(OBJDIR)\helloMsgBox.obj    \
    $(OBJDIR)\hardwareNasm.obj    \

				
CFLAGS +=$(C_CFLAGS_1)

LOCAL_CLEAN:=clear

LOCAL_ALL:

$(LOCAL_CLEAN):
	
TARGET_LIB:=

LOCAL_TEST:=hardwareGas ProcessorBrandGas extL2CacheGas


include $(TOP_DIR)/Makefile.post

# -luser32 -ladvapi32
LDFLAGS += -L$(LIB_DIR) -lHwUtils 


hardwareGas:$(OBJ_DIR)/hardwareGas.o
	$(CC) -s  -static $(SHARED_LD_FLAGS) $^ -o $@ $(LDFLAGS) $(TEST_LDFLAGS)   
	$(MOVE) $@ $(BIN_DIR)
	
ProcessorBrandGas:$(OBJ_DIR)/ProcessorBrandGas.o
	$(CC) -s $(SHARED_LD_FLAGS) $^ -o $@ $(LDFLAGS) $(TEST_LDFLAGS)   
	$(MOVE) $@ $(BIN_DIR)
	
extL2CacheGas:$(OBJ_DIR)/extL2CacheGas.o
	$(CC) -s $(SHARED_LD_FLAGS) $^ -o $@ $(LDFLAGS) $(TEST_LDFLAGS)   
	$(MOVE) $@ $(BIN_DIR)
	

install: all
	$(COPY) $(TOP_DIR)/src/include/* $(RELEASE_HOME)/include
	$(COPY) $(LIB_DIR)/* $(RELEASE_HOME)/lib
	$(COPY) $(BIN_DIR)/* $(RELEASE_HOME)/bin

#	$(RM) $(TARGET_LIB_DEF)
cleanLocal:
	$(RM) $(OBJ_DIR)
	$(RM) $(BIN_DIR)
	$(RM) $(LIB_DIR)
	