# Makefile 
# $Id$

include $(TOP_DIR)/Makefile.pre

# build as statistic library
IS_STATIC=yes

CODE_SUBDIRS := .

ASFLAGS += --defsym CHINESE=0

ASM_SRC += \
		testSymbol.s    \
    cond.s    \
    firstGas.s    \
			
ODD =\
    $(OBJDIR)\helloMsgBox.obj    \
    $(OBJDIR)\hardwareNasm.obj    \

				
CFLAGS +=$(C_CFLAGS_1)

LOCAL_CLEAN:=clear

LOCAL_ALL:

$(LOCAL_CLEAN):
	
TARGET_LIB:=

LOCAL_TEST:=testSymbol cond firstGas


include $(TOP_DIR)/Makefile.post

# -luser32 -ladvapi32
LDFLAGS += -L$(LIB_DIR) -lHwUtils 


testSymbol:$(OBJ_DIR)/testSymbol.o
	$(CC) -s  -static $(SHARED_LD_FLAGS) $^ -o $@ $(LDFLAGS) $(TEST_LDFLAGS)   
	$(MOVE) $@ $(BIN_DIR)
	
cond:$(OBJ_DIR)/cond.o
	$(CC) -s $(SHARED_LD_FLAGS) $^ -o $@ $(LDFLAGS) $(TEST_LDFLAGS)   
	$(MOVE) $@ $(BIN_DIR)
	
firstGas:$(OBJ_DIR)/firstGas.o
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
	