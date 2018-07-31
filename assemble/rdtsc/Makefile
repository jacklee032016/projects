# Makefile 
# $Id$

include $(TOP_DIR)/Makefile.pre

# build as statistic library
IS_STATIC=yes

CODE_SUBDIRS := .

SRC += \
				testRdtsc.c \
				callFuns.c \
				callAsm.c \
			
				
CFLAGS +=$(C_CFLAGS_1)

LOCAL_CLEAN:=clear

LOCAL_ALL:

$(LOCAL_CLEAN):
	
TARGET_LIB:=

LOCAL_TEST:=testRdtsc callFuns callAsm


include $(TOP_DIR)/Makefile.post

# -luser32 -ladvapi32
LDFLAGS += -L$(LIB_DIR) -lHwUtils 


testRdtsc:$(OBJ_DIR)/testRdtsc.o
	$(CC) -s  -static $(SHARED_LD_FLAGS) $^ -o $@ $(LDFLAGS) $(TEST_LDFLAGS)   
	$(MOVE) $@ $(BIN_DIR)
	
callFuns:$(OBJ_DIR)/callFuns.o
	$(CC) -s $(SHARED_LD_FLAGS) $^ -o $@ $(LDFLAGS) $(TEST_LDFLAGS)   
	$(MOVE) $@ $(BIN_DIR)
	
callAsm:$(OBJ_DIR)/callAsm.o
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
	