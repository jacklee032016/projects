#
# $Author$
# $Log$
# $Revision$
# $Id$
#

TOP_DIR:=$(shell pwd)
BUILDTIME := $(shell TZ=CN date -u "+%Y_%m_%d")

topDir:=$(shell basename $(TOP_DIR))
BACKUP_RELEASES_NAME=$(topDir)_$(BUILDTIME).tar.gz 
RELEASES_NAME=$(topDir)_$(BUILDTIME)

export TOP_DIR
export BUILDTIME
export RELEASES_NAME

	SUBDIRS += \
				cmn		\
				rdtsc \
				hw \
				hello \
					
	
ifeq ($(ARCH),arm)
	SUBDIRS += tests

endif 


drivers:
	- for i in $(SUBDIRS) ; do ( cd $$i && $(MAKE) all ) ; done

all: drivers

install:
	@$(SHELL) $(TOP_DIR)/install.sh  

back:clean
	cd ..;tar cvjf $(RELEASES_NAME).tar.bz2 winpcap

#	- for i in $(SUBDIRS) ; do ( cd $$i && $(MAKE) install ) ; done


releasedir:
	mkdir -p release/bin.$(TARGET_NAME)
	mkdir -p release/lib.$(TARGET_NAME)


cleanall:
	find . -name 'obj.*' -print -exec /bin/rm -rf {} \;
	find . -name 'bin.*' -print -exec /bin/rm -rf {} \;
	find . -name '*.d' -print -exec /bin/rm -f {} \;
	find . -name '.link_host' -print -exec /bin/rm -f {} \;
	for i in $(SUBDIRS) ; do ( cd $$i && $(MAKE) cleanall ) ; done
	rm -rf release/bin.*/*
	rm -rf release/lib.*/*
	rm -rf release/include/*

veryclean: clean
	- find . -name 'obj.*' -print -exec /bin/rm -rf {} \;
	- find . -name 'bin.*' -print -exec /bin/rm -rf {} \;
	- find . -name '*.o' -print -exec /bin/rm -f {} \;
	- find . -name '*.a' -print -exec /bin/rm -f {} \;
	- find . -name 'core' -print -exec /bin/rm -f {} \;
	- find . -name '.link_host' -print -exec /bin/rm -f {} \;


clean:
	- for i in $(SUBDIRS) ; do ( cd $$i && $(MAKE) cleanLocal ) ; done
	rm -rf releases
	- find . -name '*.d' -print -exec /bin/rm -f {} \;



backup:clean
			cd $(TOP_DIR)/.. && tar cvzf $(BACKUP_RELEASES_NAME)  $(topDir) 

