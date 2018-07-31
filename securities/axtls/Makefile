# Modified in Nov.04, 2015, Zhijie Li
# Add conditional build for WITH_DEBUG and DLL_SUPPORT options


# debug option is yes or others
NODEBUG=
#YES
DLL_SUPPORT=YES


SUBDIRS= \
			crypto \
			ssl \
			samples\tests \

			
			
			
ADD = \
			samples\first \
			httpd \

#!set QUIET=N
#

!include MakePre.mak

#	@for %d in ( $(SUBDIRS)) do @echo "Enter %d"  
# all build is run when the top level as the current path, so 'include' is simplified
all:#$(SUBDIRS)
	@for %d in ( $(SUBDIRS)) do $(COMSPEC) /c nmake /F "%d"/Makefile SRC_DIR=%d	NODEBUG=$(NODEBUG)	DLL_SUPPORT=$(DLL_SUPPORT)


clean:
        $(CLEANUP)
        
package:clean
#			echo $(MY_DATE)
      if exist data\certs\tests/  rd /s /q data\certs\tests
			set PATH=%PATH%;c:\Program Files\WinRAR
			cd ..
			rar a axtls-1.5.3.$(MY_DATE).rar axtls
