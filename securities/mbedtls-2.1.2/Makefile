# Modified in Nov.04, 2015, Zhijie Li
# Add conditional build for WITH_DEBUG and DLL_SUPPORT options


# debug option is yes or others
NODEBUG=
#YES
DLL_SUPPORT=
#YES


SUBDIRS= \
			library\crypto \
			library\x509 \
			library\tls \
			programs\aes \
			programs\hash \
			programs\random \
			programs\util \
			programs\pkey \
			programs\x509 \
			programs\test \
			programs\ssl \
			programs\selfTests \

			
			
			
ADD = \

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
			set PATH=%PATH%;c:\Program Files\WinRAR
			cd ..
			rar a mbedtls-2.1.2.$(MY_DATE).rar mbedtls-2.1.2
