# Nmake macros for building Windows 32-Bit apps
!include <win32.mak>

# When some errors,using this as link and compile flags, the detailed info can be displayed..
# /VERBOSE  
#
MY_DATE=%date:~0,4%.%date:~5,2%.%date:~8,2%

# build options
WOLFSSL_CERT_REQ=1
#set WOLFSSL_CERT_REQ

SUBDIRS= \
			src\crypto \
			src\cert \
			src\ssl \
			tests\lib	\
			examples\echoclient \
			examples\client \
			examples\server \
			examples\echoserver \
			tests\crypto \


ADD=	\


#			tests\unit	\
			
			
#			tests\benchmark \
			
# only used when PCAP is supportted
#			tests\sslSnifferTest \
			

	
# CUI test programs			
#			tests \
#			tests\pipe \

#!set QUIET=N
#

#	@for %d in ( $(SUBDIRS)) do @echo "Enter %d"  
# all build is run when the top level as the current path, so 'include' is simplified
all:#$(SUBDIRS)
	@for %d in ( $(SUBDIRS)) do $(COMSPEC) /c nmake /F "%d"/Makefile SRC_DIR=%d


clean:
        $(CLEANUP)

package: clean
#			echo $(MY_DATE)
			set PATH=%PATH%;c:\Program Files\WinRAR
			cd ..
			rar a -m5 wolfssl-$(MY_DATE).rar wolfssl
