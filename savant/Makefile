# Nmake macros for building Windows 32-Bit apps
!include <win32.mak>

# When some errors,using this as link and compile flags, the detailed info can be displayed..
# /VERBOSE  
#
MY_DATE=%date:~0,4%.%date:~5,2%.%date:~8,2%

SUBDIRS= \
			savant \
			config \
			property 

ADD = \


#!set QUIET=N
#

#	@for %d in ( $(SUBDIRS)) do @echo "Enter %d"  
# all build is run when the top level as the current path, so 'include' is simplified
all:#$(SUBDIRS)
	@for %d in ( $(SUBDIRS)) do $(COMSPEC) /c nmake /F "%d"/Makefile SRC_DIR=%d


clean:
        $(CLEANUP)

package:clean
#			echo $(MY_DATE)
			set PATH=%PATH%;c:\Program Files\WinRAR
			cd ..
			rar a savant.$(MY_DATE).rar savant
