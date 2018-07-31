
			Assembly in Windows
								Zhijie LI

Dec.23,2015
	Add build environment for MinGW: make
	Support Windows SDK: nmake -f Makefile.win32
	

Dec.14,2015
	Build in Windows 7-x64 platform.
	
	"SetEnv.cmd /x86"	: x86 platform, fully compatible with Windows7-x86
	"setEnv.cmd (/x64)" : binary code of local platform, eg. x64. So symbol of '_printf' can not be found.
	
