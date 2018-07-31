#define	DLL_LIBRARY_EXPORT

#include "myDllDefs.h"
#include <locale.h>

LPFN_ISWOW64PROCESS	fnIsWow64Process;
LPFN_WOW64DISABLE		fnWow64Disable;
LPFN_WOW64REVERT		fnWow64Revert;

HINSTANCE dllModuleHandle;

/* the module must be a DLL which had mapped into the process space of calling process;
* so module name must without any path name, and moduleName can omit expansion name
* function name must be in single-byte char
*/
FARPROC DLL_DECLARE loadFunctionFromModule(PTCHAR moduleName, PCHAR functionName) 
{ 
	HMODULE	modHandle;
	FARPROC		functionPointer;

	if(  (modHandle = GetModuleHandle(moduleName)) == NULL ) 
	{ 
		DEBUG_ERROR(L"GetModuleHandle\n" );
		return NULL;
	} 

	functionPointer = GetProcAddress(modHandle, ( LPCSTR )functionName);
	if( !functionPointer ) 
	{ 
		DEBUG_ERROR( L"GetProcAddress\n" );
		return NULL;
	}

	/* close handler */

	return functionPointer;
} 




static DWORD _initDll(void)
{
/* this C++ syntax */
/*
LPFN_ISWOW64PROCESS	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(_T("kernel32")),"IsWow64Process");
LPFN_WOW64DISABLE	fnWow64Disable	 = (LPFN_WOW64DISABLE)GetProcAddress(GetModuleHandle(_T("kernel32")),"Wow64DisableWow64FsRedirection");
LPFN_WOW64REVERT	fnWow64Revert	 = (LPFN_WOW64REVERT)GetProcAddress(GetModuleHandle(_T("kernel32")),"Wow64RevertWow64FsRedirection");
*/

	return 0;
}

BOOL APIENTRY DllMain( HINSTANCE  hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved)
{
//	BOOL bx64 = IsXP64Bit();
	dllModuleHandle = hModule;
	lpReserved = lpReserved;
	
	switch(ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		{
			/* set locale, so the character set of current C runtime know the charset we want to use
			* After that, when printf or wprintf output, CRT know how to transfer the wide char into multi-char
			* Note: All output in console, no matter print or wprintf is used, are in form of single-byte-char
			*/
			setlocale(LC_ALL, "");
			
			if(determineOSVersion()==2)
			{
				_initDll();
			}
		}

		break;
		
		case DLL_PROCESS_DETACH:
			{
				if(determineOSVersion()==2)
				{
				}
			}
		break;
		
	}
	return TRUE;
}


