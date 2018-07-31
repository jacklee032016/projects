/*
* Resolves URIs into local filenames and/or redirects PHASE: URI Translation
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "savant.h"

extern SOCKADDR_IN stLclAddr;

//Private data structure definitions
struct DirInfo
{
	char				*LocalDirStr;
	BOOL			AllowDirList;
	SCRIPT_TYPE_T	scripting;
	
	char				*AuthUserStr;
	AUTH_LOC_T		authLoc;
};


//Private global variables
static int NumDirs;
static char **Dirs;
static int *DirLens;
static DirInfo **DirInfos;


//Loads the UMSDOS FAT to URL directory mappings into memory
void loadHTTPPathMap()
{
#if 0
	BOOL fAllowDirList;
	char szNumDirs[6], szAuthUser[101], szAuthLoc[101], szScripting[101];
	char szDir[MAX_PATH], szLocalDir[MAX_PATH];
	char *lpszTemp;
	DirInfo *lpTempDirInfo;
	DWORD dwValueType, dwBuffSize;
	FILETIME junk;
	HKEY hDirMapKey, hDirKey;
	int i, j, temp;
	SCRIPT_TYPE_T nScripting;
	AUTH_LOC_T		nAuthLoc;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Directory Mappings", 0, KEY_ALL_ACCESS, &hDirMapKey) != ERROR_SUCCESS)
	{
		DEBUG_REGISTER_ERR();
	}
	dwBuffSize = 5;
	if (RegQueryValueEx(hDirMapKey, "Number of Directories", 0, &dwValueType, (LPBYTE)szNumDirs, &dwBuffSize) != ERROR_SUCCESS)
	{
		DEBUG_REGISTER_ERR();
	}
	
	NumDirs = atoi(szNumDirs);
	Dirs = new char *[NumDirs];
	DirLens = new int[NumDirs];
	DirInfos = new DirInfo *[NumDirs];

	//create directory data arrays
	for (i=0; i<NumDirs; i++)
	{
		dwBuffSize = MAX_PATH;
		if (RegEnumKeyEx(hDirMapKey, i, szDir, &dwBuffSize, 0, NULL, 0, &junk) != ERROR_SUCCESS)
		{
			DEBUG_REGISTER_ERR();
		}
		if (RegOpenKeyEx(hDirMapKey, szDir, 0, KEY_ALL_ACCESS, &hDirKey) != ERROR_SUCCESS)
		{
			DEBUG_REGISTER_ERR();
		}
		
		if (szDir[strlen(szDir) - 1] == '/')
			szDir[strlen(szDir) - 1] = '\0';
		
		dwBuffSize = MAX_PATH;
		//get directories from config file
		if (RegQueryValueEx(hDirKey, "Local Directory", 0, &dwValueType,	 (LPBYTE)szLocalDir, &dwBuffSize) != ERROR_SUCCESS)
		{
			DEBUG_REGISTER_ERR();
		}
		
		//get local directory
		if (getRegFlag(fAllowDirList, hDirKey, "Allow Directory Listings") != 0)
		{
			DEBUG_REGISTER_ERR();
		}
		dwBuffSize = 100;
		if (RegQueryValueEx(hDirKey, "Scripting", 0, &dwValueType,  (LPBYTE)szScripting, &dwBuffSize) != ERROR_SUCCESS)
		{
			DEBUG_REGISTER_ERR();
		}
		
		if (strcmpi(szScripting, "None") == 0)
			nScripting = SCRIPT_TYPE_NONE;
		else
		if (strcmpi(szScripting, "CGI") == 0)
			nScripting = SCRIPT_TYPE_CGI;
		else
		if (strcmpi(szScripting, "WinCGI") == 0) 
			nScripting = SCRIPT_TYPE_WINCGI;
		else
		if (strcmpi(szScripting, "ISAPI") == 0)
			nScripting = SCRIPT_TYPE_ISAPI;
		else
			nScripting = SCRIPT_TYPE_NONE;
		
		dwBuffSize = 100;
		//get scripting type allowed
		if (RegQueryValueEx(hDirKey, "Authorized User", 0, &dwValueType, (LPBYTE)szAuthUser, &dwBuffSize) != ERROR_SUCCESS)
		{
			DEBUG_REGISTER_ERR();
		}

		//get authorized users [if any]
		dwBuffSize = 100;
		if (RegQueryValueEx(hDirKey, "Authorized Location", 0, &dwValueType, (LPBYTE)szAuthLoc, &dwBuffSize) != ERROR_SUCCESS)
		{
			DEBUG_REGISTER_ERR();
		}
		
		if (strcmpi(szAuthLoc, "Anywhere") == 0)
			nAuthLoc = AUTH_LOC_ANYWHERE;
		else
		if(strcmpi(szAuthLoc, "Class A Subnet") == 0)
			nAuthLoc = AUTH_LOC_CLASSA;
		else
		if(strcmpi(szAuthLoc, "Class B Subnet") == 0)
			nAuthLoc = AUTH_LOC_CLASSB;
		else
		if(strcmpi(szAuthLoc, "Class C Subnet") == 0)
			nAuthLoc = AUTH_LOC_CLASSC;
		else
		if(strcmpi(szAuthLoc, "Class D Subnet") == 0)
			nAuthLoc = AUTH_LOC_CLASSD;
		else
			nAuthLoc = AUTH_LOC_ANYWHERE;
		
		//get authorized location
		if (RegCloseKey(hDirKey) != ERROR_SUCCESS)
		{
			logError("Error closing directory key");
		}
		
		Dirs[i] = new char[strlen(szDir)+1];
		strcpy(Dirs[i], szDir);
		
		DirLens[i] = strlen(szDir);
		
		DirInfos[i] = new DirInfo;
		DirInfos[i]->LocalDirStr = new char[strlen(szLocalDir)+1];
		strcpy(DirInfos[i]->LocalDirStr, szLocalDir);
		DirInfos[i]->AllowDirList = fAllowDirList;
		DirInfos[i]->scripting = nScripting;
		DirInfos[i]->AuthUserStr = new char[strlen(szAuthUser)+1];
		strcpy(DirInfos[i]->AuthUserStr, szAuthUser);
		DirInfos[i]->authLoc = nAuthLoc;
		
	}

	//add directory to data arrays

	for (i=NumDirs-1; i>0; i--)
	{
		for (j=0; j<i; j++)
			if (DirLens[j] < DirLens[j+1])
			{
				temp = DirLens[j];
				DirLens[j] = DirLens[j+1];
				DirLens[j+1] = temp;
				lpszTemp = Dirs[j];
				Dirs[j] = Dirs[j+1];
				Dirs[j+1] = lpszTemp;
				lpTempDirInfo = DirInfos[j];
				DirInfos[j] = DirInfos[j+1];
				DirInfos[j+1] = lpTempDirInfo;
			}
	}

	//sort directories using insertion sort
	if (RegCloseKey(hDirMapKey) != ERROR_SUCCESS)
		logError("Error closing registry key");
#else
	NumDirs = 1;
	Dirs = new char *[NumDirs];
	DirLens = new int[NumDirs];
	DirInfos = new DirInfo *[NumDirs];
#endif

	TRACE();  
}


//Unloads UMSDOS FAT to URL mapping from memory
void unloadHTTPPathMap()
{
	int i;

	for (i=0; i<NumDirs; i++)
	{
		delete[] Dirs[i];
		delete[] DirInfos[i]->LocalDirStr;
		delete[] DirInfos[i]->AuthUserStr;
		delete DirInfos[i];
	}
	
	delete[] Dirs;
	delete[] DirLens;
	delete[] DirInfos;
}


//Replaces URL with local file/directory, and gets access attributes
int mapHTTPPath(char *URIStr, THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	char *lpszIP;
	int i, j, nLocalA, nLocalB, nLocalC, nLocalD, nRemoteA, nRemoteB, nRemoteC, nRemoteD;

#define LenOk (strlen(URIStr) >= DirLens[i])
#define SubStrMatch (strnicmp(URIStr, Dirs[i], DirLens[i]) == 0)
#define NotSubElement ((URIStr[DirLens[i]] == '\0') || (URIStr[DirLens[i]] == '/') || (URIStr[DirLens[i]] == '\\'))

	if (strstr(URIStr, "%2f.."))
		return MP_STATUS_FORBIDDEN;

	
	strcpy(thInfo->parsedReq.szRemoteRealm, "/");
	strcpy(thInfo->parsedReq.szLocalRealm, "d:\\works\\temp\\");
	strcpy(thInfo->parsedReq.szFilePath, "d:\\works\\temp\\");
	thInfo->parsedReq.bAllowDirList = TRUE;
	thInfo->parsedReq.scriptType = SCRIPT_TYPE_NONE;
	return MP_STATUS_PATH_FOUND;

	i = 0;
	while ((i < NumDirs) && !(LenOk && SubStrMatch && NotSubElement))
		i++;
	
	if (i == NumDirs)
		return MP_STATUS_ERROR;//make sure directory is valid
		
	strcpy(thInfo->parsedReq.szRemoteRealm, Dirs[i]);
	strcpy(thInfo->parsedReq.szLocalRealm, DirInfos[i]->LocalDirStr);
	strcpy(thInfo->parsedReq.szFilePath, DirInfos[i]->LocalDirStr);
	//get base file path
	
	thInfo->parsedReq.bAllowDirList = DirInfos[i]->AllowDirList;
	thInfo->parsedReq.scriptType = DirInfos[i]->scripting;
	
	if (DirInfos[i]->authLoc != AUTH_LOC_ANYWHERE)
	{
		lpszIP = inet_ntoa(stLclAddr.sin_addr);
		nLocalA = atoi(lpszIP);
		trimInet(lpszIP);
		nLocalB = atoi(lpszIP);
		trimInet(lpszIP);
		nLocalC = atoi(lpszIP);
		trimInet(lpszIP);
		nLocalD = atoi(lpszIP);
		lpszIP = inet_ntoa( thInfo->ClientSockAddr.sin_addr);
		nRemoteA = atoi(lpszIP);
		trimInet(lpszIP);
		nRemoteB = atoi(lpszIP);
		trimInet(lpszIP);
		nRemoteC = atoi(lpszIP);
		trimInet(lpszIP);
		nRemoteD = atoi(lpszIP);
		
		switch(DirInfos[i]->authLoc)
		{
			case AUTH_LOC_CLASSA:
				if (nLocalA != nRemoteA)
					return MP_STATUS_NO_ACCESS;
				break;
			
			case AUTH_LOC_CLASSB:
				if ((nLocalA != nRemoteA) || (nLocalB != nRemoteB))
					return MP_STATUS_NO_ACCESS;
				break;
			
			case AUTH_LOC_CLASSC:
				if ((nLocalA != nRemoteA) || (nLocalB != nRemoteB) || (nLocalC != nRemoteC))
					return MP_STATUS_NO_ACCESS;
				break;
			
			case AUTH_LOC_CLASSD:
				if ((nLocalA != nRemoteA) || (nLocalB != nRemoteB) || (nLocalC != nRemoteC) || (nLocalD != nRemoteD))
					return MP_STATUS_NO_ACCESS;
				break;
			
		}
	}
	
	//check user name and password
	if (strcmpi(DirInfos[i]->AuthUserStr, "Anyone") != 0)
	{
		if (req->AuthorizationStr[0] == 0)
			return MP_STATUS_NO_ACCESS;
		else
			if (HTTPCheckUser(req->AuthorizationStr, DirInfos[i]->AuthUserStr, req->AuthorizedUserStr) == FALSE)
				return MP_STATUS_NO_ACCESS;
	}

	
	//convert directory name to URL
	j = DirLens[i];
	i = strlen(thInfo->parsedReq.szFilePath);
	if (thInfo->parsedReq.szFilePath[i - 1] == '\\')
		i--;
	
	while (URIStr[j] != 0)
	{
		if (URIStr[j] == '/')
			thInfo->parsedReq.szFilePath[i] = '\\';
		else if ((URIStr[j] == '%') && (URIStr[j+1] != 0) && (URIStr[j+2] != 0) && (URIStr[j+1] != '%'))
		{
			thInfo->parsedReq.szFilePath[i] = 16 * hexVal(URIStr[j+1]) + hexVal(URIStr[j+2]);
			j += 2;
		}
		else
			thInfo->parsedReq.szFilePath[i] = URIStr[j];
		
		i++;
		j++;
	}
	
	thInfo->parsedReq.szFilePath[i] = 0;
	if (strstr(thInfo->parsedReq.szFilePath, "\\.") != 0)
		return MP_STATUS_FORBIDDEN;
	//check entered URL is not security violation
	
	return MP_STATUS_PATH_FOUND;
}

