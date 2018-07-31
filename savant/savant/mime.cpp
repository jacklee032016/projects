/*
* Handles MIME<=>extensions translation
*/


#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "savant.h"

static char **MIMEExts, **MIMEDescs;
static int NumMIMEMappings;

//Loads and initializes the MIME table from the registry
void loadHTTPMIMETable()
{
	char szNumTypes[6], szMIMEExtBuff[16], szMIMEDescBuff[128];
	char *lpszTemp;
	DWORD dwValueType, dwBuffSize;
	HKEY hMIMEKey, hExtKey;
	int i, j;

#if 0
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\MIME", 0, KEY_ALL_ACCESS, &hMIMEKey) != ERROR_SUCCESS)
	{
		DEBUG_REGISTER_ERR();
	}
	dwBuffSize = 5;
	if (RegQueryValueEx(hMIMEKey, "MIME Types", 0, &dwValueType, (LPBYTE)szNumTypes, &dwBuffSize) != ERROR_SUCCESS)
	{
		DEBUG_REGISTER_ERR();
	}
	
	NumMIMEMappings = atoi(szNumTypes);
	MIMEExts = new char *[NumMIMEMappings];
	MIMEDescs = new char *[NumMIMEMappings];
	FILETIME Junk;
	for (i=0; i<NumMIMEMappings; i++)
	{
		dwBuffSize = 15;
		if (RegEnumKeyEx(hMIMEKey, i, szMIMEExtBuff, &dwBuffSize, 0, NULL, 0, &Junk) != ERROR_SUCCESS)
		{
			DEBUG_REGISTER_ERR();
		}
		
		if (RegOpenKeyEx(hMIMEKey, szMIMEExtBuff, 0, KEY_ALL_ACCESS, &hExtKey) != ERROR_SUCCESS)
		{
			DEBUG_REGISTER_ERR();
		}
		
		dwBuffSize = 127;
		if (RegQueryValueEx(hExtKey, "MIME Description", 0, &dwValueType, (LPBYTE)szMIMEDescBuff, &dwBuffSize) != ERROR_SUCCESS)
		{
			DEBUG_REGISTER_ERR();
		}
		
		if (RegCloseKey(hExtKey) != ERROR_SUCCESS)
			logError("Error closing registry key");
		
		MIMEExts[i] = new char [strlen(szMIMEExtBuff) + 1];
		MIMEDescs[i] = new char [strlen(szMIMEDescBuff) + 1];
		strcpy(MIMEExts[i], szMIMEExtBuff);
		strcpy(MIMEDescs[i], szMIMEDescBuff);
	}
	
	if (RegCloseKey(hMIMEKey) != ERROR_SUCCESS)
		logError("Error closing registry key");
#else
#endif
	
	for (i=0; i<NumMIMEMappings; i++)
		CharUpper(MIMEExts[i]);
	
	for (i=NumMIMEMappings-1; i>0; i--)
	{
		for (j=0; j<i; j++)
		{
			if (strcmp(MIMEExts[j], MIMEExts[j+1]) > 0)
			{
				lpszTemp = MIMEExts[j];
				MIMEExts[j] = MIMEExts[j+1];
				MIMEExts[j+1] = lpszTemp;
				lpszTemp = MIMEDescs[j];
				MIMEDescs[j] = MIMEDescs[j+1];
				MIMEDescs[j+1] = lpszTemp;
			}
		}
	}

	TRACE();
}


//Gets a MIME file descriptor based on file extension
static char *_getHTTPMIMEByExt(char *Ext)
{
	char szWorkingExt[20];
	int nLow, nHigh, nGuess, nCompResult;

	nLow = 0;
	nHigh = NumMIMEMappings - 1;
	if (Ext == NULL)
		return NULL;
	
	strncpy(szWorkingExt, Ext, 20);
	szWorkingExt[19] = 0;
	CharUpper(szWorkingExt);
	
	while (nLow <= nHigh)
	{
		nGuess = (nLow + nHigh) / 2;
		nCompResult = strcmp(szWorkingExt, MIMEExts[nGuess]);
		if (nCompResult < 0)
			nHigh = nGuess - 1;
		else
		if (nCompResult > 0)
			nLow = nGuess + 1;
		else
			return MIMEDescs[nGuess];
	}
	
	return "text/html";
}


//Gets a MIME descriptor based on an entire file path
char *getHTTPMIMEByPath(char *Path)
{
	char szExt[20];

	getExtension(Path, szExt);
	return _getHTTPMIMEByExt(szExt);
}


//Removes MIME support from memory
void unloadHTTPMIMETable()
{
	int i;

	for (i=0; i < NumMIMEMappings; i++)
	{
		delete[] MIMEExts[i];
		delete[] MIMEDescs[i];
	}
	
	delete[] MIMEExts;
	delete[] MIMEDescs;
}

