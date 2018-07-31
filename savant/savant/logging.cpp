/*
*
*/


#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <commctrl.h>

#include "savant.h"

extern int nConsolePos;
extern HWND hwndConsole;
extern HWND hwndLV;


static BOOL ComLogEnabled, ComLogLookupIP, RefLogEnabled;
static BOOL CntLogCountConnects, CntLogCountFiles, CntLogCountKBytes;
static char *ComLogFileNameStr, *RefLogFileNameStr;
static char ComLogPath[MAX_PATH],  RefLogPath[MAX_PATH];
static CRITICAL_SECTION CommonLogCritSec, CountLogCritSec, ReferenceLogCritSec;
char ErrorLogPath[MAX_PATH];
BOOL CriticalErrorFlag = FALSE;

//Initializes HTTP logs
void initHTTPLogs()
{
	char *lpszLogDir;

	lpszLogDir = cfg->LogDirStr;
	CMN_LOG_FLAGS(ComLogEnabled, ComLogFileNameStr, ComLogLookupIP);
	COUNT_LOG_FLAGS( CntLogCountFiles, CntLogCountConnects, CntLogCountKBytes);
	REFERENCE_FLAGS(RefLogEnabled, RefLogFileNameStr);
										//load configuration info from registry
	strcpy(ComLogPath, lpszLogDir);
	strcat(ComLogPath, cfg->ComLogFileNameStr);

	strcpy(RefLogPath, lpszLogDir);
	strcat(RefLogPath, RefLogFileNameStr);
										//create error file paths
	InitializeCriticalSection(&CommonLogCritSec);
	InitializeCriticalSection(&CountLogCritSec);
	InitializeCriticalSection(&ReferenceLogCritSec);

	TRACE();  											
}


//Cleans up after HTTP logging activity
void cleanUpHTTPLogs()
{
	DeleteCriticalSection(&CommonLogCritSec);
	DeleteCriticalSection(&CountLogCritSec);
	DeleteCriticalSection(&ReferenceLogCritSec);
}


//Writes an entry to the common log and the console window
void HTTPLogCommonEntry(SOCKADDR_IN *Address, int AddressLength ,char *AuthNameStr,
	                     char *DateStr, char *MethodStr, char *URIStr,
                        char *StatusCodeStr, long Size)
{
	char szTemp[128];
	char szLogEntry[500], szNum[33], szConvAuthName[100], szCRLF[3];
	DWORD junk;
	HANDLE hFile;
	LV_ITEM lvi;
	int i,j;

	i = 0;
	//  if (ComLogEnabled == FALSE)
	//    return;
	szLogEntry[0] = 0;
	EnterCriticalSection(&CommonLogCritSec);

	//create date string for console display, insert as item
	for(j=0; j < 6; j++)
		szTemp[j] = DateStr[j];
	szTemp[6] = 0;
	lvi.mask = LVIF_TEXT;
	lvi.stateMask = LVIS_STATEIMAGEMASK;
	lvi.iItem = 0;		//insert at top of list view
	lvi.iSubItem = 0;
	lvi.pszText = (LPSTR)szTemp;
	ListView_InsertItem(hwndLV, &lvi);

	//create time string for console, insert as subitem 1
	for(j=12; j < 20; j++)
		szTemp[j-12] = DateStr[j];
	szTemp[8] = 0;
	ListView_SetItemText(hwndLV, 0, 1, (LPSTR)szTemp);

	if (ComLogLookupIP == FALSE)
	{
		strcat(szLogEntry, inet_ntoa(Address->sin_addr));
		ListView_SetItemText(hwndLV, 0, 2, (LPSTR)inet_ntoa(Address->sin_addr));
	}
	else
	{
		hostent *DNSResult;
		DNSResult = gethostbyaddr((char*)&(Address->sin_addr), AddressLength, PF_INET);
		if (DNSResult == NULL)
		{
			strcat(szLogEntry, inet_ntoa(Address->sin_addr));
			ListView_SetItemText(hwndLV, 0, 2, (LPSTR)inet_ntoa(Address->sin_addr));
		}
		else
		{
			strcat(szLogEntry, DNSResult->h_name);
			ListView_SetItemText(hwndLV, 0, 2, (LPSTR)DNSResult->h_name);
		}
	}

	//perform reverse DNS look-up
	strcat(szLogEntry, " -");
	if ((AuthNameStr == NULL) || (AuthNameStr[0] == 0))
		strcat(szLogEntry, " -");
	else
	{
		while (AuthNameStr[i] != 0)
		{
			if ((AuthNameStr[i] == ' ') || (AuthNameStr[i] == '\t'))
				szConvAuthName[i] = '_';
			else
				szConvAuthName[i] = AuthNameStr[i];
			i++;
		}
		szConvAuthName[i] = 0;
		strcat(szLogEntry, " ");
		strcat(szLogEntry, szConvAuthName);
	}

	//authorized user name
	strcat(szLogEntry, " [");
	strcat(szLogEntry, DateStr);
	strcat(szLogEntry, "]");		//date of request
	strcat(szLogEntry, " \"");
	strcat(szLogEntry, MethodStr);
	strcat(szLogEntry, " ");
	strcat(szLogEntry, URIStr);
	strcat(szLogEntry, "\" ");		//request info
	strcat(szLogEntry, StatusCodeStr);
							//status of request
	strcat(szLogEntry, " ");
	ltoa(Size, szNum, 10);
	strcat(szLogEntry, szNum);	//number of bytes sent
	szCRLF[0]=13;
	szCRLF[1]=10;
	szCRLF[2]=0;
	strcat(szLogEntry, szCRLF);

	ListView_SetItemText(hwndLV, 0, 3, (LPSTR)URIStr);
	ListView_SetItemText(hwndLV, 0, 4, (LPSTR)StatusCodeStr);


	hFile = CreateFile(ComLogPath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(hFile, 0, NULL, FILE_END);
	WriteFile(hFile, szLogEntry, strlen(szLogEntry), &junk, NULL);
	CloseHandle(hFile);
	LeaveCriticalSection(&CommonLogCritSec);
}


//Logs a request reference
void HTTPLogRefEntry(char *URIStr, char *RefStr, char *DateStr)
{
	char szEntryStr[100];
	long lCount;

	if (RefLogEnabled == FALSE)
		return;
	
	szEntryStr[0] = 0;
	if ((RefStr == NULL) || (RefStr[0] == 0))
	RefStr = "Direct";/* KEY */
	EnterCriticalSection(&ReferenceLogCritSec);
	GetPrivateProfileString(URIStr/* section */, RefStr, "0", szEntryStr, 100, RefLogPath);
	lCount = atol(szEntryStr);
	lCount++;
	ltoa(lCount, szEntryStr, 10);
	strcat(szEntryStr, " ");
	strcat(szEntryStr, DateStr);
	WritePrivateProfileString(URIStr, RefStr, szEntryStr, RefLogPath);
	LeaveCriticalSection(&ReferenceLogCritSec);
}


//Setup variables and prepare logs for error messages
void openErrorLog()
{
	char szLogDir[MAX_PATH];

	GetCurrentDirectory(MAX_PATH, szLogDir);
	strcpy(ErrorLogPath, szLogDir);
	strcat(ErrorLogPath, "\\ERROR.TXT");

	logDebug("Log inited OK!\n");
	TRACE();

}

//Writes a message to the error log
void logError(char *Msg)
{
	HANDLE hErrorLog;
	DWORD dwNumWritten;

	hErrorLog = CreateFile(ErrorLogPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(hErrorLog, 0, 0, FILE_END);
	WriteFile(hErrorLog, "Error: ", 7, &dwNumWritten, NULL);
	WriteFile(hErrorLog, Msg, strlen(Msg), &dwNumWritten, NULL);
	WriteFile(hErrorLog, "\r\n", 2, &dwNumWritten, NULL);

	CloseHandle(hErrorLog);
}


//Writes a critical error to the error log
void logCriticalError(char *Msg)
{
	char szLastError[33], szMsgBox[200];
	DWORD dwNumWritten, dwLastError;
	HANDLE hErrorLog;

	dwLastError = GetLastError();
	hErrorLog = CreateFile(ErrorLogPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(hErrorLog, 0, 0, FILE_END);
	WriteFile(hErrorLog, "Critical Error: ", 16, &dwNumWritten, NULL);
	WriteFile(hErrorLog, Msg, strlen(Msg), &dwNumWritten, NULL);
	WriteFile(hErrorLog, "\r\n", 2, &dwNumWritten, NULL);
	ultoa(dwLastError, szLastError, 16);
	WriteFile(hErrorLog, "Last Error = 0x", 15, &dwNumWritten, NULL);
	WriteFile(hErrorLog, szLastError, strlen(szLastError), &dwNumWritten, NULL);
	WriteFile(hErrorLog, "\r\n", 2, &dwNumWritten, NULL);
	CloseHandle(hErrorLog);
	strcpy(szMsgBox, "Critical Error: ");
	strcat(szMsgBox, Msg);
	strcat(szMsgBox, "\nSavant will be shut down.");
	
	MessageBox(http->msgWindow, szMsgBox, "Savant Server", MB_OK | MB_ICONERROR);
	PostMessage(http->msgWindow, WM_DESTROY, 0, 0);

	CriticalErrorFlag = TRUE;
}


//Returns true if a critical error exists
BOOL gotCriticalError()
{
	return CriticalErrorFlag;
} 

//Cleans up after error logging
void closeErrorLog()
{
	HANDLE hErrorLog;
	DWORD dwNumWritten;

	hErrorLog = CreateFile(ErrorLogPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(hErrorLog, 0, 0, FILE_END);
	WriteFile(hErrorLog, "-\r\n", 3, &dwNumWritten, NULL);
	CloseHandle(hErrorLog);
}

void logDebug(char *format, ...)
{
	static char debugStr[1024];
#if 1
	va_list marker;

	va_start( marker, format );     /* Initialize variable arguments. */
	memset(debugStr, 0, sizeof(debugStr));

	/* vsprintf : param of va_list; sprintf : param of varied params such as 'format ...' */
	vsprintf(debugStr, format, marker);
	
	va_end( marker);
#else
	SNPRINTF(debugStr, sizeof(debugStr), format, __VA_ARGS__ );
#endif
	logError(debugStr );
	OutputDebugString(debugStr);
}



