/*
*
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <process.h>
#include <direct.h>

#include "savant.h"

extern HWND mainWindow;


static const DWORD CGITimeout = 5 * 60 * 1000; //5 min timeout


#define MAX_OTHER_CGI_HEADERS 10
#define CGI_ENV_SIZE 4096


struct CGIHTTPHeaders
{
  char Status[200];
  char Location[200];
  char ContentType[200];
  char Pragma[200];
  int NumOthers;
  char Others[MAX_OTHER_CGI_HEADERS][200];
};

struct CGIWatchdogParams
{
  HANDLE ProcessToWatch;
  HANDLE ResetTimeoutEvent;
  HANDLE StdoutWriteHandle;
  HANDLE StdoutReadHandle;
};


void CGIWatchdogThread(HGLOBAL);
void generateCGIEnv(char*, THREAD_INFO_T*,	REQ_INFO_T*, char*, char*);



static void _getCGIHeaders(CGIHTTPHeaders &Headers, BYTE *Buffer, DWORD NumInBuffer, DWORD &NumParsed,
                   BOOL &DontParse, BOOL &GotHeaders, int ThreadNum)
{
  BOOL fDone;
  char szLineBuffer[1024];
  int i, nBufferIndex;

  fDone = FALSE;
  nBufferIndex = NumParsed;
  do
  {
    i = 0;
    while ((nBufferIndex < NumInBuffer) && (Buffer[nBufferIndex] != 10))
    {
      if ((Buffer[nBufferIndex] != 10) && (Buffer[nBufferIndex] != 13))
      {
        szLineBuffer[i] = Buffer[nBufferIndex];
        i++;
      }
      nBufferIndex++;
    }
    if (nBufferIndex == NumInBuffer)
      return;
    else
    {
      szLineBuffer[i] = 0;
      nBufferIndex++;
      NumParsed = nBufferIndex;
    }
    if (szLineBuffer[0] == 0)
    {
      fDone = TRUE;
      GotHeaders = TRUE;
    }
    else
      if (strnicmp(szLineBuffer, "HTTP/", 5) == 0)
      {
        fDone = TRUE;
        NumParsed = 0;
        GotHeaders = TRUE;
        DontParse = TRUE;
      }
      else
        if (strnicmp(szLineBuffer, "Status:", 7) == 0)
        {
          i = 8;
          while ((szLineBuffer[i] != 0) && ((szLineBuffer[i] == ' ') || (szLineBuffer[i] == '\t')))
            i++;
          strcpy(Headers.Status, szLineBuffer + i);
        }
        else
          if (strnicmp(szLineBuffer, "Location:", 9) == 0)
          {
            i = 9;
            while ((szLineBuffer[i] != 0) && ((szLineBuffer[i] == ' ') || (szLineBuffer[i] == '\t')))
              i++;
            if (szLineBuffer[i] == '/')
            {
              strcpy(Headers.Location, "Location: http://");
              strcat(Headers.Location, SERVER_NAME());
              strcat(Headers.Location, szLineBuffer + i);
            }
            else
              strcpy(Headers.Location, szLineBuffer);
          }
          else
            if (strnicmp(szLineBuffer, "Content-type:", 13) == 0)
              strcpy(Headers.ContentType, szLineBuffer);
            else
              if (strnicmp(szLineBuffer, "Pragma:", 7) == 0)
                strcpy(Headers.Pragma, szLineBuffer);
              else
                if (Headers.NumOthers < MAX_OTHER_CGI_HEADERS)
                {
                  strcpy(Headers.Others[Headers.NumOthers], szLineBuffer);
                  Headers.NumOthers++;
                }
  }while (!fDone);
}


//Sends CGI headers to client
int _sendCGIHeaders(CGIHTTPHeaders &Headers, THREAD_INFO_T *thInfo, DWORD &NumSent, char *StatusCode)
{
	char szHeader[2048];
	int nHeaderLength, junk, i;

	if (Headers.Status[0] != 0)
	{
	strcpy(szHeader, "HTTP/1.1 ");
	strcat(szHeader, Headers.Status);
	strcat(szHeader, "\r\n");
	getWord(StatusCode, Headers.Status, 0, junk);
	}
	else
	if (Headers.Location[0] != 0)
	{
	strcpy(szHeader, "HTTP/1.1 302 MOVED\r\n");
	strcpy(StatusCode, "302");
	}
	else
	{
	strcpy(szHeader, "HTTP/1.1 200 OK\r\n");
	strcpy(StatusCode, "200");
	}
	if (Headers.Location[0] != 0)
	{
	strcat(szHeader, Headers.Location);
	strcat(szHeader, "\r\n");
	}
	if (Headers.Pragma[0] != 0)
	{
	strcat(szHeader, Headers.Pragma);
	strcat(szHeader, "\r\n");
	}
	else
	strcat(szHeader, "Pragma: no-cache\r\n");
	if (Headers.ContentType[0] != 0)
	{
	strcat(szHeader, Headers.ContentType);
	strcat(szHeader,"\r\n");
	}
	else
	strcat(szHeader, "Content-type: text/html\r\n");
	for (i=0; i < Headers.NumOthers; i++)
	{
	strcat(szHeader, Headers.Others[i]);
	strcat(szHeader, "\r\n");
	}
	strcat(szHeader, "Server: Savant/3.1\r\n");
	strcat(szHeader, "\r\n");
	nHeaderLength = strlen(szHeader);
	NumSent = nHeaderLength;
	
	return sendData(thInfo, (BYTE*)szHeader, nHeaderLength );
}


//Processes a CGI script/program, with appropriate logging and error handling
void processCGIScript(THREAD_INFO_T *thInfo, REQ_INFO_T *req, char *QueryStr, char *FilePath)
{
	BOOL fSentHeaders, fGotHeaders, fDontParse, fIOError;
	CGIHTTPHeaders headers;
	CGIWatchdogParams *lpWatchdogParams;
	char szStatusCode[10], szThreadNum[17], szExt[20], szCurDate[100];
	char szScriptEnv[CGI_ENV_SIZE];
	char szFileName[MAX_PATH], szDir[MAX_PATH], szCommandLine[MAX_PATH], szDefDir[MAX_PATH];
	char szCGIStderrFileName[MAX_PATH], szCGIStdinFileName[MAX_PATH];
	DWORD dwFileAttr, dwNumWritten, dwNumRead;
	DWORD dwNumInBuffer, dwNumParsed, dwTotalSent, dwTotalNumWritten;
	HANDLE hScriptStderr, hScriptStdin, hStdoutRead, hStdoutWrite;
	HANDLE hResetTimeoutEvent, hWatchdogParamMem;
	PROCESS_INFORMATION processInfo;
	SECURITY_ATTRIBUTES inheritSA;
	STARTUPINFO startUpInfo;
	SYSTEMTIME curDate;

	dwNumInBuffer = 0;
	dwNumParsed = 0;
	dwTotalSent = 0;
	dwTotalNumWritten = 0;
	fSentHeaders = FALSE;
	fGotHeaders = FALSE;
	fDontParse = FALSE;
	fIOError = FALSE;
	strcpy(szStatusCode, "200");
	dwFileAttr = GetFileAttributes(FilePath);
	if (dwFileAttr == 0xFFFFFFFF)
	{
		sendHTTPError(404, "File Not Found", "Could not find CGI script", thInfo, req);
		return;
	}										//makes sure script/program is not a directory
			//and does exist
	else
	if ((dwFileAttr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
	{
		sendHTTPError(405, "Method Not Supported", "This resource does not support query", thInfo, req);
		return;
	}
	generateCGIEnv(szScriptEnv, thInfo, req, QueryStr, FilePath);
	inheritSA.nLength = sizeof(SECURITY_ATTRIBUTES);
	inheritSA.bInheritHandle = TRUE;
	inheritSA.lpSecurityDescriptor = NULL;
			//setup inheritable security attributes

	itoa(thInfo->ThreadNum, szThreadNum, 10);
	strcpy(szCGIStderrFileName, SERVER_TEMP_DIR());
	strcat(szCGIStderrFileName, "CSE");
	strcat(szCGIStderrFileName, szThreadNum);
	strcat(szCGIStderrFileName, ".TXT");
	hScriptStderr = CreateFile(szCGIStderrFileName, GENERIC_WRITE, FILE_SHARE_READ,
	&inheritSA, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hScriptStderr == INVALID_HANDLE_VALUE)
	{
		logError("Failure to create CGI StdErr pipe");
		sendHTTPError(501, "Internal Server Error", "Failure to create CGI pipe", thInfo, req);
		return;
	}										//create standard error file

	SetFilePointer(hScriptStderr, 0, 0, FILE_END );
	strcpy(szCGIStdinFileName, SERVER_TEMP_DIR());
	strcat(szCGIStdinFileName, "CSI");
	strcat(szCGIStdinFileName, szThreadNum);
	strcat(szCGIStdinFileName, ".TXT");
	hScriptStdin = CreateFile(szCGIStdinFileName, GENERIC_WRITE, 0, NULL,	CREATE_ALWAYS,
	FILE_ATTRIBUTE_NORMAL, NULL);
	if (hScriptStdin == INVALID_HANDLE_VALUE)
	{
		logError("Failure to create CGI StdIn pipe");
		sendHTTPError(501, "Internal Server Error", "Failure to create CGI pipe", thInfo, req);
		return;
	}										//create standard input file

	while (dwTotalNumWritten < req->ContentLength)
	{
		WriteFile(hScriptStdin, req->Content + dwTotalNumWritten,
		req->ContentLength - dwTotalNumWritten, &dwNumWritten, NULL);
		dwTotalNumWritten = dwTotalNumWritten + dwNumWritten;
	}
	CloseHandle(hScriptStdin);
	hScriptStdin = CreateFile(szCGIStdinFileName, GENERIC_READ, 0, &inheritSA, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (CreatePipe(&hStdoutRead, &hStdoutWrite, &inheritSA, 4096) == false)
	{
		logError("Failure to create CGI pipe");
		sendHTTPError(501, "Internal Server Error", "Failure to create CGI pipe", thInfo, req);
		return;
	}

	splitPath(FilePath, szDir, szFileName);
	getExtension(szFileName, szExt);
	if ((strcmpi("EXE", szExt) == 0) || (strcmpi("BAT", szExt) == 0))
		szCommandLine[0] = 0;
	else									//executes CGI if it's a program
	{
		FindExecutable(FilePath, szDefDir, szCommandLine);
		strcat(szCommandLine, " ");
	}                          		//finds associated executable if CGI is a script

	strcat(szCommandLine, FilePath);
	if (strchr(QueryStr,'=') == NULL)
	{
		strcat(szCommandLine, " ");
		strcat(szCommandLine, QueryStr);
	}
	GetStartupInfo(&startUpInfo);
	startUpInfo.dwFlags = STARTF_USESHOWWINDOW |  STARTF_USESTDHANDLES;
	startUpInfo.wShowWindow = SW_HIDE;
	startUpInfo.hStdInput = hScriptStdin;
	startUpInfo.hStdOutput = hStdoutWrite;
	startUpInfo.hStdError = hScriptStderr;
	if (CreateProcess(NULL, szCommandLine, &inheritSA, &inheritSA, TRUE, DETACHED_PROCESS, szScriptEnv, szDir, &startUpInfo, &processInfo) == FALSE)
	{
		logError("Failure to create CGI Process");
		sendHTTPError(501, "Internal Server Error", "Failure to create CGI Process", thInfo, req);
		CloseHandle(hScriptStdin);
		CloseHandle(hScriptStderr);
		CloseHandle(hStdoutRead);
		CloseHandle(hStdoutWrite);
		return;
	}										//creates and starts CGI process

	hResetTimeoutEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	hWatchdogParamMem = GlobalAlloc(0, sizeof(CGIWatchdogParams));
	lpWatchdogParams = (CGIWatchdogParams*) GlobalLock(hWatchdogParamMem);
	lpWatchdogParams->ProcessToWatch = processInfo.hProcess;
	lpWatchdogParams->ResetTimeoutEvent = hResetTimeoutEvent;
	lpWatchdogParams->StdoutWriteHandle = hStdoutWrite;
	lpWatchdogParams->StdoutReadHandle = hStdoutRead;
	GlobalUnlock(hWatchdogParamMem);
	_beginthread(CGIWatchdogThread, 4096, (void *)hWatchdogParamMem);
			//starts a watchdog process

	fIOError = FALSE;
	if (strnicmp("nph-", szFileName, 4) == 0)
	{                              //headers are not to be parsed
		while(ReadFile(hStdoutRead, thInfo->IOBuffer, thInfo->IOBufferSize, &dwNumRead, NULL) == TRUE)
		{
			PulseEvent(hResetTimeoutEvent);
			if (!fIOError)
			{
				if (sendData(thInfo, thInfo->IOBuffer, dwNumRead) == -1)
					fIOError = TRUE;
				dwTotalSent = dwTotalSent + dwNumRead;
			}
		}
	}
	else
	{										//headers are parsed
		memset(&headers, 0, sizeof(CGIHTTPHeaders));
		while(ReadFile(hStdoutRead, thInfo->IOBuffer + dwNumInBuffer, thInfo->IOBufferSize - dwNumInBuffer, &dwNumRead, NULL) == TRUE)
		{
			PulseEvent(hResetTimeoutEvent);
			dwNumInBuffer = dwNumInBuffer + dwNumRead;
			if (!fGotHeaders)
				_getCGIHeaders(headers, thInfo->IOBuffer, dwNumInBuffer, dwNumParsed, fDontParse, fGotHeaders, thInfo->ThreadNum);
			if (fGotHeaders && (!fSentHeaders))
			{
				if (!fDontParse)
				_sendCGIHeaders(headers, thInfo, dwTotalSent, szStatusCode );
				fSentHeaders = TRUE;
			}
			
			if (fSentHeaders)
			{
				if (!fIOError)
				{
					if (sendData(thInfo, thInfo->IOBuffer + dwNumParsed,  dwNumInBuffer - dwNumParsed) == -1)
						fIOError = TRUE;
					dwTotalSent = dwTotalSent + (dwNumInBuffer - dwNumParsed);
				}
			}
			dwNumInBuffer = 0;
			dwNumParsed = 0;
		}
	}
	CloseHandle(hScriptStdin);
	CloseHandle(hScriptStderr);
	CloseHandle(hStdoutRead);
	//  CloseHandle(hStdoutWrite);
	DeleteFile(szCGIStderrFileName);
	DeleteFile(szCGIStdinFileName);
	thInfo->KeepAlive = FALSE; //clean up after CGI execution

	GetLocalTime(&curDate);
	dateToOffsetFormatStr(&curDate, szCurDate);
	HTTPLogCommonEntry(&(thInfo->ClientSockAddr), thInfo->AddrLen,
	req->AuthorizedUserStr, szCurDate, req->MethodStr,
	req->URIStr, szStatusCode, dwTotalSent);
	STATUS_SENDOUT_INFO(req->URIStr, szCurDate, dwTotalSent);
	HTTPLogRefEntry(req->URIStr, req->RefererStr, szCurDate);
			//log CGI transaction
}


//Watches CGI process execution, waits for time out or termination to close
//CGI process pipes and files.
void CGIWatchdogThread(HGLOBAL ParamMem)
{
  CGIWatchdogParams *lpParameters;
  DWORD dwWaitResult;
  HANDLE hProcessToWatch, hResetTimeoutEvent, hStdoutWrite, hWaitObjects[2];

  lpParameters = (CGIWatchdogParams *)GlobalLock(ParamMem);
  hProcessToWatch = lpParameters->ProcessToWatch;
  hResetTimeoutEvent = lpParameters->ResetTimeoutEvent;
  hStdoutWrite = lpParameters->StdoutWriteHandle;
  											//gets CGI process parameters

  GlobalUnlock(ParamMem);
  GlobalFree(ParamMem);
  hWaitObjects[0] = hResetTimeoutEvent;
  hWaitObjects[1] = hProcessToWatch;
  do
  {
    dwWaitResult = WaitForMultipleObjects(2, hWaitObjects, FALSE, CGITimeout);
  } while(dwWaitResult == WAIT_OBJECT_0);
  											//checks for process time out/termination

  if (dwWaitResult == WAIT_TIMEOUT)
  {
    TerminateProcess(hProcessToWatch, -1);
	 WaitForSingleObject(hProcessToWatch, CGITimeout);
  }										//kill process
  Sleep(1000);
  CloseHandle(hStdoutWrite);
  _endthread();
}



	//Creates environment segment to pass to a CGI process
void generateCGIEnv(char *ScriptEnv, THREAD_INFO_T *thInfo, REQ_INFO_T *req, char *QueryStr, char*)
{
	char szNum[33], szHostName[200];
	char *lpszAddr;
	hostent *DNSResult;
	int nScriptEnvIndex, nLength, i;

	nScriptEnvIndex = 0;
	if (req->ContentEncodingStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "CONTENT_ENCODING=", 13);
		nScriptEnvIndex = nScriptEnvIndex + 13;
		nLength = strlen(req->ContentEncodingStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->ContentEncodingStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}
	
	if (req->ContentTypeStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "CONTENT_TYPE=", 13);
		nScriptEnvIndex = nScriptEnvIndex + 13;
		nLength = strlen(req->ContentTypeStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->ContentTypeStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}
	if (req->ContentLengthStr[0] == '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "CONTENT_LENGTH=0", 17);
		nScriptEnvIndex = nScriptEnvIndex + 17;
	}
	else
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "CONTENT_LENGTH=", 15);
		nScriptEnvIndex = nScriptEnvIndex + 15;
		nLength = strlen(req->ContentLengthStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->ContentLengthStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}

	memcpy(ScriptEnv + nScriptEnvIndex, "SERVER_SOFTWARE=Savant/3.1", 27);
	nScriptEnvIndex = nScriptEnvIndex + 27;
	memcpy(ScriptEnv + nScriptEnvIndex, "SERVER_NAME=", 12);
	nScriptEnvIndex = nScriptEnvIndex + 12;
	nLength = strlen(SERVER_NAME()) + 1;
	memcpy(ScriptEnv + nScriptEnvIndex, SERVER_NAME(), nLength);
	nScriptEnvIndex = nScriptEnvIndex + nLength;
	memcpy(ScriptEnv + nScriptEnvIndex, "GATEWAY_INTERFACE=CGI/1.1", 26);
	nScriptEnvIndex = nScriptEnvIndex + 26;
	memcpy(ScriptEnv + nScriptEnvIndex, "REQUEST_METHOD=", 15);
	nScriptEnvIndex = nScriptEnvIndex + 15;
	nLength = strlen(req->MethodStr) + 1;
	memcpy(ScriptEnv + nScriptEnvIndex, req->MethodStr, nLength);
	nScriptEnvIndex = nScriptEnvIndex + nLength;
	memcpy(ScriptEnv + nScriptEnvIndex, "SERVER_PROTOCOL=", 16);
	nScriptEnvIndex = nScriptEnvIndex + 16;
	nLength = strlen(req->VersionStr) + 1;
	memcpy(ScriptEnv + nScriptEnvIndex, req->VersionStr, nLength);
	nScriptEnvIndex = nScriptEnvIndex + nLength;
	itoa( PORT_NUM(), szNum, 10);
	memcpy(ScriptEnv + nScriptEnvIndex, "SERVER_PORT=", 12);
	nScriptEnvIndex = nScriptEnvIndex + 12;
	nLength = strlen(szNum) + 1;
	memcpy(ScriptEnv + nScriptEnvIndex, szNum, nLength);
	nScriptEnvIndex = nScriptEnvIndex + nLength;

	if (req->AuthorizedUserStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "REMOTE_USER=", 12);
		nScriptEnvIndex = nScriptEnvIndex + 12;
		nLength = strlen(req->AuthorizedUserStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->AuthorizedUserStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
		memcpy(ScriptEnv + nScriptEnvIndex, "AUTH_TYPE=Basic", 16);
		nScriptEnvIndex = nScriptEnvIndex + 16;
	}

	memcpy(ScriptEnv + nScriptEnvIndex, "REMOTE_HOST=", 12);
	nScriptEnvIndex = nScriptEnvIndex + 12;
	if ( cfg->ScriptDNS == TRUE)
		DNSResult = gethostbyaddr((char *)&(thInfo->ClientSockAddr.sin_addr), thInfo->AddrLen, PF_INET);
	else
		DNSResult = NULL;
	
	if (DNSResult == NULL)
		strcpy(szHostName, inet_ntoa(thInfo->ClientSockAddr.sin_addr));
	else
		strcpy(szHostName, DNSResult->h_name);
	nLength = strlen(szHostName) + 1;
	memcpy(ScriptEnv + nScriptEnvIndex, szHostName, nLength);
	nScriptEnvIndex = nScriptEnvIndex + nLength;
	lpszAddr = inet_ntoa(thInfo->ClientSockAddr.sin_addr);
	memcpy(ScriptEnv + nScriptEnvIndex, "REMOTE_ADDR=", 12);
	nScriptEnvIndex = nScriptEnvIndex + 12;
	nLength = strlen(lpszAddr) + 1;
	memcpy(ScriptEnv + nScriptEnvIndex, lpszAddr, nLength);
	nScriptEnvIndex = nScriptEnvIndex + nLength;
	memcpy(ScriptEnv + nScriptEnvIndex, "QUERY_STRING=", 13);
	nScriptEnvIndex = nScriptEnvIndex + 13;
	nLength = strlen(QueryStr) + 1;
	memcpy(ScriptEnv + nScriptEnvIndex, QueryStr, nLength);
	nScriptEnvIndex = nScriptEnvIndex + nLength;
	memcpy(ScriptEnv + nScriptEnvIndex, "PATH_INFO=", 10);
	nScriptEnvIndex = nScriptEnvIndex + 10;
	nLength = strlen(req->PathInfoStr) + 1;
	memcpy(ScriptEnv + nScriptEnvIndex, req->PathInfoStr, nLength);
	nScriptEnvIndex = nScriptEnvIndex + nLength;
	memcpy(ScriptEnv + nScriptEnvIndex, "PATH_TRANSLATED=", 16);
	nScriptEnvIndex = nScriptEnvIndex + 16;
	nLength = strlen(req->PathTranslatedStr) + 1;
	memcpy(ScriptEnv + nScriptEnvIndex, req->PathTranslatedStr, nLength);
	nScriptEnvIndex = nScriptEnvIndex + nLength;
	memcpy(ScriptEnv + nScriptEnvIndex, "SCRIPT_NAME=", 12);
	nScriptEnvIndex = nScriptEnvIndex + 12;
	nLength = strlen(req->ScriptNameStr) + 1;
	memcpy(ScriptEnv + nScriptEnvIndex, req->ScriptNameStr, nLength);
	nScriptEnvIndex = nScriptEnvIndex + nLength;
	if (req->UserAgentStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "HTTP_USER_AGENT=", 16);
		nScriptEnvIndex = nScriptEnvIndex + 16;
		nLength = strlen(req->UserAgentStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->UserAgentStr, nLength);
		nScriptEnvIndex += nLength;
	}

	if (req->AcceptStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "HTTP_ACCEPT=", 12);
		nScriptEnvIndex = nScriptEnvIndex + 12;
		nLength = strlen(req->AcceptStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->AcceptStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}

	if (req->AcceptLangStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "HTTP_ACCEPT_LANGUAGE=", 12);
		nScriptEnvIndex = nScriptEnvIndex + 12;
		nLength = strlen(req->AcceptLangStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->AcceptLangStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}

	if (req->RefererStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "HTTP_REFERER=", 13);
		nScriptEnvIndex = nScriptEnvIndex + 13;
		nLength = strlen(req->RefererStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->RefererStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}
	if (req->IfModSinceStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "HTTP_PRAGMA=", 12);
		nScriptEnvIndex = nScriptEnvIndex + 12;
		nLength = strlen(req->IfModSinceStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->IfModSinceStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}

	if (req->PragmaStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "HTTP_PRAGMA=", 12);
		nScriptEnvIndex = nScriptEnvIndex + 12;
		nLength = strlen(req->PragmaStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->PragmaStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}

	if (req->FromStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "HTTP_FROM=", 12);
		nScriptEnvIndex = nScriptEnvIndex + 12;
		nLength = strlen(req->FromStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->FromStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}

	if (req->DateStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "HTTP_DATE=", 12);
		nScriptEnvIndex = nScriptEnvIndex + 12;
		nLength = strlen(req->DateStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->DateStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}

	if (req->MIMEVerStr[0] != '\0')
	{
		memcpy(ScriptEnv + nScriptEnvIndex, "HTTP_MIME_VERSION=", 12);
		nScriptEnvIndex = nScriptEnvIndex + 12;
		nLength = strlen(req->MIMEVerStr) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, req->MIMEVerStr, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}

	RequestHeaderT OtherHeader;
	for (i=0; i<req->NumOtherHeaders; i++)
	{
		OtherHeader = req->OtherHeaders[i];
		memcpy(ScriptEnv + nScriptEnvIndex, "HTTP_", 5);
		nScriptEnvIndex = nScriptEnvIndex + 5;
		nLength = strlen(OtherHeader.Var);
		memcpy(ScriptEnv + nScriptEnvIndex, OtherHeader.Var, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
		memcpy(ScriptEnv + nScriptEnvIndex, "=", 1);
		nScriptEnvIndex = nScriptEnvIndex + 1;
		nLength = strlen(OtherHeader.Val) + 1;
		memcpy(ScriptEnv + nScriptEnvIndex, OtherHeader.Val, nLength);
		nScriptEnvIndex = nScriptEnvIndex + nLength;
	}

	ScriptEnv[nScriptEnvIndex] = 0;
}


