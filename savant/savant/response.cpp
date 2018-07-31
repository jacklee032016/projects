//****************************************************************************
//*       MODULE: response.cpp
//*      PURPOSE: Sends the requested file or hands the request off to the 
//*               appropriate content handler
//*        PHASE: Response
//****************************************************************************



#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <process.h>

#include "savant.h"
#include "isapi.h"

#define IS_NOT_EXIST(dwFileAttr) \
			((dwFileAttr == 0xFFFFFFFF) )


#define IS_NOT_FILE(dwFileAttr) \
	((dwFileAttr == 0xFFFFFFFF) || ((dwFileAttr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY))
	
#define IS_DIRECTORY(dwFileAttr) \
		 ((dwFileAttr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
	

//Sends a "not modified" message to a client socket (HTTP 1.1 compatibility)
static void _sendHTTPNotModified(THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	char szHeader[500], szCurLocalTime[100];
	int nHeaderLength;
	SYSTEMTIME curLocalTime;

	STATUS_PROCESS_INCREASE();
	GetLocalTime(&curLocalTime);
	szHeader[0] = 0;
	strcat(szHeader, "HTTP/1.1 304 Not Modified\r\n");
	strcat(szHeader, "Server: Savant/3.1\r\n");
	if (strcmpi(req->ConnectionStr, "Keep-Alive") == 0)
	{
		strcat(szHeader, "Connection: Keep-Alive\r\n");
		strcat(szHeader, "Keep-Alive: timeout=180\r\n");
		thInfo->KeepAlive = TRUE;
	}
	else
		thInfo->KeepAlive = FALSE;
	
	strcat(szHeader, "Content-Length: 0\r\n");
	strcat(szHeader, "\r\n");
	nHeaderLength = strlen(szHeader);	//build redirection header

	sendData(thInfo, (BYTE*)szHeader, nHeaderLength);
								//send redirection header to client socket

	dateToOffsetFormatStr(&curLocalTime, szCurLocalTime);
	HTTPLogCommonEntry(&(thInfo->ClientSockAddr), thInfo->AddrLen, 
		req->AuthorizedUserStr, szCurLocalTime, req->MethodStr,
		req->URIStr, "304", nHeaderLength);
	 				//log redirection
	}


//Checks to see if a file was modified since the last time a client socket requested it
static BOOL _checkIMSDate(SYSTEMTIME &FileTime, char *IMSStr)
{
	SYSTEMTIME IMSTime;

	if (strToDate(IMSStr, &IMSTime) != 0)
		return TRUE;
	if(FileTime.wYear > IMSTime.wYear)
		return TRUE;
	if(FileTime.wYear < IMSTime.wYear)
		return FALSE;
	if(FileTime.wMonth > IMSTime.wMonth)
		return TRUE;
	if(FileTime.wMonth < IMSTime.wMonth)
		return FALSE;
	if(FileTime.wDay > IMSTime.wDay)
		return TRUE;
	if(FileTime.wDay < IMSTime.wDay)
		return FALSE;
	if(FileTime.wHour > IMSTime.wHour)
		return TRUE;
	if(FileTime.wHour < IMSTime.wHour)
		return FALSE;
	if(FileTime.wMinute > IMSTime.wMinute)
		return TRUE;
	if(FileTime.wMinute < IMSTime.wMinute)
		return FALSE;
	if(FileTime.wSecond > IMSTime.wSecond)
		return TRUE;
	if(FileTime.wSecond < IMSTime.wSecond)
		return FALSE;
	
	return FALSE;
}

//Sends a client socket an access-right verification challenge
static void _sendHTTPBasicChallenge(char *Realm, THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	BOOL bFileFound;
	char szErrorFile[MAX_PATH];
	char szHeader[512], szBody[512], szBodyLength[33], szCurLocalTime[100];
	DWORD dwBodyLength, dwFileSizeLo, dwFileSizeHi;
	HANDLE hFile;
	int nHeaderLength;
	SYSTEMTIME localTime;

	strcpy(szErrorFile, ERROE_MSG_PATH());
	strcat(szErrorFile, "401.HTML");
	hFile = CreateFile(szErrorFile, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		bFileFound = FALSE;
	else
		bFileFound = TRUE;
	
	if (bFileFound == TRUE)
	{
		dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);
		dwBodyLength = dwFileSizeLo;
		CloseHandle(hFile);
	}										//see if HTML error file exists
	else
	{
		strcpy(szBody, "<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY>\n");
		strcat(szBody, "<H1>ACCESS DENIED</H1>\n");
		strcat(szBody, "You do not have access to ");
		strcat(szBody, Realm);
		strcat(szBody, "\n</BODY></HTML>");
		dwBodyLength = strlen(szBody);
	}										//build default HTML error if file does not exist

	szHeader[0] = 0;
	strcat(szHeader, "HTTP/1.1 401 Access Denied\r\n");
	strcat(szHeader, "Server: Savant/3.1\r\n");
	strcat(szHeader, "WWW-Authenticate: Basic realm=\"");
	strcat(szHeader, Realm);
	strcat(szHeader, "\"\r\n");
	thInfo->KeepAlive = FALSE;
	strcat(szHeader, "Content-Type: text/html\n");
	ultoa(dwBodyLength, szBodyLength, 10);
	strcat(szHeader, "Content-Length: ");
	strcat(szHeader, szBodyLength);
	strcat(szHeader, "\r\n");
	strcat(szHeader, "\r\n");
	nHeaderLength = strlen(szHeader);	//build HTTP header

	if ((bFileFound == TRUE) && (strcmpi(req->MethodStr, "HEAD") != 0))
		sendFile(thInfo, szErrorFile, (BYTE*)szHeader, strlen(szHeader), NULL, 0);
	else
		sendData(thInfo, (BYTE*)szHeader, strlen(szHeader));
	
	if ((bFileFound == FALSE) && (strcmpi(req->MethodStr, "HEAD") != 0))
		sendData(thInfo, (BYTE*)szBody, dwBodyLength );
	//send HTTP header and HTML error to client socket

	GetLocalTime(&localTime);
	dateToOffsetFormatStr(&localTime, szCurLocalTime);

	HTTPLogCommonEntry(&(thInfo->ClientSockAddr), thInfo->AddrLen,
		req->AuthorizedUserStr, szCurLocalTime, req->MethodStr, req->URIStr, "401", nHeaderLength + dwBodyLength);
	//log data request
}


//Processes a HTTP v0.9 request (simple)
static void _processSimpleRequest(THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	DWORD dwFileAttr;
	HANDLE hFile;
	int nResult;

	nResult = mapHTTPPath(req->URIStr, thInfo, req );
	if ( thInfo->parsedReq.scriptType != SCRIPT_TYPE_NONE)
	{
		sendHTTPError(403, "Method Not Supported", "CGI not supported for simple requests", thInfo, req);
		return;
	}
	
	if (nResult !=  MP_STATUS_PATH_FOUND)
	{
		sendData( thInfo, (BYTE*)"File not found", 14);
		return;
	}

	dwFileAttr = GetFileAttributes( thInfo->parsedReq.szFilePath);
	if(IS_NOT_EXIST(dwFileAttr))
	{
		sendData(thInfo, (BYTE*)"File not found", 14 );
		return;
	}
	
	hFile = CreateFile( thInfo->parsedReq.szFilePath, 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		sendData(thInfo, (BYTE*)"File IO Error", 14);
		return;
	}

	CloseHandle(hFile);
	sendFile(thInfo,  thInfo->parsedReq.szFilePath, NULL, 0, NULL, 0);
}

//Sends a file to a client socket with appropriate logging
static void _sendHTTPFile(char *FileName, THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	char szHeader[512], szContentLength[34], szCurDate[100], szFileDate[100];
	char szCurLocalTime[100];
	char *lpszContentType;
	DWORD dwFileSize, dwFileSizeLo, dwFileSizeHi;
	FILETIME lastWriteFTime;
	HANDLE hFile;
	SYSTEMTIME lastWriteDate, curLocalTime, curTime;

	STATUS_PROCESS_INCREASE();
	GetSystemTime(&curTime);
	dateToOffsetFormatStr(&curTime, szCurDate);
	hFile = CreateFile(FileName, 0, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		logError("File IO Error");
		sendHTTPError(500, "Internal Server Error", "Failure to open requested file", thInfo, req);
		return;
	}
	
	dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);
	dwFileSize = dwFileSizeLo;
	if (GetFileTime(hFile, NULL, NULL, &lastWriteFTime) != TRUE)
	{
		logError("Invalid or missing file time");
		CloseHandle(hFile);
		sendHTTPError(500, "Internal Server Error", "Failure to get requested file date", thInfo, req);
		return;
	}
	CloseHandle(hFile);			//verify that file exists and is transferrable

	if (FileTimeToSystemTime(&lastWriteFTime, &lastWriteDate) != TRUE)
	{
		logError("Couldn't convert file times");
		CloseHandle(hFile);
		sendHTTPError(500, "Internal Server Error", "Failure to convert file time", thInfo, req);
		return;
	}
	
	if ((req->IfModSinceStr[0] != 0) &&  _checkIMSDate(lastWriteDate, req->IfModSinceStr) == FALSE)
	{
		_sendHTTPNotModified(thInfo, req);
		return;
	}
	
	dateToRFCFormatStr(&lastWriteDate, szFileDate);
	szHeader[0] = 0;
	strcat(szHeader, "HTTP/1.1 200 OK\r\n");
	strcat(szHeader, "Server: Savant/3.1\r\n");
	if (strcmpi(req->ConnectionStr, "Keep-Alive") == 0)
	{
		strcat(szHeader, "Connection: Keep-Alive\r\n");
		strcat(szHeader, "Keep-Alive: timeout=180\r\n");
		thInfo->KeepAlive = TRUE;
	}
	else
		thInfo->KeepAlive = FALSE;
	
	strcat(szHeader, "Last-Modified: ");
	strcat(szHeader, szFileDate);
	strcat(szHeader, "\r\n");
	lpszContentType = getHTTPMIMEByPath(FileName);
	strcat(szHeader, "Content-Type: ");
	if (lpszContentType == NULL)
		strcat(szHeader, "application/octet-stream");
	else
		strcat(szHeader, lpszContentType);
	
	strcat(szHeader, "\r\n");
	ltoa(dwFileSize, szContentLength, 10);
	strcat(szHeader, "Content-Length: ");
	strcat(szHeader, szContentLength);
	strcat(szHeader, "\r\n");
	strcat(szHeader, "\r\n");			//builds HTTP header

	if (strcmp(req->MethodStr, "HEAD") != 0)
		sendFile(thInfo, FileName, (BYTE*) szHeader, strlen(szHeader), NULL, 0);
	//send file using HTTP protocol
	else
		sendData(thInfo, (BYTE*)szHeader, strlen(szHeader));
	//send HTTP header
	
	GetLocalTime(&curLocalTime);
	dateToOffsetFormatStr(&curLocalTime, szCurLocalTime);
	HTTPLogCommonEntry(&(thInfo->ClientSockAddr), thInfo->AddrLen, req->AuthorizedUserStr, szCurLocalTime, req->MethodStr,
		req->URIStr, "200", dwFileSize);
	STATUS_SENDOUT_INFO(req->URIStr, szCurLocalTime, dwFileSize);
	HTTPLogRefEntry(req->URIStr, req->RefererStr, szCurLocalTime);
	//log the transfer
}

//Parses request, and sends to proper function to send a response or handle an error
void dispatchRequest(THREAD_INFO_T *thInfo)
{
	int nGetHeadersResult;
	REQ_INFO_T req;

	memset(&req, 0 , sizeof(REQ_INFO_T));
	
	setSavantToolTip(TRUE);
	
	do
	{
		nGetHeadersResult = getHTTPHeaders(thInfo, &req);

		switch(nGetHeadersResult)
		{
			case GH_SIMPLE_REQUEST:
				_processSimpleRequest(thInfo, &req);
				thInfo->KeepAlive = FALSE;
				break;
				
			case GH_10_REQUEST:
				process10Request(thInfo, &req);
				break;
				
			case GH_UNKNOWN_VERSION:
				sendHTTPError(400, "HTTP Version not supported", "Only 0.9 and 1.X requests supported", thInfo, &req);
				break;
				
			case GH_ERROR:
				thInfo->KeepAlive = FALSE;
				break;
		}

		//determine which HTTP version is being used to
		//make the request, and pass to proper function
		cleanUpHTTPHeaders(thInfo, &req);
	} while (thInfo->KeepAlive == TRUE);
	
	closeSocket(thInfo->ClientSocket);

	setSavantToolTip(FALSE);
}

static int __responseWithLocalFile(THREAD_INFO_T *thInfo, REQ_INFO_T *req )
{
	char szLocalRealm[MAX_PATH], szIndexPath[MAX_PATH], szNewURL[MAX_PATH];
	char szExtraPath[MAX_PATH], szScriptFilePath[MAX_PATH], szExtension[20], szJunk[32];
	DWORD dwFileAttr, dwIndexAttr;
	int filePathLen = strlen(thInfo->parsedReq.szFilePath);
	
	if (thInfo->parsedReq.szFilePath[filePathLen - 1] == '\\')
	{
		thInfo->parsedReq.szFilePath[filePathLen - 1] = 0;
	}	

	logDebug("Local file '%s'", thInfo->parsedReq.szFilePath);
	dwFileAttr = GetFileAttributes(thInfo->parsedReq.szFilePath);
	if(IS_NOT_EXIST(dwFileAttr) )
	{
		logDebug("Local file '%s' is not exist!", thInfo->parsedReq.szFilePath);
		sendHTTPError(404, "File Not Found", "Could not find the requested element", thInfo, req);
		return 0;
	}

	TRACE();
	if(IS_DIRECTORY(dwFileAttr))
	{/* DIR */
		logDebug("Local file '%s' is directory!", thInfo->parsedReq.szFilePath);
		strcpy(szIndexPath, thInfo->parsedReq.szFilePath);
		strcat(szIndexPath, "\\");
		strcat(szIndexPath, cfg->IndexFileNameStr );
		logDebug("local file of '%s'", szIndexPath);
		
		dwIndexAttr = GetFileAttributes(szIndexPath);
		if(IS_NOT_EXIST(dwFileAttr) )
		{
			if (thInfo->parsedReq.bAllowDirList)
			{
#if 1			
				/* when it is a dir*/
				logDebug("Files List in of '%s'", szIndexPath);
				sendHTTPDirList(thInfo->parsedReq.szFilePath, thInfo->parsedReq.szRemoteRealm, thInfo, req);
#else
				/* when it is a dir*/
				logDebug("Redirect in of '%s'", szIndexPath);
				strcpy(szNewURL, "http://");
				strcat(szNewURL, SERVER_NAME());
				strcat(szNewURL, thInfo->parsedReq.szURI);
				strcat(szNewURL, "/");
				sendHTTPRedirect(szNewURL, thInfo, req);
#endif
			}
			else
			{
				TRACE();
				sendHTTPError(404, "File Not Found", "Could not find the requested element", thInfo, req);
			}

			return 0;
		}
#if 0
		if(IS_DIRECTORY(dwFileAttr) )
		{
				TRACE();
			strcpy(szNewURL, "http://");
			strcat(szNewURL, SERVER_NAME());
			if (PORT_NUM() != 80)
			{
				strcat(szNewURL, ":");
				strcat(szNewURL, itoa(PORT_NUM(), szJunk, 10)); //?? szJunk , how is assigned value
			}
			strcat(szNewURL, thInfo->parsedReq.szURI);
			strcat(szNewURL, cfg->IndexFileNameStr );
				TRACE();
			sendHTTPRedirect(szNewURL, thInfo, req);
			return 0;
		}
#endif

		TRACE();
		_sendHTTPFile(szIndexPath, thInfo, req);

		return 0;
	}

				TRACE();
	getExtension(thInfo->parsedReq.szFilePath, szExtension);
	if (strcmpi("map", szExtension) == 0)
	{
				TRACE();
		processImageMap(thInfo, req, thInfo->parsedReq.szQuery, thInfo->parsedReq.szFilePath);
	}
	else
	{
				TRACE();
		_sendHTTPFile(thInfo->parsedReq.szFilePath, thInfo, req);
	}

	return 0;
}

static int __responseWithScript(THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	char szIndexPath[MAX_PATH], szNewURL[MAX_PATH];
	char szExtraPath[MAX_PATH], szScriptFilePath[MAX_PATH], szExtension[20], szJunk[32];
	DWORD dwFileAttr, dwIndexAttr;
	char *lpszExtraPathWork;
	int nScripting, nMapResult, nFilePathLen, nScriptNameStrLen, i;
	int ScriptFilePathStrLen;

	int LocalRealmStrLen = strlen(thInfo->parsedReq.szLocalRealm);
	
	
	strcpy(szExtraPath, thInfo->parsedReq.szFilePath + LocalRealmStrLen);
	strcpy(szScriptFilePath, thInfo->parsedReq.szLocalRealm);
	
	ScriptFilePathStrLen = strlen(szScriptFilePath);
	lpszExtraPathWork = szExtraPath;
	dwFileAttr = GetFileAttributes(szScriptFilePath);
		

	while (IS_NOT_FILE(dwFileAttr) && (lpszExtraPathWork[0] != '\0'))
	{
		szScriptFilePath[ScriptFilePathStrLen] = lpszExtraPathWork[0];
		ScriptFilePathStrLen++;
		lpszExtraPathWork++;
		while((lpszExtraPathWork[0] != 0) && (lpszExtraPathWork[0] != '\\'))
		{
			szScriptFilePath[ScriptFilePathStrLen] = lpszExtraPathWork[0];
			ScriptFilePathStrLen++;
			lpszExtraPathWork++;
		}
		
		szScriptFilePath[ScriptFilePathStrLen] = '\0';
		dwFileAttr = GetFileAttributes(szScriptFilePath);
	}

	strcpy(req->PathInfoStr, lpszExtraPathWork);
	strcpy(req->PathTranslatedStr, szScriptFilePath);
	i = strlen(req->PathTranslatedStr) + 1;

	while ((i > 0) && (req->PathTranslatedStr[i] != '\\') && ( req->PathTranslatedStr[i] != '/') )
		i--;

	req->PathTranslatedStr[i] = '\0';
	strcat(req->PathTranslatedStr, req->PathInfoStr);
	i = 0;

	//finds CGI script/program file
	while(req->PathInfoStr[i] != '\0')
	{
		if (req->PathInfoStr[i] == '\\')
			req->PathInfoStr[i] = '/';
		i++;
	}

	//convert slash direction
	nScriptNameStrLen = strlen(thInfo->parsedReq.szURI) - strlen(req->PathInfoStr);
	strncpy(req->ScriptNameStr, thInfo->parsedReq.szURI, nScriptNameStrLen);
	req->ScriptNameStr[nScriptNameStrLen] = '\0';

	if (IS_NOT_FILE(dwFileAttr) )
	{
		sendHTTPError(404, "File Not Found", "Could not find the requested element", thInfo, req);
		return 0;
	}

	switch(nScripting)
	{
		case SCRIPT_TYPE_CGI:
			processCGIScript(thInfo, req, thInfo->parsedReq.szQuery, szScriptFilePath);
			break;
			
		case SCRIPT_TYPE_WINCGI:
			processWinCGIScript(thInfo, req, thInfo->parsedReq.szQuery, szScriptFilePath);
			break;
			
		case SCRIPT_TYPE_ISAPI:
			processISAPIScript(thInfo, req, thInfo->parsedReq.szQuery, szScriptFilePath);
			break;
			
		default:
			sendHTTPError(500, "Internal Server Error", "Unknown scripting value", thInfo, req);
			break;
	}

	return 0;
}

//Processes a 1.0 or 1.1 HTTP request
void process10Request(THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	char szIndexPath[MAX_PATH], szNewURL[MAX_PATH];
	char szExtraPath[MAX_PATH], szScriptFilePath[MAX_PATH], szExtension[20], szJunk[32];
	char *lpszExtraPathWork;
	DWORD dwFileAttr, dwIndexAttr;
	int nMapResult, nFilePathLen, nScriptNameStrLen, i;


	splitQuery(thInfo, req);
#if 0 ///??? why?
	if ((szURI[1] == '%') && (szURI[2] == '0') && (szURI[3] == '0'))
	{
		sendHTTPError(403, "Forbidden", "You do not have access to this resource", thInfo, req );
		return;
	}
	logDebug("Splitted URI is '%s' + '%s'", szURI, szQuery);
#endif

	TRACE();

	nMapResult = mapHTTPPath(thInfo->parsedReq.szURI, thInfo, req);
	switch(nMapResult)
	{
		case MP_STATUS_FORBIDDEN:
			sendHTTPError(403, "Forbidden", "You do not have access to this resource", thInfo, req);
			return;
			
		case MP_STATUS_NO_ACCESS:
			_sendHTTPBasicChallenge(thInfo->parsedReq.szRemoteRealm, thInfo, req);
			return;
			
		case MP_STATUS_REDIRECT:
			sendHTTPError(501, "Internal Server Error", "Mapped redirection not supported", thInfo, req);
			return;
			
		case MP_STATUS_ERROR:
			sendHTTPError(500, "Internal Server Error", "Error mapping path", thInfo, req);
			return;
	}
	//maps virtual path and gets access attributes
	
	TRACE();
	if (thInfo->parsedReq.scriptType== SCRIPT_TYPE_NONE)
	{
		if (!((strcmp(req->MethodStr, "GET" ) == 0) || (strcmp(req->MethodStr, "HEAD") == 0)))
		{
			sendHTTPError(405, "Method Not Supported", "Only GET and HEAD requests supported for this resource", thInfo, req);
			return;
		}
	}
	
	
	if (thInfo->parsedReq.scriptType == SCRIPT_TYPE_NONE)
	{//formats and sends a HTTP file
	TRACE();
		__responseWithLocalFile(thInfo, req);
	}
	else
	{
	TRACE();
		__responseWithScript(thInfo, req);
	}
}


//Sends an error message to a client socket
void sendHTTPError(int ErrorNum, char *ErrorTitleStr, char *ErrorDescStr, THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	BOOL bFileFound;
	char szErrorFile[MAX_PATH], szHeader[512], szBody[512], szErrorNum[17];
	char szBodyLength[17], szCurLocalTime[100];
	DWORD dwBodyLength, dwFileSizeLo, dwFileSizeHi;
	HANDLE hFile;
	int nHeaderLength;
	SYSTEMTIME curLocalTime;

	STATUS_PROCESS_INCREASE();
	itoa(ErrorNum, szErrorNum, 10);
	strcpy(szErrorFile, ERROE_MSG_PATH());
	strcat(szErrorFile, szErrorNum);
	strcat(szErrorFile, ".HTML");
	hFile = CreateFile(szErrorFile, 0, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		bFileFound = FALSE;
	else
		bFileFound = TRUE;
	
	if (bFileFound == TRUE)
	{//use HTML error file if it exists
		dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);
		dwBodyLength = dwFileSizeLo;
		CloseHandle(hFile);
	}
	else
	{
		szBody[0] = 0;
		strcat(szBody, "<HTML><HEAD><TITLE>Server Error</TITLE></HEAD><BODY>\n");
		strcat(szBody, "<H1>Error ");
		strcat(szBody, szErrorNum);
		strcat(szBody, ": ");
		strcat(szBody, ErrorTitleStr);
		strcat(szBody, "</H1>\n");
		strcat(szBody, ErrorDescStr);
		strcat(szBody, "\n</BODY></HTML>");
		dwBodyLength = (DWORD) strlen(szBody);
	}

	szHeader[0] = 0;
	strcat(szHeader, "HTTP/1.1 ");
	strcat(szHeader, szErrorNum);
	strcat(szHeader, " ");
	strcat(szHeader, ErrorDescStr);
	strcat(szHeader, "\r\n");
	strcat(szHeader, "Server: Savant/3.1\r\n");

	thInfo->KeepAlive = FALSE;
	
	strcat(szHeader, "Content-Type: text/html\r\n");
	itoa(dwBodyLength, szBodyLength, 10);
	strcat(szHeader, "Content-Length: ");
	strcat(szHeader, szBodyLength);
	strcat(szHeader, "\r\n");
	strcat(szHeader, "\r\n");
	nHeaderLength = strlen(szHeader);	//build HTTP header

	if ((bFileFound == TRUE) && (strcmpi(req->MethodStr, "HEAD") != 0))
		sendFile(thInfo, szErrorFile, (BYTE*)szHeader, strlen(szHeader), NULL, 0);
	else
		sendData(thInfo, (BYTE*)szHeader, strlen(szHeader) );
	
	if ((bFileFound == FALSE) && (strcmpi(req->MethodStr, "HEAD") != 0))
		sendData(thInfo, (BYTE*)szBody, dwBodyLength);
	//sends HTTP header and HTML error to client socket

	GetLocalTime(&curLocalTime);
	dateToOffsetFormatStr(&curLocalTime, szCurLocalTime);
	HTTPLogCommonEntry(&(thInfo->ClientSockAddr), thInfo->AddrLen, req->AuthorizedUserStr, szCurLocalTime, req->MethodStr,
		req->URIStr, szErrorNum, nHeaderLength + dwBodyLength);
	
	HTTPLogRefEntry(req->URIStr, req->RefererStr, szCurLocalTime);
	//log error file transfer
}


//Sends a "modified" message to the client socket (HTTP 1.1 compatibility)
void sendHTTPRedirect(char *NewURL, THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	char szHeader[500], szCurLocalTime[100];
	int nHeaderLength;
	SYSTEMTIME curLocalTime;

	STATUS_PROCESS_INCREASE();
	szHeader[0] = 0;
	strcat(szHeader, "HTTP/1.1 301 Moved\r\n");
	strcat(szHeader, "Server: Savant/3.1\r\n");
	strcat(szHeader, "Location: ");
	strcat(szHeader, NewURL);
	strcat(szHeader, "\r\n");
	if (strcmpi(req->ConnectionStr, "Keep-Alive") == 0)
	{
		strcat(szHeader, "Connection: Keep-Alive\n");
		strcat(szHeader, "Keep-Alive: timeout=180\n");
		thInfo->KeepAlive = TRUE;
	}
	else
		thInfo->KeepAlive = FALSE;
	
	strcat(szHeader, "Content-Length: 0\r\n");
	strcat(szHeader, "\r\n");
	nHeaderLength = strlen(szHeader);	//build redirection header

	sendData(thInfo, (BYTE*)szHeader, nHeaderLength);

	GetLocalTime(&curLocalTime);
	dateToOffsetFormatStr(&curLocalTime, szCurLocalTime);
	HTTPLogCommonEntry(&(thInfo->ClientSockAddr), thInfo->AddrLen,
		req->AuthorizedUserStr, szCurLocalTime, req->MethodStr,
		req->URIStr, "301", nHeaderLength);
}

