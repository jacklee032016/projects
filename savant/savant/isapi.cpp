/*
* Execute ISAPI applications contained in DLL files
* PHASE: Content Handler, called when appropriate by Response phase
*/


#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "savant.h"

#include "isapi.h"

#define MAX_VAR_STR_LEN 256
#define ISAPI_PENDING_TIMEOUT 60 * 60 * 1000

struct ConnTableEntry 
{
	BOOL Allocated;
	THREAD_INFO_T *thInfo;
	REQ_INFO_T *req;
	char *QueryStr;
	HANDLE ISAPIDoneEvent;
};

static ConnTableEntry *ConnTable;
static int MaxNumConn;
static CRITICAL_SECTION GetTableEntryCritSec;

BOOL WINAPI GetServerVariableExport(HCONN, LPSTR, LPVOID, LPDWORD);
BOOL WINAPI WriteClientExport(HCONN, LPVOID, LPDWORD, DWORD);
BOOL WINAPI ReadClientExport(HCONN, LPVOID, LPDWORD);
BOOL WINAPI ServerSupportFunctionExport(HCONN, DWORD, LPVOID, LPDWORD, LPDWORD);
ConnTableEntry *HConnToConnTableEntry(HCONN);


//Send an HTTP redirect if requested by the client
static void _isapiRedirect(char *URL, THREAD_INFO_T *thInfo, REQ_INFO_T *req) 
{
	char NewURL[MAX_PATH];
	int i;

	i = 0;
	while ((URL[i] != 0) && (URL[i] != ':') && (URL[i] != '/')) 
	{
		i++;
	}
	
	if (URL[i] == ':') 
	{
		sendHTTPRedirect(URL, thInfo, req);
	}
	else 
	{
		strcpy(NewURL, "http://");
		strcat(NewURL, SERVER_NAME());
		if (URL[0] != '/') 
			strcat(NewURL, "/");
		
		strcat(NewURL, URL);
		sendHTTPRedirect(NewURL, thInfo, req);
	}
}

//Pass the URI to the dll
static void _isapiSendURI(char *URI, THREAD_INFO_T *thInfo, REQ_INFO_T *req) 
{
	strcpy(req->URIStr, URI);
	req->PathInfoStr[0] = '\0';
	req->PathTranslatedStr[0] = '\0';
	req->ScriptNameStr[0] = '\0';
	process10Request(thInfo, req);
}

//Pass headers to the dll
static void _isapiSendHeaders(char *Status, char *OtherHeaders, DWORD OtherHeadersLen, THREAD_INFO_T *thInfo, REQ_INFO_T *req) 
{
	char StatusLine[200];
	char Headers[200];

	if (Status == NULL) 
	{
		strcpy(StatusLine, "HTTP/1.0 200 OK\r\n");
	}
	else 
	{
		strcpy(StatusLine, "HTTP/1.0 ");
		strcat(StatusLine, Status);
		strcat(StatusLine, "\r\n");
	}
	
	strcat(StatusLine, "Server: Savant\r\n");
	if (sendData(thInfo, (BYTE *) StatusLine, strlen(StatusLine)) == -1) 
	{
		return;
	}
	
	if (OtherHeaders == NULL) 
	{
		strcpy(Headers, "Content-Type: text/html\r\n\r\n");
		sendData(thInfo, (BYTE *) Headers, strlen(Headers));
	}
	else 
	{
		sendData(thInfo, (BYTE *) OtherHeaders, OtherHeadersLen);
	}
}

void ISAPIBuildAllHTTP(char*, LPDWORD, THREAD_INFO_T*, REQ_INFO_T*);

void initISAPI() 
{
	int i;

	InitializeCriticalSection(&GetTableEntryCritSec);
	MaxNumConn = cfg->MaxNumThreads;
	ConnTable = new ConnTableEntry[MaxNumConn];
	for (i=0; i<MaxNumConn; i++) 
		ConnTable[i].Allocated = FALSE;
}


void cleanUpISAPI() 
{
	DeleteCriticalSection(&GetTableEntryCritSec);
	delete[] ConnTable;
}


void processISAPIScript(THREAD_INFO_T *thInfo, REQ_INFO_T *req, char *QueryStr, char *FilePath)
{
	DWORD FileAttr, Ret;
  EXTENSION_CONTROL_BLOCK ExtCtrlBlk;
  HMODULE AppHnd;
  HSE_VERSION_INFO Ver;
  int ConnIndex;
  PFN_GETEXTENSIONVERSION GetExtensionVersion;
  PFN_HTTPEXTENSIONPROC HttpExtensionProc;

	FileAttr = GetFileAttributes(FilePath);
	if (FileAttr == 0xFFFFFFFF) 
  {
		sendHTTPError(404, "File Not Found", "Could not find ISAPI Application module", thInfo, req);
		return;
	}
	else 
    if ((FileAttr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) 
    {
		  sendHTTPError(405, "Method Not Supported", "This resource does not support query", thInfo, req);
		  return;
		}
  
  EnterCriticalSection(&GetTableEntryCritSec);
  ConnIndex = 0;
  while ((ConnTable[ConnIndex].Allocated != FALSE) && (ConnIndex < MaxNumConn)) 
  {
   	ConnIndex++;
  }
  LeaveCriticalSection(&GetTableEntryCritSec);

  if (ConnIndex == MaxNumConn) 
  {
    logError("Unable to find free space in ISAPI Connection Table");
    sendHTTPError(501, "Internal Server Error", "Unable to find free space in ISAPI Connection Table", thInfo, req);
    return;
 	}

  ConnTable[ConnIndex].Allocated = TRUE;
  ConnTable[ConnIndex].thInfo = thInfo;
  ConnTable[ConnIndex].req = req;
  ConnTable[ConnIndex].QueryStr = QueryStr;
  ConnTable[ConnIndex].ISAPIDoneEvent = CreateEvent(NULL, TRUE, FALSE, NULL);  //Off, ManualReset;

  AppHnd = LoadLibrary(FilePath);
  if (AppHnd == NULL) 
  {
    logError("Failure to load ISAPI application module");
    sendHTTPError(501, "Internal Server Error", "Failure to load ISAPI application module", thInfo, req);
    return;
 	}

  GetExtensionVersion = (PFN_GETEXTENSIONVERSION) GetProcAddress(AppHnd, "GetExtensionVersion");
  if (GetExtensionVersion == NULL) 
  {
    logError("Failure to get pointer to GetExtensionVersion() in ISAPI application module");
    sendHTTPError(501, "Internal Server Error", "Failure to get pointer to GetExtensionVersion() in ISAPI application module", thInfo, req);
    return;
 	}
  if(!GetExtensionVersion(&Ver)) 
  {
    logError("ISAPI GetExtensionVersion() returned FALSE");
    sendHTTPError(501, "Internal Server Error", "ISAPI GetExtensionVersion() returned FALSE", thInfo, req);
    return;
  }
  if (Ver.dwExtensionVersion > MAKELONG(HSE_VERSION_MINOR, HSE_VERSION_MAJOR)) 
  {
    logError("ISAPI version not supported");
    sendHTTPError(501, "Internal Server Error", "ISAPI version not supported", thInfo, req);
    return;
 	}

  memset(&ExtCtrlBlk, 0, sizeof(ExtCtrlBlk));
  ExtCtrlBlk.cbSize = sizeof(ExtCtrlBlk);
  ExtCtrlBlk.dwVersion = MAKELONG(HSE_VERSION_MINOR, HSE_VERSION_MAJOR);
  ExtCtrlBlk.GetServerVariable = GetServerVariableExport;
	ExtCtrlBlk.ReadClient  = ReadClientExport;
	ExtCtrlBlk.WriteClient = WriteClientExport;
	ExtCtrlBlk.ServerSupportFunction = ServerSupportFunctionExport;
  ExtCtrlBlk.ConnID = (HCONN) (ConnIndex + 1);
  ExtCtrlBlk.dwHttpStatusCode = 200;
  ExtCtrlBlk.lpszLogData[0] = '\0';
  ExtCtrlBlk.lpszMethod = req->MethodStr;
  ExtCtrlBlk.lpszQueryString = QueryStr;
  ExtCtrlBlk.lpszPathInfo = req->PathInfoStr;
  ExtCtrlBlk.lpszPathTranslated = req->PathTranslatedStr;
  ExtCtrlBlk.cbTotalBytes = req->ContentLength;
  ExtCtrlBlk.cbAvailable = req->ContentLength;
  ExtCtrlBlk.lpbData = req->Content;
  ExtCtrlBlk.lpszContentType = req->ContentTypeStr;

  //call the dll's entry procedure
  HttpExtensionProc = (PFN_HTTPEXTENSIONPROC)GetProcAddress(AppHnd, "HttpExtensionProc");
  if (HttpExtensionProc == NULL) 
  {
    logError("Failure to get pointer to HttpExtensionProc() in ISAPI application module");
    sendHTTPError(501, "Internal Server Error", "Failure to get pointer to HttpExtensionProc() in ISAPI application module", thInfo, req);
    return;
 	}
  Ret = HttpExtensionProc(&ExtCtrlBlk);
  if (Ret == HSE_STATUS_PENDING) 
  {
    WaitForSingleObject(ConnTable[ConnIndex].ISAPIDoneEvent, ISAPI_PENDING_TIMEOUT);
  }

  switch(Ret) 
  {
    case HSE_STATUS_SUCCESS_AND_KEEP_CONN:
      thInfo->KeepAlive = TRUE;
    case HSE_STATUS_SUCCESS:
    case HSE_STATUS_ERROR:
    default:
      thInfo->KeepAlive = FALSE;
  }

  //remove the connection from the table
  FreeLibrary(AppHnd);
  ConnTable[ConnIndex].Allocated = FALSE;

  //Log the transaction
}



//Get server environment variable headers to send to dll
BOOL WINAPI GetServerVariableExport(HCONN hConn, LPSTR lpszVariableName, LPVOID lpvBuffer, LPDWORD lpdwSize) 
{
  char VarStr[MAX_VAR_STR_LEN], NumStr[33], HostName[200];
  ConnTableEntry *ConnInfo;
  hostent *DNSResult;
  REQ_INFO_T *req;
  THREAD_INFO_T *thInfo;


  ConnInfo = HConnToConnTableEntry(hConn);
  if (ConnInfo == NULL) 
  {
    logError("ISAPI exported function GetServerVariable got invalid hConn");
    SetLastError(ERROR_INVALID_PARAMETER);
   	return FALSE;
 	}
  req = ConnInfo->req;
  thInfo = ConnInfo->thInfo;

  strncpy(VarStr, lpszVariableName, MAX_VAR_STR_LEN);
  VarStr[MAX_VAR_STR_LEN] = '\0';
  CharUpper(VarStr);

  if (strcmp("REQUEST_METHOD", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->MethodStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
	else 
  if (strcmp("SERVER_PROTOCOL", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->VersionStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
  else 
  if (strcmp("HTTP_DATE", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->DateStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
  else 
  if (strcmp("HTTP_MIME_VERSION", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->MIMEVerStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
  else 
  if (strcmp("HTTP_PRAGMA", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->PragmaStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
  else 
  if (strcmp("HTTP_FROM", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->FromStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
  else 
  if (strcmp("HTTP_IF_MODIFIED_SINCE", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->IfModSinceStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
  else 
  if (strcmp("HTTP_REFERER", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->RefererStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
  else 
  if (strcmp("HTTP_USER_AGENT", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->UserAgentStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
  else 
  if (strcmp("CONTENT_ENCODING", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->ContentEncodingStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
  else 
  if (strcmp("CONTENT_TYPE", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->ContentTypeStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
  else 
  if (strcmp("CONTENT_LENGTH", VarStr) == 0) 
  {
    if (req->ContentLengthStr[0] == '\0') 
    {
      strncpy((char *) lpvBuffer, "0", *lpdwSize);
    }
    else 
    {
      strncpy((char *) lpvBuffer, req->ContentLengthStr, *lpdwSize);
    }    
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
  else 
  if (strcmp("HTTP_ACCEPT", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->AcceptStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
  else 
  if (strcmp("HTTP_ACCEPT_LANGUAGE", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->AcceptLangStr, *lpdwSize);
   ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
  else 
  if (strcmp("HTTP_CONNECTION", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->ConnectionStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
  else 
  if (strcmp("AUTH_TYPE", VarStr) == 0) 
  {
    if (req->AuthorizedUserStr[0] != 0) 
    {
      strncpy((char *) lpvBuffer, "Basic", *lpdwSize);
      ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
    }
    else 
    {
      ((char *) lpvBuffer)[0] = '\0';
   	}
 	}
  else 
  if (strcmp("REMOTE_USER", VarStr) == 0) 
  {
   	if (req->AuthorizedUserStr[0] != 0) 
    {
      strncpy((char *) lpvBuffer, req->AuthorizedUserStr, *lpdwSize);
      ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
    }
    else 
    {
      ((char *) lpvBuffer)[0] = '\0';
   	}
 	}
	else 
  if (strcmp("GATEWAY_INTERFACE", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, "CGI/1.1", *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
  }
	else 
  if (strcmp("REMOTE_HOST", VarStr) == 0) 
  {
    if (cfg->ScriptDNS== TRUE) 
	    DNSResult = gethostbyaddr((char *)&(thInfo->ClientSockAddr.sin_addr), thInfo->AddrLen, PF_INET);
    else 
      DNSResult = NULL;
	  if (DNSResult == NULL) 
		  strcpy(HostName, inet_ntoa(thInfo->ClientSockAddr.sin_addr));
    else 
		  strcpy(HostName, DNSResult->h_name);
    strncpy((char *) lpvBuffer, HostName, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
  else 
  if (strcmp("REMOTE_ADDR", VarStr) == 0) 
  {
	  char *AddrStr;
	  AddrStr = inet_ntoa(thInfo->ClientSockAddr.sin_addr);
    strncpy((char *) lpvBuffer, AddrStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
	else 
  if (strcmp("SERVER_NAME", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, SERVER_NAME(), *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
	else 
  if (strcmp("SERVER_PORT", VarStr) == 0) 
  {
    itoa(PORT_NUM(), NumStr, 10);
    strncpy((char *) lpvBuffer, NumStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
	else 
  if (strcmp("SERVER_SOFTWARE", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, "Savant", *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
	else 
  if (strcmp("QUERY_STRING", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, ConnInfo->QueryStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
	else 
  if (strcmp("PATH_INFO", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->PathInfoStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
	else 
  if (strcmp("PATH_TRANSLATED", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->PathTranslatedStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
	else 
  if (strcmp("SCRIPT_NAME", VarStr) == 0) 
  {
    strncpy((char *) lpvBuffer, req->ScriptNameStr, *lpdwSize);
    ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
 	}
  else 
  if (strcmp("ALL_HTTP", VarStr) == 0) 
  {
    ISAPIBuildAllHTTP((char *) lpvBuffer, lpdwSize, thInfo, req);
 	}
  else 
  if (strncmp("HTTP_", VarStr, 5) == 0) 
  {
    int i;
    char *HTTPVarStr;

    HTTPVarStr = VarStr + 5;
    i = 0;
    while ((i<req->NumOtherHeaders) && (strcmp(req->OtherHeaders[i].Var, HTTPVarStr) != 0))
    {
      i++;
    }
    if (i < req->NumOtherHeaders) 
    {
      strncpy((char *) lpvBuffer, req->OtherHeaders[i].Val, *lpdwSize);
      ((char *)lpvBuffer)[*lpdwSize - 1] = '\0';
    }
    else 
    {
      *lpdwSize = 0;
      SetLastError(ERROR_NO_DATA);
      return FALSE;
    }
 	}
  else 
  {
    *lpdwSize = 0;
    SetLastError(ERROR_INVALID_INDEX);
    return FALSE;
 	}
  *lpdwSize = strlen((char *) lpvBuffer) + 1;
  return TRUE;
}


//Transmits output from dll to client browser
BOOL WINAPI WriteClientExport(HCONN hConn, LPVOID Buffer, LPDWORD lpdwBytes, DWORD dwReserved)
{
  ConnTableEntry *ConnInfo;
  int Ret;
  THREAD_INFO_T *thInfo;

  ConnInfo = HConnToConnTableEntry(hConn);
  if (ConnInfo == NULL) 
  {
    logError("ISAPI exported function WriteClientExport got invalid hConn");
    SetLastError(ERROR_INVALID_PARAMETER);
   	return FALSE;
  }
  
  thInfo = ConnInfo->thInfo;
  Ret = sendData(thInfo, (BYTE *) Buffer, *lpdwBytes);
  if (Ret == -1) 
  {
    *lpdwBytes = 0;
    return FALSE;
 	}
  else 
  {
  //*lpdwBytes = *lpdwBytes  (everything sent)
    return TRUE;
  }
}


//Read data from client browser to be sent to dll
BOOL WINAPI ReadClientExport(HCONN hConn, LPVOID lpvBuffer, LPDWORD lpdwSize ) 
{
	ConnTableEntry *ConnInfo;
	int NumRead;
	THREAD_INFO_T *thInfo;

	ConnInfo = HConnToConnTableEntry(hConn);
	if (ConnInfo == NULL) 
	{
		logError("ISAPI exported function ReadClientExport got invalid hConn");
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	thInfo = ConnInfo->thInfo;

	NumRead = getData(thInfo, (BYTE *) lpvBuffer, *lpdwSize );
	if (NumRead == -1) 
	{
		*lpdwSize = 0;
		return FALSE;
	}
	else 
	{
		*lpdwSize = NumRead;
		return TRUE;
	}
}


//Entry point for dll utility routines
BOOL WINAPI ServerSupportFunctionExport(HCONN hConn, DWORD dwHSERRequest,
	                   LPVOID lpvBuffer, LPDWORD lpdwSize, LPDWORD lpdwDataType) 
{
	ConnTableEntry *ConnInfo;

	ConnInfo = HConnToConnTableEntry(hConn);
	if (ConnInfo == NULL) 
	{
		logError("ISAPI exported funciton ServerSupportFunctionExport got invalid hConn");
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	switch (dwHSERRequest) 
	{
		case HSE_REQ_SEND_URL_REDIRECT_RESP:
			_isapiRedirect((char *)lpvBuffer, ConnInfo->thInfo, ConnInfo->req );
			break;
		
		case HSE_REQ_SEND_URL:
			_isapiSendURI((char*)lpvBuffer, ConnInfo->thInfo, ConnInfo->req );
			break;

		case HSE_REQ_SEND_RESPONSE_HEADER:
			_isapiSendHeaders((char*)lpvBuffer, (char*)lpdwDataType, *lpdwSize, ConnInfo->thInfo, ConnInfo->req );
			break;

		case HSE_REQ_DONE_WITH_SESSION:
			SetEvent(ConnInfo->ISAPIDoneEvent);
			break;

		default:
		return FALSE;
	}
	return TRUE;
}


//Add a connection to the table
ConnTableEntry *HConnToConnTableEntry(HCONN hConn) 
{
	int ConnIndex;

	ConnIndex = ((int) hConn) - 1;
	ConnTableEntry *ConnInfo;
	if ((ConnIndex < 0) || (ConnIndex >= MaxNumConn)) 
	{
		return NULL;
	}
	
	ConnInfo = &(ConnTable[ConnIndex]);
	if (ConnInfo->Allocated == FALSE) 
	{
		return NULL;
	}
	return ConnInfo;
}


//Set the environment variables to pass to the dll
void ISAPIBuildAllHTTP(char *ValStr, LPDWORD lpdwSize, THREAD_INFO_T *thInfo, REQ_INFO_T *req) 
{
  int ValMaxLen, ValLen, i;

  ValStr[0] = '\0';
  ValLen = 0;
  ValMaxLen = *lpdwSize - 1;

  if (req->DateStr[0] != '\0') 
  {
    strncat(ValStr, "HTTP_DATE ", ValMaxLen - ValLen);
    ValLen += strlen("HTTP_DATE ");
 	}
  if (req->MIMEVerStr[0] != '\0') 
  {
    strncat(ValStr, "HTTP_MIME_VERSION ", ValMaxLen - ValLen);
    ValLen += strlen("HTTP_MIME_VERSION ");
 	}
  if (req->PragmaStr[0] != '\0') 
  {
    strncat(ValStr, "HTTP_PRAGMA ", ValMaxLen - ValLen);
    ValLen += strlen("HTTP_PRAGMA ");
 	}
  if (req->FromStr[0] != '\0') 
  {
    strncat(ValStr, "HTTP_FROM ", ValMaxLen - ValLen);
    ValLen += strlen("HTTP_FROM ");
 	}
  if (req->IfModSinceStr[0] != '\0') 
  {
    strncat(ValStr, "HTTP_IF_MODIFIED_SINCE ", ValMaxLen - ValLen);
    ValLen += strlen("HTTP_IF_MODIFIED_SINCE ");
 	}
  if (req->RefererStr[0] != '\0') 
  {
    strncat(ValStr, "HTTP_REFERER ", ValMaxLen - ValLen);
    ValLen += strlen("HTTP_REFERER ");
 	}
  if (req->UserAgentStr[0] != '\0') 
  {
    strncat(ValStr, "HTTP_USER_AGENT ", ValMaxLen - ValLen);
    ValLen += strlen("HTTP_USER_AGENT ");
 	}
  if (req->AcceptStr[0] != '\0') 
  {
    strncat(ValStr, "HTTP_ACCEPT ", ValMaxLen - ValLen);
    ValLen += strlen("HTTP_ACCEPT ");
	}
  if (req->UserAgentStr[0] != '\0') 
  {
    strncat(ValStr, "HTTP_ACCEPT_LANGUAGE ", ValMaxLen - ValLen);
    ValLen += strlen("HTTP_ACCEPT_LANGUAGE ");
 	}
  if (req->ConnectionStr[0] != '\0') 
  {
    strncat(ValStr, "HTTP_CONNECTION ", ValMaxLen - ValLen);
    ValLen += strlen("HTTP_CONNECTION ");
 	}
  for(i=0; i<req->NumOtherHeaders; i++) 
  {
    strncat(ValStr, "HTTP_", ValMaxLen - ValLen);
    ValLen += strlen("HTTP_");
    strncat(ValStr, req->OtherHeaders[i].Val, ValMaxLen - ValLen);
    ValLen += strlen(req->OtherHeaders[i].Val);
    strncat(ValStr, " ", ValMaxLen - ValLen);
    ValLen += strlen(" ");
 	}
}


