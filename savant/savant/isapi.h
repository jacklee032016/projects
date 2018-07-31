//****************************************************************************
//*       MODULE: isapi.h [isapi.cpp]
//*      PURPOSE: Execute ISAPI applications contained in DLL files
//*        PHASE: Content Handler, called when appropriate by Response phase
//****************************************************************************


#ifndef _ISAPI_H
#define _ISAPI_H


#define HSE_VERSION_MAJOR 1
#define HSE_VERSION_MINOR 0
#define HSE_LOG_BUFFER_LEN 80
#define HSE_MAX_EXT_DLL_NAME_LEN 256

//status codes returned by ISAPI dll
#define HSE_STATUS_SUCCESS 1
#define HSE_STATUS_SUCCESS_AND_KEEP_CONN 2
#define HSE_STATUS_PENDING 3
#define HSE_STATUS_ERROR 4

//server support call codes
#define HSE_REQ_BASE 0
#define HSE_REQ_SEND_URL_REDIRECT_RESP (HSE_REQ_BASE + 1)
#define HSE_REQ_SEND_URL (HSE_REQ_BASE + 2)
#define HSE_REQ_SEND_RESPONSE_HEADER (HSE_REQ_BASE + 3)
#define HSE_REQ_DONE_WITH_SESSION (HSE_REQ_BASE + 4)
#define HSE_REQ_END_RESERVED 1000
#define HSE_REQ_MAP_URL_TO_PATH (HSE_REQ_END_RESERVED+1)
#define HSE_REQ_GET_SSPI_INFO (HSE_REQ_END_RESERVED+2)


typedef LPVOID HCONN;

typedef struct _HSE_VERSION_INFO 
{
  DWORD dwExtensionVersion;
  CHAR lpszExtensionDesc[HSE_MAX_EXT_DLL_NAME_LEN];
} HSE_VERSION_INFO, *LPHSE_VERSION_INFO;

typedef struct _EXTENSION_CONTROL_BLOCK 
{
  DWORD cbSize;
  DWORD dwVersion;
  HCONN ConnID;
  DWORD dwHttpStatusCode;
  CHAR lpszLogData[HSE_LOG_BUFFER_LEN];
  LPSTR lpszMethod;
  LPSTR lpszQueryString;
  LPSTR lpszPathInfo;
  LPSTR lpszPathTranslated;
  DWORD cbTotalBytes;
  DWORD cbAvailable;
  LPBYTE lpbData;
  LPSTR lpszContentType;
  BOOL (WINAPI * GetServerVariable)(HCONN hConn, LPSTR lpszVariableName, 						                      							  					
				                            LPVOID lpvBuffer, LPDWORD lpdwSize);
  BOOL (WINAPI * WriteClient)(HCONN ConnID, LPVOID Buffer, LPDWORD lpdwBytes, DWORD dwReserved);
  BOOL (WINAPI * ReadClient)(HCONN ConnID, LPVOID lpvBuffer, LPDWORD lpdwSize);
  BOOL (WINAPI * ServerSupportFunction)(HCONN hConn, DWORD dwHSERRequest, LPVOID lpvBuffer,
                                        LPDWORD lpdwSize, LPDWORD lpdwDataType);
} EXTENSION_CONTROL_BLOCK, *LPEXTENSION_CONTROL_BLOCK;


//functions taken from ISAPI dll
BOOL WINAPI GetExtensionVersion(HSE_VERSION_INFO *pVer);
DWORD WINAPI HttpExtensionProc(EXTENSION_CONTROL_BLOCK *pECB);

//server functions
typedef BOOL (WINAPI * PFN_GETEXTENSIONVERSION)(HSE_VERSION_INFO *pVer);
typedef DWORD (WINAPI * PFN_HTTPEXTENSIONPROC)(EXTENSION_CONTROL_BLOCK *pECB);

//Public functions
void initISAPI();
void cleanUpISAPI();
void processISAPIScript(THREAD_INFO_T *, REQ_INFO_T *,char*, char*);

#endif
