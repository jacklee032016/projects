/*
*
*/


#ifndef _SAVANT_H
#define _SAVANT_H

#include "defines.h"
#include "svrConfig.h"

void decNumFreeThreads();
void incNumFreeThreads();

void setSavantToolTip(BOOL isAddConnection);

void sendHTTPDirList(char*, char*, THREAD_INFO_T*, REQ_INFO_T*);

void processCGIScript(THREAD_INFO_T*, REQ_INFO_T*, char*, char*);

void processWinCGIScript(THREAD_INFO_T *RequestInfo, REQ_INFO_T *RequestFields,
	char *QueryStr, char *FilePath);


//Public function declarations
void loadHTTPPathMap();
int mapHTTPPath(char *URIStr, THREAD_INFO_T *thInfo, REQ_INFO_T *req);
void unloadHTTPPathMap();


void cleanUpHTTPHeaders(THREAD_INFO_T *thInfo, REQ_INFO_T *req);
int getHTTPHeaders(THREAD_INFO_T *thInfo, REQ_INFO_T *req);

void dispatchRequest(THREAD_INFO_T *thInfo);
void process10Request(THREAD_INFO_T*, REQ_INFO_T*);
void sendHTTPError(int, char*, char*, THREAD_INFO_T*, REQ_INFO_T*);
void sendHTTPRedirect(char*, THREAD_INFO_T*, REQ_INFO_T*);

void requestThread(HGLOBAL);
BOOL splitQuery(THREAD_INFO_T *thInfo, REQ_INFO_T *req );



char* getHTTPMIMEByPath(char*);
void loadHTTPMIMETable();
void unloadHTTPMIMETable();


void processImageMap(THREAD_INFO_T*, REQ_INFO_T *, char*, char*);

//Public function declarations
BOOL HTTPCheckUser(char*, char*, char*);

void authLoadUsers(HTTP_SERVICE *service);
void authUnloadUsers(HTTP_SERVICE *service);



//Public function declarations
int getRegFlag(BOOL&, HKEY, char*);
int loadRegistryVars(RUNNING_CONFIG *config);




void cleanUpHTTPLogs();
void closeErrorLog();
BOOL gotCriticalError();
void HTTPLogCommonEntry(SOCKADDR_IN*, int, char*, char*, char*, char*, char*, long);
void HTTPLogRefEntry(char*, char*, char*);
void initHTTPLogs();
void logCriticalError(char*);
void logError(char*);
void openErrorLog();



//Public function declarations
void dateToRFCFormatStr(SYSTEMTIME*, char*);
void dateToOffsetFormatStr(SYSTEMTIME*, char*);
int strToDate(char*, SYSTEMTIME*);



//Public function declarations
int answerListeningSocket(SOCKET, SOCKET*, SOCKADDR_IN*, int *);
void cleanUpNetIO();
void closeSocket(SOCKET &);
int createListeningSocket(HTTP_SERVICE *http, WORD SocketMsg);
void destroyListeningSocket(HTTP_SERVICE *http);

int getData(THREAD_INFO_T *thInfo, BYTE *IOBuffer, int IOBufferSize);
int getLine(char *OutStr, THREAD_INFO_T *thInfo, int *BufferIndex, int *DataInBuffer);

char *getLocalName();
void initNetIO();
int sendData(THREAD_INFO_T *thInfo, BYTE *SendBuffer, int NumToSend);
int sendFile(THREAD_INFO_T *thInfo, char *FileName, BYTE *Header, int HeaderSize, BYTE *Trailer, int TrailerSize);


//Public function declarations
void getExtension(char*, char*);
void getLastWord(char*, const char*, int&);
void getWord(char*, const char*, const int, int&);
int hexVal(char);
void splitPath(char*, char*, char*);
void translateEscapeString(char*);
void trim(char*);
void trimInet(char*);
void trimRight(char*);

#include "isapi.h"

void httpServerEnd(HTTP_SERVICE *http);
void httpServerStart(HTTP_SERVICE *http);
void httpServerProcessMsg(HTTP_SERVICE *http, WPARAM Socket, LPARAM MsgInfo);
void httpServerWatchdogHandler(HTTP_SERVICE *http);

#endif
