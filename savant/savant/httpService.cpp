/*
* 
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <commctrl.h>
#include <windowsx.h>
#include <process.h>

#include "savant.h"

static CRITICAL_SECTION FreeThreadsCritSec;
static int NumFreeThreads = 0;

static int NumKeepFree;
static BOOL ThreadsStarted = FALSE;
static int LeastNumFree = 0;
static int NextThreadId = FIRST_THREAD_ID;
static int *ThreadIds;
static HANDLE *GoEventHnds;
static HANDLE *FreeEventHnds;
static HGLOBAL *ParamMems;

//Creates a new process to handle a socket connection
static void _createHTTPHandlerThread(HTTP_SERVICE *http)
{
	int i, nThreadIndex, nThreadId;
	THREAD_STATUS_T *parameters;
	SECURITY_ATTRIBUTES inheritSA;

	if (http->status.currentThreadNumber >= http->cfg.MaxNumThreads)
		return;
	
	nThreadIndex = http->status.currentThreadNumber;
	http->status.currentThreadNumber++;
	
	do
	{
		nThreadId = NextThreadId;
		NextThreadId++;
		if (NextThreadId == LAST_THREAD_ID)
			NextThreadId = FIRST_THREAD_ID;
		i = 0;
		
		while ((i < nThreadIndex) && (nThreadId != ThreadIds[i]))
			i++;
	} while ((i < nThreadIndex));	//assign the process an internal ID

	ThreadIds[nThreadIndex] = nThreadId;

	
	//set process parameters
	GoEventHnds[nThreadIndex] = CreateEvent(NULL, FALSE, FALSE, NULL);
	FreeEventHnds[nThreadIndex] = CreateEvent(NULL, FALSE, TRUE, NULL);
	
	ParamMems[nThreadIndex] = GlobalAlloc(0, sizeof(RequestThreadMessageT));
	parameters = (RequestThreadMessageT *) GlobalLock(ParamMems[nThreadIndex]);
	parameters->GoEventHnd = GoEventHnds[nThreadIndex];
	parameters->FreeEventHnd = FreeEventHnds[nThreadIndex];
	parameters->Shutdown = FALSE;
	parameters->CloseHandles = FALSE;
	parameters->ThreadId = nThreadId;
	GlobalUnlock(ParamMems[nThreadIndex]);

	//get security attributes for process
	inheritSA.nLength = sizeof(SECURITY_ATTRIBUTES);
	inheritSA.bInheritHandle = TRUE;
	inheritSA.lpSecurityDescriptor = NULL;

	logDebug("Thread No. %d is created\n", nThreadId );
	_beginthread(requestThread, INIT_THREAD_STACK_SIZE, (void *)ParamMems[nThreadIndex]);
}




//Kills a process handling a socket connection
static BOOL _destroyHTTPHandlerThread(HTTP_SERVICE *http)
{
	DWORD dwThreadIndex;
	int nRet, i;
	RequestThreadMessageT *parameters;

	nRet = WaitForMultipleObjects(http->status.currentThreadNumber, FreeEventHnds, FALSE, 0);
	if (nRet == WAIT_TIMEOUT)
		return FALSE;

	if (nRet == WAIT_FAILED)
	{
		logError("Failure waiting for an available thread");
		return FALSE;
	}
	
	dwThreadIndex = nRet - WAIT_OBJECT_0;
	if (dwThreadIndex >= http->status.currentThreadNumber)
	{
		logCriticalError("Process Snafu");
		return FALSE;
	}
	
	parameters = (RequestThreadMessageT*) GlobalLock(ParamMems[dwThreadIndex]);
	parameters->Shutdown = TRUE;
	parameters->CloseHandles = TRUE;
	GlobalUnlock(ParamMems[dwThreadIndex]);
	ResetEvent(FreeEventHnds[dwThreadIndex]);
	PulseEvent(GoEventHnds[dwThreadIndex]);
						//kill client socket process

	for(i=dwThreadIndex; i < http->status.currentThreadNumber-1; i++)
	{
		FreeEventHnds[i] = FreeEventHnds[i+1];
		GoEventHnds[i] = GoEventHnds[i+1];
		ParamMems[i] = ParamMems[i+1];
		ThreadIds[i] = ThreadIds[i+1];
	}
	
	//update process record arrays
	http->status.currentThreadNumber--;
	return TRUE;
}



//Kills all active processes
static void _destroyAllHTTPHandlerThreads(HTTP_SERVICE *http)
{
	int i;
	RequestThreadMessageT *parameters;

	WaitForMultipleObjects(http->status.currentThreadNumber, FreeEventHnds, TRUE, TIME_OF_WATCHDOG);
	//wait for processes to complete current task

	for (i=0; i<http->status.currentThreadNumber; i++)
	{
		parameters = (RequestThreadMessageT*)GlobalLock(ParamMems[i]);
		parameters->Shutdown = TRUE;
		parameters->CloseHandles = FALSE;
		GlobalUnlock(ParamMems[i]);
		ResetEvent(FreeEventHnds[i]);
		PulseEvent(GoEventHnds[i]);
	}										//kill processes

	WaitForMultipleObjects(http->status.currentThreadNumber, FreeEventHnds, TRUE, TIME_OF_SHUTDOWN);
	//wait for processes to die

	for (i=0; i<http->status.currentThreadNumber; i++)
	{
		CloseHandle(FreeEventHnds[i]);
		CloseHandle(GoEventHnds[i]);
	}
	
	http->status.currentThreadNumber = 0;
	NumFreeThreads = 0;
	LeastNumFree = 0;					//close handles to processes
}

//Increments number of available processes when a process terminates
void incNumFreeThreads()
{
	EnterCriticalSection(&FreeThreadsCritSec);
	NumFreeThreads++;
	LeaveCriticalSection(&FreeThreadsCritSec);
}


//Decrements number of available processes when a process is requested
void decNumFreeThreads()
{
	EnterCriticalSection(&FreeThreadsCritSec);
	NumFreeThreads--;
	if (NumFreeThreads < LeastNumFree)
		LeastNumFree = NumFreeThreads;
	LeaveCriticalSection(&FreeThreadsCritSec);
}


//Loads registry configuration info and starts HTTP server
void httpServerStart(HTTP_SERVICE *http)
{
	int i;

	InitializeCriticalSection(&FreeThreadsCritSec);

	NumKeepFree = http->cfg.NumThreadsKeepFree;
	loadHTTPMIMETable();
	loadHTTPPathMap();
	initHTTPLogs();
	initISAPI();

	createListeningSocket(http, HTTP_SERVER_MSG);

	GoEventHnds = new HANDLE[http->cfg.MaxNumThreads];
	FreeEventHnds = new HANDLE[http->cfg.MaxNumThreads];
	ParamMems = new HGLOBAL[http->cfg.MaxNumThreads];
	ThreadIds = new int[http->cfg.MaxNumThreads];
	//create process control arrays

	for (i=0; i <http->cfg.InitNumThreads; i++)
		_createHTTPHandlerThread(http);

	ThreadsStarted = TRUE;
	
	http->watchDogID = SetTimer(http->msgWindow, HTTP_TIMER_ID, http->cfg.ThreadCompactPeriod, NULL);
	//hook Windows timer event for process watchdogging
}



//Cleans up and terminates the HTTP server
void httpServerEnd(HTTP_SERVICE *http)
{
	//unhook Windows timer event
	KillTimer(NULL, http->watchDogID);

	destroyListeningSocket(http);
	//destroy server socket
	if (ThreadsStarted)
	{
		_destroyAllHTTPHandlerThreads( http);
		delete[] FreeEventHnds;
		delete[] GoEventHnds;
		delete[] ParamMems;
		delete[] ThreadIds;
		ThreadsStarted = FALSE;
	}
	//kill processes
	cleanUpISAPI();
	cleanUpHTTPLogs();
	unloadHTTPMIMETable();
	unloadHTTPPathMap();
	DeleteCriticalSection(&FreeThreadsCritSec);
  											//unload configuration info from memory
}


//Processes Windows WM_TIMER messages for process watchdogging
void httpServerWatchdogHandler(HTTP_SERVICE *http)
{
	BOOL bRet;
	int nNumToKill;

	bRet = TRUE;
	if (LeastNumFree > NumKeepFree)
		nNumToKill = (LeastNumFree - NumKeepFree + ( cfg->ThreadCompactLaziness - 1)) /  cfg->ThreadCompactLaziness;
	else
		nNumToKill = 0;
	
	while ((nNumToKill > 0) && (bRet == TRUE))
	{
		bRet = _destroyHTTPHandlerThread(http);
		nNumToKill--;
	}
	
	LeastNumFree = http->status.currentThreadNumber;
}


//Answers request for a socket connection
static void _httpServerAnswer(HTTP_SERVICE *http)
{
	DWORD dwReadyThread;
	int nRet, nAddrLen;
	MSG message;
	SOCKADDR_IN clientSockAddr;
	SOCKET clientSocket;
	RequestThreadMessageT *parameters;

	nAddrLen = sizeof(SOCKADDR_IN);
	
	if ((NumFreeThreads - 1) < NumKeepFree)
		_createHTTPHandlerThread(http);
	
	nRet = WaitForMultipleObjects(http->status.currentThreadNumber, FreeEventHnds, FALSE, 0);
	while (nRet == WAIT_TIMEOUT)
	{
		if (PeekMessage(&message, http->msgWindow, 0, 0, PM_REMOVE))
			DispatchMessage(&message);
		
		Sleep(0);
		nRet = WaitForMultipleObjects(http->status.currentThreadNumber, FreeEventHnds, FALSE, 0);
	}
	
	if (nRet == WAIT_FAILED)
	{
		logCriticalError("Failure waiting for an available thread");
		return;
	}
	
	dwReadyThread = nRet - WAIT_OBJECT_0;
	if (dwReadyThread >= http->status.currentThreadNumber)
	{//wait until a process is free
		logCriticalError("Process Snafu");
		return;
	}

	answerListeningSocket(http->serverSocket, &clientSocket, &clientSockAddr, &nAddrLen);
	STATUS_CONNECTIONS_COUNT();
	
	parameters = (RequestThreadMessageT*) GlobalLock(ParamMems[dwReadyThread]);
	parameters->ClientSockAddr = clientSockAddr;
	parameters->ClientSocket = clientSocket;
	parameters->AddrLen = nAddrLen;
	parameters->Shutdown = FALSE;
	parameters->CloseHandles = FALSE;
	GlobalUnlock(ParamMems[dwReadyThread]);
	//binds free process to socket

	ResetEvent(FreeEventHnds[dwReadyThread]);
	PulseEvent(GoEventHnds[dwReadyThread]);
	//start process
}


//Handles internal HTTP server messages
void httpServerProcessMsg(HTTP_SERVICE *http, WPARAM Socket, LPARAM MsgInfo)
{
	if (Socket != http->serverSocket)
	{
		logError("Invalid client socket");
		return;
	}
	logDebug("RX HTTP Requirement");
	
	switch (WSAGETSELECTEVENT(MsgInfo))
	{
		case FD_ACCEPT:
			switch (WSAGETSELECTERROR(MsgInfo))
			{
				case WSAENETDOWN:
					logCriticalError("Network Down");
					break;

				default:
					_httpServerAnswer(http);
			}
			break;
			
		default:
			logError("Unknown Message");
			break;
	}
}

