/*
*  Gets and interprets a client (browser) request
*/



#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <process.h>

#include "savant.h"

//Requests a process
void requestThread(HGLOBAL ParamMem)
{
	BOOL bShutdown, bCloseHandles;
	BYTE *IOBuffer;
	HANDLE hGoEvent, hFreeEvent;
	int nAddrLen, nThreadNum;
	RequestThreadMessageT *parameters;
	SOCKADDR_IN clientSockAddr;
	SOCKET clientSocket;
	THREAD_INFO_T	thInfo;

	IOBuffer = new BYTE[IO_BUFFER_SIZE];
	memset(IOBuffer, 0, IO_BUFFER_SIZE);
	
	parameters = (THREAD_STATUS_T *)GlobalLock(ParamMem);
	hGoEvent = parameters->GoEventHnd;
	hFreeEvent = parameters->FreeEventHnd;
	nThreadNum = parameters->ThreadId;
	GlobalUnlock(ParamMem);
	
	do
	{
		SetEvent(hFreeEvent);
		incNumFreeThreads();
		WaitForSingleObject(hGoEvent, INFINITE);
		decNumFreeThreads();
		
		parameters = (RequestThreadMessageT*)GlobalLock(ParamMem);
		thInfo.ClientSocket = parameters->ClientSocket;
		thInfo.ClientSockAddr = parameters->ClientSockAddr;
		thInfo.AddrLen = parameters->AddrLen;
		thInfo.IOBuffer = IOBuffer;
		thInfo.IOBufferSize = IO_BUFFER_SIZE;
		thInfo.ThreadNum = nThreadNum;
		thInfo.KeepAlive = FALSE;
		
		bShutdown = parameters->Shutdown;
		bCloseHandles = parameters->CloseHandles;
		GlobalUnlock(ParamMem);
		
		if (bShutdown != TRUE)
		{
			if (clientSocket != INVALID_SOCKET)
				dispatchRequest( &thInfo);
			else
				logError("Invalid client socket");
		}	
		else
		{
			GlobalFree(ParamMem);
			delete[] IOBuffer;
		}
	} while (!bShutdown);//binds the process to a TCP socket
	
	if (bCloseHandles)
	{
		CloseHandle(hFreeEvent);
		CloseHandle(hGoEvent);
	}
	else
		SetEvent(hFreeEvent);

	_endthread();
}


//Seperates URI into 2 parts of file and query parts (splits at '?')
BOOL splitQuery(THREAD_INFO_T *thInfo, REQ_INFO_T *req )
{
	int nQuestionMarkPos, i, j;
	char *FileStr, *QueryStr;
	char	*URIStr = req->URIStr;

	FileStr = thInfo->parsedReq.szURI;
	QueryStr = thInfo->parsedReq.szQuery;
	
	i=0;
	while ((URIStr[i] != '?') && (URIStr[i] != 0))
		i++;
	
	if (URIStr[i] == '?')
	{
		nQuestionMarkPos = i;
		for (i=0; i < nQuestionMarkPos; i++)
			FileStr[i] = URIStr[i];
		
		FileStr[nQuestionMarkPos] = 0;
		i = nQuestionMarkPos + 1;
		j = 0;
		while (URIStr[i] != 0)
		{
			QueryStr[j] = URIStr[i];
			i++;
			j++;
		}
		QueryStr[j] = 0;
		return TRUE;
	}

	strcpy(FileStr, URIStr);
	QueryStr[0] = 0;
	return FALSE;
}



