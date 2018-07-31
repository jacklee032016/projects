/*
*
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "savant.h"

//Private defines
#define MAXHOSTNAME 100
#define NETIO_CONN_TIMEOUT 180


//Private global variables
DWORD LocalIPNumber;
char LocalName[MAXHOSTNAME];
SOCKADDR_IN stLclAddr;


//Gets IP address of current server host
DWORD getHostID()
{
	char szLclHost[MAXHOSTNAME];
	int nRet;
	LPHOSTENT lpstHostent;
	SOCKET hSock;
	SOCKADDR_IN stRmtAddr;

	int nAddrSize = sizeof(SOCKADDR);
	stLclAddr.sin_addr.s_addr = INADDR_ANY;
	nRet = gethostname(szLclHost, MAXHOSTNAME);
	//get local host name

	if (nRet != SOCKET_ERROR)
	{
		lpstHostent = gethostbyname((LPSTR)szLclHost);
		if (lpstHostent)
			stLclAddr.sin_addr.s_addr = *((u_long FAR*) (lpstHostent->h_addr));
	}
	//resolve host name

	if (stLclAddr.sin_addr.s_addr == INADDR_ANY)
	{
		hSock = socket(AF_INET, SOCK_DGRAM, 0);
		//create a UDP socket
		if (hSock != INVALID_SOCKET)
		{
			stRmtAddr.sin_family = AF_INET;
			stRmtAddr.sin_port = htons(IPPORT_ECHO);
			stRmtAddr.sin_addr.s_addr = inet_addr("161.6.18.1");
			nRet = connect(hSock, (LPSOCKADDR)&stRmtAddr, sizeof(SOCKADDR));
			if (nRet != SOCKET_ERROR)
				getsockname(hSock, (LPSOCKADDR)&stLclAddr, (int FAR*)&nAddrSize);
			
			closesocket(hSock);
		}
		//connect to arbitrary host & port
	}
	return (stLclAddr.sin_addr.s_addr);
	//break host name out of return packet
}


//Initializes and starts WinSock
void initNetIO()
{
	WSADATA data;

	if (WSAStartup(MAKEWORD(1, 1), &data) != 0)
		logCriticalError("Failure to start winsock\n");
	LocalIPNumber = getHostID();
	LocalName[0] = 0;
}

//Shuts down and unloads WinSock
void cleanUpNetIO()
{
	WSAUnhookBlockingHook();
	if (WSACleanup() == SOCKET_ERROR)
		logError("Failure to cleanup Winsock");
}


//Gets the local domain name, or dotted IP address if none
char *getLocalName()
{
	hostent *DNSresult;
	in_addr localInAddr;

	if (LocalName[0] == 0)
	{
		localInAddr.s_addr = LocalIPNumber;
		DNSresult = gethostbyaddr((char *)&(localInAddr), 4, PF_INET);

		if (DNSresult == NULL)
			strcpy(LocalName, inet_ntoa(localInAddr));
		else
		{
			strcpy(LocalName, DNSresult->h_name);
			CharLower(LocalName);
		}
	}
	return LocalName;
}


//Create and activate a server socket
int createListeningSocket(HTTP_SERVICE *http, WORD SocketMsg)
{
	SOCKADDR_IN serverSockAddr;

	memset(&serverSockAddr, 0, sizeof(serverSockAddr));
	serverSockAddr.sin_port = htons((WORD)http->cfg.PortNum);
	serverSockAddr.sin_family = AF_INET;
	serverSockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	http->serverSocket = socket(AF_INET, SOCK_STREAM, 0);

	if (http->serverSocket == INVALID_SOCKET)
	{
		logCriticalError("Failure to create socket");
		return -1;
	}
	
	if (bind(http->serverSocket, (LPSOCKADDR)&serverSockAddr, sizeof(serverSockAddr)) == SOCKET_ERROR)
	{
		logCriticalError("Couldn't bind socket");
		return -1;
	}

	if (listen(http->serverSocket, 5) == SOCKET_ERROR)
	{
		logCriticalError("Failure to start listening socket");
		return -1;
	}

	//create internal event for socket connections
	if (WSAAsyncSelect(http->serverSocket, http->msgWindow, SocketMsg, FD_ACCEPT) == SOCKET_ERROR)
	{
		logCriticalError("Failure to create asynchronous event");
		return -1;
	}
	
	return 0;
}


//Send a "live" response message to a client socket
int answerListeningSocket(SOCKET ServerSocket, SOCKET *ClientSocket, SOCKADDR_IN *ClientSockAddr, int *AddrLen)
{
	*ClientSocket = accept(ServerSocket, (LPSOCKADDR)ClientSockAddr, AddrLen);
	if ( *ClientSocket == INVALID_SOCKET)
	{
		logError("Invalid client socket");
		return -1;
	}
	logDebug("Peer Address is '%s'",  inet_ntoa(ClientSockAddr->sin_addr) );
	return 0;
}


//Destroy server socket
void destroyListeningSocket(HTTP_SERVICE *http)
{
	WSAAsyncSelect(http->serverSocket, http->msgWindow, 0, 0);
	
	closeSocket(http->serverSocket);
}


//Destroy a connection to a client socket
void closeSocket(SOCKET &TargetSocket)
{
	if (TargetSocket != INVALID_SOCKET)
	{
		shutdown(TargetSocket, 2);
		closesocket(TargetSocket);
		TargetSocket = INVALID_SOCKET;
	}
}

//Gets data from a client socket
int getData(THREAD_INFO_T *thInfo, BYTE *IOBuffer, int IOBufferSize)
{
	fd_set socketSet;
	int nReceived, nError;
	struct timeval timeout;

	FD_ZERO(&socketSet);
	FD_SET(thInfo->ClientSocket, &socketSet);
	
	timeout.tv_sec = NETIO_CONN_TIMEOUT;
	timeout.tv_usec = 0;
	
	do
	{
		nReceived = recv(thInfo->ClientSocket, (char*)IOBuffer, IOBufferSize, 0);
		if (nReceived == 0) //connection lost
			return -1;
		if (nReceived == SOCKET_ERROR)
		{
			nError = WSAGetLastError();
			if (nError == WSAEWOULDBLOCK)
			{
				nReceived = 0;
				if (select(0, &socketSet, NULL, NULL, &timeout) != 1)
					return -1;
			}
			else
				return -1;
		}//socket timed out
	} while(nReceived == 0);

	logDebug("Recv %d bytes from socket: '%s' OK!", nReceived, IOBuffer);
	
	return nReceived;
}


//Gets a line of text from a client socket
int getLine(char *OutStr, THREAD_INFO_T *thInfo, int *bufferIndex, int *dataIndex)
{
	char curChar;
	int i = 0;

	do
	{
		if (*bufferIndex == *dataIndex )
		{
			*dataIndex = getData(thInfo, thInfo->IOBuffer, thInfo->IOBufferSize);
			if (*dataIndex == -1)
				return -1;
			*bufferIndex = 0;
		}
		
		curChar = thInfo->IOBuffer[*bufferIndex];
		*bufferIndex = *bufferIndex+1;//+;
		if ((curChar != 10) && (curChar != 13))
		{
			OutStr[i] = curChar;
			i++;
		}
//		logDebug("char %c at index=%d", curChar, i);
	} while ((curChar != 10) && (i < NETIO_MAX_LINE));
	
	if (i == NETIO_MAX_LINE)
	{
		logError("TCP buffer overflow");
		return -1;
	}
	
	OutStr[i] = 0;
	logDebug("READ Line length is %d bytes, content is '%s'", i, OutStr);
	
	return 0;
}


//Sends a data stream to a client socket
int sendData(THREAD_INFO_T *thInfo, BYTE *SendBuffer, int NumToSend)
{
	fd_set socketSet;
	int nError, nOffset, nSent;
	struct timeval timeout;

	nOffset = 0;
	FD_ZERO(&socketSet);
	FD_SET(thInfo->ClientSocket, &socketSet);
	
	timeout.tv_sec = NETIO_CONN_TIMEOUT;
	timeout.tv_usec = 0;
	while (NumToSend > 0)
	{
		nSent = send(thInfo->ClientSocket, (char*)SendBuffer + nOffset, NumToSend, 0);
		if (nSent == 0)
			return -1;

		if (nSent == SOCKET_ERROR)
		{
			nError = WSAGetLastError();
			if (nError == WSAEWOULDBLOCK)
			{
				nSent = 0;
				if (select(0, NULL, &socketSet, NULL, &timeout) != 1)
					return -1;
			}
			else
				return -1;
		}
		
		NumToSend = NumToSend - nSent;
		nOffset = nOffset + nSent;
	}
	return 0;
}


//Sends a file to a client socket via a data stream
int sendFile(THREAD_INFO_T *thInfo, char *FileName, BYTE *Header, int HeaderSize, BYTE *Trailer, int TrailerSize)
{
	BYTE *mapView;
	DWORD dwFileSize, dwFileSizeLo, dwFileSizeHi;
	HANDLE hFileMap, hFile;

	if (HeaderSize > 0)
		if (sendData(thInfo, Header, HeaderSize) == -1)
			return -1;
		
	hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		logError("File I/O error");
		return -1;
	}										//verify file exists

	dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);
	dwFileSize = dwFileSizeLo;

	hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, NULL);
	if (hFileMap == INVALID_HANDLE_VALUE)
	{
		logError("File I/O error");
		return -1;
	}
	mapView = (BYTE*)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	//keep stuff from modifying the file while xferred

	if (hFile == INVALID_HANDLE_VALUE)
	{
		logError("File I/O error");
		return -1;
	}
	
	if (sendData(thInfo, mapView, dwFileSize) == -1)
		return -1;
		
	if(!UnmapViewOfFile(mapView))
	{
		logError("File I/O error");
		return -1;
	}
	CloseHandle(hFileMap);

	CloseHandle(hFile);

	if (TrailerSize > 0)
	{
		if (sendData(thInfo, Trailer, TrailerSize) == -1)
			return -1;
	}
	
	return 0;
}

