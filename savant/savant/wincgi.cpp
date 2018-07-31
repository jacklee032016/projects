/*
* Execute WinCGI programs (compiled Visual Basic)
*
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "savant.h"

void processWinCGIScript(THREAD_INFO_T *thInfo, REQ_INFO_T *req, char *QueryStr, char *FilePath) 
{
	char *AddrStr;
	char szStatusCode[5], ThreadNumStr[17], szCurDate[100], NumStr[33], CRLF[3], CommandLine[MAX_PATH];
	char CGIConFilePath[MAX_PATH], CGIDataFilePath[MAX_PATH], CGIOutFilePath[MAX_PATH];
	DWORD NumWritten, TotalNumWritten, FileAttr;
	HANDLE ConFileHandle, DataFileHandle, OutFileHandle;
	int Length, BufferIndex;
	LONG TZBias;
	PROCESS_INFORMATION ProcessInfo;
	STARTUPINFO StartUpInfo;
	SYSTEMTIME curDate;
	TIME_ZONE_INFORMATION TZInfo;


	CRLF[0] = 13;
	CRLF[1] = 10;
	CRLF[2] = 0;
	BufferIndex = 0;

	FileAttr = GetFileAttributes(FilePath);
	if (FileAttr == 0xFFFFFFFF) 
	{
		sendHTTPError(404, "File not found", "Could not find WinCGI script", thInfo, req);
		return;
	}
	else 
	if ((FileAttr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) 
	{
		sendHTTPError(400, "Querry not supported", "This resource does not support query", thInfo, req);
		return;
	}

	itoa(thInfo->ThreadNum, ThreadNumStr, 10);
	strcpy(CGIDataFilePath, SERVER_TEMP_DIR());
	strcat(CGIDataFilePath, "W_DAT");
	strcat(CGIDataFilePath, ThreadNumStr);
	strcat(CGIDataFilePath, ".INI");

	strcpy(CGIConFilePath, SERVER_TEMP_DIR());
	strcat(CGIConFilePath, "W_CON");
	strcat(CGIConFilePath, ThreadNumStr);
	strcat(CGIConFilePath, ".TXT");

	strcpy(CGIOutFilePath, SERVER_TEMP_DIR());
	strcat(CGIOutFilePath, "W_OUT");
	strcat(CGIOutFilePath, ThreadNumStr);


	ConFileHandle = CreateFile(CGIConFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (ConFileHandle == INVALID_HANDLE_VALUE) 
	{
		logError("Failure to create WinCGI Content file");
		sendHTTPError(501, "Internal WinCGI Server Error", "Failure to create WinCGI Content file", thInfo, req);
		return;
	}

	TotalNumWritten = 0;
	while (TotalNumWritten < req->ContentLength) 
	{
		WriteFile(ConFileHandle, req->Content + TotalNumWritten, req->ContentLength - TotalNumWritten, &NumWritten, NULL);
		TotalNumWritten += NumWritten;
	}
	CloseHandle(ConFileHandle);

	//Build up data for script initialization file
	memcpy(thInfo->IOBuffer + BufferIndex, "[CGI]", 5);
	BufferIndex += 5;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "CGI Version=CGI/1.3a WIN", 24);
	BufferIndex += 24;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "Request Protocol=", 17);
	BufferIndex += 17;
	Length = strlen(req->VersionStr);
	memcpy(thInfo->IOBuffer + BufferIndex, req->VersionStr, Length);
	BufferIndex += Length;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "Request Method=", 15);
	BufferIndex += 15;
	Length = strlen(req->MethodStr);
	memcpy(thInfo->IOBuffer + BufferIndex, req->MethodStr, Length);
	BufferIndex += Length;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "Request Keep-Alive=No", 21);
	BufferIndex += 21;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "Executable Path=", 16);
	BufferIndex += 16;
	Length = strlen(FilePath);
	memcpy(thInfo->IOBuffer + BufferIndex, FilePath, Length);
	BufferIndex += Length;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	if (QueryStr[0] != 0) 
	{
		memcpy(thInfo->IOBuffer + BufferIndex, "Query String=", 13);
		BufferIndex += 13;
		Length = strlen(QueryStr);
		memcpy(thInfo->IOBuffer + BufferIndex, QueryStr, Length);
		BufferIndex += Length;
		memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
		BufferIndex += 2;
	}

	if (req->RefererStr[0] != 0) 
	{
		memcpy(thInfo->IOBuffer + BufferIndex, "Referer=", 8);
		BufferIndex += 8;
		Length = strlen(req->RefererStr);
		memcpy(thInfo->IOBuffer + BufferIndex, req->RefererStr, Length);
		BufferIndex += Length;
		memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
		BufferIndex += 2;
	}

	memcpy(thInfo->IOBuffer + BufferIndex, "User Agent=", 11);
	BufferIndex +=11;
	Length = strlen(req->UserAgentStr);
	memcpy(thInfo->IOBuffer + BufferIndex, req->UserAgentStr, Length);
	BufferIndex += Length;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	if (req->ContentTypeStr[0] != 0) 
	{
		memcpy(thInfo->IOBuffer + BufferIndex, "Content Type=", 13);
		BufferIndex += 13;
		Length = strlen(req->ContentTypeStr);
		memcpy(thInfo->IOBuffer + BufferIndex, req->ContentTypeStr, Length);
		BufferIndex += Length;
		memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
		BufferIndex += 2;
	}

	if (req->ContentLengthStr[0] == 0) 
	{
		memcpy(thInfo->IOBuffer + BufferIndex, "Content Length=0", 16);
		BufferIndex += 16;
	}
	else 
	{
		memcpy(thInfo->IOBuffer + BufferIndex, "Content Length=", 15);
		BufferIndex += 15;
		Length = strlen(req->ContentLengthStr);
		memcpy(thInfo->IOBuffer + BufferIndex, req->ContentLengthStr, Length);
		BufferIndex += Length;
	}
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "Content File=", 13);
	BufferIndex += 13;
	Length = strlen(CGIConFilePath);
	memcpy(thInfo->IOBuffer + BufferIndex, CGIConFilePath, Length);
	BufferIndex += Length;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "Server Software=Savant", 22);
	BufferIndex += 22;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "Server Name=", 12);
	BufferIndex += 12;
	Length = strlen(SERVER_TEMP_DIR());
	memcpy(thInfo->IOBuffer + BufferIndex, SERVER_TEMP_DIR(), Length);
	BufferIndex += Length;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	itoa(PORT_NUM(), NumStr, 10);
	memcpy(thInfo->IOBuffer + BufferIndex, "Server Port=", 12);
	BufferIndex += 12;
	Length = strlen(NumStr);
	memcpy(thInfo->IOBuffer + BufferIndex, NumStr, Length);
	BufferIndex += Length;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	AddrStr = inet_ntoa(thInfo->ClientSockAddr.sin_addr);
	memcpy(thInfo->IOBuffer + BufferIndex, "Remote Address=", 15);
	BufferIndex += 15;
	Length = strlen(AddrStr);
	memcpy(thInfo->IOBuffer + BufferIndex, AddrStr, Length);
	BufferIndex += Length;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "[System]", 8);
	BufferIndex += 8;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "Output File=", 12);
	BufferIndex += 12;
	Length = strlen(CGIOutFilePath);
	memcpy(thInfo->IOBuffer + BufferIndex, CGIOutFilePath, Length);
	BufferIndex += Length;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "Content File=", 13);
	BufferIndex += 13;
	Length = strlen(CGIConFilePath);
	memcpy(thInfo->IOBuffer + BufferIndex, CGIConFilePath, Length);
	BufferIndex += Length;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	GetTimeZoneInformation(&TZInfo);
	TZBias = TZInfo.Bias * -60;
	ltoa(TZBias, NumStr, 10);
	memcpy(thInfo->IOBuffer + BufferIndex, "GMT Offset=", 11);
	BufferIndex += 11;
	Length = strlen(NumStr);
	memcpy(thInfo->IOBuffer + BufferIndex, NumStr, Length);
	BufferIndex += Length;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;

	memcpy(thInfo->IOBuffer + BufferIndex, "Debug Mode=No", 13);
	BufferIndex += 13;
	memcpy(thInfo->IOBuffer + BufferIndex, CRLF, 2);
	BufferIndex += 2;


	DataFileHandle = CreateFile(CGIDataFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (DataFileHandle == INVALID_HANDLE_VALUE) 
	{
		logError("Failure to create WinCGI Data file");
		sendHTTPError(501, "Internal WinCGI Server Error", "Failure to create WinCGI Data file", thInfo, req);
		return;
	}
	
	TotalNumWritten = 0;
	while (TotalNumWritten < BufferIndex) 
	{
		WriteFile(DataFileHandle, thInfo->IOBuffer + NumWritten,
		BufferIndex - TotalNumWritten, &NumWritten, NULL);
		TotalNumWritten += NumWritten;
	}
	CloseHandle(DataFileHandle);

	OutFileHandle = CreateFile(CGIOutFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (DataFileHandle == INVALID_HANDLE_VALUE) 
	{
		logError("Failure to create WinCGI Output file");
		sendHTTPError(501, "Internal WinCGI Server Error", "Failure to create WinCGI Output file", thInfo, req);
		return;
	}
	CloseHandle(OutFileHandle);

	strcpy(CommandLine, FilePath);
	strcat(CommandLine, " ");
	strcat(CommandLine, CGIDataFilePath);

	//Start the WinCGI process
	GetStartupInfo(&StartUpInfo);
	StartUpInfo.dwFlags = STARTF_USESHOWWINDOW;
	StartUpInfo.wShowWindow = SW_SHOWMINNOACTIVE;
	if (CreateProcess(0, CommandLine, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &StartUpInfo, &ProcessInfo) == FALSE) 
	{
		logError("Failure to create WinCGI Process");
		sendHTTPError(501, "Internal WinCGI Server Error", "Failure to create WinCGI Process", thInfo, req);
		return;
	}

	//If process times out (which is pretty likely with VB under load)...
	if (WaitForSingleObject(ProcessInfo.hProcess, 5 * 60 * 1000) != WAIT_OBJECT_0) 
	{
		TerminateProcess(ProcessInfo.hProcess , -1);
		logError("WinCGI script timed out");
		sendHTTPError(501, "Internal Server Error", "WinCGI Script Timed Out", thInfo, req);
		return;
	}

	sendFile(thInfo, CGIOutFilePath, NULL, 0, NULL, 0);
	thInfo->KeepAlive = FALSE;

	strcpy(szStatusCode, "200");
	GetLocalTime(&curDate);
	dateToOffsetFormatStr(&curDate, szCurDate);
	HTTPLogCommonEntry(&(thInfo->ClientSockAddr), thInfo->AddrLen, req->AuthorizedUserStr, szCurDate, req->MethodStr,
		req->URIStr, szStatusCode, 1024);
	STATUS_SENDOUT_INFO(req->URIStr, szCurDate, 1024);
	HTTPLogRefEntry(req->URIStr, req->RefererStr, szCurDate);
}

