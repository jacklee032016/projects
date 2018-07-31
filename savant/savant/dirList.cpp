/*
*
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "savant.h"

#define NameFieldLen 23
#define DateFieldLen 19
#define SizeFieldLen 10

typedef struct DirectoryDataType
{
	BOOL IsDirectory;
	char *Name;
	char *HTMLLine;
	DWORD HTMLLineLen;
	DirectoryDataType *Next;
} DirDataNode;



//Divide a linked list into two lists
DirDataNode *_divide(DirDataNode *FirstNode)
{
  DirDataNode *lpOneStepNode, *lpTwoStepNode, *lpHalfNode;

  lpOneStepNode = FirstNode;
  if (FirstNode->Next != NULL)
	 lpTwoStepNode = FirstNode->Next->Next;
  else
	 lpTwoStepNode = FirstNode->Next;
  while(lpTwoStepNode != NULL)
  {
	 lpOneStepNode = lpOneStepNode->Next;
	 lpTwoStepNode = lpTwoStepNode->Next;
	 if(lpTwoStepNode != NULL)
		lpTwoStepNode = lpTwoStepNode->Next;
  }
  lpHalfNode = lpOneStepNode->Next;
  lpOneStepNode->Next = NULL;
  return lpHalfNode;
}

//Merge two linked lists together
DirDataNode *_merge(DirDataNode *FirstHalf, DirDataNode *SecondHalf)
{
  DirDataNode *lpNewHeadNode, *lpNewLastNode;
  int nCompResult;

  lpNewHeadNode = NULL;
  lpNewLastNode = NULL;
  while ((FirstHalf != NULL) && (SecondHalf != NULL))
  {
	 if ((FirstHalf->IsDirectory) && (!SecondHalf->IsDirectory))
		nCompResult = -1;
	 else
      if ((!FirstHalf->IsDirectory) && (SecondHalf->IsDirectory))
		  nCompResult = 1;
		else
		  nCompResult = strcmpi(FirstHalf->Name, SecondHalf->Name);
	 if (nCompResult <= 0)
    {
		if (lpNewHeadNode == NULL)
      {
		  lpNewHeadNode = FirstHalf;
		  lpNewLastNode = FirstHalf;
      }
		else
      {
		  lpNewLastNode->Next = FirstHalf;
		  lpNewLastNode = FirstHalf;
      }
		FirstHalf = FirstHalf->Next;
		lpNewLastNode->Next = NULL;
    }
	 else
    {
		if (lpNewHeadNode == NULL)
      {
		  lpNewHeadNode = SecondHalf;
		  lpNewLastNode = SecondHalf;
      }
		else
      {
		  lpNewLastNode->Next = SecondHalf;
		  lpNewLastNode = SecondHalf;
      }
		SecondHalf = SecondHalf->Next;
		lpNewLastNode->Next = NULL;
    }
  }
  if (FirstHalf != NULL)
	 if (lpNewHeadNode == NULL)
		lpNewHeadNode = FirstHalf;
	 else
		lpNewLastNode->Next = FirstHalf;
  if (SecondHalf != NULL)
	 if (lpNewHeadNode == NULL)
		lpNewHeadNode = SecondHalf;
	 else
		lpNewLastNode->Next = SecondHalf;
  return lpNewHeadNode;
}

//Create a new node to hold directory information
DirDataNode *createNode(DirDataNode* &FirstNode, DirDataNode* &LastNode)
{
	DirDataNode *lpNewNode;

	lpNewNode = new DirDataNode;
	lpNewNode->IsDirectory = FALSE;
	lpNewNode->Name = NULL;
	lpNewNode->HTMLLine = NULL;
	lpNewNode->HTMLLineLen = 0;
	lpNewNode->Next = NULL;
	if (FirstNode == NULL)
	{
		FirstNode = lpNewNode;
		LastNode = lpNewNode;
	}
	else
	{
		LastNode->Next = lpNewNode;
		LastNode = lpNewNode;
	}
	return lpNewNode;
}

//Delete all of the nodes in a linked list
void deleteNodes(DirDataNode *FirstNode)
{
	DirDataNode *lpLoopNode, *lpTargetNode;

	lpLoopNode = FirstNode;
	while (lpLoopNode != NULL)
	{
		lpTargetNode = lpLoopNode;
		lpLoopNode = lpLoopNode->Next;
		
		delete[] lpTargetNode->Name;
		delete[] lpTargetNode->HTMLLine;
		delete lpTargetNode;
	}
}


//Merge sort a linked list
DirDataNode *mergeSort(DirDataNode *FirstNode)
{
	DirDataNode *lpFirstHalf, *lpSecondHalf, *lpWhole;

	lpWhole = FirstNode;
	lpFirstHalf = FirstNode;
	if((lpWhole != NULL) && (lpWhole->Next != NULL))
	{
		lpSecondHalf = _divide(lpWhole);
		lpFirstHalf = mergeSort(lpFirstHalf);
		lpSecondHalf = mergeSort(lpSecondHalf);
		lpWhole = _merge(lpFirstHalf, lpSecondHalf);
	}
	return lpWhole;
}


//Sends a directory listing in HTTPd format to a client
void sendHTTPDirList(char *DirStr, char *Realm, THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	BOOL fIsDirectory, fEndRef;
	char szCurDate[100], szHeaderStr[512], szTrailer[512], szHTMLLine[1024];
	char szLength[17], szFileDate[50], szFileSize[50], szHeader[512], szTemp[256];
	char szTranslatedURI[REQ_URL_LEN], szSearch[MAX_PATH], szUpLink[REQ_URL_LEN];
	DirDataNode *lpCurNode, *lpLoopNode, *lpFirstNode, *lpLastNode;
	DWORD dwHeaderLength, dwTrailerLength, dwFileSize, dwDataLength;
	FILETIME localFileTime;
	HANDLE hFileFind;
	int i, j, nLength, nHTMLLineIndex, nDigit;
	long lDataInBuffer;
	SYSTEMTIME fileDate, curTime;
	WIN32_FIND_DATA fileInfo;

	lpFirstNode = NULL;
	lpLastNode = NULL;
	dwDataLength = 0;
	GetSystemTime(&curTime);
	dateToOffsetFormatStr(&curTime, szCurDate);
	strcpy(szHeaderStr, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n");
	strcat(szHeaderStr, "<HTML>\n");
	strcat(szHeaderStr, " <HEAD>\n");
	strcat(szHeaderStr, "  <TITLE>Index of ");
	strcat(szHeaderStr, req->URIStr);
	strcat(szHeaderStr, "</TITLE>\n");
	strcat(szHeaderStr, " </HEAD>\n");
	strcat(szHeaderStr, " <BODY>\n");
	strcat(szHeaderStr, "<H1>Index of ");
	strcpy(szTranslatedURI, req->URIStr);
	translateEscapeString(szTranslatedURI);
	strcat(szHeaderStr, szTranslatedURI);
	strcat(szHeaderStr, "</H1>\n");
	strcat(szHeaderStr, "<PRE>Name                    ");
	strcat(szHeaderStr, "Last modified       ");
	strcat(szHeaderStr, "Size      ");
	strcat(szHeaderStr, "Description\n");
	strcat(szHeaderStr, "<HR>\n");
	strcpy(szUpLink, req->URIStr);
	nLength = strlen(szUpLink);
	if (nLength - 2 > 0)
		i = nLength - 2;
	else
		i = 0;
	
	while ((i > 0) && (szUpLink[i] != '/'))
		i--;
	
	szUpLink[i + 1] = 0;
	if ((strlen(szUpLink) > strlen(Realm)) && (strlen(szUpLink) != strlen(req->URIStr)))
	{
		strcat(szHeaderStr, "<A HREF=\"");
		strcat(szHeaderStr, szUpLink);
		strcat(szHeaderStr, "\">Parent Directory</A>\n");
	}
	//link to traverse up directory tree

	
	dwHeaderLength = strlen(szHeaderStr);
	dwDataLength += dwHeaderLength;
	strcpy(szSearch, DirStr);
	strcat(szSearch, "\\*.*");		//get names of all files in directory
	hFileFind = FindFirstFile(szSearch, &fileInfo);
	if (hFileFind == INVALID_HANDLE_VALUE)
	{
		logError("Failure to create directory listing");
		sendHTTPError(500, "Internal Server Error", "Failure to create directory listing", thInfo, req);
	}

	do
	{
		if (! ( (strcmp(fileInfo.cFileName, ".") == 0) || (strcmp(fileInfo.cFileName, "..") == 0)))
		{
			fIsDirectory = (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY;
			lpCurNode = createNode(lpFirstNode, lpLastNode);

			if(fIsDirectory)
				lpCurNode->IsDirectory = TRUE;
			else
				lpCurNode->IsDirectory = FALSE;

			lpCurNode->Name = new char[strlen(fileInfo.cFileName) + 2];
			strcpy(lpCurNode->Name, fileInfo.cFileName);
			if (lpCurNode->IsDirectory == TRUE)
				strcat(lpCurNode->Name, "/");
			//place file in linked list
			
			memcpy(szHTMLLine, "<A HREF=\"", 9);
			nHTMLLineIndex = 9;
			i = 0;

			while (fileInfo.cFileName[i] != '\0')
			{
				if (((fileInfo.cFileName[i] >= 'a') && (fileInfo.cFileName[i] <= 'z')) ||
					((fileInfo.cFileName[i] >= 'A') && (fileInfo.cFileName[i] <= 'Z')) ||
					((fileInfo.cFileName[i] >= '0') && (fileInfo.cFileName[i] <= '9')) ||
					(fileInfo.cFileName[i] == '.') || (fileInfo.cFileName[i] == '/'))
				{
					szHTMLLine[nHTMLLineIndex] = fileInfo.cFileName[i];
					nHTMLLineIndex++;
				}
				else
				{
					szHTMLLine[nHTMLLineIndex] = '%';
					nHTMLLineIndex++;
					nDigit = fileInfo.cFileName[i] / 16;
					if (nDigit <= 9)
						szHTMLLine[nHTMLLineIndex] = '0' + nDigit;
					else
						szHTMLLine[nHTMLLineIndex] = 'A' + (nDigit - 10);
					
					nHTMLLineIndex++;
					nDigit = fileInfo.cFileName[i] % 16;
					if (nDigit <= 9)
						szHTMLLine[nHTMLLineIndex] = '0' + nDigit;
					else
						szHTMLLine[nHTMLLineIndex] = 'A' + (nDigit - 10);

					nHTMLLineIndex++;
				}
				i++;
			}
			
			if (fIsDirectory)
			{
				szHTMLLine[nHTMLLineIndex] = '/';
				nHTMLLineIndex++;
			}
			
			memcpy(szHTMLLine + nHTMLLineIndex, "\">", 2);
			nHTMLLineIndex += 2;
			j = 0;
			strcpy(szTemp, fileInfo.cFileName);
			if (strlen(szTemp) >= 23)
			{
				szTemp[20] = '.';
				szTemp[21] = '.';
				szTemp[22] = '>';
				szTemp[23] = '\0';
			}
			
			fEndRef = FALSE;
			for (i = 0; i < NameFieldLen; i++)
			{
				if (szTemp[j] == '\0')
				{
					if (fEndRef == FALSE)
					{
						fEndRef = TRUE;
						szHTMLLine[nHTMLLineIndex] = ' ';
						memcpy(szHTMLLine + nHTMLLineIndex, "</A>", 4);
						nHTMLLineIndex = nHTMLLineIndex + 4;
						szHTMLLine[nHTMLLineIndex] = ' ';
					}
					else
					{
						szHTMLLine[nHTMLLineIndex] = ' ';
					}
				}
				else
				{
					szHTMLLine[nHTMLLineIndex] = szTemp[j];
					j++;
				}
				nHTMLLineIndex++;
			}
			
			if (strlen(szTemp) >= 23)
			{
				memcpy(szHTMLLine + nHTMLLineIndex, "</A>", 4);
				nHTMLLineIndex = nHTMLLineIndex + 4;
			}
			
			szHTMLLine[nHTMLLineIndex] = ' ';
			nHTMLLineIndex++;
			if (FileTimeToLocalFileTime(&(fileInfo.ftLastWriteTime), &localFileTime) != TRUE)
			{
				logError("Couldn't convert file times");
				CloseHandle(hFileFind);
				return;
			}
			
			if (FileTimeToSystemTime(&localFileTime, &fileDate) != TRUE)
			{
				logError("Couldn't convert file times");
				CloseHandle(hFileFind);
				return;
			}
			
			dateToOffsetFormatStr(&fileDate, szFileDate);
			szFileDate[2] = '-';
			szFileDate[6] = '-';
			szFileDate[11] = ' ';
			szFileDate[17] = '\0';
			j = 0;
			for (i=0; i<DateFieldLen; i++)
			{
				if (szFileDate[j] == '\0')
					szHTMLLine[nHTMLLineIndex] = ' ';
				else
				{
					szHTMLLine[nHTMLLineIndex] = szFileDate[j];
					j++;
				}
				
				nHTMLLineIndex++;
			}
			
			szHTMLLine[nHTMLLineIndex] = ' ';
			nHTMLLineIndex++;
			dwFileSize = fileInfo.nFileSizeLow;
			if (fIsDirectory)
				strcpy(szFileSize, "-");
			else
			if (dwFileSize < 1024)
				ultoa(dwFileSize, szFileSize, 10);
			else
			{
				dwFileSize = dwFileSize / 1024;
				ultoa(dwFileSize, szFileSize, 10);
				strcat(szFileSize, "k");
			}
			
			j = 0;
			for (i=0; i<SizeFieldLen; i++)
			{
				if (szFileSize[j] == '\0')
					szHTMLLine[nHTMLLineIndex] = ' ';
				else
				{
					szHTMLLine[nHTMLLineIndex] = szFileSize[j];
					j++;
				}
				nHTMLLineIndex++;
			}
			szHTMLLine[nHTMLLineIndex] = ' ';
			nHTMLLineIndex++;
			memcpy(szHTMLLine + nHTMLLineIndex, "\n", 1);
			nHTMLLineIndex = nHTMLLineIndex + 1;
			szHTMLLine[nHTMLLineIndex] = '\0';
			lpCurNode->HTMLLineLen = nHTMLLineIndex;
			dwDataLength = dwDataLength + nHTMLLineIndex;
			lpCurNode->HTMLLine = new char[nHTMLLineIndex + 1];
			memcpy(lpCurNode->HTMLLine, szHTMLLine, nHTMLLineIndex + 1);
		}
	} while(FindNextFile(hFileFind, &fileInfo) == TRUE);

	//build HTML line for file listing

	FindClose(hFileFind);
	strcpy(szTrailer, "</PRE><HR>\n");
	strcat(szTrailer, "<ADDRESS>Savant/3.1 Server at ");
	strcat(szTrailer, SERVER_NAME());
	strcat(szTrailer, "</ADDRESS>\n");
	strcat(szTrailer, "</BODY></HTML>\n");
	dwTrailerLength = strlen(szTrailer);
	dwDataLength = dwDataLength + dwTrailerLength;
	szHeader[0] = 0;
	strcat(szHeader, "HTTP/1.0 200 OK\r\n");
	strcat(szHeader, "Server: Savant\r\n");
	if (strcmpi(req->ConnectionStr, "Keep-Alive") == 0)
	{
		strcat(szHeader, "Connection: Keep-Alive\r\n");
		strcat(szHeader, "Keep-Alive: timeout=180\r\n");
		thInfo->KeepAlive = TRUE;
	}
	else
		thInfo->KeepAlive = FALSE;
	
	strcat(szHeader, "Content-Type: text/html\r\n");
	itoa(dwDataLength, szLength, 10);
	strcat(szHeader, "Content-Length: ");
	strcat(szHeader, szLength);
	strcat(szHeader, "\r\n");
	strcat(szHeader, "\r\n");
	//build HTML header
	
	if (sendData(thInfo, (BYTE *) szHeader, strlen(szHeader) ) == -1)
		return;
	if (sendData(thInfo, (BYTE *) szHeaderStr, dwHeaderLength) == -1)
		return;
	//send header to client
	
	lpFirstNode = mergeSort(lpFirstNode);
									//sort directory entries
	lpLoopNode = lpFirstNode;
	while(lpLoopNode != NULL)
	{
		lDataInBuffer = 0;
		while((lpLoopNode != NULL) && (lDataInBuffer + lpLoopNode->HTMLLineLen < thInfo->IOBufferSize))
		{
			memcpy(thInfo->IOBuffer + lDataInBuffer, lpLoopNode->HTMLLine,  lpLoopNode->HTMLLineLen);
			lDataInBuffer = lDataInBuffer + lpLoopNode->HTMLLineLen;
			lpLoopNode = lpLoopNode->Next;
		}
		
		if (sendData(thInfo, thInfo->IOBuffer, lDataInBuffer) == -1)
			return;
	}
	if (sendData(thInfo, (BYTE *) szTrailer, dwTrailerLength ) == -1)
		return;
	//send directory data to client
	
	HTTPLogCommonEntry(&(thInfo->ClientSockAddr), thInfo->AddrLen,
	req->AuthorizedUserStr, szCurDate, req->MethodStr,
	req->URIStr, "200", strlen(szHeader) + dwDataLength);
	STATUS_SENDOUT_INFO(req->URIStr, szCurDate, strlen(szHeader) + dwDataLength);
	HTTPLogRefEntry(req->URIStr, req->RefererStr, szCurDate);
									//log transaction
	deleteNodes(lpFirstNode);
}

