/*
*
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <process.h>

#include "savant.h"


//Gets and parses HTTPd request headers
int getHTTPHeaders(THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	char szCurLine[NETIO_MAX_LINE], szNextLine[NETIO_MAX_LINE];
	char szFieldName[MAX_HTTP_FIELD_NAME_LEN], szFieldVal[MAX_HTTP_FIELD_LEN];
	int nReadBufferIndex, nDataInBuffer, nStart, nEnd, nLen, nNumRecv;

	memset(req, 0, sizeof(REQ_INFO_T));
	nReadBufferIndex = 0;
	nDataInBuffer = 0;
	if (getLine(szCurLine, thInfo, &nReadBufferIndex, &nDataInBuffer) != 0)
	{
		logDebug("Error in first line of Requirement");
		return GH_ERROR;
	}

	do
	{
		if(getLine(szNextLine, thInfo, &nReadBufferIndex, &nDataInBuffer) != 0)
		{
			logDebug("Error in read line of Requirement");
			return GH_ERROR;
		}
		
		if ((szNextLine[0] == ' ') || (szNextLine[0] == '\t'))
			strcat(szCurLine, szNextLine);
	} while ((szNextLine[0] == ' ') || (szNextLine[0] == '\t'));
	//get remainder of request
	
	nStart = 0;
	getWord(req->MethodStr, szCurLine, nStart, nEnd);
	CharUpper(req->MethodStr);
	getLastWord(req->VersionStr, szCurLine, nStart);
	CharUpper(req->VersionStr);

	//parse method string
	if (strncmp(req->VersionStr, "HTTP/", 5) != 0)
	{
		memcpy(req->URIStr, szCurLine + nEnd, strlen(szCurLine) + 1 - nEnd);
		logDebug("SIMPLE_REQUEST : %s", req->URIStr);
		return GH_SIMPLE_REQUEST;
	}
	
	memcpy(req->URIStr, szCurLine + nEnd, nStart - nEnd);
	req->URIStr[nStart - nEnd] = 0;
	trimRight(req->URIStr);
	if (strncmp(req->VersionStr, "HTTP/1.", 7) != 0)
	{
		logDebug("UNKNOWN_VERSION : %s", req->VersionStr);
		return GH_UNKNOWN_VERSION;
	}
	
	strcpy(szCurLine, szNextLine);		//parse version string
	while (szCurLine[0] != 0)
	{
		do
		{
			if (getLine(szNextLine, thInfo, &nReadBufferIndex, &nDataInBuffer) != 0)
				return GH_ERROR;
			
			if ((szNextLine[0] == ' ') || (szNextLine[0] == '\t'))
				strcat(szCurLine, szNextLine);
		} while ((szNextLine[0] == ' ') || (szNextLine[0] == '\t'));
		//get remainder of request
		
		nStart = 0;
		getWord(szFieldName, szCurLine, nStart, nEnd);
		CharUpper(szFieldName);
		nLen = strlen(szCurLine) - nEnd;
		memcpy(szFieldVal, szCurLine + nEnd, nLen);
		szFieldVal[nLen] = 0;				//read header into buffer
		
		if (strcmp("ACCEPT:", szFieldName) == 0)
		{
			if (req->AcceptStr[0] == '\0')
			{
				strncpy(req->AcceptStr, szFieldVal, ReqAcceptStrLen - 1);
				if (nLen >= ReqAcceptStrLen)
					logError("Acceptance field truncated");
			}
			else
			{
				int AcceptStrLen = strlen(req->AcceptStr);
				if ((ReqAcceptStrLen - AcceptStrLen) >= 10)
				{
					strncat(req->AcceptStr, ", ", ReqAcceptStrLen - AcceptStrLen - 1);
					strncat(req->AcceptStr, szFieldVal, ReqAcceptStrLen - AcceptStrLen - 3);
					if ((nLen + 3 + AcceptStrLen)  > ReqAcceptStrLen)
						logError("Acceptance field truncated");
				}
				else
				{
					logError("Acceptance field truncated");
				}
			}
		}
		else
			if (strcmp("DATE:", szFieldName) == 0)
			{
				strncpy(req->DateStr, szFieldVal, REQ_DATA_LEN - 1);
				if (nLen >= REQ_DATA_LEN)
					logError("Date field truncated");
			}
			else
			if (strcmp("USER-AGENT:", szFieldName) == 0)
			{
				strncpy(req->UserAgentStr, szFieldVal, ReqUserAgentStrLen - 1);
				if (nLen >= ReqUserAgentStrLen)
				{
					logError("User Agent field truncated, value follows");
					logError(req->UserAgentStr);
				}
			}
			else
			if (strcmp("CONNECTION:", szFieldName) == 0)
			{
				strncpy(req->ConnectionStr, szFieldVal, ReqConnectionStrLen - 1);
				if (nLen >= ReqConnectionStrLen)
					logError("Connection field truncated");
			}
			else
			if (strcmp("ACCEPT-LANGUAGE:", szFieldName) == 0)
			{
				strncpy(req->AcceptLangStr, szFieldVal, ReqAcceptLangStrLen - 1);
				if (nLen >= ReqAcceptLangStrLen)
					logError("Accept-Language field truncated");
			}
		else
			if (strcmp("REFERER:", szFieldName) == 0)
			{
				strncpy(req->RefererStr, szFieldVal, ReqRefererStrLen - 1);
				if (nLen >= ReqRefererStrLen)
					logError("Referer field truncated");
			}
			else
			if (strcmp("IF-MODIFIED-SINCE:", szFieldName) == 0)
			{
				strncpy(req->IfModSinceStr, szFieldVal, ReqIfModSinceStrLen - 1);
				if (nLen >= ReqIfModSinceStrLen)
					logError("If Modified Since field truncated");
			}
			else
			if (strcmp("FROM:", szFieldName) == 0)
			{
				strncpy(req->FromStr, szFieldVal, ReqFromStrLen - 1);
				if (nLen >= ReqFromStrLen)
					logError("From field truncated");
			}
			else
			if (strcmp("MIME-VERSION:", szFieldName) == 0)
			{
				strncpy(req->MIMEVerStr, szFieldVal, ReqMIMEVerStrLen - 1);
				if (nLen >= ReqMIMEVerStrLen)
					logError("MIME Version field truncated");
			}
			else
			if (strcmp("PRAGMA:", szFieldName) == 0)
			{
				strncpy(req->PragmaStr, szFieldVal, ReqPragmaStrLen - 1);
				if (nLen >= ReqPragmaStrLen)
					logError("Pragma field truncated");
			}
			else
			if (strcmp("AUTHORIZATION:", szFieldName) == 0)
			{
				strncpy(req->AuthorizationStr, szFieldVal, ReqAuthorizationStrLen - 1);
				if (nLen >= ReqAuthorizationStrLen)
					logError("Authorization field truncated");
			}
			else
			if (strcmp("CONTENT-LENGTH:", szFieldName) == 0)
			{
				strncpy(req->ContentLengthStr, szFieldVal, ReqContentLengthStrLen - 1);
				if (nLen >= ReqContentLengthStrLen)
					logError("Content Length field truncated");
			}
			else
			if (strcmp("CONTENT-TYPE:", szFieldName) == 0)
			{
				strncpy(req->ContentTypeStr, szFieldVal, ReqContentTypeStrLen - 1);
				if (nLen >= ReqContentTypeStrLen)
					logError("Content Type field truncated");
			}
			else
			if (strcmp("CONTENT-ENCODING:", szFieldName) == 0)
			{
				strncpy(req->ContentEncodingStr, szFieldVal, ReqContentEncodingStrLen - 1);
				if (nLen >= ReqContentEncodingStrLen)
					logError("Content Encoding field truncated");
			}
			else if (req->NumOtherHeaders < (MAX_OTHER_HEADERS - 1))
			{
				int VarLen = strlen(szFieldName);
				if (szFieldName[VarLen - 1] == ':')
				{
					szFieldName[VarLen - 1] = '\0';
					VarLen--;
				}
				req->OtherHeaders[req->NumOtherHeaders].Var = new char[VarLen + 1];
				req->OtherHeaders[req->NumOtherHeaders].Val = new char[nLen + 1];
				strcpy(req->OtherHeaders[req->NumOtherHeaders].Var, szFieldName);
				strcpy(req->OtherHeaders[req->NumOtherHeaders].Val, szFieldVal);
				req->NumOtherHeaders++;
			}
			
		strcpy(szCurLine, szNextLine);
	}
	
	if (req->ContentLengthStr[0] != 0)
	{
		req->ContentLength = atol(req->ContentLengthStr);
		if (req->ContentLength > 0)
		{
			req->Content = new BYTE[req->ContentLength];
			nNumRecv = nDataInBuffer - nReadBufferIndex;
			if (nNumRecv >req->ContentLength)
				nNumRecv = req->ContentLength;
			
			memcpy(req->Content, thInfo->IOBuffer + nReadBufferIndex,nNumRecv);
			while (nNumRecv < req->ContentLength)
			{
				nNumRecv = getData(thInfo, req->Content + nNumRecv, req->ContentLength - nNumRecv);
				if (nNumRecv < 0)
					return GH_ERROR;
			}
		}
		else
		{
			req->Content = NULL;
			req->ContentLength = 0;
		}
	}
	else
	{
		req->Content = NULL;
		req->ContentLength = 0;
	}

	//parse headers
	logDebug("GH_10_REQUEST");
	return GH_10_REQUEST;
}


//Cleans up dynamic memory used by HTTP headers
void cleanUpHTTPHeaders(THREAD_INFO_T *thInfo, REQ_INFO_T *req)
{
	if (req->Content != NULL)
		delete[] req->Content;
	
	while (req->NumOtherHeaders > 0)
	{
		req->NumOtherHeaders--;
		delete[] req->OtherHeaders[req->NumOtherHeaders].Var;
		delete[] req->OtherHeaders[req->NumOtherHeaders].Val;
	}
}

