/*
* Log accesses and errors to flat text files
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "savant.h"

#define MAXNUMSTR 33
#define MAXLINE 500
#define MAXVERTS 100
#define X 0
#define Y 1


enum RegionType {RectRgn, CircleRgn, PolyRgn, DefaultRgn, PointRgn};


void strToPoints(char *WorkStr, double Point[2]);
BOOL getImageMapLine(HANDLE InFileHnd, BYTE *Buffer, int BufferLen,
	                  int &DataInBuffer, int &BufferIndex, char *LineBuffer,
                     int LineBufferLen);
BOOL parseImageMapLine(char *LineBuf, enum RegionType &Region, char *URI,
	                    double Coords[MAXVERTS][2], int &NumCoords,
                       char *MapFileNameStr, int LineNum);
void logImageMapParseError(char *ErrorDescStr, char *MapFileNameStr, int LineNum);
BOOL pointInRect(double Point[2], double Coords[MAXVERTS][2]);
BOOL pointInCircle(double Point[2], double Coords[MAXVERTS][2]);
BOOL pointInPoly(double point[2], double pgon[MAXVERTS][2], int numverts);


//Processes a server-side image map
void processImageMap(THREAD_INFO_T *thInfo, REQ_INFO_T *req, char *QueryStr, char *MapFilePath)
{
  BOOL fMatch;
  char szURIBuffer[MAX_PATH], szNewURL[MAX_PATH], szBestURI[MAX_PATH], szLineBuffer[MAXLINE + 1];
  double dDist, dBestURIDist, dTestPoint[2], dCoords[MAXVERTS][2];
  enum RegionType Region;
  HANDLE hMapFile;
  int i, nNumCoords, nLineNum, nIOBufferIndex, nDataInIOBuffer;

  nLineNum = 0;
  nIOBufferIndex = 0;
  nDataInIOBuffer = 0;
  fMatch = FALSE;
  if (QueryStr[0] == 0)
  {
    sendHTTPError(501, "Internal Server Error", "Expected parameters for image map",  thInfo, req);
    return;
  }
  strToPoints(QueryStr, dTestPoint);
  hMapFile = CreateFile(MapFilePath, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ,
                          NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (hMapFile == INVALID_HANDLE_VALUE)
  {
    sendHTTPError(404, "File Not Found", "Image map not found",  thInfo, req);
	 return;
  }										//open image map definition file
  szBestURI[0] = 0;
  dBestURIDist = 0;
  while((!fMatch) && (getImageMapLine(hMapFile, thInfo->IOBuffer, thInfo->IOBufferSize,
         	                         nDataInIOBuffer, nIOBufferIndex, szLineBuffer, MAXLINE + 1)))
  {
     nLineNum++;
     if (parseImageMapLine(szLineBuffer, Region, szURIBuffer, dCoords, nNumCoords,
      	                  MapFilePath, nLineNum))
     {
       switch (Region)
       {
      	case RectRgn: if (nNumCoords < 2)
            			  {
   					       logImageMapParseError("rectangle expected 2 points",
      					    MapFilePath, nLineNum);
      				       return;
   					     }
         		        if (pointInRect(dTestPoint, dCoords))
                       {
            		       fMatch = TRUE;
               	       strcpy(szBestURI, szURIBuffer);
            		     }
         		        break;
         case CircleRgn: if (nNumCoords < 2)
                         {
   					         logImageMapParseError("circle expected 2 points",
                                        	       MapFilePath, nLineNum);
   					         return;
   					       }
         	     	       if (pointInCircle(dTestPoint, dCoords))
                         {
            		         fMatch = TRUE;
               	         strcpy(szBestURI, szURIBuffer);
            		       }
					          break;
         case PolyRgn: if (nNumCoords < 3)
                       {
   					       logImageMapParseError("polygon expected at least 3 points",
      					                           MapFilePath, nLineNum);
   					       return;
   					     }
         		        if (pointInPoly(dTestPoint, dCoords, nNumCoords))
                       {
            		       fMatch = TRUE;
               	       strcpy(szBestURI, szURIBuffer);
            		     }
         		        break;
         case DefaultRgn: strcpy(szBestURI, szURIBuffer);
            	           dBestURIDist = 0;
         		           break;
			case PointRgn: if (nNumCoords < 1)
                        {
   					        logImageMapParseError("point expected at least 1 point",
      					                           MapFilePath, nLineNum);
   					        return;
                        }
            	         dDist = ((dTestPoint[X] - dCoords[0][X]) *
            		             (dTestPoint[X] - dCoords[0][X])) + ((dTestPoint[Y] - dCoords[0][Y]) *
            		             (dTestPoint[Y] - dCoords[0][Y]));
                        if ((szBestURI[0] == 0) || (dDist < dBestURIDist))
                        {
         			        strcpy(szBestURI, szURIBuffer);
            		        dBestURIDist = dDist;
               	      }
         		         break;
         default: logError("Unexpected region value in image map");
       }
    }   									//parse line from image map definition file
  }
  if (szBestURI[0] == 0)
    sendHTTPError(404, "File Not Found", "No URL was associated with the selected point",  thInfo, req);
  else
  {
    i = 0;
    while ((szBestURI[i] != 0) && (szBestURI[i] != ':') && (szBestURI[i] != '/'))
      i++;
    if (szBestURI[i] == ':')
      sendHTTPRedirect(szBestURI, thInfo, req);
    else
    {
		strcpy(szNewURL, "http://");
      strcat(szNewURL, SERVER_NAME());
      if (szBestURI[0] != '/')
        strcat(szNewURL, "/");
      strcat(szNewURL, szBestURI);
      sendHTTPRedirect(szNewURL, thInfo, req);
    }
  }                              //redirect browser to URL associated with coordinates
  CloseHandle(hMapFile);
}


//----------------------------------------------------------------------------


//Converts a NCSA style coordinate string to a pair of float coordinates
void strToPoints(char *WorkStr, double Point[2])
{
  char szNum[MAXNUMSTR];
  int i, j;

  i = 0;
  j = 0;
  while ((WorkStr[i] != ',') && (WorkStr[i] != 0) && (j < MAXNUMSTR))
  {
    szNum[j] = WorkStr[i];
    i++;
    j++;
  }
  szNum[j] = 0;
  Point[X] = (double) atol(szNum);
  if (WorkStr[i] == ',')
    i++;
  j = 0;
  while ((WorkStr[i] != ',') && (WorkStr[i] != 0) && (j < MAXNUMSTR))
  {
    szNum[j] = WorkStr[i];
    i++;
    j++;
  }
  szNum[j] = 0;
  Point[Y] = (double) atol(szNum);
}


//----------------------------------------------------------------------------


//Gets a line of data from an NCSA style image map file
BOOL getImageMapLine(HANDLE InFileHnd, BYTE *Buffer, int BufferLen,
	                  int &DataInBuffer, int &BufferIndex, char *LineBuffer, int LineBufferLen)
{
  char curChar;
  DWORD dwNumRead;
  int i;

  i = 0;
  do
  {
	 if (BufferIndex >= DataInBuffer)
    {
      if (ReadFile(InFileHnd, Buffer, BufferLen, &dwNumRead, NULL) != TRUE)
      {
        if (i == 0)
          return FALSE;
        else
        {
          LineBuffer[i] = 0;
			 return TRUE;
        }
      }
		DataInBuffer = dwNumRead;
      BufferIndex = 0;
		if (DataInBuffer == 0)
      {
        if (i == 0)
          return FALSE;
        else
        {
          LineBuffer[i] = 0;
			 return TRUE;
        }
      }
    }
	 curChar = Buffer[BufferIndex];
	 BufferIndex++;
	 if ((curChar != 10) && (curChar != 13))
    {
		LineBuffer[i] = curChar;
		i++;
    }
  } while ((curChar != 10) && (i < LineBufferLen));
  if (i == LineBufferLen)
  {
	 logError("Buffer overflow in image map");
	 return FALSE;
  }
  LineBuffer[i] = 0;
  return TRUE;
}


//----------------------------------------------------------------------------


//Converts a line of data from an NCSA map file to internal variable representations
BOOL parseImageMapLine(char *LineBuf, enum RegionType &Region, char *URI,
	                    double Coords[MAXVERTS][2], int &NumCoords,
                       char *MapFileNameStr, int LineNum)
{
  char szWork[MAXLINE];
  int nLineIndex, nNextLineIndex;

  nNextLineIndex = 0;
  nLineIndex = 0;
  trim(LineBuf);
  getWord(szWork, LineBuf, nLineIndex, nNextLineIndex);
  nLineIndex = nNextLineIndex;
  if ((szWork[0] == 0) || (szWork[0] == '#') || (szWork[0] == '/') || (szWork[0] == '\''))
    return FALSE;
  else
    if ((strcmpi("rect", szWork) == 0) || (strcmpi("rectangle", szWork) == 0))
      Region = RectRgn;
    else
      if (strcmpi("circle", szWork) == 0)
        Region = CircleRgn;
      else
        if ((strcmpi("poly", szWork) == 0) || (strcmpi("polygon", szWork) == 0))
          Region = PolyRgn;
        else
          if (strcmpi("default", szWork) == 0)
            Region = DefaultRgn;
          else
            if (strcmpi("point", szWork) == 0)
              Region = PointRgn;
            else
            {
		        logImageMapParseError("Unexpected region type", MapFileNameStr, LineNum);
              return FALSE;
   	      }
  getWord(URI, LineBuf, nLineIndex, nNextLineIndex);
  nLineIndex = nNextLineIndex;
  if (URI[0] == 0)
  {
	 logImageMapParseError("Expected URI to associate with region", MapFileNameStr, LineNum);
    return FALSE;
  }
  NumCoords = 0;
  getWord(szWork, LineBuf, nLineIndex, nNextLineIndex);
  nLineIndex = nNextLineIndex;
  while (szWork[0] != 0)
  {
    strToPoints(szWork, Coords[NumCoords]);
    NumCoords++;
    getWord(szWork, LineBuf, nLineIndex, nNextLineIndex);
    nLineIndex = nNextLineIndex;
  }
  return TRUE;
}


//----------------------------------------------------------------------------


//Logs an error if an image map file is invalid or corrupted
void logImageMapParseError(char *ErrorDescStr, char *MapFileNameStr, int LineNum)
{
  char szError[MAX_PATH + MAX_PATH], szNum[17];

  strcpy(szError, "Parse error in image map ");
  strcat(szError, MapFileNameStr);
  strcat(szError, " line number ");
  itoa(LineNum, szNum, 10);
  strcat(szError, szNum);
  strcat(szError, " ");
  strcat(szError, ErrorDescStr);
  logError(szError);
}


//----------------------------------------------------------------------------


//Determines if a point is in a rectangle
BOOL pointInRect(double Point[2], double Coords[MAXVERTS][2])
{
  double temp;

  if (Coords[0][X] > Coords[1][X])
  {
    temp = Coords[0][X];
    Coords[0][X] = Coords[1][X];
    Coords[1][X] = temp;
  }
  if (Coords[0][Y] > Coords[1][Y])
  {
    temp = Coords[0][Y];
    Coords[0][Y] = Coords[1][Y];
    Coords[1][Y] = temp;
  }
  return (((Point[X] >= Coords[0][X]) && (Point[X] <= Coords[1][X])) &&
           ((Point[Y] >= Coords[0][Y]) && (Point[Y] <= Coords[1][Y])));
}


//----------------------------------------------------------------------------


//Determines if a point is in a circle
BOOL pointInCircle(double Point[2], double Coords[MAXVERTS][2])
{
  double dRadius1, dRadius2;

  dRadius1 = ((Coords[0][Y] - Coords[1][Y]) * (Coords[0][Y] - Coords[1][Y])) +
   	      ((Coords[0][X] - Coords[1][X]) * (Coords[0][X] - Coords[1][X]));
  dRadius2 = ((Coords[0][Y] - Point[Y]) * (Coords[0][Y] - Point[Y])) +
		      ((Coords[0][X] - Point[X]) * (Coords[0][X] - Point[X]));
  return (dRadius2 <= dRadius1);
}


//----------------------------------------------------------------------------


//Determines if a point is in a polygon
BOOL pointInPoly(double point[2], double pgon[MAXVERTS][2], int numverts)
{
  int nInsideFlag, nXflag, nCrossings;
  double *p, *stop, tx, ty, y;

  nCrossings = 0;
  tx = point[X];
  ty = point[Y];
  y = pgon[numverts - 1][Y];
  p = (double*)pgon + 1;
  if ((y >= ty) != (*p >= ty))
  {
    if ((nXflag = (pgon[numverts - 1][X] >= tx)) == (*(double*)pgon >= tx))
      if (nXflag)
        nCrossings++;
    else
      nCrossings = ((pgon[numverts - 1][X] - (y - ty) *
         	       (*(double*)pgon - pgon[numverts - 1][X]) / (*p - y)) >= tx) + nCrossings;
  }
  stop = pgon[numverts];
  for (y = *p, p=p+2; p < stop; y = *p, p=p+2)
  {
    if (y >= ty)
    {
      while ((p < stop) && (*p >= ty))
        p += 2;
      if (p >= stop)
        break;
      if ((nXflag = (*(p - 3) >= tx)) == (*(p - 1) >= tx))
        if (nXflag)
          nCrossings++;
      else
        nCrossings = ((*(p - 3) - (*(p - 2) - ty) *
            	      (*(p - 1) - *(p - 3)) / (*p - *(p - 2))) >= tx) + nCrossings;
    }
    else
    {
      while ((p < stop) && (*p < ty))
        p = p + 2;
      if (p >= stop)
        break;
      if ((nXflag = (*(p - 3) >= tx)) == (*(p - 1) >= tx))
        if (nXflag)
          nCrossings++;
      else
        nCrossings = ((*(p - 3) - (*(p - 2) - ty) *
            	      (*(p - 1) - *(p - 3)) / (*p - *(p - 2))) >= tx) + nCrossings;
    }
  }
  nInsideFlag = nCrossings & 0x01;
  return (nInsideFlag);
}

