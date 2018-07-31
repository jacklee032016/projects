/*
*
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "savant.h"

//Converts a hexadecimal number to a decimal number
int hexVal(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  else
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
	 else
      if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
	   else
        return 0;
}


//Removes spaces and tabs from right end of string
void trimLeft(char *TargetStr)
{
  int i, nNewStrSize;

  i = 0;
  while ((TargetStr[i] == ' ') || (TargetStr[i] == '\t'))
	 i++;
  if (i > 0)
  {
	 nNewStrSize = strlen(TargetStr) - i + 1;
	 memmove(TargetStr, TargetStr + i, nNewStrSize);
  }
}



//Removes the leftmost integer from a dotted inet address.
void trimInet(char *TargetStr)
{
	int i, nNewStrSize;

	i = 0;
	while (TargetStr[i] != '.')
		i++;

	i++;
	if (i > 0)
	{
		nNewStrSize = strlen(TargetStr) - i + 1;
		memmove(TargetStr, TargetStr + i, nNewStrSize);
	}
}


//Removes spaces and tabs from left end of string
void trimRight(char *TargetStr)
{
  int i;

  i = strlen(TargetStr) - 1;
  while ((i >= 0) && ((TargetStr[i] == ' ') || (TargetStr[i] == '\t')) )
	 i--;
  TargetStr[i+1] = 0;
}



//Removes spaces and tabs from both ends of a string
void trim(char *TargetStr)
{
  trimRight(TargetStr);
  trimLeft(TargetStr);
}


//Gets leftmost word in a string
void getWord(char *DestStr, const char *SourceStr, const int Start, int &End)
{
  int i, nLen;

  nLen = 0;
  i = Start;
  while ((SourceStr[i] != ' ') && (SourceStr[i] != '\t') && (SourceStr[i] != 0))
  {
	 nLen++;
	 i++;
  }
  memcpy(DestStr, SourceStr + Start, nLen);
  DestStr[nLen] = 0;
  while ((SourceStr[i] != 0) && ((SourceStr[i] == ' ') || (SourceStr[i] == '\t')))
	 i ++;
  End = i;
}


//Gets rightmost word in a string
void getLastWord(char *DestString, const char *SourceStr, int &Start)
{
  int nSourceLen, i, nLen;

  nLen = 0;
  nSourceLen = strlen(SourceStr);
  i = nSourceLen - 1;
  while ((i >= 0) && (SourceStr[i] != ' ') && (SourceStr[i] != '\t'))
  {
	 nLen++;
	 i--;
  }
  memcpy(DestString, SourceStr + nSourceLen - nLen, nLen);
  DestString[nLen] = 0;
  Start = i + 1;
}


//Splits a file path into a directory and filename
void splitPath(char *Path, char *Dir, char *FileName)
{
  int nSplitPoint, i, j;

  i = 0;
  j = 0;
  nSplitPoint = strlen(Path) - 1;
  while ((nSplitPoint > 0) && (Path[nSplitPoint] != '\\'))
  	 nSplitPoint--;
  if ((nSplitPoint == 0) && (Path[nSplitPoint] != '\\'))
  {
	 Dir[0] = 0;
	 strcpy(FileName, Path);
  }
  else
  {
	 nSplitPoint++;
		while (i < nSplitPoint)
      {
		  Dir[i] = Path[i];
		  i++;
      }
    Dir[i] = 0;
  while (Path[i] != 0)
  {
	 FileName[j] = Path[i];
	 j++;
	 i++;
  }
  FileName[j] = 0;
  }
}


//Gets the extention of a file contained in a path string
void getExtension(char *Path, char *Extention)
{
  int nDot, nPathLen;

  nPathLen = strlen(Path) - 1;
  nDot = nPathLen;
  while ((nDot > 0) && (Path[nDot] != '.'))
	 nDot--;
  if (nDot > 0)
	 strcpy(Extention, Path + nDot + 1);
  else
	 Extention[0] = 0;
}

//Translates HTTP escape sequences
void translateEscapeString(char *TargetStr)
{
  int i, j;

  i = 0;
  j = 0;
  while (TargetStr[i] != 0)
  {
	 if ((TargetStr[i] == '%') && (TargetStr[i+1] != 0) && (TargetStr[i+2] != 0))
    {
		TargetStr[j] = 16 * hexVal(TargetStr[i+1]) + hexVal(TargetStr[i+2]);
		i = i + 3;
    }
	 else
    {
		TargetStr[j] = TargetStr[i];
		i++;
    }
    j++;
  }
  TargetStr[j] = 0;
}

