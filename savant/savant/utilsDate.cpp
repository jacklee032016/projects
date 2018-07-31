/*
* Convert dates to and from RFC 822 format
*/


#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "savant.h"

//Converts Win32 style date string to RFC 822 format
void dateToRFCFormatStr(SYSTEMTIME *CurTime, char *CurTimeStr)
{
  char szWork[17];

  switch(CurTime->wDayOfWeek)
  {
	 case 0:
      strcpy(CurTimeStr, "Sun");
		break;
	 case 1:
      strcpy(CurTimeStr, "Mon");
		break;
    case 2:
    	strcpy(CurTimeStr, "Tue");
		break;
    case 3:
      strcpy(CurTimeStr, "Wed");
      break;
    case 4:
      strcpy(CurTimeStr, "Thu");
	   break;
    case 5:
      strcpy(CurTimeStr, "Fri");
	   break;
    case 6:
      strcpy(CurTimeStr, "Sat");
	   break;
  }										//day of week
  strcat(CurTimeStr, ", ");
  CurTimeStr[5] = 0;
  if (CurTime->wDay < 10)
  {
	 CurTimeStr[5] = '0';
	 CurTimeStr[6] = 0;
  }										//numerical date
  itoa(CurTime->wDay, szWork, 10);
  strcat(CurTimeStr, szWork);
  CurTimeStr[7] = ' ';
  switch(CurTime->wMonth)
  {
	 case 1:
      strcat(CurTimeStr, "Jan");
	   break;
    case 2:
      strcat(CurTimeStr, "Feb");
	   break;
    case 3:
      strcat(CurTimeStr, "Mar");
	   break;
    case 4:
      strcat(CurTimeStr, "Apr");
	   break;
    case 5:
      strcat(CurTimeStr, "May");
	   break;
    case 6:
      strcat(CurTimeStr, "Jun");
	   break;
    case 7:
      strcat(CurTimeStr, "Jul");
	   break;
    case 8:
      strcat(CurTimeStr, "Aug");
	   break;
	 case 9:
      strcat(CurTimeStr, "Sep");
	   break;
    case 10:
      strcat(CurTimeStr, "Oct");
	   break;
    case 11:
      strcat(CurTimeStr, "Nov");
	   break;
    case 12:
      strcat(CurTimeStr, "Dec");
	   break;
  }										//month
  CurTimeStr[11] = ' ';
  CurTimeStr[12] = 0;
  itoa(CurTime->wYear, szWork, 10);
  strcat(CurTimeStr, szWork);
  CurTimeStr[16] = ' ';
  CurTimeStr[17] = 0;				//year
  if (CurTime->wHour == 0)
  {
	 CurTimeStr[17] = '0';
	 CurTimeStr[18] = '0';
	 CurTimeStr[19] = 0;
  }
  else
    if (CurTime->wHour < 10)
    {
	   CurTimeStr[17] = '0';
		CurTimeStr[18] = 0;
		itoa(CurTime->wHour, szWork, 10);
		strcat(CurTimeStr, szWork);
    }
	 else
    {
		itoa(CurTime->wHour, szWork, 10);
		strcat(CurTimeStr, szWork);
    }
  CurTimeStr[19] = ':';
  CurTimeStr[20] = 0;				//hour
  if (CurTime->wMinute == 0)
  {
	 CurTimeStr[20] = '0';
	 CurTimeStr[21] = '0';
	 CurTimeStr[22] = 0;
  }
  else
    if (CurTime->wMinute < 10)
    {
		CurTimeStr[20] = '0';
		CurTimeStr[21] = 0;
		itoa(CurTime->wMinute, szWork, 10);
		strcat(CurTimeStr, szWork);
    }
	 else
    {
		itoa(CurTime->wMinute, szWork, 10);
		strcat(CurTimeStr, szWork);
    }
  itoa(CurTime->wMinute, szWork, 10);
  strcat(CurTimeStr, szWork);
  CurTimeStr[22] = ':';
  CurTimeStr[23] = 0;				//minutes
  if (CurTime->wSecond == 0)
  {
	 CurTimeStr[23] = '0';
	 CurTimeStr[24] = '0';
	 CurTimeStr[25] = 0;
  }
  else
    if (CurTime->wSecond < 10)
    {
		CurTimeStr[23] = '0';
		CurTimeStr[24] = 0;
		itoa(CurTime->wSecond, szWork, 10);
		strcat(CurTimeStr, szWork);
    }
	 else
    {
		itoa(CurTime->wSecond, szWork, 10);
		strcat(CurTimeStr, szWork);
    }
  itoa(CurTime->wSecond, szWork, 10);
  strcat(CurTimeStr, szWork);	//seconds
  strcat(CurTimeStr, " GMT");
  CurTimeStr[29] = 0;				//GMT tag
}


//Converts a Win32 style date string to HTTPd date format
void dateToOffsetFormatStr(SYSTEMTIME *CurTime, char *CurTimeStr)
{
  char szWork[33];
  int nOffsetMin, nOffsetSec, i;
  TIME_ZONE_INFORMATION timeZoneInfo;

  for (i = 0; i < sizeof(CurTimeStr); i++)
    CurTimeStr[i] = 0;
  CurTimeStr[0] = 0;
  if (CurTime->wDay < 10)
  {
	 CurTimeStr[0] = '0';
	 CurTimeStr[1] = 0;
  }										//day
  itoa(CurTime->wDay, szWork, 10);
  strcat(CurTimeStr, szWork);
  CurTimeStr[2] = '/';
  switch(CurTime->wMonth)
  {
	 case 1:
      strcat(CurTimeStr, "Jan");
	   break;
    case 2:
      strcat(CurTimeStr, "Feb");
	   break;
    case 3:
      strcat(CurTimeStr, "Mar");
	   break;
    case 4:
      strcat(CurTimeStr, "Apr");
	   break;
    case 5:
      strcat(CurTimeStr, "May");
	   break;
    case 6:
      strcat(CurTimeStr, "Jun");
	   break;
    case 7:
      strcat(CurTimeStr, "Jul");
	   break;
    case 8:
      strcat(CurTimeStr, "Aug");
	   break;
	 case 9:
      strcat(CurTimeStr, "Sep");
	   break;
    case 10:
      strcat(CurTimeStr, "Oct");
	   break;
    case 11:
      strcat(CurTimeStr, "Nov");
	   break;
    case 12:
      strcat(CurTimeStr, "Dec");
	   break;
  }
  CurTimeStr[6] = '/';
  CurTimeStr[7] = 0;
  itoa(CurTime->wYear, szWork, 10);
  strcat(CurTimeStr, szWork);	//month
  CurTimeStr[11] = ':';
  CurTimeStr[12] = 0;				//year
  if (CurTime->wHour == 0)
  {
	 CurTimeStr[12] = '0';
	 CurTimeStr[13] = '0';
	 CurTimeStr[14] = 0;
  }
  else
    if (CurTime->wHour < 10)
    {
		CurTimeStr[12] = '0';
		CurTimeStr[13] = 0;
		itoa(CurTime->wHour, szWork, 10);
		strcat(CurTimeStr, szWork);
    }
	 else
    {
		itoa(CurTime->wHour, szWork, 10);
		strcat(CurTimeStr, szWork);
    }										//hour
  CurTimeStr[14] = ':';
  CurTimeStr[15] = 0;
  if (CurTime->wMinute == 0)
  {
	 CurTimeStr[15] = '0';
	 CurTimeStr[16] = '0';
	 CurTimeStr[17] = 0;
  }
  else
    if (CurTime->wMinute < 10)
    {
		CurTimeStr[15] = '0';
		CurTimeStr[16] = 0;
		itoa(CurTime->wMinute, szWork, 10);
		strcat(CurTimeStr, szWork);
    }
	 else
    {
		itoa(CurTime->wMinute, szWork, 10);
		strcat(CurTimeStr, szWork);
    }										//minute
  itoa(CurTime->wMinute, szWork, 10);
  strcat(CurTimeStr, szWork);
  CurTimeStr[17] = ':';
  CurTimeStr[18] = 0;
  if (CurTime->wSecond == 0)
  {
	 CurTimeStr[18] = '0';
	 CurTimeStr[19] = '0';
	 CurTimeStr[20] = 0;
  }
  else
    if (CurTime->wSecond < 10)
    {
		CurTimeStr[18] = '0';
		CurTimeStr[19] = 0;
		itoa(CurTime->wSecond, szWork, 10);
		strcat(CurTimeStr, szWork);
    }
	 else
    {
		itoa(CurTime->wSecond, szWork, 10);
		strcat(CurTimeStr, szWork);
    }										//second
  itoa(CurTime->wSecond, szWork, 10);
  strcat(CurTimeStr, szWork);
  CurTimeStr[20] = ' ';
  CurTimeStr[21] = 0;
  GetTimeZoneInformation(&timeZoneInfo);
  if (timeZoneInfo.Bias >= 0)
	 CurTimeStr[21] = '-';
  else
	 CurTimeStr[21] = '+';
  nOffsetMin = abs(timeZoneInfo.Bias / 60);
  nOffsetSec = abs(timeZoneInfo.Bias % 60);
  											//offset for time zone
  if (nOffsetMin < 10)
  {
    CurTimeStr[22] = '0';
    CurTimeStr[23] = 0;
  }
  else
    CurTimeStr[22] = 0;
  itoa(nOffsetMin, szWork, 10);
  strcat(CurTimeStr, szWork);
  if (nOffsetSec < 10)
  {
    CurTimeStr[24] = '0';
    CurTimeStr[25] = 0;
  }
  else
    CurTimeStr[24] = 0;				//parse minutes and seconds
  itoa(nOffsetSec, szWork, 10);
  strcat(CurTimeStr, szWork);
}


//Converts a date string in one of the three RFC formats to Win32 style
int strToDate(char *PassedCurTimeStr, SYSTEMTIME *CurTime)
{
  char szCurTime[200];
  char szWork[17];
  int nOffset;

  nOffset = 0;
  strcpy(szCurTime, PassedCurTimeStr);
  CharUpper(szCurTime);			//make an uppercase copy of the string
  CurTime->wMilliseconds = 0;		//get rid of milliseconds field
  if(szCurTime[3] == ',')
  {                              //RFC 822 date string
	 szWork[0] = szCurTime[0];
	 szWork[1] = szCurTime[1];
	 szWork[2] = szCurTime[2];
	 szWork[3] = 0;
	 if (strcmp(szWork, "SUN") == 0)
		CurTime->wDayOfWeek = 0;
	 else
      if (strcmp(szWork, "MON") == 0)
		  CurTime->wDayOfWeek = 1;
		else
        if (strcmp(szWork, "TUE") == 0)
			 CurTime->wDayOfWeek = 2;
		  else
          if (strcmp(szWork, "WED") == 0)
			   CurTime->wDayOfWeek = 3;
		    else
            if (strcmp(szWork, "THU") == 0)
			     CurTime->wDayOfWeek = 4;
		      else
              if (strcmp(szWork, "FRI") == 0)
			       CurTime->wDayOfWeek = 5;
		        else
                if (strcmp(szWork, "SAT") == 0)
			         CurTime->wDayOfWeek = 6;
		          else
                {
                  logError("Failure to convert RFC 822 time string");
			         return -1;
			       }						//day of week
	 if ((szCurTime[5] == '0') || (szCurTime[5] == ' '))
    {
		szWork[0] = szCurTime[6];
		szWork[1] = 0;
    }
	 else
    {
		szWork[0] = szCurTime[5];
		szWork[1] = szCurTime[6];
		szWork[2] = 0;
    }
	 if ((CurTime->wDay = (WORD) atoi(szWork)) == 0)
    {
		logError("Failure to convert RFC 822 time string");
		return -1;
    }
	 else
      if (CurTime->wDay >= 34)
      {
		  logError("Failure to convert RFC 822 time string");
		  return -1;
      }
	 szWork[0] = szCurTime[8];
	 szWork[1] = szCurTime[9];
	 szWork[2] = szCurTime[10];
	 szWork[3] = 0;					//numerical day
	 if (strcmp(szWork, "JAN") == 0)
		CurTime->wMonth = 1;
	 else
      if (strcmp(szWork, "FEB") == 0)
		  CurTime->wMonth = 2;
		else
        if (strcmp(szWork, "MAR") == 0)
			 CurTime->wMonth = 3;
		else
        if (strcmp(szWork, "APR") == 0)
			 CurTime->wMonth = 4;
		  else
          if (strcmp(szWork, "MAY") == 0)
			   CurTime->wMonth = 5;
		    else
            if (strcmp(szWork, "JUN") == 0)
			     CurTime->wMonth = 6;
		      else
              if (strcmp(szWork, "JUL") == 0)
			       CurTime->wMonth = 7;
		        else
                if (strcmp(szWork, "AUG") == 0)
			         CurTime->wMonth = 8;
		          else
                  if (strcmp(szWork, "SEP") == 0)
			           CurTime->wMonth = 9;
		            else
                    if (strcmp(szWork, "OCT") == 0)
			              CurTime->wMonth = 10;
		              else
                      if (strcmp(szWork, "NOV") == 0)
			               CurTime->wMonth = 11;
		                else
                        if (strcmp(szWork, "DEC") == 0)
			                 CurTime->wMonth = 12;
		                  else
                        {
                          logError("Failure to convert RFC 822 time string");
			                 return -1;
			               }			//month
	 szWork[0] = szCurTime[12];
	 szWork[1] = szCurTime[13];
	 szWork[2] = szCurTime[14];
	 szWork[3] = szCurTime[15];
	 szWork[4] = 0;
	 if ((CurTime->wYear = (WORD) atoi(szWork)) == 0)
    {
		logError("Failure to convert RFC 822 time string");
		return -1;
    }
	 else
      if ((CurTime->wYear < 1950) || (CurTime->wYear > 2500))
      {
		  logError("Failure to convert RFC 822 time string");
        return -1;
      }
	 szWork[0] = szCurTime[17];
	 szWork[1] = szCurTime[18];
	 szWork[2] = 0;					//year
	 CurTime->wHour = (WORD) atoi(szWork);
	 if (CurTime->wHour >= 24)
    {
		logError("Failure to convert RFC 822 time string");
		return -1;
    }
	 szWork[0] = szCurTime[20];
	 szWork[1] = szCurTime[21];
	 szWork[2] = 0;					//hour
	 CurTime->wMinute = (WORD) atoi(szWork);
	 if (CurTime->wMinute >= 60)
    {
		logError("Failure to convert RFC 822 time string");
		return -1;
    }
	 szWork[0] = szCurTime[23];
	 szWork[1] = szCurTime[24];
	 szWork[2] = 0;              //minutes
	 CurTime->wSecond = (WORD) atoi(szWork);
	 if (CurTime->wSecond >= 60)
    {
		logError("Failure to convert RFC 822 time string");
		return -1;
    }
	 szWork[0] = szCurTime[26];
	 szWork[1] = szCurTime[27];
	 szWork[2] = szCurTime[28];
	 szWork[3] = 0;					//seconds
	 if (strcmpi(szWork, "GMT") != 0)
    {
		logError("Failure to convert RFC 822 time string");
		return -1;
    }										//verify in GMT time zone
  }
  else
    if (szCurTime[3] == ' ')		//ANSI C++ date format
    {
		szWork[0] = szCurTime[0];
		szWork[1] = szCurTime[1];
		szWork[2] = szCurTime[2];
		szWork[3] = 0;
		if (strcmp(szWork, "SUN") == 0)
		  CurTime->wDayOfWeek = 0;
		else
        if (strcmp(szWork, "MON") == 0)
			 CurTime->wDayOfWeek = 1;
		  else
          if (strcmp(szWork, "TUE") == 0)
			   CurTime->wDayOfWeek = 2;
		    else
            if (strcmp(szWork, "WED") == 0)
			     CurTime->wDayOfWeek = 3;
		      else
              if (strcmp(szWork, "THU") == 0)
                CurTime->wDayOfWeek = 4;
		        else
                if (strcmp(szWork, "FRI") == 0)
			         CurTime->wDayOfWeek = 5;
		          else
                  if (strcmp(szWork, "SAT") == 0)
			           CurTime->wDayOfWeek = 6;
		            else
                  {
			           logError("Failure to convert asctime time string");
			           return -1;
			         }
		szWork[0] = szCurTime[4];
		szWork[1] = szCurTime[5];
		szWork[2] = szCurTime[6];
		szWork[3] = 0;				//day of week
		if (strcmp(szWork, "JAN") == 0)
		  CurTime->wMonth = 1;
		else
        if (strcmp(szWork, "FEB") == 0)
		    CurTime->wMonth = 2;
		  else
          if (strcmp(szWork, "MAR") == 0)
			   CurTime->wMonth = 3;
		    else
            if (strcmp(szWork, "APR") == 0)
			     CurTime->wMonth = 4;
		      else
              if (strcmp(szWork, "MAY") == 0)
			       CurTime->wMonth = 5;
		        else
                if (strcmp(szWork, "JUN") == 0)
			         CurTime->wMonth = 6;
		          else
                  if (strcmp(szWork, "JUL") == 0)
			           CurTime->wMonth = 7;
		            else
                    if (strcmp(szWork, "AUG") == 0)
			             CurTime->wMonth = 8;
		              else
                      if (strcmp(szWork, "SEP") == 0)
			               CurTime->wMonth = 9;
		                else
                        if (strcmp(szWork, "OCT") == 0)
			                 CurTime->wMonth = 10;
		                  else
                          if (strcmp(szWork, "NOV") == 0)
			                   CurTime->wMonth = 11;
		                    else
                            if (strcmp(szWork, "DEC") == 0)
			                     CurTime->wMonth = 12;
		                      else
                            {
			                     logError("Failure to convert asctime time string");
			                     return -1;
			                   }		//month
		if ((szCurTime[7] == '0') || (szCurTime[5] == ' '))
      {
		  szWork[0] = szCurTime[8];
		  szWork[1] = 0;
      }
		else
      {
		  szWork[0] = szCurTime[7];
		  szWork[1] = szCurTime[8];
		  szWork[2] = 0;
      }
		if ((CurTime->wDay = (WORD) atoi(szWork)) == 0)
      {
		  logError("Failure to convert asctime time string");
		  return -1;
		}
		else
        if (CurTime->wDay >= 34)
        {
			 logError("Failure to convert asctime time string");
			 return -1;
		  }
		szWork[0] = szCurTime[11];
		szWork[1] = szCurTime[12];
		szWork[2] = 0;				//numerical day
		CurTime->wHour = (WORD) atoi(szWork);
		if (CurTime->wHour >= 24)
      {
		  logError("Failure to convert asctime time string");
		  return -1;
      }
		szWork[0] = szCurTime[14];
		szWork[1] = szCurTime[15];
		szWork[2] = 0;				//hour
		CurTime->wMinute = (WORD) atoi(szWork);
		if (CurTime->wMinute >= 60)
      {
		  logError("Failure to convert asctime time string");
		  return -1;
		}
		szWork[0] = szCurTime[17];
		szWork[1] = szCurTime[18];
		szWork[2] = 0;				//minutes
		CurTime->wSecond = (WORD) atoi(szWork);
		if (CurTime->wSecond >= 60)
      {
		  logError("Failure to convert asctime time string");
		  return -1;
		}
		szWork[0] = szCurTime[20];
		szWork[1] = szCurTime[21];
		szWork[2] = szCurTime[22];
		szWork[3] = szCurTime[23];
		szWork[4] = 0;				//seconds
		if ((CurTime->wYear = (WORD) atoi(szWork)) == 0)
      {
		  logError("Failure to convert asctime time string");
		  return -1;
		}
		else
        if ((CurTime->wYear < 1950) || (CurTime->wYear > 2500))
        {
			 logError("Failure to convert asctime time string");
			 return -1;
		  }								//year
	 }
	 else
    {             					//RFC 850 type (obsolete)
	   while ((nOffset < 17) && (szCurTime[nOffset] != ','))
      {
		  szWork[nOffset] = szCurTime[nOffset];
		  nOffset++;
      }
		if (nOffset == 17)
      {
		  logError("Failure to convert RFC 850 time string");
		  return -1;
		}
	  szWork[nOffset] = 0;
	  if (strcmp(szWork, "SUNDAY") == 0)
		 CurTime->wDayOfWeek = 0;
	  else
       if (strcmp(szWork, "MONDAY") == 0)
			CurTime->wDayOfWeek = 1;
		 else
         if (strcmp(szWork, "TUESDAY") == 0)
			  CurTime->wDayOfWeek = 2;
		   else
           if (strcmp(szWork, "WEDNESDAY") == 0)
			    CurTime->wDayOfWeek = 3;
		     else
             if (strcmp(szWork, "THURSDAY") == 0)
			      CurTime->wDayOfWeek = 4;
		       else
               if (strcmp(szWork, "FRIDAY") == 0)
			        CurTime->wDayOfWeek = 5;
		         else
                 if (strcmp(szWork, "SATURDAY") == 0)
			          CurTime->wDayOfWeek = 6;
		           else
                 {
			          logError("Failure to convert RFC 850 time string");
			          return -1;
			        }					//day of week
	  if ((szCurTime[nOffset+2] == '0') || (szCurTime[nOffset+2] == ' '))
     {
		 szWork[0] = szCurTime[nOffset+3];
		 szWork[1] = 0;
     }
	  else
       {
			szWork[0] = szCurTime[nOffset+2];
			szWork[1] = szCurTime[nOffset+3];
			szWork[2] = 0;
       }
	  if ((CurTime->wDay = (WORD) atoi(szWork)) == 0)
     {
		 logError("Failure to convert RFC 850 time string");
		 return -1;
	  }
	  else
       if (CurTime->wDay >= 34)
       {
			logError("Failure to convert RFC 850 time string");
			return -1;
		 }
	  szWork[0] = szCurTime[nOffset+5];
	  szWork[1] = szCurTime[nOffset+6];
	  szWork[2] = szCurTime[nOffset+7];
	  szWork[3] = 0;					//numerical day
	  if (strcmp(szWork, "JAN") == 0)
		 CurTime->wMonth = 1;
	  else
       if (strcmp(szWork, "FEB") == 0)
			CurTime->wMonth = 2;
		 else
         if (strcmp(szWork, "MAR") == 0)
			  CurTime->wMonth = 3;
		   else
           if (strcmp(szWork, "APR") == 0)
			    CurTime->wMonth = 4;
		     else
             if (strcmp(szWork, "MAY") == 0)
			      CurTime->wMonth = 5;
		       else
               if (strcmp(szWork, "JUN") == 0)
			        CurTime->wMonth = 6;
		         else
                 if (strcmp(szWork, "JUL") == 0)
			          CurTime->wMonth = 7;
		           else
                   if (strcmp(szWork, "AUG") == 0)
			            CurTime->wMonth = 8;
		             else
                     if (strcmp(szWork, "SEP") == 0)
			              CurTime->wMonth = 9;
		               else
                       if (strcmp(szWork, "OCT") == 0)
			                CurTime->wMonth = 10;
		                 else
                         if (strcmp(szWork, "NOV") == 0)
			                  CurTime->wMonth = 11;
		                   else
                           if (strcmp(szWork, "DEC") == 0)
			                    CurTime->wMonth = 12;
		                     else
                           {
			                    logError("Failure to convert RFC 850 time string");
			                    return -1;
			                  }
	  szWork[0] = szCurTime[nOffset+9];
	  szWork[1] = szCurTime[nOffset+10];
	  szWork[4] = 0;					//month
	  CurTime->wYear = (WORD) atoi(szWork);
	  if (CurTime->wYear > 70)
		 CurTime->wYear += (WORD) 1900;
	  else
		 CurTime->wYear += (WORD) 2000;
	  szWork[0] = szCurTime[nOffset+12];
	  szWork[1] = szCurTime[nOffset+13];
	  szWork[2] = 0;					//year
	  CurTime->wHour = (WORD) atoi(szWork);
	  if (CurTime->wHour >= 24)
     {
		 logError("Failure to convert RFC 850 time string");
		 return -1;
	  }
	  szWork[0] = szCurTime[nOffset+15];
	  szWork[1] = szCurTime[nOffset+16];
	  szWork[2] = 0;					//hour
	  CurTime->wMinute = (WORD) atoi(szWork);
	  if (CurTime->wMinute >= 60)
     {
		 logError("Failure to convert RFC 850 time string");
		 return -1;
	  }
	  szWork[0] = szCurTime[nOffset+18];
	  szWork[1] = szCurTime[nOffset+19];
	  szWork[2] = 0;					//minutes
	  CurTime->wSecond = (WORD) atoi(szWork);
	  if (CurTime->wSecond >= 60)
     {
		 logError("Failure to convert RFC 850 time string");
		 return -1;
	  }
	  szWork[0] = szCurTime[nOffset+21];
	  szWork[1] = szCurTime[nOffset+22];
	  szWork[2] = szCurTime[nOffset+23];
	  szWork[3] = 0;					//seconds
	  if (strcmpi(szWork, "GMT") != 0)
     {
		 logError("Failure to convert RFC 850 time string");
		 return -1;
	  }									//verify in GMT time zone
  }
  return 0;
}

