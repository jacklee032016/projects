/*
*
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "savant.h"


RUNNING_CONFIG runConfig;


//Gets a boolean value from the registry
int getRegFlag(BOOL &Flag, HKEY RegKey, char *ValName)
{
	char szBool[4];
	DWORD dwValueType, dwBuffSize;

	dwBuffSize = 3;
	if (RegQueryValueEx(RegKey, ValName, 0, &dwValueType, (LPBYTE)szBool,&dwBuffSize) != ERROR_SUCCESS)
		return -1;
	if (strcmp(szBool, "1") == 0)
		Flag = TRUE;
	else
		Flag = FALSE;
	return 0;
}

#if 0
//Loads startup information from registry
void loadRegistryVars()
{
  char szInitNumThreads[6], szMaxNumThreads[6], szNumThreadsKeepFree[6];
  char szThreadCompactPeriod[6], szThreadCompactLaziness[6], szPortNum[6];
  DWORD dwValueType, dwBuffSize;
  HKEY hLogsKey, hComLogKey, hCntLogKey, hRefLogKey, hHTTPDKey, hServerKey;

  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant",
                   0, KEY_ALL_ACCESS, &hServerKey) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  dwBuffSize = REG_MAX_SERVER_NAME;
  if (RegQueryValueEx(hServerKey, "DNS Entry", 0, &dwValueType,
		(LPBYTE)ServerNameStr, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (ServerNameStr[0] == 0)
    strcpy(ServerNameStr, getLocalName());
  if (RegCloseKey(hServerKey) != ERROR_SUCCESS)
	 logError("Error closing registry key");
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\HTTPD",
                   0, KEY_ALL_ACCESS, &hHTTPDKey) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  dwBuffSize = 5;
  if (RegQueryValueEx(hHTTPDKey, "Initial Processes", 0, &dwValueType,
		                (LPBYTE)szInitNumThreads, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  InitNumThreads = atoi(szInitNumThreads);
  dwBuffSize = 5;
  if (RegQueryValueEx(hHTTPDKey, "Max Processes", 0, &dwValueType,
		                (LPBYTE)szMaxNumThreads, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  MaxNumThreads = atoi(szMaxNumThreads);
  dwBuffSize = 5;
  if (RegQueryValueEx(hHTTPDKey, "Free Processes", 0, &dwValueType,
		                (LPBYTE)szNumThreadsKeepFree, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  NumThreadsKeepFree = atoi(szNumThreadsKeepFree);
  dwBuffSize = 5;
  if (RegQueryValueEx(hHTTPDKey, "Process Time-To-Live", 0, &dwValueType,
		                (LPBYTE)szThreadCompactPeriod, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  ThreadCompactPeriod = ((UINT) atoi(szThreadCompactPeriod)) * 1000;
  dwBuffSize = 5;
  if (RegQueryValueEx(hHTTPDKey, "Time-To-Live Checking", 0, &dwValueType,
		                (LPBYTE)szThreadCompactLaziness, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  ThreadCompactLaziness = atoi(szThreadCompactLaziness);
  dwBuffSize = 5;
  if (RegQueryValueEx(hHTTPDKey, "Port", 0, &dwValueType,
		                (LPBYTE)szPortNum, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  PortNum = (WORD)atoi(szPortNum);
  if (getRegFlag(ScriptDNS, hHTTPDKey, "Reverse DNS lookups") != 0)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  dwBuffSize = MAX_PATH;
  if (RegQueryValueEx(hHTTPDKey, "Index File Name", 0, &dwValueType,
		                (LPBYTE)IndexFileNameStr, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  dwBuffSize = MAX_PATH;
  if (RegQueryValueEx(hHTTPDKey, "Error Path", 0, &dwValueType,
		                (LPBYTE)ErrorMsgDirStr, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (ErrorMsgDirStr[strlen(ErrorMsgDirStr) - 1] != '\\')
  {
	 ErrorMsgDirStr[strlen(ErrorMsgDirStr)] = '\\';
	 ErrorMsgDirStr[strlen(ErrorMsgDirStr) + 1] = 0;
  }
  dwBuffSize = MAX_PATH;
  if (RegQueryValueEx(hHTTPDKey, "CGI Pipes", 0, &dwValueType,
		                (LPBYTE)TempDirStr, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (TempDirStr[strlen(TempDirStr) - 1] != '\\')
  {
	 TempDirStr[strlen(TempDirStr)] = '\\';
	 TempDirStr[strlen(TempDirStr) + 1] = 0;
  }
  if (RegCloseKey(hHTTPDKey) != ERROR_SUCCESS)
	 logError("Error closing HTTPD registry key");
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Logs", 0,
		             KEY_ALL_ACCESS, &hLogsKey) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  dwBuffSize = 300;
  if (RegQueryValueEx(hLogsKey, "Log Path", 0, &dwValueType,
		                (LPBYTE)LogDirStr, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (LogDirStr[strlen(LogDirStr) - 1] != '\\')
  {
	 LogDirStr[strlen(LogDirStr)] = '\\';
	 LogDirStr[strlen(LogDirStr) + 1] = 0;
  }
  if (RegOpenKeyEx(hLogsKey, "HTTPD Common", 0,
		             KEY_ALL_ACCESS, &hComLogKey) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (getRegFlag(ComLogEnabled, hComLogKey, "Enabled") != 0)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  dwBuffSize = MAX_PATH;
  if (RegQueryValueEx(hComLogKey, "File Name", 0, &dwValueType,
		                (LPBYTE)ComLogFileNameStr, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (getRegFlag(ComLogConvertIP, hComLogKey, "Reverse DNS lookup") != 0)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (RegCloseKey(hComLogKey) != ERROR_SUCCESS)
	 logError("Error closing Common Log registry key");
  if (RegOpenKeyEx(hLogsKey, "HTTPD Count", 0,
		             KEY_ALL_ACCESS, &hCntLogKey) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (getRegFlag(CntLogEnabled, hCntLogKey, "Enabled") != 0)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  dwBuffSize = MAX_PATH;
  if (RegQueryValueEx(hCntLogKey, "File Name", 0, &dwValueType,
		                (LPBYTE)CntLogFileNameStr, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (getRegFlag(CntLogCountFiles, hCntLogKey, "Count Files") != 0)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (getRegFlag(CntLogCountConnects, hCntLogKey, "Count Connects") != 0)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (getRegFlag(CntLogCountKBytes, hCntLogKey, "Count KBytes") != 0)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (RegCloseKey(hCntLogKey) != ERROR_SUCCESS)
	 logError("Error closing Count Log registry key");
  if (RegOpenKeyEx(hLogsKey, "HTTPD Reference", 0, KEY_ALL_ACCESS,
                   &hRefLogKey) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (getRegFlag(RefLogEnabled, hRefLogKey, "Enabled") != 0)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  dwBuffSize = MAX_PATH;
  if (RegQueryValueEx(hRefLogKey, "File Name", 0, &dwValueType,
		                (LPBYTE)RefLogFileNameStr, &dwBuffSize) != ERROR_SUCCESS)
  {
	 logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	 return;
  }
  if (RegCloseKey(hRefLogKey) != ERROR_SUCCESS)
	 logError("Error closing Reference Log registry key");
  if (RegCloseKey(hLogsKey) != ERROR_SUCCESS)
	 logError("Error closing Logs registry key");
}
#else

int loadRegistryVars(RUNNING_CONFIG *config)
{
	memset( config, 0, sizeof(RUNNING_CONFIG));

	strcpy(config->ServerNameStr, getLocalName());

	config->InitNumThreads = 10;
	config->MaxNumThreads = 20;
	config->NumThreadsKeepFree = 8;
	config->ThreadCompactPeriod = 10 * 1000;

	config->ThreadCompactLaziness = 5;

	config->PortNum = 8080;

	config->ScriptDNS =TRUE;
	
	SNPRINTF(config->IndexFileNameStr, MAX_PATH, "%s", "index.html") ;
	SET_DEFAULT_DIR(config->ErrorMsgDirStr);


	SET_DEFAULT_DIR(config->TempDirStr);

	SET_DEFAULT_DIR(config->LogDirStr);

	config->ComLogEnabled = TRUE;
	SNPRINTF(config->ComLogFileNameStr, MAX_PATH, "%s", "CommLog.log") ;
	config->ComLogConvertIP = TRUE;

	config->CntLogEnabled = TRUE;
	SNPRINTF(config->CntLogFileNameStr, MAX_PATH, "%s", "CntLogFile.log") ;
	
	config->CntLogCountFiles = TRUE;
	config->CntLogCountConnects = TRUE;
	config->CntLogCountKBytes = TRUE;
	config->RefLogEnabled = TRUE;

	SNPRINTF(config->RefLogFileNameStr, MAX_PATH, "%s", "RefLogFile.log") ;

	return 0;
}

#endif


