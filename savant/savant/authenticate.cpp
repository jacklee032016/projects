/*
*
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "savant.h"

//Private definitions
#define USERS_CACHE_SIZE 10


//Private global variables
int NumUsers, NumGroups;
tUser *Users;
tGroup *Groups;
BYTE MIMETable[256];
tCacheEntry Cache[USERS_CACHE_SIZE];
int LastCacheEntry;
CRITICAL_SECTION CacheSection;


//Checks to see if a user has already verified their identity
BOOL _checkCache(char *AuthStr, char *AuthUserStr, char *UserStr)
{
  int i;

  i = LastCacheEntry;
  if ((strcmpi(Cache[i].EncodedAuthInfo, AuthStr) == 0) &&
		(strcmpi(Cache[i].AuthUserStr, AuthUserStr) == 0))
  {
	 strcpy(UserStr, Cache[i].UserStr);
	 return TRUE;
  }
  i--;
  if (i < 0)
    i = USERS_CACHE_SIZE - 1;
  while((i != LastCacheEntry) && ((strcmpi(Cache[i].EncodedAuthInfo, AuthStr) != 0) ||
		  (strcmpi(Cache[i].AuthUserStr, AuthUserStr) != 0)))
  {
	 i--;
	 if (i < 0)
      i = USERS_CACHE_SIZE - 1;
  }
  if (i != LastCacheEntry)
  {
	 strcpy(UserStr, Cache[i].UserStr);
	 return TRUE;
  }
  else
	 return FALSE;
}

//Determines if a user name and password are valid
BOOL _checkUserPassword(char *UserNameStr, char *PasswordStr)
{
  int i;

  i = 0;
  while ((i < NumUsers) && (strcmpi(Users[i].NameStr, UserNameStr) != 0))
	 i++;
  if (i == NumUsers)
    return FALSE;
  if (strcmpi(Users[i].PasswordStr, PasswordStr) == 0)
    return TRUE;
  else
    return FALSE;
}

//Decodes a MIME encoded password string
void _decodeAuthStr(char *AuthStr, char *UserNameStr, char *PasswordStr)
{
  BYTE inputBuff[4], outputBuff[3];
  char szIn[4], szBasic[20], szOut[100];
  int nOutLength, nAuthLength, i, j, start;

  nAuthLength = strlen(AuthStr);
  getWord(szBasic, AuthStr, 0, start);
  if (strcmpi(szBasic, "Basic") != 0)
  {
	  UserNameStr[0] = 0;
	  PasswordStr[0] = 0;
	  return;
  }
  AuthStr = AuthStr + start;
  for(i=0; i < nAuthLength; i=i + 4)
  {
	 memcpy(szIn, AuthStr + i, 4);
	 for (j=0; j < 4; j++)
    {
		if ((i + j == nAuthLength) || (szIn[j] == '='))
		  inputBuff[j] = 0;
		else
		  inputBuff[j] = MIMETable[szIn[j]];
    }
	 outputBuff[0] = (inputBuff[0] << 2) + (inputBuff[1] >> 4);
	 outputBuff[1] = (inputBuff[1] << 4) + (inputBuff[2] >> 2);
	 outputBuff[2] = (inputBuff[2] << 6) + inputBuff[3];
	 memcpy(szOut + ((i / 4) * 3), outputBuff, 3);
  }
  szOut[((i / 4) * 3)] = 0;
  nOutLength = strlen(szOut);
  i = 0;
  while ((i < nOutLength) && (szOut[i] != ':'))
  {
	 UserNameStr[i] = szOut[i];
	 i++;
  }
  UserNameStr[i] = 0;
  j = 0;
  if (szOut[i] == ':')
    i++;
  while (i < nOutLength)
  {
	 PasswordStr[j] = szOut[i];
	 i++;
	 j++;
  }
  PasswordStr[j] = 0;
}
//Determines if a user is in a group
BOOL _userInGroup(char *UserNameStr, char *GroupNameStr)
{
  int i,j;

  i = 0;
  j = 0;
  while ((i < NumGroups) && (strcmpi(Groups[i].NameStr, GroupNameStr) != 0))
	 i++;
  if (i == NumGroups)
    return FALSE;
  while ((j < Groups[i].NumMembers) && (strcmpi(Groups[i].Members[j], UserNameStr) != 0))
	 j++;
  if (j == Groups[i].NumMembers)
    return FALSE;
  else
    return TRUE;
}

//Adds a validated user to the cache
void _addToCache(char *AuthStr, char *AuthUserStr, char *UserStr)
{
  int nNewEntry;

  EnterCriticalSection(&CacheSection);
  nNewEntry = LastCacheEntry + 1;
  if (nNewEntry == USERS_CACHE_SIZE)
	 nNewEntry = 0;
  Cache[nNewEntry].EncodedAuthInfo[0] = 0;
  strcpy(Cache[nNewEntry].AuthUserStr, AuthUserStr);
  strcpy(Cache[nNewEntry].UserStr, UserStr);
  strcpy(Cache[nNewEntry].EncodedAuthInfo, AuthStr);
  LastCacheEntry = nNewEntry;
  LeaveCriticalSection(&CacheSection);
}

//Loads users and groups from registry
void authLoadUsers(HTTP_SERVICE *service)
{
	char szNumUsers[6], szUserName[41], szPassword[41], szNumGroups[6];
	char szGroupName[41], szNumMembers[6], szMember[41];
	DWORD dwValueType, dwBuffLen;
	FILETIME junk;
	HKEY hUsersKey, hUserKey, hGroupsKey, hGroupKey, hMembersKey;
	int i, j;
	
#if 0

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Users", 0, KEY_ALL_ACCESS, &hUsersKey) != ERROR_SUCCESS)
	{
		logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
		return;
	}
	dwBuffLen = 5;
	if (RegQueryValueEx(hUsersKey, "Number of Users", 0, &dwValueType, (LPBYTE)szNumUsers, &dwBuffLen) != ERROR_SUCCESS)
	{
		logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
		return;
	}

	NumUsers = atoi(szNumUsers);
	Users = new tUser[NumUsers];
	for (i=0; i<NumUsers; i++)
	{
	dwBuffLen = 40;
	if (RegEnumKeyEx(hUsersKey, i, szUserName, &dwBuffLen, 0, NULL, 0, &junk) != ERROR_SUCCESS)
	{
	logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	return;
	}
	if (RegOpenKeyEx(hUsersKey, szUserName, 0, KEY_ALL_ACCESS, &hUserKey) != ERROR_SUCCESS)
	{
	logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	return;
	}
	dwBuffLen = 40;
	if (RegQueryValueEx(hUserKey, "Password", 0, &dwValueType,
	(LPBYTE)szPassword, &dwBuffLen) != ERROR_SUCCESS)
	{
	logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	return;
	}
	if (RegCloseKey(hUserKey) != ERROR_SUCCESS)
	logError("Error closing registry key");
	Users[i].NameStr = new char[strlen(szUserName) + 1];
	Users[i].PasswordStr = new char[strlen(szPassword) + 1];
	strcpy(Users[i].NameStr, szUserName);
	strcpy(Users[i].PasswordStr, szPassword);
	}
	if (RegCloseKey(hUsersKey) != ERROR_SUCCESS)
	logError("Error closing registry key");
			//gets user information


	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Groups", 0,
	KEY_ALL_ACCESS, &hGroupsKey) != ERROR_SUCCESS)
	{
	logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	return;
	}
	dwBuffLen = 5;
	if (RegQueryValueEx(hGroupsKey, "Number of Groups", 0, &dwValueType,
	(LPBYTE)szNumGroups, &dwBuffLen) != ERROR_SUCCESS)
	{
	logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	return;
	}
	NumGroups = atoi(szNumGroups);
	Groups = new tGroup[NumGroups];
	for(i=0; i < NumGroups; i++)
	{
	dwBuffLen = 40;
	if (RegEnumKeyEx(hGroupsKey, i, szGroupName, &dwBuffLen, 0, NULL, 0, &junk) != ERROR_SUCCESS)
	{
	logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	return;
	}
	if (RegOpenKeyEx(hGroupsKey, szGroupName, 0, KEY_ALL_ACCESS, &hGroupKey) != ERROR_SUCCESS)
	{
	logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	return;
	}
	dwBuffLen = 5;
	if (RegQueryValueEx(hGroupKey, "Number of Members", 0, &dwValueType,
	(LPBYTE)szNumMembers, &dwBuffLen) != ERROR_SUCCESS)
	{
	logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	return;
	}
	Groups[i].NumMembers = atoi(szNumMembers);
	Groups[i].NameStr = new char[strlen(szGroupName) + 1];
	Groups[i].Members = new char *[Groups[i].NumMembers];
	strcpy(Groups[i].NameStr, szGroupName);
	if (RegOpenKeyEx(hGroupKey, "Members", 0, KEY_ALL_ACCESS, &hMembersKey) != ERROR_SUCCESS)
	{
	logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	return;
	}
	for (j=0; j < Groups[i].NumMembers; j++)
	{
	dwBuffLen = 40;
	if (RegEnumKeyEx(hMembersKey, j, szMember, &dwBuffLen, 0, NULL, 0, &junk) != ERROR_SUCCESS)
	{
	logCriticalError("Corrupted Registry - See the Errors & Troubleshooting section of the help file.");
	return;
	}
	Groups[i].Members[j] = new char[strlen(szMember) + 1];
	strcpy(Groups[i].Members[j], szMember);
	}
	if (RegCloseKey(hMembersKey) != ERROR_SUCCESS)
	logError("Error closing registry key");
	if (RegCloseKey(hGroupKey) != ERROR_SUCCESS)
	logError("Error closing registry key");
	}
	if (RegCloseKey(hGroupsKey) != ERROR_SUCCESS)
	logError("Error closing registry key");
#else
#endif
	
	LastCacheEntry = USERS_CACHE_SIZE - 1;
	for (i=0; i < USERS_CACHE_SIZE; i++)
		Cache[i].EncodedAuthInfo[0] = 0;
	InitializeCriticalSection(&CacheSection);
						//gets group info from registry

	memset(MIMETable, 0, sizeof(MIMETable));
	for (i=65; i <= 90; i++)
		MIMETable[i] = i - 65;
	for (i=97; i <= 122; i++)
		MIMETable[i] = i - 97 + 26;
	for (i=48; i <= 57; i++)
		MIMETable[i] = i - 48 + 52;
	
	MIMETable[43] = 62;
	MIMETable[47] = 63;               //creates MIME decoding table

	TRACE();
}


//Removes user and group lists from memory
void authUnloadUsers(HTTP_SERVICE *service)
{
#if 0
	int i, j;

	for (i=0; i < NumUsers; i++)
	{
	delete[] Users[i].NameStr;
	delete[] Users[i].PasswordStr;
	}
	delete[] Users;
	for (i=0; i < NumGroups; i++)
	{
	delete[] Groups[i].NameStr;
	for (j=0; j < Groups[i].NumMembers; j++)
	delete[] Groups[i].Members[j];
	delete[] Groups[i].Members;
	}
	delete[] Groups;
#else
#endif
	DeleteCriticalSection(&CacheSection);

	TRACE();
}


//Determines if a user name and password allow access to a resource
BOOL HTTPCheckUser(char *AuthStr, char *AuthUser, char *UserStr)
{
  char szPassword[50];

  if (_checkCache(AuthStr, AuthUser, UserStr) == TRUE)
	 return TRUE;						//checks if user has already verified identity

  _decodeAuthStr(AuthStr, UserStr, szPassword);
  if (_checkUserPassword(UserStr, szPassword) == FALSE)
	 return FALSE;						//checks password

  if (strcmpi(UserStr, AuthUser) == 0)
  {
	 _addToCache(AuthStr, AuthUser, UserStr);
	 return TRUE;
  }
  if (_userInGroup(UserStr, AuthUser) == TRUE)
  {
	 _addToCache(AuthStr, AuthUser, UserStr);
	 return TRUE;
  }										//adds user to cache
  else
	 return FALSE;
}

