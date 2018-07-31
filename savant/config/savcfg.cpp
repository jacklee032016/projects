/*
* Entrypoint for config program, read data from registry
*/

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include "savcfg.h"


tDirInfo **dirInfo;
UserInfo **userInfo;
GroupInfo *groupInfo;
tMIMEInfo **MIMEinfo;

char szAppName[] = "Savant HTTP Server Configuration";
HINSTANCE hInst;
HWND hwndMain = NULL;
HICON hiconApp;  // Application icon
TsavantData savantData;
int usersToRead, dirsToRead, MIMEToRead;


//Reads directory and path information from Windows 95 registry
void getPathData()
{
	DWORD bufflen, typeValue;
	FILETIME garbage;
	HKEY pathKeyHandle, dirKeyHandle;
	int i;
	char szDirName[51], szLocalDirName[201], szScripting[10], szAuthorizedUser[31];
	char szAuthorizedLocation[31], szList[2];

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Directory Mappings", 0,KEY_ALL_ACCESS,	&pathKeyHandle) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 5;
	if (RegQueryValueEx(pathKeyHandle, "Number of Directories", 0, &typeValue, (LPBYTE)savantData.szNumDirs, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	
	dirInfo = new tDirInfo*[atoi(savantData.szNumDirs)];
	dirsToRead = atoi(savantData.szNumDirs);
	for (i=0; i < atoi(savantData.szNumDirs); i++)
	{
		bufflen = 50;
		if (RegEnumKeyEx(pathKeyHandle, i, szDirName, &bufflen, 0, NULL, 0, &garbage) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		if (RegOpenKeyEx(pathKeyHandle, szDirName, 0, KEY_ALL_ACCESS, &dirKeyHandle) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		bufflen = 200;
		if (RegQueryValueEx(dirKeyHandle, "Local Directory", 0, &typeValue, (LPBYTE)szLocalDirName, &bufflen) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		bufflen = 2;
		if (RegQueryValueEx(dirKeyHandle, "Allow Directory Listings", 0, &typeValue, (LPBYTE)szList, &bufflen) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		bufflen = 9;
		if (RegQueryValueEx(dirKeyHandle, "Scripting", 0, &typeValue, (LPBYTE)szScripting, &bufflen) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		bufflen = 30;
		if (RegQueryValueEx(dirKeyHandle, "Authorized User", 0, &typeValue, (LPBYTE)szAuthorizedUser, &bufflen) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		bufflen = 30;
		if (RegQueryValueEx(dirKeyHandle, "Authorized Location", 0, &typeValue, (LPBYTE)szAuthorizedLocation, &bufflen) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		RegCloseKey(dirKeyHandle);
		
		dirInfo[i] = new tDirInfo;
		strcpy(dirInfo[i]->HTTPname, szDirName);
		strcpy(dirInfo[i]->FATname, szLocalDirName);
		strcpy(dirInfo[i]->allowList, szList);
		strcpy(dirInfo[i]->scriptType, szScripting);
		strcpy(dirInfo[i]->authUser, szAuthorizedUser);
		strcpy(dirInfo[i]->authLocation, szAuthorizedLocation);
	}
	
	RegCloseKey(pathKeyHandle);
	
}


//Read user information from Windows 95 registry
void getUserData()
{
	DWORD bufflen, typeValue;
	FILETIME garbage;
	HKEY usersKeyHandle, userKeyHandle;
	int i;
	char szUserName[31], szPassword[31];

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Users", 0,KEY_ALL_ACCESS, &usersKeyHandle) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}

	bufflen = 6;
	if (RegQueryValueEx(usersKeyHandle, "Number of Users", 0, &typeValue, (LPBYTE)savantData.szNumUsers, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	
	userInfo = new UserInfo*[atoi(savantData.szNumUsers)];
	usersToRead = atoi(savantData.szNumUsers);
	for (i=0; i < atoi(savantData.szNumUsers); i++)
	{
		bufflen = 30;
		if (RegEnumKeyEx(usersKeyHandle, i, szUserName, &bufflen, 0, NULL, 0, &garbage) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		if (RegOpenKeyEx(usersKeyHandle, szUserName, 0, KEY_ALL_ACCESS, &userKeyHandle) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		bufflen = 30;
		if (RegQueryValueEx(userKeyHandle, "Password", 0, &typeValue, (LPBYTE)szPassword, &bufflen) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		RegCloseKey(userKeyHandle);
		userInfo[i] = new UserInfo;
		strcpy(userInfo[i]->name, szUserName);
		strcpy(userInfo[i]->password, szPassword);
	}
	RegCloseKey(usersKeyHandle);
}


//Read group information from Windows 95 registry
void getGroupsData()
{
	DWORD bufflen, typeValue;
	FILETIME garbage;
	HKEY groupsKeyHandle, groupKeyHandle, membersKeyHandle;
	int i,j;
	char szGroupName[31], szNumMembers[7], szMember[31];

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Groups", 0,KEY_ALL_ACCESS, &groupsKeyHandle) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	
	bufflen = 6;
	if (RegQueryValueEx(groupsKeyHandle, "Number of Groups", 0, &typeValue, (LPBYTE)savantData.szNumGroups, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	
	groupInfo = new GroupInfo[(atoi(savantData.szNumGroups))+50];
	for (i=0; i < atoi(savantData.szNumGroups); i++)
	{
		bufflen = 30;
		if (RegEnumKeyEx(groupsKeyHandle, i, szGroupName, &bufflen, 0, NULL, 0, &garbage) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		if (RegOpenKeyEx(groupsKeyHandle, szGroupName, 0, KEY_ALL_ACCESS, &groupKeyHandle) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		bufflen = 6;
		if (RegQueryValueEx(groupKeyHandle, "Number of Members", 0, &typeValue, (LPBYTE)szNumMembers, &bufflen) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		groupInfo[i].numMembers = atoi(szNumMembers);
		strcpy(groupInfo[i].name, szGroupName);
		groupInfo[i].members = new char*[groupInfo[i].numMembers];
		
		if (RegOpenKeyEx(groupKeyHandle, "Members", 0, KEY_ALL_ACCESS, &membersKeyHandle) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		for (j=0; j < groupInfo[i].numMembers; j++)
		{
			bufflen = 30;
			if (RegEnumKeyEx(membersKeyHandle, j, szMember, &bufflen, 0, NULL, 0, &garbage) != ERROR_SUCCESS)
			{
				HANDLER_REGISTER_ERR();
			}
			groupInfo[i].members[j] = new char[31];
			strcpy(groupInfo[i].members[j], szMember);
		}
		
		RegCloseKey(membersKeyHandle);
		RegCloseKey(groupKeyHandle);
	}
	RegCloseKey(groupsKeyHandle);
}


//Read MIME information from registry
void getMIMEData()
{
	DWORD bufflen, typeValue;
	FILETIME garbage;
	HKEY MIMEKeyHandle, extKeyHandle;
	int i;
	char szExtension[6], szDescription[128];

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\MIME", 0,KEY_ALL_ACCESS, &MIMEKeyHandle) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	
	bufflen = 6;
	if (RegQueryValueEx(MIMEKeyHandle, "MIME Types", 0, &typeValue, (LPBYTE)savantData.szNumMIME, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	
	MIMEToRead = atoi(savantData.szNumMIME);
	MIMEinfo = new tMIMEInfo*[atoi(savantData.szNumMIME)];
	for (i=0; i < atoi(savantData.szNumMIME); i++)
	{
		bufflen = 6;
		if (RegEnumKeyEx(MIMEKeyHandle, i, szExtension, &bufflen, 0, NULL, 0, &garbage) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		if (RegOpenKeyEx(MIMEKeyHandle, szExtension, 0, KEY_ALL_ACCESS, &extKeyHandle) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		bufflen = 127;
		if (RegQueryValueEx(extKeyHandle, "MIME Description", 0, &typeValue, (LPBYTE)szDescription, &bufflen) != ERROR_SUCCESS)
		{
			HANDLER_REGISTER_ERR();
		}
		
		RegCloseKey(extKeyHandle);
		MIMEinfo[i] = new tMIMEInfo;
		strcpy(MIMEinfo[i]->extension, szExtension);
		strcpy(MIMEinfo[i]->description, szDescription);
	}
	RegCloseKey(MIMEKeyHandle);
}


//Read server configuration information from the Windows registry
void getRegistryData()
{
	DWORD bufflen, typeValue;
	HKEY configKeyHandle;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant", 0, KEY_ALL_ACCESS, &configKeyHandle) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 150;
	if (RegQueryValueEx(configKeyHandle, "DNS Entry", 0, &typeValue, (LPBYTE)savantData.szDNS, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	RegCloseKey(configKeyHandle);

	
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\HTTPd", 0, KEY_ALL_ACCESS, &configKeyHandle) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}

	bufflen = 5;
	if (RegQueryValueEx(configKeyHandle, "Port", 0, &typeValue, (LPBYTE)savantData.szPort, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 5;
	if (RegQueryValueEx(configKeyHandle, "Processes", 0, &typeValue, (LPBYTE)savantData.szInitialProcesses, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 20;
	if (RegQueryValueEx(configKeyHandle, "Index File Name", 0, &typeValue, (LPBYTE)savantData.szIndex, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 200;
	if (RegQueryValueEx(configKeyHandle, "Error Path", 0, &typeValue, (LPBYTE)savantData.szErrorMsgPath, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}

	bufflen = 200;
	if (RegQueryValueEx(configKeyHandle, "CGI Pipes", 0, &typeValue, (LPBYTE)savantData.szCGITempPipe, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	
	bufflen = 5;
	if (RegQueryValueEx(configKeyHandle, "Initial Processes", 0, &typeValue, (LPBYTE)savantData.szInitialProcesses, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}

	bufflen = 5;
	if (RegQueryValueEx(configKeyHandle, "Max Processes", 0, &typeValue, (LPBYTE)savantData.szMaxProcesses, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}

	bufflen = 5;
	if (RegQueryValueEx(configKeyHandle, "Free Processes", 0, &typeValue, (LPBYTE)savantData.szFreeProcesses, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 5;
	if (RegQueryValueEx(configKeyHandle, "Process Time-To-Live", 0, &typeValue, (LPBYTE)savantData.szProcessCompactPeriod, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}

	bufflen = 5;
	if (RegQueryValueEx(configKeyHandle, "Time-To-Live Checking", 0, &typeValue, (LPBYTE)savantData.szProcessCompactLaziness, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	RegCloseKey(configKeyHandle);

	
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Logs", 0, KEY_ALL_ACCESS, &configKeyHandle) != ERROR_SUCCESS)
	{
	HANDLER_REGISTER_ERR();
	}
	bufflen = 200;
	if (RegQueryValueEx(configKeyHandle, "Log Path", 0, &typeValue, (LPBYTE)savantData.szPathToStoreLogs, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	RegCloseKey(configKeyHandle);


	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Logs\\HTTPd Common", 0, KEY_ALL_ACCESS, &configKeyHandle) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 2;
	if (RegQueryValueEx(configKeyHandle, "Enabled", 0, &typeValue, (LPBYTE)savantData.szGeneralLogEnabled, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 200;
	if (RegQueryValueEx(configKeyHandle, "File Name", 0, &typeValue, (LPBYTE)savantData.szGeneralLogFile, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 2;
	if (RegQueryValueEx(configKeyHandle, "Reverse DNS Lookup", 0, &typeValue, (LPBYTE)savantData.szGeneralLogLookup, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	RegCloseKey(configKeyHandle);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Logs\\HTTPd Count", 0, KEY_ALL_ACCESS, &configKeyHandle) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 2;
	if (RegQueryValueEx(configKeyHandle, "Enabled", 0, &typeValue, (LPBYTE)savantData.szHitEnabled, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 200;
	if (RegQueryValueEx(configKeyHandle, "File Name", 0, &typeValue, (LPBYTE)savantData.szHitLogFile, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 2;
	if (RegQueryValueEx(configKeyHandle, "Count Files", 0, &typeValue, (LPBYTE)savantData.szHitRecordFiles, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 2;
	if (RegQueryValueEx(configKeyHandle, "Count Connects", 0, &typeValue, (LPBYTE)savantData.szHitRecordConnections, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 2;
	if (RegQueryValueEx(configKeyHandle, "Count Kbytes", 0, &typeValue, (LPBYTE)savantData.szHitRecordKB, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	RegCloseKey(configKeyHandle);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Logs\\HTTPd Reference", 0, KEY_ALL_ACCESS, 	&configKeyHandle) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 2;
	if (RegQueryValueEx(configKeyHandle, "Enabled", 0, &typeValue, (LPBYTE)savantData.szReferenceEnabled, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	bufflen = 200;
	if (RegQueryValueEx(configKeyHandle, "File Name", 0, &typeValue, (LPBYTE)savantData.szReferenceLogFile, &bufflen) != ERROR_SUCCESS)
	{
		HANDLER_REGISTER_ERR();
	}
	RegCloseKey(configKeyHandle);

	getPathData();
	getUserData();
	getGroupsData();
	getMIMEData();
}



//Windows callback function for configuration program
LRESULT CALLBACK WndProc(HWND hwnd, UINT mMsg, WPARAM wParam, LPARAM lParam)
{
	switch (mMsg)
	{
		case WM_CREATE:
		case WM_INITDIALOG:
//			getRegistryData();
			CreatePropertySheet(hwnd);
			return 0;
		
		case WM_COMMAND:
			return 0;
			
		case WM_DESTROY:
			PostQuitMessage(0);
			return 0;
			
		default:
			return (DefWindowProc(hwnd, mMsg, wParam, lParam));
	}
}


//Program entrypoint and main function
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpszCmdLine, int cmdShow)
{
	HWND hwnd;
	MSG msg;
	WNDCLASSEX wc;

	hInst = hInstance;
	hiconApp = LoadIcon(hInst, MAKEINTRESOURCE(IDI_APP));
	ZeroMemory(&wc, sizeof(WNDCLASSEX));
	wc.cbSize = sizeof(wc);
	wc.lpszClassName = "MAIN";
	wc.hInstance = hInstance;
	wc.lpfnWndProc = WndProc;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hIcon = hiconApp;
	wc.lpszMenuName = NULL;
	wc.hbrBackground = (HBRUSH)(COLOR_APPWORKSPACE + 1);
	wc.hIconSm = hiconApp;
	RegisterClassEx(&wc);			//create and register window class

	hwndMain = hwnd = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW, "MAIN", szAppName, WS_OVERLAPPEDWINDOW,
		10, 10, 600, 700, NULL, NULL, hInstance, NULL);
	
//	ShowWindow(hwnd, SW_HIDE);
	ShowWindow(hwnd, SW_SHOWDEFAULT);
	UpdateWindow(hwnd);  			//create hidden window
	InitCommonControls();			//init common controls (i.e. property pages)

	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	
	return msg.wParam;
}


