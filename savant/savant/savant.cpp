/*
* entry points and GUI
*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <commctrl.h>
#include <windowsx.h>
#include <process.h>

#include "savant.h"

HTTP_SERVICE	httpService;
HTTP_SERVICE	*http;

RUNNING_CONFIG		*cfg;

#define trayID 1006


HINSTANCE hInstance;
HWND hStatusBar, hStatus, hwndLV, mainWindow;
char szConsole[30000];
int nConsolePos;
HWND hwndConsole;

NOTIFYICONDATA nid;

CRITICAL_SECTION newToolTip;

static HWND MsgWindow;


BOOL CALLBACK AboutDlgProc(HWND hDlg, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	switch(iMsg)
	{
		case WM_COMMAND:
			switch(LOWORD(wParam))  //respond to user-initiated actions
			{
				case IDOK:
				case IDCANCEL:
					EndDialog(hDlg, 0);
					return TRUE;
			}
			break;
	}
	return FALSE;
}

static void _shutdownSavant(HTTP_SERVICE *http)
{
	int result;

	result = MessageBox(http->msgWindow, "Are you sure you want to shut down Savant?", "Savant", MB_YESNO | MB_ICONQUESTION);
	if (result == IDYES)
		DestroyWindow(http->msgWindow);
}

//Loads the Savant configuration utility
static void _loadSavantControl(HTTP_SERVICE *http)
{
	BOOL result;
	PROCESS_INFORMATION processInfo;
	STARTUPINFO startupInfo;
	unsigned long threadStatus;

	httpServerEnd(http);
	authUnloadUsers(http );
	cleanUpNetIO();
	closeErrorLog();
	GetStartupInfo(&startupInfo);
	
	result = CreateProcess(PROGRAM_CONFIG, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
	if(!result)
		MessageBox(http->msgWindow, "Savant Configuration program not found!", "Savant Server", MB_OK | MB_ICONERROR);

	do
	{
		GetExitCodeThread(processInfo.hThread, &threadStatus);
		Sleep(500);
	}  while (threadStatus == STILL_ACTIVE);
	
	openErrorLog( );
	initNetIO();
	loadRegistryVars( &http->cfg);
	authLoadUsers(http);
	
	httpServerStart(http);
}

//Displays the Savant server menu when the tray icon is right-clicked
static void _displayTrayMenu(HTTP_SERVICE *http)
{
	HMENU hTrayMenu;
	int width, height, selectedItem;
	POINT mousePosition;

	hTrayMenu = CreatePopupMenu();
	AppendMenu(hTrayMenu, MF_ENABLED, 1, "Control Console");
	AppendMenu(hTrayMenu, MF_ENABLED, 2, "Configuration");
	AppendMenu(hTrayMenu, MF_SEPARATOR, -1, "");
	AppendMenu(hTrayMenu, MF_ENABLED, 3, "Help");
	AppendMenu(hTrayMenu, MF_ENABLED, 4, "About");
	AppendMenu(hTrayMenu, MF_SEPARATOR, -1, "");
	AppendMenu(hTrayMenu, MF_ENABLED, 5, "Shutdown");

	GetCursorPos(&mousePosition);
	width = GetSystemMetrics(SM_CXSCREEN);
	height = GetSystemMetrics(SM_CYSCREEN);
	SetForegroundWindow(http->msgWindow );
	if ((mousePosition.x >= (width / 2)) && (mousePosition.y >= (height / 2)))
		selectedItem = TrackPopupMenu(hTrayMenu,TPM_BOTTOMALIGN | TPM_RIGHTALIGN | TPM_RETURNCMD | TPM_LEFTBUTTON,
	             mousePosition.x, height, 0, http->msgWindow, NULL);
	else
		if (mousePosition.y < (height / 2))
			selectedItem = TrackPopupMenu(hTrayMenu,TPM_TOPALIGN | TPM_RIGHTALIGN | TPM_RETURNCMD | TPM_LEFTBUTTON,
				mousePosition.x, mousePosition.y, 0, http->msgWindow, NULL);
		else
			selectedItem = TrackPopupMenu(hTrayMenu,TPM_BOTTOMALIGN | TPM_LEFTALIGN | TPM_RETURNCMD | TPM_LEFTBUTTON,
				mousePosition.x, height, 0, http->msgWindow, NULL);

	SetForegroundWindow(http->msgWindow);
	DestroyMenu(hTrayMenu);
	
	if (selectedItem == 1)
		ShowWindow(http->msgWindow, SW_RESTORE);
	else
		if (selectedItem == 2)
			_loadSavantControl(http);
		else
			if (selectedItem == 3)
				WinHelp(http->msgWindow, "Savant.hlp", HELP_FINDER,0);
			else
				if (selectedItem == 4)
					DialogBox(hInstance, "ABOUT", http->msgWindow, AboutDlgProc);
				else
					if (selectedItem == 5)
						_shutdownSavant(http);
					
}


static void _initStatusBar()
{
	HDC hDC;
	RECT rect;
	SIZE size;
	char current[6], total[6];
	int ptArray[5];

	itoa(http->status.numProcesses, current, 10);
	itoa(http->status.totalNumProcesses, total, 10);
	
	hDC = GetDC(hStatus);
	GetClientRect(hStatus, &rect);
	ptArray[4] = rect.right;
	if (GetTextExtentPoint(hDC, "0", 9, &size))
		ptArray[3] = ptArray[4] - (size.cx) - 8;
	else
		ptArray[3] = 0;
	
	if (GetTextExtentPoint(hDC, "Total Xfers:", 10, &size))
		ptArray[2] = ptArray[3] - (size.cx) - 8;
	else
		ptArray[2] = 0;
	
	if (GetTextExtentPoint(hDC, "0", 5, &size))
		ptArray[1] = ptArray[2] - (size.cx) - 8;
	else
		ptArray[1] = 0;
	
	if (GetTextExtentPoint(hDC, "Active Xfers:", 11, &size))
		ptArray[0] = ptArray[1] - (size.cx) - 8;
	else
		ptArray[0] = 0;
	
	ReleaseDC(hStatus, hDC);
	SendMessage(hStatusBar, SB_SETPARTS, sizeof(ptArray)/sizeof(ptArray[0]), (LPARAM)(LPINT)ptArray);
	SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)SERVER_NAME());
	SendMessage(hStatusBar, SB_SETTEXT, 1 | SBT_POPOUT, (LPARAM)"Active Xfers:");
	SendMessage(hStatusBar, SB_SETTEXT, 2, (LPARAM)current);
	SendMessage(hStatusBar, SB_SETTEXT, 3 | SBT_POPOUT, (LPARAM)"Total Xfers:");
	SendMessage(hStatusBar, SB_SETTEXT, 4, (LPARAM)total); 
}


//Removes the Savant icon from the system tray
static void _removeSavantFromTray()
{
	DeleteCriticalSection(&newToolTip);
	Shell_NotifyIcon(NIM_DELETE, &nid);
}

//Processes tray messages received via Win32
static int _processTrayMsg(HWND Window, WPARAM WParam, LPARAM LParam)
{
	if (WParam == trayID)
	{
		if (LParam == WM_RBUTTONDOWN)
		{
			_displayTrayMenu(http);
			return TRUE;
		}
		else
		{
			if (LParam == WM_LBUTTONDBLCLK)
			{
				ShowWindow(mainWindow, SW_RESTORE);
				return TRUE;
			}
		}
	}
	return FALSE;
}

//Creates the Savant tray tool tip
void setSavantToolTip(BOOL isAddConnection)
{
	char numStr[15];

	if(isAddConnection)
		http->status.numProcesses++;
	else
		http->status.numProcesses--;

	EnterCriticalSection(&newToolTip);
	
	strcpy(nid.szTip, "Savant: ");
	itoa(http->status.numProcesses, numStr, 10);
	strcat(nid.szTip, numStr);
	strcat(nid.szTip, " Processes Active");
	
	Shell_NotifyIcon(NIM_MODIFY, &nid);
	_initStatusBar();
	LeaveCriticalSection(&newToolTip);
}


//Win32 message processing function
LRESULT CALLBACK WndProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	LV_COLUMN lvc;
	RECT rect;

	switch(message)
	{
		case WM_CREATE:
			hStatusBar = CreateStatusWindow(WS_CHILD | WS_VISIBLE | WS_BORDER, "", window, IDM_STATUSBAR);//create status bar
			hStatus = window;
			
			GetClientRect(window, &rect);
			hwndLV = CreateWindow(WC_LISTVIEW, "", WS_VISIBLE | WS_CHILD | LVS_NOSORTHEADER |LVS_REPORT,
				0, 0, rect.right-rect.left, rect.bottom-rect.top - 20, window, (HMENU)IDD_LISTVIEW, hInstance, NULL);//create list view

			lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
			lvc.fmt = LVCFMT_LEFT;
			lvc.cx = 60;
			lvc.pszText = "Date";
			ListView_InsertColumn(hwndLV, 0, &lvc);
			lvc.cx = 60;
			lvc.pszText = "Time";
			ListView_InsertColumn(hwndLV, 1, &lvc);
			lvc.cx = 140;
			lvc.pszText = "Client";
			ListView_InsertColumn(hwndLV, 2, &lvc);
			lvc.cx = 175;
			lvc.pszText = "Request";
			ListView_InsertColumn(hwndLV, 3, &lvc);
			lvc.cx = 50;
			lvc.pszText = "Status";
			ListView_InsertColumn(hwndLV, 4, &lvc);
			return 0;

		case HTTP_SERVER_MSG:
			httpServerProcessMsg(http, wparam, lparam);
			return 0;

		case WM_CLOSE:
			_shutdownSavant(http);
			return 0;

		case WM_SIZE:
			if (wparam == SIZE_MINIMIZED)
			{
				ShowWindow(mainWindow, SW_HIDE);
				break;
			}
			else
			{
				MoveWindow(GetDlgItem(window, IDD_LISTVIEW), 0, 0, LOWORD(lparam),
				HIWORD(lparam)-20, TRUE);
				MoveWindow(hwndConsole, 0, 0, LOWORD(lparam), HIWORD(lparam), TRUE);
				SendMessage(hStatusBar, message, wparam, lparam);
				_initStatusBar();
				return 0;
			}

		case WM_TIMER:
			if (wparam == HTTP_TIMER_ID)
				httpServerWatchdogHandler(http);
			break;

		case TrayMsg:
			return _processTrayMsg(window, wparam, lparam);

		case WM_DESTROY:
			httpServerEnd(http);
			
			authUnloadUsers(http);
			cleanUpNetIO();
			closeErrorLog();
			_removeSavantFromTray();
			PostQuitMessage(0);
			return 0;

		case WM_COMMAND:
			switch (LOWORD(wparam))
			{
				case IDM_CONFIG:
					_loadSavantControl(http);
					return 0;
				
				case IDM_SHUTDOWN:
					_shutdownSavant(http);
					return 0;
				
				case IDM_HELP:
					WinHelp(mainWindow, "Savant.hlp", HELP_FINDER,0);
					return 0;
				
				case IDM_ABOUT:
					DialogBox(hInstance, "ABOUT", mainWindow, AboutDlgProc);
					return 0;
			}
			break;
			
		default:
			return DefWindowProc(window, message, wparam, lparam);
	}
	return(0);
}

//Add the Savant icon to the system tray
static void _addSavantToTray(HWND hWnd, HICON trayIcon)
{

	InitializeCriticalSection(&newToolTip);
	nid.cbSize = sizeof(NOTIFYICONDATA);
	nid.hWnd = hWnd;
	nid.uID = trayID;
	nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
	nid.uCallbackMessage = TrayMsg;
	nid.hIcon = trayIcon;				//create tray icon

	strcpy(nid.szTip, "Savant: 0 Processes Active");
											//create default tool tip
	Shell_NotifyIcon(NIM_ADD, &nid);
	TRACE();
}

int WINAPI WinMain(HINSTANCE Instance, HINSTANCE hPrevInstance, PSTR lpszCmdLine, int cmdShow)
{
	MSG msg;
	WNDCLASSEX wndClass;
	HICON trayIcon;

	http = &httpService;
	cfg = &http->cfg;

	ZeroMemory(&szConsole, sizeof(szConsole));
	nConsolePos = 0;
	hInstance = Instance;
	trayIcon = LoadIcon(Instance, "TRAY_ICON");
											//create tray icon
	ZeroMemory(&wndClass, sizeof(WNDCLASSEX));
	wndClass.cbSize = sizeof(wndClass);
	wndClass.lpszClassName = "SAVANT";
	wndClass.hInstance = Instance;
	wndClass.lpfnWndProc = WndProc;
	wndClass.hCursor = LoadCursor(NULL, IDC_ARROW);
	wndClass.hIcon = LoadIcon(Instance, MAKEINTRESOURCE(PROGRAM_ICON));
	wndClass.lpszMenuName = "IDM_MENU";
	wndClass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wndClass.hIconSm = trayIcon;
	RegisterClassEx(&wndClass);
	
	mainWindow = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW, "SAVANT", "Savant 3.1",
	                      WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 10, 500, 350, NULL,
	                      NULL, Instance, NULL);

	ShowWindow(mainWindow, SW_SHOWDEFAULT);
	UpdateWindow(mainWindow);
	InitCommonControls();

	http->serverSocket =  INVALID_SOCKET;
	http->msgWindow = mainWindow;
	
	openErrorLog();
	TRACE();

	_addSavantToTray(mainWindow, trayIcon);
	initNetIO();
	
	loadRegistryVars(cfg);
	
	authLoadUsers( http );
	_initStatusBar();


	if (!gotCriticalError())
		httpServerStart(http);

	while(GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return msg.wParam;			//message processing loop
}


