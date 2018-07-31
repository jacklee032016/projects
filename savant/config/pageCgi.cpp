/*
*
*/

#include <windows.h>
#include <prsht.h>
#include "savcfg.h"

HWND hwndCtrl;

//Callback function for property page messages
UINT CALLBACK CGIPageProc(HWND hwnd, UINT uMsg, LPPROPSHEETPAGE ppsp)
{
	switch(uMsg)
	{
		case PSPCB_CREATE: return TRUE;
		case PSPCB_RELEASE: return 0;
	}
	return 0;
}


//Extract data from property page and write to registry
static void _fetchCGIData(HWND hwndDlg)
{
	HKEY hInfo;

	hwndCtrl = GetDlgItem(hwndDlg, IDC_CGI_PIPE_PATH);
	GetWindowText(hwndCtrl, savantData.szCGITempPipe, 201);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\HTTPd", 0, KEY_ALL_ACCESS, &hInfo);
	RegSetValueEx(hInfo, "CGI Pipes", 0, REG_SZ, (const unsigned char *)(savantData.szCGITempPipe), strlen(savantData.szCGITempPipe));
	RegCloseKey(hInfo);
}


//Callback function for property page actions
BOOL CALLBACK CGIDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch(msg)
	{
		case WM_INITDIALOG:
		{                       	//initialize property page
			sht2 = false;
			hwndCtrl = GetDlgItem(hwndDlg, IDC_CGI_PIPE_PATH);
			SetWindowText(hwndCtrl, savantData.szCGITempPipe);
			return TRUE;            //place text strings in proper edit controls
		}
		
		case WM_COMMAND:
		return TRUE;				//respond to user-initiated actions (placeholder)
		case WM_HELP:
		{
		WinHelp(hwndMain, "Savant.hlp", HELP_FINDER,0);
		return TRUE;
		}

		//respond to help messages
		case WM_NOTIFY:
		{                         //respond to user actions in property page
			LPNMHDR pnmh = (LPNMHDR) lParam;
			LPPSHNOTIFY psh = (LPPSHNOTIFY)lParam;
			if (pnmh->code == PSN_HELP)
			WinHelp(hwndDlg, "Savant.hlp", HELP_FINDER, 0);
			
			if (pnmh->code == PSN_APPLY)
			{
				_fetchCGIData(hwndDlg);
				
				if (psh->lParam == FALSE)
					return TRUE;
			}
			//save data if Apply button pressed
			if (((pnmh->code == PSN_RESET) || (pnmh->code == PSN_APPLY)) && ((sht1) && (sht3) && (sht4) && (sht5) && (sht6) && (sht7) && (sht8)))
				PostQuitMessage(0);
			else
				if (pnmh->code == PSN_RESET || pnmh->code == PSN_APPLY)
					sht2 = true;
				return TRUE;            //handle OK/Cancel button presses
		}
		
		default: return FALSE;
	}
}

