/*  HTTPd property page
*/


#include <windows.h>
#include <prsht.h>
#include "savcfg.h"


static HWND hwndCtrl;


//Extract data from property page and write to registry
static void _fetchHTTPData(HWND hwndDlg)
{
	HKEY hInfo;

	hwndCtrl = GetDlgItem(hwndDlg, IDC_SERVER_DNS);
	GetWindowText(hwndCtrl, savantData.szDNS, 151);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_SERVER_PORT);
	GetWindowText(hwndCtrl, savantData.szPort, 6);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_INDEX_FILE);
	GetWindowText(hwndCtrl, savantData.szIndex, 21);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_ERROR_PATH);
	GetWindowText(hwndCtrl, savantData.szErrorMsgPath, 201);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant", 0, KEY_ALL_ACCESS, &hInfo);
	RegSetValueEx(hInfo, "DNS Entry", 0, REG_SZ, (const unsigned char *)savantData.szDNS, strlen(savantData.szDNS));
	RegCloseKey(hInfo);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\HTTPd", 0, KEY_ALL_ACCESS, &hInfo);
	RegSetValueEx(hInfo, "Port", 0, REG_SZ, (const unsigned char *)savantData.szPort, strlen(savantData.szPort));
	RegSetValueEx(hInfo, "Index File Name", 0, REG_SZ, (const unsigned char *)savantData.szIndex, strlen(savantData.szIndex));
	RegSetValueEx(hInfo, "Error Path", 0, REG_SZ, (const unsigned char *)savantData.szErrorMsgPath, strlen(savantData.szErrorMsgPath));
	RegCloseKey(hInfo);
}


//Callback function for property page messages
UINT CALLBACK HTTPPageProc(HWND hwnd, UINT uMsg, LPPROPSHEETPAGE ppsp)
{
	switch(uMsg)
	{
		case PSPCB_CREATE: return TRUE;
		case PSPCB_RELEASE: return 0;
	}
	return 0;
}


//Callback function for property page actions
BOOL CALLBACK HTTPDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch(msg)
	{
		case WM_INITDIALOG:
		{         						//initialize property page
			sht1 = false;
			hwndCtrl = GetDlgItem(hwndDlg, IDC_SERVER_DNS);
			SetWindowText(hwndCtrl, savantData.szDNS);
			hwndCtrl = GetDlgItem(hwndDlg, IDC_SERVER_PORT);
			SetWindowText(hwndCtrl, savantData.szPort);
			hwndCtrl = GetDlgItem(hwndDlg, IDC_INDEX_FILE);
			SetWindowText(hwndCtrl, savantData.szIndex);
			hwndCtrl = GetDlgItem(hwndDlg, IDC_ERROR_PATH);
			SetWindowText(hwndCtrl, savantData.szErrorMsgPath);
			return TRUE;				//place text strings in appropriate edit controls
		}
		
		case WM_COMMAND:
		{									//respond to user-initiated actions
			WORD wID = LOWORD(wParam);

			switch(wID)
			{
				case(IDC_ERROR_PATH):
				case(IDC_INDEX_FILE):
				case(IDC_SERVER_PORT):
				case(IDC_SERVER_DNS):
					hwndCtrl = GetParent(hwndDlg);
					PropSheet_Changed(hwndCtrl, hwndDlg);
					break;					//enable Apply button when data altered by user
			}
			return TRUE;
		}
		
		case WM_HELP:
		{
			WinHelp(hwndDlg, "Savant.hlp", HELP_FINDER, 0);
			return TRUE;				//respond to help messages
		}
		
		case WM_NOTIFY:
		{									//respond to user actions in property page
			LPNMHDR pnmh = (LPNMHDR)lParam;
			LPPSHNOTIFY psh = (LPPSHNOTIFY)lParam;
			if (pnmh->code == PSN_HELP)
				WinHelp(hwndDlg, "Savant.hlp", HELP_FINDER, 0);
			
			if (pnmh->code == PSN_APPLY)
			{
				_fetchHTTPData(hwndDlg);
				if (psh->lParam == FALSE)
				return TRUE;
			}

			//save data if Apply button pressed
			if ((pnmh->code == PSN_RESET || pnmh->code == PSN_APPLY) && ((sht2) && (sht3) && (sht4) && (sht5) && (sht6) && (sht7) && (sht8)))
				PostQuitMessage(0);
			else
				
			if (pnmh->code == PSN_RESET || pnmh->code == PSN_APPLY)
				sht1 = true;
				return TRUE;            //handle OK/Cancel button presses
		}
		
		default:
			return FALSE;
	}
}

