
#include <windows.h>
#include <prsht.h>
#include "savcfg.h"


static HWND hwndCtrl;


UINT CALLBACK LoggingPageProc(HWND hwnd, UINT uMsg, LPPROPSHEETPAGE ppsp)
{
	switch(uMsg)
	{
		case PSPCB_CREATE: return TRUE;
		case PSPCB_RELEASE: return 0;
	}
	return 0 ;
}

//Extract data from property page and write to registry
static void _fetchLogData(HWND hwndDlg)
{
	HKEY hInfo;
	int i;

	hwndCtrl = GetDlgItem(hwndDlg, IDC_LOG_STORAGE_PATH);
	GetWindowText(hwndCtrl, savantData.szPathToStoreLogs, 201);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_GENERAL_LOG_NAME);
	GetWindowText(hwndCtrl, savantData.szGeneralLogFile, 201);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_HIT_LOG_FILE);
	GetWindowText(hwndCtrl, savantData.szHitLogFile, 201);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_REFERENCE_LOG_FILE);
	GetWindowText(hwndCtrl, savantData.szReferenceLogFile, 201);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_GENERAL_LOG_ENABLED);
	i = (int)SendMessage(hwndCtrl, BM_GETCHECK, 0, 0);
	itoa(i, savantData.szGeneralLogEnabled, 10);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_GENERAL_LOG_LOOKUP);
	i = (int)SendMessage(hwndCtrl, BM_GETCHECK, 0, 0);
	itoa(i, savantData.szGeneralLogLookup, 10);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_HIT_LOG_ENABLED);
	i = (int)SendMessage(hwndCtrl, BM_GETCHECK, 0, 0);
	itoa(i, savantData.szHitEnabled, 10);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_RECORD_CONNECTIONS);
	i = (int)SendMessage(hwndCtrl, BM_GETCHECK, 0, 0);
	itoa(i, savantData.szHitRecordConnections, 10);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_RECORD_KB_SENT);
	i = (int)SendMessage(hwndCtrl, BM_GETCHECK, 0, 0);
	itoa(i, savantData.szHitRecordKB, 10);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_RECORD_FILES_SENT);
	i = (int)SendMessage(hwndCtrl, BM_GETCHECK, 0, 0);
	itoa(i, savantData.szHitRecordFiles, 10);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_REFERENCE_LOG_ENABLED);
	SendMessage(hwndCtrl, BM_GETCHECK, 0, 0);
	itoa(i, savantData.szReferenceEnabled, 10);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Logs", 0, KEY_ALL_ACCESS, &hInfo);
	RegSetValueEx(hInfo, "Log Path", 0, REG_SZ, (const unsigned char *)savantData.szPathToStoreLogs, strlen(savantData.szPathToStoreLogs));
	RegCloseKey(hInfo);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Logs\\HTTPd Common", 0, KEY_ALL_ACCESS, &hInfo);
	RegSetValueEx(hInfo, "Enabled", 0, REG_SZ, (const unsigned char *)savantData.szGeneralLogEnabled, strlen(savantData.szGeneralLogEnabled));
	RegSetValueEx(hInfo, "File Name", 0, REG_SZ, (const unsigned char *)savantData.szGeneralLogFile, strlen(savantData.szGeneralLogFile));
	RegSetValueEx(hInfo, "Reverse DNS Lookup", 0, REG_SZ, (const unsigned char *)savantData.szGeneralLogLookup, strlen(savantData.szGeneralLogLookup));
	RegCloseKey(hInfo);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Logs\\HTTPd Count", 0, KEY_ALL_ACCESS, &hInfo);
	RegSetValueEx(hInfo, "Enabled", 0, REG_SZ, (const unsigned char *)savantData.szHitEnabled, strlen(savantData.szHitEnabled));
	RegSetValueEx(hInfo, "File Name", 0, REG_SZ, (const unsigned char *)savantData.szHitLogFile, strlen(savantData.szHitLogFile));
	RegSetValueEx(hInfo, "Count Files", 0, REG_SZ, (const unsigned char *)savantData.szHitRecordFiles, strlen(savantData.szHitRecordFiles));
	RegSetValueEx(hInfo, "Count Connects", 0, REG_SZ, (const unsigned char *)savantData.szHitRecordConnections, strlen(savantData.szHitRecordConnections));
	RegSetValueEx(hInfo, "Count Kbytes", 0, REG_SZ, (const unsigned char *)savantData.szHitRecordKB, strlen(savantData.szHitRecordKB));
	RegCloseKey(hInfo);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\Logs\\HTTPd Reference", 0, KEY_ALL_ACCESS, &hInfo);
	RegSetValueEx(hInfo, "Enabled", 0, REG_SZ, (const unsigned char *)savantData.szReferenceEnabled, strlen(savantData.szReferenceEnabled));
	RegSetValueEx(hInfo, "File Name", 0, REG_SZ, (const unsigned char *)savantData.szReferenceLogFile, strlen(savantData.szReferenceLogFile));
	RegCloseKey(hInfo);
}


//Callback function for property page actions
BOOL CALLBACK LoggingDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch(msg)
	{
		case WM_INITDIALOG:
		{                         //initialize property page
			sht4 = false;
			hwndCtrl = GetDlgItem(hwndDlg, IDC_LOG_STORAGE_PATH);
			SetWindowText(hwndCtrl, savantData.szPathToStoreLogs);
			hwndCtrl = GetDlgItem(hwndDlg, IDC_GENERAL_LOG_NAME);
			SetWindowText(hwndCtrl, savantData.szGeneralLogFile);
			hwndCtrl = GetDlgItem(hwndDlg, IDC_HIT_LOG_FILE);
			SetWindowText(hwndCtrl, savantData.szHitLogFile);
			hwndCtrl = GetDlgItem(hwndDlg, IDC_REFERENCE_LOG_FILE);
			SetWindowText(hwndCtrl, savantData.szReferenceLogFile);
			//place text strings in proper edit controls
			if (atoi(savantData.szGeneralLogEnabled))
			{
				hwndCtrl = GetDlgItem(hwndDlg, IDC_GENERAL_LOG_ENABLED);
				SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
			}
			if (atoi(savantData.szGeneralLogLookup))
			{
				hwndCtrl = GetDlgItem(hwndDlg, IDC_GENERAL_LOG_LOOKUP);
				SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
			}
			if (atoi(savantData.szHitEnabled))
			{
				hwndCtrl = GetDlgItem(hwndDlg, IDC_HIT_LOG_ENABLED);
				SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
			}
			
			if (atoi(savantData.szHitRecordConnections))
			{
				hwndCtrl = GetDlgItem(hwndDlg, IDC_RECORD_CONNECTIONS);
				SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
			}
			if (atoi(savantData.szHitRecordKB))
			{
				hwndCtrl = GetDlgItem(hwndDlg, IDC_RECORD_KB_SENT);
				SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
			}
			
			if (atoi(savantData.szHitRecordFiles))
			{
				hwndCtrl = GetDlgItem(hwndDlg, IDC_RECORD_FILES_SENT);
				SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
			}
			
			if (atoi(savantData.szReferenceEnabled))
			{
				hwndCtrl = GetDlgItem(hwndDlg, IDC_REFERENCE_LOG_ENABLED);
				SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
			}
			return TRUE;            //set checkboxes to values read from registry
		}
		
		case WM_COMMAND:
			return TRUE;
		
		case WM_HELP:
		{
			WinHelp(hwndMain, "Savant.hlp", HELP_FINDER,0);
			return TRUE ;
		}

		case WM_NOTIFY:
		{                         //respond to user actions in property page
			LPPSHNOTIFY psh = (LPPSHNOTIFY)lParam;
			LPNMHDR pnmh = (LPNMHDR) lParam;
			if (pnmh->code == PSN_HELP)
				WinHelp(hwndDlg, "Savant.hlp", HELP_FINDER, 0);
			
			if (pnmh->code == PSN_APPLY)
			{
				_fetchLogData(hwndDlg);
				if (psh->lParam == 0)
					return TRUE;
			}


			if (((pnmh->code == PSN_RESET) || (pnmh->code == PSN_APPLY)) && ((sht1) && (sht2) && (sht3) && (sht5) && (sht6) && (sht7) && (sht8)))
				PostQuitMessage(0);
			else
				if (pnmh->code == PSN_RESET || pnmh->code == PSN_APPLY)
					sht4 = true;
				
			return TRUE;
		}
		
		default: return FALSE;
	}
}

