/*
* Processes property page
*/

#include <windows.h>
#include <prsht.h>
#include "savcfg.h"

static HWND hwndCtrl;

//Extract data from property page and write to registry
void fetchProcessData(HWND hwndDlg)
{
	HKEY hInfo;

	hwndCtrl = GetDlgItem(hwndDlg, IDC_NUMBER_OF_PROCESSES);
	GetWindowText(hwndCtrl, savantData.szInitialProcesses, 6);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_MAX_PROCESSES);
	GetWindowText(hwndCtrl, savantData.szMaxProcesses, 6);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_FREE_PROCESSES);
	GetWindowText(hwndCtrl, savantData.szFreeProcesses, 6);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_COMPACT_PERIOD);
	GetWindowText(hwndCtrl, savantData.szProcessCompactPeriod, 6);
	hwndCtrl = GetDlgItem(hwndDlg, IDC_COMPACT_LAZINESS);
	GetWindowText(hwndCtrl, savantData.szProcessCompactLaziness, 6);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant\\HTTPd", 0, KEY_ALL_ACCESS, &hInfo);
	RegSetValueEx(hInfo, "Processes", 0, REG_SZ, (const unsigned char *)savantData.szMaxProcesses, strlen(savantData.szMaxProcesses));
	RegSetValueEx(hInfo, "Initial Processes", 0, REG_SZ, (const unsigned char *)savantData.szInitialProcesses, strlen(savantData.szInitialProcesses));
	RegSetValueEx(hInfo, "Max Processes", 0, REG_SZ, (const unsigned char *)savantData.szMaxProcesses, strlen(savantData.szMaxProcesses));
	RegSetValueEx(hInfo, "Free Processes", 0, REG_SZ, (const unsigned char *)savantData.szFreeProcesses, strlen(savantData.szFreeProcesses));
	RegSetValueEx(hInfo, "Process Time-To-Live", 0, REG_SZ, (const unsigned char *)savantData.szProcessCompactPeriod, strlen(savantData.szProcessCompactPeriod));
	RegSetValueEx(hInfo, "Time-To-Live Checking", 0, REG_SZ, (const unsigned char *)savantData.szProcessCompactLaziness, strlen(savantData.szProcessCompactLaziness));
	RegCloseKey(hInfo);
}


//Callback function for property page messages
UINT CALLBACK ProcessesPageProc(HWND hwnd, UINT uMsg, LPPROPSHEETPAGE ppsp)
{
	switch(uMsg)
	{
		case PSPCB_CREATE: return TRUE;
		case PSPCB_RELEASE: return 0;
	}
	return 0 ;
}

//Callback function for property page actions
BOOL CALLBACK ProcessesDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch(msg)
	{
		case WM_INITDIALOG:
		{                     		//initialize property page
			sht3 = false;
			hwndCtrl = GetDlgItem(hwndDlg, IDC_NUMBER_OF_PROCESSES);
			SetWindowText(hwndCtrl, savantData.szInitialProcesses);
			hwndCtrl = GetDlgItem(hwndDlg, IDC_MAX_PROCESSES);
			SetWindowText(hwndCtrl, savantData.szMaxProcesses);
			hwndCtrl = GetDlgItem(hwndDlg, IDC_FREE_PROCESSES);
			SetWindowText(hwndCtrl, savantData.szFreeProcesses);
			hwndCtrl = GetDlgItem(hwndDlg, IDC_COMPACT_PERIOD);
			SetWindowText(hwndCtrl, savantData.szProcessCompactPeriod);
			hwndCtrl = GetDlgItem(hwndDlg, IDC_COMPACT_LAZINESS);
			SetWindowText(hwndCtrl, savantData.szProcessCompactLaziness);
			return TRUE;      		//place text strings in proper edit controls
		}
		
		case WM_COMMAND:
			return TRUE;				//respond to user-initiated actions (placeholder)
			
		case WM_HELP:
		{
			WinHelp(hwndMain, "Savant.hlp", HELP_FINDER,0);
			return TRUE;
		}

		case WM_NOTIFY:
		{                         //respond to user actions in property page
			LPNMHDR pnmh = (LPNMHDR) lParam;
			LPPSHNOTIFY psh = (LPPSHNOTIFY)lParam;
			
			if (pnmh->code == PSN_HELP)
				WinHelp(hwndDlg, "Savant.hlp", HELP_FINDER, 0);
			
			if (pnmh->code == PSN_APPLY)
			{
				fetchProcessData(hwndDlg);
				if (psh->lParam == 0)
					return TRUE;
			}                       //save data if Apply button pressed
			
			if (((pnmh->code == PSN_RESET) || (pnmh->code == PSN_APPLY)) && ((sht1) && (sht2) && (sht4) && (sht5) && (sht6) && (sht7) && (sht8)))
				PostQuitMessage(0);
			else
				if (pnmh->code == PSN_RESET || pnmh->code == PSN_APPLY)
					sht3 = true;
				
			return TRUE;       		//handle OK/Cancel button presses
		}
		
		default: return FALSE;
	}
}

