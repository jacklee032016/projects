
#include <windows.h>
#include <prsht.h>
#include "savcfg.h"

static HWND hwndCtrl, hwndTxt;
static bool bEdit, bOKflag;
static int index;


//Callback function for new/edit MIME type dialog
static BOOL CALLBACK _mimeDlgProc(HWND hDlg, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	int i, j;

	switch(iMsg)
	{
		case WM_INITDIALOG:       //initialize dialog
			if (bEdit)
			{
				hwndCtrl = GetDlgItem(hDlg, IDC_EXTENSION);
				SetWindowText(hwndCtrl, MIMEinfo[index]->extension);
				hwndCtrl = GetDlgItem(hDlg, IDC_DESCRIPTION);
				SetWindowText(hwndCtrl, MIMEinfo[index]->description);
			}
			return TRUE;      		//place existing info in dialog box if being edited
		
		case WM_COMMAND:
			switch(LOWORD(wParam))  //respond to user-initiated actions
			{
				case IDOK:
					hwndCtrl = GetDlgItem(hDlg, IDC_EXTENSION);
					i = SendMessage(hwndCtrl, WM_GETTEXTLENGTH, 0, 0);
					hwndCtrl = GetDlgItem(hDlg, IDC_DESCRIPTION);
					j = SendMessage(hwndCtrl, WM_GETTEXTLENGTH, 0, 0);
					if ((i < 1) || (j < 1))
					{
						EndDialog(hDlg, 0);
						bOKflag = false;
						return TRUE;
					}                	//make sure that dialog box has valid data
					
					if (!bEdit)
					{
						index = atoi(savantData.szNumMIME);
						MIMEinfo[MIMEToRead] = new tMIMEInfo;
						i = index;
						i++;
						itoa(i, savantData.szNumMIME, 10);
					}                   //allocate new data structure for new data

					hwndCtrl = GetDlgItem(hDlg, IDC_EXTENSION);
					GetWindowText(hwndCtrl, MIMEinfo[index]->extension, 6);
					hwndCtrl = GetDlgItem(hDlg, IDC_DESCRIPTION);
					GetWindowText(hwndCtrl, MIMEinfo[index]->description, 128);
					EndDialog(hDlg, 0);
					bOKflag = true;
					return TRUE;   		//get data from dialog box and write to memory structure
				
				case IDCANCEL:
					EndDialog(hDlg, 0);
					bOKflag = false;
					return TRUE;    		//end dialog without saving data if Cancel pressed
			}
			
		break;
	}
	
	return FALSE;
}


static void _fetchMIMEData(HWND hwndDlg)
{
	HKEY hInfo, hTemp;
	int i;

	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant", 0, KEY_ALL_ACCESS, &hInfo);
	RegDeleteKey(hInfo, "MIME");
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant", 0, KEY_ALL_ACCESS, &hTemp);
	RegCreateKeyEx(hTemp, "MIME", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hInfo, NULL);
	RegCloseKey(hTemp);
	RegSetValueEx(hInfo, "MIME Types", 0, REG_SZ, (const unsigned char *)savantData.szNumMIME, strlen(savantData.szNumMIME));
	for(i=0; i < MIMEToRead; i++)
	{
		RegCreateKeyEx(hInfo, MIMEinfo[i]->extension, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hTemp, NULL);
		RegSetValueEx(hTemp, "MIME Description", 0, REG_SZ, (const unsigned char *)MIMEinfo[i]->description, strlen(MIMEinfo[i]->description));
		RegCloseKey(hTemp);
	}
	RegCloseKey(hInfo);
}


UINT CALLBACK MIMEPageProc(HWND hwnd, UINT uMsg, LPPROPSHEETPAGE ppsp)
{
	switch(uMsg)
	{
		case PSPCB_CREATE: return TRUE;
		case PSPCB_RELEASE: return 0;
	}
	return 0 ;
}

//Callback function for property page actions
BOOL CALLBACK MIMEDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	int i, j;

	switch(msg)
	{
		case WM_INITDIALOG:
		{                         //initialize property page
			sht8 = false;
			hwndCtrl = GetDlgItem(hwndDlg, IDC_MIME_EXTENSIONS);
			for (i=0; i < atoi(savantData.szNumMIME); i++)
			{
				SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)MIMEinfo[i]->extension);
			}
			return TRUE;            //place MIME extensions in combo box
		}
		
		case WM_COMMAND:
		{                         //respond to user-initiated actions
			char temp[51];

			if (HIWORD(wParam) == BN_CLICKED)
			{
				if (((int)LOWORD(wParam)) == IDC_NEW_MIME)
				{
					bEdit = false;
					DialogBox(hInst, "MIME", hwndDlg, _mimeDlgProc);
					if (bOKflag)
					{
						hwndCtrl = GetDlgItem(hwndDlg, IDC_MIME_EXTENSIONS);
						SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)MIMEinfo[index]->extension);
						MIMEToRead++;
					}
				}            			//create new MIME, put extension in combo box

				if (((int)LOWORD(wParam)) == IDC_EDIT_MIME)
				{
					hwndCtrl = GetDlgItem(hwndDlg, IDC_MIME_EXTENSIONS);
					j = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
					if (j == CB_ERR)
						return TRUE;

					SendMessage(hwndCtrl, CB_GETLBTEXT, j, (LPARAM)temp);
					index = -1;
					do
					{
						index++;
					} while ((strcmp(temp, MIMEinfo[index]->extension) != 0) && (index <= MIMEToRead));
					
					bEdit = true;
					DialogBox(hInst, "MIME", hwndDlg, _mimeDlgProc);
					if (bOKflag)
					{
						hwndCtrl = GetDlgItem(hwndDlg, IDC_MIME_EXTENSIONS);
						SendMessage(hwndCtrl, CB_DELETESTRING, (WPARAM)j, 0);
						SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)MIMEinfo[index]->extension);
					}
				}                     //edit MIME type, update extension in combo box
				
				if (((int)LOWORD(wParam)) == IDC_DELETE_MIME)
				{
					hwndCtrl = GetDlgItem(hwndDlg, IDC_MIME_EXTENSIONS);
					i = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
					if (i == CB_ERR)
					return TRUE;
					
					SendMessage(hwndCtrl, CB_GETLBTEXT, i, (LPARAM)temp);
					SendMessage(hwndCtrl, CB_DELETESTRING, (WPARAM)i, 0);
					index = -1;
					do
					{
						index++;
					} while ((strcmp(temp, MIMEinfo[index]->extension) != 0) && (index <= atoi(savantData.szNumMIME)));

					delete[] MIMEinfo[index];
					i = atoi(savantData.szNumMIME);
					i--;
					itoa(i, savantData.szNumMIME, 10);
				}
			}                       //remove MIME type from combo box and delete from registry

			if (HIWORD(wParam) == CBN_SELCHANGE)
			{
				hwndCtrl = GetDlgItem(hwndDlg, IDC_MIME_EXTENSIONS);
				index = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
				SendMessage(hwndCtrl, CB_GETLBTEXT, index, (LPARAM)temp);
				index = -1;
				do
				{
					index++;
				} while ((strcmp(temp, MIMEinfo[index]->extension) != 0) && (index <= atoi(savantData.szNumMIME)));
				hwndTxt = GetDlgItem(hwndDlg, IDC_MIME_DESCRIPTION);
				SetWindowText(hwndTxt, MIMEinfo[index]->description);
			}
			return TRUE;   			//update data in text control when user changes selection
		}
		
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
				_fetchMIMEData(hwndDlg);
				if (psh->lParam == 0)
					return TRUE;
			}
			
			if (((pnmh->code == PSN_RESET) || (pnmh->code == PSN_APPLY)) && ((sht1) && (sht2) && (sht3) && (sht4) && (sht5) && (sht6) && (sht7)))
				PostQuitMessage(0);
			else
				if (pnmh->code == PSN_RESET || pnmh->code == PSN_APPLY)
					sht8 = true;
			return TRUE;  				//handle OK/Cancel button presses
		}
		
		default:
			return FALSE;
	}
}

