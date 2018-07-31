
#include <windows.h>
#include <prsht.h>
#include "savcfg.h"


static HWND hwndCtrl;
static bool bEdit, bOKflag;
static int index;

//Callback function for new/edit user dialog
static BOOL CALLBACK _userDlgProc(HWND hDlg, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	int i;

	switch(iMsg)
	{
		case WM_INITDIALOG:       //initialize dialog
			if (bEdit)
			{
				hwndCtrl = GetDlgItem(hDlg, IDC_NAME);
				SetWindowText(hwndCtrl, userInfo[index]->name);
				hwndCtrl = GetDlgItem(hDlg, IDC_PASSWORD);
				SetWindowText(hwndCtrl, userInfo[index]->password);
			}
			return TRUE;    			//place existing info in dialog box if being edited
		
		case WM_COMMAND:
			switch(LOWORD(wParam))  //respond to user-initiated actions
			{
				case IDOK:
					hwndCtrl = GetDlgItem(hDlg, IDC_NAME);
					i = SendMessage(hwndCtrl, WM_GETTEXTLENGTH, 0, 0);
					if (i < 1)
					{
						EndDialog(hDlg, 0);
						bOKflag = false;
						return TRUE;
					}

					//make sure that dialog box has valid data
					if (!bEdit)
					{
						index = usersToRead;
						userInfo[index] = new UserInfo;
						i = atoi(savantData.szNumUsers);
						i++;
						itoa(i, savantData.szNumUsers, 10);
					}                   //allocate new data structure for new data

					hwndCtrl = GetDlgItem(hDlg, IDC_NAME);
					GetWindowText(hwndCtrl, userInfo[index]->name, 31);
					hwndCtrl = GetDlgItem(hDlg, IDC_PASSWORD);
					GetWindowText(hwndCtrl, userInfo[index]->password, 31);
					EndDialog(hDlg, 0);
					bOKflag = true;  	//get data from dialog box and write to memory structure
					return TRUE;
				
				case IDCANCEL:
					EndDialog(hDlg, 0);
					bOKflag = false;
					
					return TRUE; 			//end dialog without saving data if Cancel pressed
			}
		break;
	}
	return FALSE;
}


//Extract data from property page and write to registry
static void _fetchUserData(HWND hwndDlg)
{
	HKEY hInfo, hTemp;
	int i;

	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant", 0, KEY_ALL_ACCESS, &hInfo);
	RegDeleteKey(hInfo, "Users");
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant", 0, KEY_ALL_ACCESS, &hTemp);
	RegCreateKeyEx(hTemp, "Users", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hInfo, NULL);
	RegCloseKey(hTemp);
	RegSetValueEx(hInfo, "Number of Users", 0, REG_SZ, (const unsigned char *)savantData.szNumUsers, strlen(savantData.szNumUsers));
	for(i=0; i < usersToRead; i++)
	{
		if (strcmp("_DELUSER_", userInfo[i]->name) != 0)
		{
			RegCreateKeyEx(hInfo, userInfo[i]->name, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hTemp, NULL);
			RegSetValueEx(hTemp, "Password", 0, REG_SZ, (const unsigned char *)userInfo[i]->password, strlen(userInfo[i]->password));
			RegCloseKey(hTemp);
		}
	}
	RegCloseKey(hInfo);
}


UINT CALLBACK UsersPageProc(HWND hwnd, UINT uMsg, LPPROPSHEETPAGE ppsp)
{
	switch(uMsg)
	{
		case PSPCB_CREATE: return TRUE;
		case PSPCB_RELEASE: return 0;
	}
	return 0 ;
}

//Callback function for property page actions
BOOL CALLBACK UsersDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	int i, j;

	switch(msg)
	{
		case WM_INITDIALOG:
		{
			sht6 = false;
			hwndCtrl = GetDlgItem(hwndDlg, IDC_USER_LIST);
			for (i=0; i < atoi(savantData.szNumUsers); i++)
			{
				SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)userInfo[i]->name);
			}
			return TRUE;            //place user names in combo box
		}
		
		case WM_COMMAND:
		{
			char temp[51];

			if (HIWORD(wParam) == BN_CLICKED)
			{
				if (((int)LOWORD(wParam)) == IDC_NEW_USER)
				{
					bEdit = false;
					DialogBox(hInst, "USERS", hwndDlg, _userDlgProc);
					if (bOKflag)
					{
						hwndCtrl = GetDlgItem(hwndDlg, IDC_USER_LIST);
						SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)userInfo[index]->name);
						usersToRead++;
					}
				}                     //create a new user, add name to combo box

				if (((int)LOWORD(wParam)) == IDC_EDIT_USER)
				{
					hwndCtrl = GetDlgItem(hwndDlg, IDC_USER_LIST);
					j = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
					if (j == CB_ERR)
						return TRUE;
					
					SendMessage(hwndCtrl, CB_GETLBTEXT, j, (LPARAM)temp);
					index = -1;
					do
					{
						index++;
					} while ((strcmp(temp, userInfo[index]->name) != 0) && (index <= atoi(savantData.szNumUsers)));

					bEdit = true;
					DialogBox(hInst, "USERS", hwndDlg, _userDlgProc);
					if (bOKflag)
					{
						hwndCtrl = GetDlgItem(hwndDlg, IDC_USER_LIST);
						SendMessage(hwndCtrl, CB_DELETESTRING, (WPARAM)j, 0);
						SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)userInfo[index]->name);
					}
				}                     //edit a user, update name in combo box

				if (((int)LOWORD(wParam)) == IDC_DELETE_USER)
				{
					hwndCtrl = GetDlgItem(hwndDlg, IDC_USER_LIST);
					i = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
					if (i == CB_ERR)
						return TRUE;
					
					SendMessage(hwndCtrl, CB_GETLBTEXT, i, (LPARAM)temp);
					SendMessage(hwndCtrl, CB_DELETESTRING, (WPARAM)i, 0);
					index = -1;
					do
					{
						index++;
					} while ((strcmp(temp, userInfo[index]->name) != 0) && (index <= usersToRead));
					
					strcpy(userInfo[index]->name, "_DELUSER_");
					i = atoi(savantData.szNumUsers);
					i--;
					itoa(i, savantData.szNumUsers, 10);
				}
			}
			return TRUE;   			//delete user name from combo box and info from registry
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
				_fetchUserData(hwndDlg);
				if (psh->lParam == 0)
					return TRUE;
			}

			if (((pnmh->code == PSN_RESET) || (pnmh->code == PSN_APPLY)) && ((sht1) && (sht2) && (sht3) && (sht4) && (sht5) && (sht7) && (sht8)))
				PostQuitMessage(0);
			else
			if (pnmh->code == PSN_RESET || pnmh->code == PSN_APPLY)
				sht6 = true;
					return TRUE;    			//handle OK/Cancel button presses
		}
		
		default:
			return FALSE;
		}
	}


