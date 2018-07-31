
#include <windows.h>
#include <prsht.h>
#include <shlobj.h>
#include "savcfg.h"


static HWND hwndCtrl, hwndTxt;
static bool bEdit, bOKflag;
static int index;


//Callback function for new/edit path dialog
static BOOL CALLBACK _pathDlgProc(HWND hDlg, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	int i, j;

	switch(iMsg)
	{
		case WM_INITDIALOG:       //initialize dialog
			hwndCtrl = GetDlgItem(hDlg, IDC_OWNER_LIST);
			for (i=0; i < atoi(savantData.szNumUsers); i++)
				SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)userInfo[i]->name);
			for (i=0; i < atoi(savantData.szNumGroups); i++)
				SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)groupInfo[i].name);
			
			i = (int)SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)"Anyone");
			SendMessage(hwndCtrl, CB_SETCURSEL, (WPARAM)i, 0);
			hwndCtrl = GetDlgItem(hDlg, IDC_LOCATION);
			SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)"Anywhere");
			SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)"Class A Subnet");
			SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)"Class B Subnet");
			SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)"Class C Subnet");
			SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)"Class D Subnet");
			SendMessage(hwndCtrl, CB_SETCURSEL, (WPARAM)0, 0);
			hwndCtrl = GetDlgItem(hDlg, IDC_NO_SCRIPTING);
			SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
			
			//place owners and access locations in combo boxes
			if (bEdit)
			{
				hwndCtrl = GetDlgItem(hDlg, IDC_HTTP_PATH);
				SetWindowText(hwndCtrl, dirInfo[index]->HTTPname);
				hwndCtrl = GetDlgItem(hDlg, IDC_LOCAL_PATH);
				SetWindowText(hwndCtrl, dirInfo[index]->FATname);
				hwndCtrl = GetDlgItem(hDlg, IDC_ALLOW_LIST);
				
				if (strcmp(dirInfo[index]->allowList, "1") == 0)
					SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
				if (strcmp(dirInfo[index]->scriptType, "CGI") == 0)
				{
					hwndCtrl = GetDlgItem(hDlg, IDC_CGI_SCRIPTING);
					SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
					hwndCtrl = GetDlgItem(hDlg, IDC_NO_SCRIPTING);
					SendMessage(hwndCtrl, BM_SETCHECK, 0, 0);
				}
				
				if (strcmp(dirInfo[index]->scriptType, "WinCGI") == 0)
				{
					hwndCtrl = GetDlgItem(hDlg, IDC_WINCGI_SCRIPTING);
					SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
					hwndCtrl = GetDlgItem(hDlg, IDC_NO_SCRIPTING);
					SendMessage(hwndCtrl, BM_SETCHECK, 0, 0);
				}
				
				if (strcmp(dirInfo[index]->scriptType, "ISAPI") == 0)
				{
					hwndCtrl = GetDlgItem(hDlg, IDC_ISAPI_SCRIPTING);
					SendMessage(hwndCtrl, BM_SETCHECK, 1, 0);
					hwndCtrl = GetDlgItem(hDlg, IDC_NO_SCRIPTING);
					SendMessage(hwndCtrl, BM_SETCHECK, 0, 0);
				}
				
				hwndCtrl = GetDlgItem(hDlg, IDC_OWNER_LIST);
				i = (int)SendMessage(hwndCtrl, CB_FINDSTRING, (WPARAM)-1, (LPARAM)dirInfo[index]->authUser);
				if (i == CB_ERR)
					i = 0;
				
				SendMessage(hwndCtrl, CB_SETCURSEL, (WPARAM)i, 0);
				hwndCtrl = GetDlgItem(hDlg, IDC_LOCATION);
				i = (int)SendMessage(hwndCtrl, CB_FINDSTRING, (WPARAM)-1, (LPARAM)dirInfo[index]->authLocation);
				if (i == CB_ERR)
					i = 0;
				SendMessage(hwndCtrl, CB_SETCURSEL, (WPARAM)i, 0);
			}
			return TRUE;				//place existing info in dialog box if being edited

		
		case WM_COMMAND:
			switch(LOWORD(wParam))  //respond to user-initiated actions
			{
				case IDC_BROWSE:
					static BROWSEINFO bi;
					char filePath[260];

					bi.hwndOwner = hDlg;
					bi.pidlRoot = NULL;
					bi.pszDisplayName = filePath;
					bi.lpszTitle = "Select The Directory To Be Served:";
					SHGetPathFromIDList(SHBrowseForFolder(&bi), filePath);
					hwndCtrl = GetDlgItem(hDlg,IDC_LOCAL_PATH);
					SendMessage(hwndCtrl, WM_SETTEXT, 0, (LPARAM)(LPCSTR)filePath);
					break;
				
				case IDOK:
					hwndCtrl = GetDlgItem(hDlg, IDC_HTTP_PATH);
					i = SendMessage(hwndCtrl, WM_GETTEXTLENGTH, 0, 0);
					hwndCtrl = GetDlgItem(hDlg, IDC_LOCAL_PATH);
					
					j = SendMessage(hwndCtrl, WM_GETTEXTLENGTH, 0, 0);
					if (j < 1)
					{
						MessageBox(hDlg, "Please enter a local path to be served.", "Missing Data",
						MB_OK | MB_ICONWARNING);
						return TRUE;
					}
					
					if (i < 1)
					{
						MessageBox(hDlg,"Please enter an HTTP path.", "Missing Data",MB_OK | MB_ICONWARNING);
						return TRUE;
					}
					
					hwndCtrl = GetDlgItem(hDlg, IDC_HTTP_PATH);
					GetWindowText(hwndCtrl, filePath, 51);
					if (filePath[0] != '/')
					{
						MessageBox(hDlg, "HTTP paths must begin with a forward slash (/)", "Incorrect Format", MB_OK | MB_ICONWARNING);
						return TRUE;
					}                  	   //make sure that dialog box has valid data
					
					if (!bEdit)
					{
						index = atoi(savantData.szNumDirs);
						dirInfo[dirsToRead] = new tDirInfo;
						i = atoi(savantData.szNumDirs);
						i++;
						itoa(i, savantData.szNumDirs, 10);
					}                   //allocate new data structure for new data

					hwndCtrl = GetDlgItem(hDlg, IDC_HTTP_PATH);
					GetWindowText(hwndCtrl, dirInfo[index]->HTTPname, 51);
					hwndCtrl = GetDlgItem(hDlg, IDC_LOCAL_PATH);
					GetWindowText(hwndCtrl, dirInfo[index]->FATname, 201);
					strcpy(dirInfo[index]->scriptType, "None");
					hwndCtrl = GetDlgItem(hDlg, IDC_CGI_SCRIPTING);
					if ((int)SendMessage(hwndCtrl, BM_GETCHECK, 0, 0))
						strcpy(dirInfo[index]->scriptType, "CGI");
					hwndCtrl = GetDlgItem(hDlg, IDC_WINCGI_SCRIPTING);
					
					if ((int)SendMessage(hwndCtrl, BM_GETCHECK, 0, 0))
						strcpy(dirInfo[index]->scriptType, "WinCGI");
					hwndCtrl = GetDlgItem(hDlg, IDC_ISAPI_SCRIPTING);
					
					if ((int)SendMessage(hwndCtrl, BM_GETCHECK, 0, 0))
						strcpy(dirInfo[index]->scriptType, "ISAPI");
					
					hwndCtrl = GetDlgItem(hDlg, IDC_ALLOW_LIST);
					i = (int)SendMessage(hwndCtrl, BM_GETCHECK, 0, 0);
					if (i)
						strcpy(dirInfo[index]->allowList, "1");
					else
						strcpy(dirInfo[index]->allowList, "0");
					
					hwndCtrl = GetDlgItem(hDlg, IDC_OWNER_LIST);
					i = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
					if (i == CB_ERR)
						strcpy(dirInfo[index]->authUser, "Anyone");
					else
						SendMessage(hwndCtrl, CB_GETLBTEXT, i, (LPARAM)dirInfo[index]->authUser);
					
					hwndCtrl = GetDlgItem(hDlg, IDC_LOCATION);
					i = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
					if (i == CB_ERR)
						strcpy(dirInfo[index]->authLocation, "Anywhere");
					else
						SendMessage(hwndCtrl, CB_GETLBTEXT, i, (LPARAM)dirInfo[index]->authLocation);
					
					EndDialog(hDlg, 0);
					bOKflag = true;
					return TRUE;
				
				case IDCANCEL:
					EndDialog(hDlg, 0);
					bOKflag = false;
					return TRUE;			//end dialog without saving data if Cancel pressed
			}
		break;
	}
	return FALSE;
}


//Extract data from property page and write to registry
static void _fetchPathData(HWND hwndDlg)
{
	HKEY hInfo, hTemp;
	int i;

	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant", 0, KEY_ALL_ACCESS, &hInfo);
	RegDeleteKey(hInfo, "Directory Mappings");
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant", 0, KEY_ALL_ACCESS, &hTemp);
	RegCreateKeyEx(hTemp, "Directory Mappings", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hInfo, NULL);
	RegCloseKey(hTemp);
	RegSetValueEx(hInfo, "Number of Directories", 0, REG_SZ, (const unsigned char *)savantData.szNumDirs, strlen(savantData.szNumDirs));
	for(i=0; i < dirsToRead; i++)
	{
		RegCreateKeyEx(hInfo, dirInfo[i]->HTTPname, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hTemp, NULL);

		RegSetValueEx(hTemp, "Local Directory", 0, REG_SZ, (const unsigned char *)dirInfo[i]->FATname, strlen(dirInfo[i]->FATname));
		RegSetValueEx(hTemp, "Authorized User", 0, REG_SZ, (const unsigned char *)dirInfo[i]->authUser, strlen(dirInfo[i]->authUser));
		RegSetValueEx(hTemp, "Allow Directory Listings", 0, REG_SZ, (const unsigned char *)dirInfo[i]->allowList, strlen(dirInfo[i]->allowList));
		RegSetValueEx(hTemp, "Scripting", 0, REG_SZ, (const unsigned char *)dirInfo[i]->scriptType, strlen(dirInfo[i]->scriptType));
		RegSetValueEx(hTemp, "Authorized Location", 0, REG_SZ, (const unsigned char *)dirInfo[i]->authLocation, strlen(dirInfo[i]->authLocation));
		RegCloseKey(hTemp);
	}
	
	RegCloseKey(hInfo);
}

//Callback function for property page messages
UINT CALLBACK PathsPageProc(HWND hwnd, UINT uMsg, LPPROPSHEETPAGE ppsp)
{
	switch(uMsg)
	{
		case PSPCB_CREATE: return TRUE;
		case PSPCB_RELEASE: return 0;
	}
	return 0 ;
}

//Callback function for property page actions
BOOL CALLBACK PathsDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	int i, j;

	switch(msg)
	{
		case WM_INITDIALOG:
		{                         //initialize property page
			sht5 = false;
			hwndCtrl = GetDlgItem(hwndDlg, IDC_PATHS_BOX);
			for (i=0; i < atoi(savantData.szNumDirs); i++)
			{
				SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)dirInfo[i]->HTTPname);
			}
			return TRUE;            //put directory names in combo box
		}
		
		case WM_COMMAND:
		{                         //respond to user-initiated actions
			char temp[51];

			if (HIWORD(wParam) == BN_CLICKED)
			{
				if (((int)LOWORD(wParam)) == IDC_NEW_PATH)
				{
					bEdit = false;
					DialogBox(hInst, "PATHS", hwndDlg, _pathDlgProc);
					if (bOKflag)
					{
						hwndCtrl = GetDlgItem(hwndDlg, IDC_PATHS_BOX);
						SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)dirInfo[index]->HTTPname);
						dirsToRead++;
					}
				}                     //create new path, place name in combo box

				if (((int)LOWORD(wParam)) == IDC_EDIT_PATH)
				{
					hwndCtrl = GetDlgItem(hwndDlg, IDC_PATHS_BOX);
					j = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
					if (j == CB_ERR)
						return TRUE;
					
					SendMessage(hwndCtrl, CB_GETLBTEXT, j, (LPARAM)temp);
					index = -1;
					do
					{
						index++;
					}while ((strcmp(temp, dirInfo[index]->HTTPname) != 0) && (index <= dirsToRead));
					
					bEdit = true;
					DialogBox(hInst, "PATHS", hwndDlg, _pathDlgProc);
					if (bOKflag)
					{
						hwndCtrl = GetDlgItem(hwndDlg, IDC_PATHS_BOX);
						SendMessage(hwndCtrl, CB_DELETESTRING, (WPARAM)j, 0);
						SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)dirInfo[index]->HTTPname);
					}
				}                     //edit a path, update name in combo box

				if (((int)LOWORD(wParam)) == IDC_DELETE_PATH)
				{
					hwndCtrl = GetDlgItem(hwndDlg, IDC_PATHS_BOX);
					i = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
					if (i == CB_ERR)
						return TRUE;
					
					SendMessage(hwndCtrl, CB_GETLBTEXT, i, (LPARAM)temp);
					SendMessage(hwndCtrl, CB_DELETESTRING, (WPARAM)i, 0);
					index = -1;
					do
					{
						index++;
					} while ((strcmp(temp, dirInfo[index]->HTTPname) != 0) && (index <= atoi(savantData.szNumDirs)));

					strcpy(dirInfo[index]->HTTPname, "_DIRDEL_");
					i = atoi(savantData.szNumDirs);
					i--;
					itoa(i, savantData.szNumDirs, 10);
				}
			}                       //delete a path, remove name from combo box and info
							//from registry
			if (HIWORD(wParam) == CBN_SELCHANGE)
			{
				hwndCtrl = GetDlgItem(hwndDlg, IDC_PATHS_BOX);
				index = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
				SendMessage(hwndCtrl, CB_GETLBTEXT, index, (LPARAM)temp);
				index = -1;
				do
				{
					index++;
				} while ((strcmp(temp, dirInfo[index]->HTTPname) != 0) && (index <= atoi(savantData.szNumDirs)));

				hwndTxt = GetDlgItem(hwndDlg, IDC_PATH_LOCAL);
				SetWindowText(hwndTxt, dirInfo[index]->FATname);
				hwndTxt = GetDlgItem(hwndDlg, IDC_PATH_TYPE);
				if (strcmpi(dirInfo[index]->scriptType, "none") == 0)
					SetWindowText(hwndTxt, "Normal");
				else
					SetWindowText(hwndTxt, dirInfo[index]->scriptType);
				
				hwndTxt = GetDlgItem(hwndDlg, IDC_PATH_LISTING);
				if (strcmp(dirInfo[index]->allowList, "1") == 0)
					SetWindowText(hwndTxt, "Yes");
				else
					SetWindowText(hwndTxt, "No");
				
				hwndTxt = GetDlgItem(hwndDlg, IDC_PATH_USER);
				SetWindowText(hwndTxt, dirInfo[index]->authUser);
				hwndTxt = GetDlgItem(hwndDlg, IDC_PATH_ACCESS);
				
				if (strlen(dirInfo[index]->authLocation) < 10)
					SetWindowText(hwndTxt, "Anywhere");
				else
					SetWindowText(hwndTxt, dirInfo[index]->authLocation);
			}
			return TRUE;   			//update info in data boxes when user changes selection
		}

		
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
				_fetchPathData(hwndDlg);
				if (psh->lParam == 0)
					return TRUE;
			}


			if (((pnmh->code == PSN_RESET) || (pnmh->code == PSN_APPLY)) && ((sht1) && (sht2) && (sht3) && (sht4) && (sht6) && (sht7) && (sht8)))
				PostQuitMessage(0);
			else
				if (pnmh->code == PSN_RESET || pnmh->code == PSN_APPLY)
					sht5 = true;
			return TRUE;
			
		}
		
		default:
			return FALSE;
	}
}


