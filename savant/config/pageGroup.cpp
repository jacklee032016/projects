
#include <windows.h>
#include <prsht.h>
#include "savcfg.h"


static HWND hwndCtrl;
static bool bEdit, bOKflag;
static int index;

//Callback function for new/edit group dialog
static BOOL CALLBACK _groupDlgProc(HWND hDlg, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
  char szTemp[51];
  int i, j;
  HWND hwndBox;

  switch(iMsg)
  {
    case WM_INITDIALOG:       //initialize dialog
      hwndCtrl = GetDlgItem(hDlg, IDC_USERS);
      for(i = 0; i < atoi(savantData.szNumUsers); i++)
        SendMessage(hwndCtrl, LB_ADDSTRING, 0, (LPARAM)userInfo[i]->name);
        								//place users in appropriate list box

      if (bEdit)
      {
        hwndBox = GetDlgItem(hDlg, IDC_MEMBERS);
        for(i = 0; i < groupInfo[index].numMembers; i++)
        {
          SendMessage(hwndBox, LB_ADDSTRING, 0, (LPARAM)groupInfo[index].members[i]);
          j = SendMessage(hwndCtrl, LB_FINDSTRINGEXACT, -1, (LPARAM)groupInfo[index].members[i]);
          if (j != LB_ERR)
            SendMessage(hwndCtrl, LB_DELETESTRING, (WPARAM)j, 0);
        }
        hwndCtrl = GetDlgItem(hDlg, IDC_GROUP_NAME);
        SetWindowText(hwndCtrl, groupInfo[index].name);
      }
      return TRUE;            //place existing info in dialog box if being edited
    case WM_COMMAND:
      switch(LOWORD(wParam))  //respond to user-initiated actions
      {
        case IDC_ADD:
          hwndCtrl = GetDlgItem(hDlg, IDC_USERS);
          i = SendMessage(hwndCtrl, LB_GETCURSEL, 0, 0);
          if (i != LB_ERR)
          {
            SendMessage(hwndCtrl, LB_GETTEXT, i, (LPARAM)szTemp);
            SendMessage(hwndCtrl, LB_DELETESTRING, (WPARAM)i, 0);
            hwndCtrl = GetDlgItem(hDlg, IDC_MEMBERS);
            SendMessage(hwndCtrl, LB_ADDSTRING, 0, (LPARAM)szTemp);
          }
          return TRUE;  		//move user from USERS box to MEMBERS box
        case IDC_REMOVE:
          hwndCtrl = GetDlgItem(hDlg, IDC_MEMBERS);
          i = SendMessage(hwndCtrl, LB_GETCURSEL, 0, 0);
          if (i != LB_ERR)
          {
            SendMessage(hwndCtrl, LB_GETTEXT, i, (LPARAM)szTemp);
            SendMessage(hwndCtrl, LB_DELETESTRING, (WPARAM)i, 0);
            hwndCtrl = GetDlgItem(hDlg, IDC_USERS);
            SendMessage(hwndCtrl, LB_ADDSTRING, 0, (LPARAM)szTemp);
          }
          return TRUE;        //remove user from MEMBERS box to USERS box
        case IDOK:
          hwndCtrl = GetDlgItem(hDlg, IDC_GROUP_NAME);
          i = SendMessage(hwndCtrl, WM_GETTEXTLENGTH, 0, 0);
          if (i < 1)
          {
            EndDialog(hDlg, 0);
            bOKflag = false;
            return TRUE;
          }               		//make sure that dialog box has valid data
          if (!bEdit)
          {
            index = atoi(savantData.szNumGroups);
            i = index;
            i++;
            itoa(i, savantData.szNumGroups, 10);
          }
          else
            {
              for(i = 0; i < groupInfo[index].numMembers; i++)
                delete[] groupInfo[index].members[i];
              delete[] groupInfo[index].members;
            }                 //allocate new data structure for new data

          hwndCtrl = GetDlgItem(hDlg, IDC_GROUP_NAME);
          GetWindowText(hwndCtrl, groupInfo[index].name, 51);
          hwndCtrl = GetDlgItem(hDlg, IDC_MEMBERS);
          i = SendMessage(hwndCtrl, LB_GETCOUNT, 0, 0);
          groupInfo[index].numMembers = i;
          groupInfo[index].members = new char*[i];
          for (j = 0; j < i; j++)
          {
            groupInfo[index].members[j] = new char[31];
            SendMessage(hwndCtrl, LB_GETTEXT, j, (LPARAM)groupInfo[index].members[j]);
          }
          EndDialog(hDlg, 0);
          bOKflag = true;
          return TRUE;  		//get data from dialog box and write to memory structure
        case IDCANCEL:
          EndDialog(hDlg, 0);
          bOKflag = false;
          return TRUE;   		//end dialog without saving data if Cancel pressed
      }
      break;
  }
  return FALSE;
}



static void _fetchGroupData(HWND hwndDlg)
{
  char temp[100];
  HKEY hInfo, hTemp, hCurr;
  int i, j;

  RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant", 0, KEY_ALL_ACCESS, &hInfo);
  RegDeleteKey(hInfo, "Groups");
  RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\DAEMONS\\Savant", 0, KEY_ALL_ACCESS, &hTemp);
  RegCreateKeyEx(hTemp, "Groups", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hInfo, NULL);
  RegCloseKey(hTemp);
  RegSetValueEx(hInfo, "Number of Groups", 0, REG_SZ, (const unsigned char *)savantData.szNumGroups, strlen(savantData.szNumGroups));
  for(i=0; i < atoi(savantData.szNumGroups); i++)
  {
    if (strcmp("__FunkelSkuzzy", groupInfo[i].name) != 0)
    {
      RegCreateKeyEx(hInfo, groupInfo[i].name, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hTemp, NULL);
      itoa(groupInfo[i].numMembers, temp, 10);
      RegSetValueEx(hTemp, "Number of Members", 0, REG_SZ, (const unsigned char *)temp, strlen(temp));
      RegCreateKeyEx(hTemp, "Members", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hCurr, NULL);
      RegCloseKey(hTemp);
      for(j=0; j < groupInfo[i].numMembers; j++)
      {
        RegCreateKeyEx(hCurr, groupInfo[i].members[j], 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hTemp, NULL);
        RegCloseKey(hTemp);
      }
      RegCloseKey(hTemp);
    }
  }
  RegCloseKey(hInfo);
}

//Callback function for property page messages
UINT CALLBACK GroupsPageProc(HWND hwnd, UINT uMsg, LPPROPSHEETPAGE ppsp)
{
	switch(uMsg)
	{
		case PSPCB_CREATE: return TRUE;
		case PSPCB_RELEASE: return 0;
	}
	return 0 ;
}


//Callback function for property page actions
BOOL CALLBACK GroupsDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
  int i, j;

  switch(msg)
  {
    case WM_INITDIALOG:
    {                         //initialize property page
      sht7 = false;
      hwndCtrl = GetDlgItem(hwndDlg, IDC_GROUPS_LIST);
      for (i=0; i < atoi(savantData.szNumGroups); i++)
      {
        SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)groupInfo[i].name);
      }
      return TRUE;            //place group names in combo box
    }
    case WM_COMMAND:
    {                         //respond to user-initiated actions
      char temp[51];

      if (HIWORD(wParam) == BN_CLICKED)
      {
        if (((int)LOWORD(wParam)) == IDC_NEW_GROUP)
        {
          bEdit = false;
          DialogBox(hInst, "GROUPS", hwndDlg, _groupDlgProc);
          if (bOKflag)
          {
            hwndCtrl = GetDlgItem(hwndDlg, IDC_GROUPS_LIST);
            SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)groupInfo[index].name);
          }
        }           				//create new group, place name in combo box

        if (((int)LOWORD(wParam)) == IDC_EDIT_GROUP)
        {
          hwndCtrl = GetDlgItem(hwndDlg, IDC_GROUPS_LIST);
          j = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
          if (j == CB_ERR)
            return TRUE;
          SendMessage(hwndCtrl, CB_GETLBTEXT, j, (LPARAM)temp);
          index = -1;
          do
          {
            index++;
          } while ((strcmp(temp, groupInfo[index].name) != 0) && (index <= atoi(savantData.szNumGroups)));
          bEdit = true;
          DialogBox(hInst, "GROUPS", hwndDlg, _groupDlgProc);
          if (bOKflag)
          {
            hwndCtrl = GetDlgItem(hwndDlg, IDC_GROUPS_LIST);
            SendMessage(hwndCtrl, CB_DELETESTRING, (WPARAM)j, 0);
            SendMessage(hwndCtrl, CB_ADDSTRING, 0, (LPARAM)groupInfo[index].name);
          }
        }               		//edit group, update name in combo box

        if (((int)LOWORD(wParam)) == IDC_DELETE_GROUP)
        {
          hwndCtrl = GetDlgItem(hwndDlg, IDC_GROUPS_LIST);
          i = SendMessage(hwndCtrl, CB_GETCURSEL, 0, 0);
          if (i == CB_ERR)
            return TRUE;
          SendMessage(hwndCtrl, CB_GETLBTEXT, i, (LPARAM)temp);
          SendMessage(hwndCtrl, CB_DELETESTRING, (WPARAM)i, 0);
          index = -1;
          do
          {
            index++;
          } while ((strcmp(temp, groupInfo[index].name) != 0) && (index <= atoi(savantData.szNumGroups)));
          strcpy(groupInfo[index].name, "__FunkelSkuzzy");
          groupInfo[index].numMembers = NULL;
          delete[] groupInfo[index].members;
          i = atoi(savantData.szNumGroups);
          i--;
          itoa(i, savantData.szNumGroups, 10);
        }
      }                 		//remove group from combo box and delete from registry
      return TRUE;
    }
    case WM_HELP:
    {
      WinHelp(hwndMain, "Savant.hlp", HELP_FINDER,0);
      return TRUE;
    }                         //respond to help messages
    case WM_NOTIFY:
    {                         //respond to user actions in property page
      LPNMHDR pnmh = (LPNMHDR) lParam;
      LPPSHNOTIFY psh = (LPPSHNOTIFY)lParam;
      if (pnmh->code == PSN_HELP)
        WinHelp(hwndDlg, "Savant.hlp", HELP_FINDER, 0);
      if (pnmh->code == PSN_APPLY)
      {
        _fetchGroupData(hwndDlg);
        if (psh->lParam == 0)
          return TRUE;
      }                       //save data if Apply button pressed
      if (((pnmh->code == PSN_RESET) || (pnmh->code == PSN_APPLY)) && ((sht1) && (sht2) && (sht3) && (sht4) && (sht5) && (sht6) && (sht8)))
		  PostQuitMessage(0);
      else
        if (pnmh->code == PSN_RESET || pnmh->code == PSN_APPLY)
          sht7 = true;
      return TRUE;       		//handle OK/Cancel button presses
    }
    default: return FALSE;
  }
}


