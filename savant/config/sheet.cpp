/*
* Create property sheet
*/

#include "savcfg.h"

extern HINSTANCE hInst;
extern HICON hiconApp;

BOOL sht1, sht2, sht3, sht4, sht5, sht6, sht7, sht8;

//Callback function for the property sheet (do-nothing placeholder)
int CALLBACK PropSheetProc(HWND hwndDlg, UINT uMsg, LPARAM lParam)
{
	return 0;
}

//Create property sheet and set up structure for 8 property pages
BOOL CreatePropertySheet(HWND hwndParent)
{
	PROPSHEETHEADER pshead;
	PROPSHEETPAGE pspage[8];

	OutputDebugString("Create Properties Pages");

	ZeroMemory(&pshead, sizeof(PROPSHEETHEADER));
	pshead.dwSize = sizeof(PROPSHEETHEADER);
	pshead.dwFlags = PSH_PROPTITLE | PSH_PROPSHEETPAGE | PSH_USECALLBACK;
pshead.dwFlags          = PSH_PROPSHEETPAGE | PSH_USEICONID | PSH_USECALLBACK;
	pshead.hwndParent = hwndParent;
	pshead.hInstance = hInst;
	pshead.pszCaption = TEXT("Savant HTTP Server");
	pshead.nPages = sizeof(pspage) / sizeof(PROPSHEETPAGE);;
	pshead.nStartPage = 1;
	pshead.ppsp =  (LPCPROPSHEETPAGE) &pspage;
	pshead.pfnCallback = (PFNPROPSHEETCALLBACK) PropSheetProc;

	ZeroMemory(&pspage, 8 * sizeof(PROPSHEETPAGE));

	sht1 = true;
	sht2 = true;
	sht3 = true;
	sht4 = true;
	sht5 = true;
	sht6 = true;
	sht7 = true;
	sht8 = true;						

	//init shutdown watchdog variables	
	pspage[0].dwSize = sizeof (PROPSHEETPAGE);
	pspage[0].dwFlags = PSP_USECALLBACK | PSP_HASHELP;
	pspage[0].hInstance = hInst;
	pspage[0].pszTemplate = MAKEINTRESOURCE(PAGE1);
	pspage[0].pfnDlgProc = HTTPDlgProc;
	pspage[0].lParam = NULL;
	pspage[0].pfnCallback = HTTPPageProc;
	
	//init page 1 of property sheet
	pspage[1].dwSize = sizeof(PROPSHEETPAGE);
	pspage[1].dwFlags = PSP_USECALLBACK | PSP_HASHELP;
	pspage[1].hInstance = hInst;
	pspage[1].pszTemplate = MAKEINTRESOURCE(PAGE2);
	pspage[1].pfnDlgProc = CGIDlgProc;
	pspage[1].lParam = NULL;
	pspage[1].pfnCallback = CGIPageProc;

	pspage[2].dwSize = sizeof(PROPSHEETPAGE);
	pspage[2].dwFlags = PSP_USECALLBACK | PSP_HASHELP;
	pspage[2].hInstance = hInst;
	pspage[2].pszTemplate = MAKEINTRESOURCE(PAGE3);
	pspage[2].pfnDlgProc = ProcessesDlgProc;
	pspage[2].lParam = NULL;
	pspage[2].pfnCallback = ProcessesPageProc;

	pspage[3].dwSize = sizeof(PROPSHEETPAGE);
	pspage[3].dwFlags = PSP_USECALLBACK | PSP_HASHELP;
	pspage[3].hInstance = hInst;
	pspage[3].pszTemplate = MAKEINTRESOURCE(PAGE4);
	pspage[3].pfnDlgProc = LoggingDlgProc;
	pspage[3].lParam = NULL;
	pspage[3].pfnCallback = LoggingPageProc;

	pspage[4].dwSize = sizeof(PROPSHEETPAGE);
	pspage[4].dwFlags = PSP_USECALLBACK | PSP_HASHELP;
	pspage[4].hInstance = hInst;
	pspage[4].pszTemplate = MAKEINTRESOURCE(PAGE5);
	pspage[4].pfnDlgProc = PathsDlgProc;
	pspage[4].lParam = NULL;
	pspage[4].pfnCallback = PathsPageProc;

	pspage[5].dwSize = sizeof(PROPSHEETPAGE);
	pspage[5].dwFlags = PSP_USECALLBACK | PSP_HASHELP;
	pspage[5].hInstance = hInst;
	pspage[5].pszTemplate = MAKEINTRESOURCE(PAGE6);
	pspage[5].pfnDlgProc = UsersDlgProc;
	pspage[5].lParam = NULL;
	pspage[5].pfnCallback = UsersPageProc;

	pspage[6].dwSize = sizeof(PROPSHEETPAGE);
	pspage[6].dwFlags = PSP_USECALLBACK | PSP_HASHELP;
	pspage[6].hInstance = hInst;
	pspage[6].pszTemplate = MAKEINTRESOURCE(PAGE7);
	pspage[6].pfnDlgProc = GroupsDlgProc;
	pspage[6].lParam = NULL;
	pspage[6].pfnCallback = GroupsPageProc;

	pspage[7].dwSize = sizeof(PROPSHEETPAGE);
	pspage[7].dwFlags = PSP_USECALLBACK | PSP_HASHELP;
	pspage[7].hInstance = hInst;
	pspage[7].pszTemplate = MAKEINTRESOURCE(PAGE8);
	pspage[7].pfnDlgProc = MIMEDlgProc;
	pspage[7].lParam = NULL;
	pspage[7].pfnCallback = MIMEPageProc;

	//init page 8 of property sheet
	return PropertySheet(&pshead);
}

