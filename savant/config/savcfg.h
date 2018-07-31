
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

// Menu item identifiers
#define IDC_BROWSE	108
#define IDC_BUTTON1	108
#define IDI_APP 1000
#define IDC_DELETE_MIME	104
#define IDC_EDIT_MIME	103
#define IDC_NEW_MIME	102
#define IDC_MIME_EXTENSIONS	101
#define IDC_MIME_DESCRIPTION	150
#define IDC_DELETE_GROUP	104
#define IDC_EDIT_GROUP	103
#define IDC_NEW_GROUP	102
#define IDC_GROUPS_LIST 101
#define IDC_EDIT_USER	103
#define IDC_NEW_USER	102
#define IDC_DELETE_USER 101
#define IDC_USER_LIST	105
#define IDC_PATH_ACCESS	109
#define IDC_PATH_USER	108
#define IDC_PATH_LISTING	107
#define IDC_PATH_TYPE 106
#define IDC_PATH_LOCAL 105
#define IDC_DELETE_PATH	104
#define IDC_EDIT_PATH	103
#define IDC_NEW_PATH	102
#define IDC_PATHS_BOX	101
#define IDC_COMPACT_LAZINESS 106
#define IDC_NUMBER_OF_PROCESSES 105
#define IDC_COMPACT_PERIOD	104
#define IDC_FREE_PROCESSES	103
#define IDC_MAX_PROCESSES	102
#define IDC_CGI_PIPE_PATH	101
#define IDC_ERROR_PATH 104
#define IDC_INDEX_FILE	103
#define IDC_SERVER_PORT	102
#define IDC_SERVER_DNS	101
#define VERSIONINFO_1	1
#define IDC_REFERENCE_LOG_FILE	109
#define IDC_REFERENCE_LOG_ENABLED	110
#define IDC_RECORD_FILES_SENT	108
#define IDC_RECORD_KB_SENT	107
#define IDC_RECORD_CONNECTIONS	106
#define IDC_HIT_LOG_FILE 111
#define IDC_HIT_LOG_ENABLED 105
#define IDC_GENERAL_LOG_NAME	104
#define IDC_GENERAL_LOG_LOOKUP	103
#define IDC_LOG_STORAGE_PATH	101
#define IDC_GENERAL_LOG_ENABLED	102
#define IDC_LOCAL_PATH 101
#define IDC_HTTP_PATH 102
#define IDC_ALLOW_LIST 103
#define IDC_NO_SCRIPTING 104
#define IDC_CGI_SCRIPTING 105
#define IDC_OWNER_LIST 106
#define IDC_LOCATION 107
#define IDC_WINCGI_SCRIPTING 109
#define IDC_ISAPI_SCRIPTING 110
#define IDC_NAME 101
#define IDC_PASSWORD 102
#define IDC_USERS 101
#define IDC_MEMBERS 102
#define IDC_ADD 103
#define IDC_REMOVE 104
#define IDC_GROUP_NAME 105
#define IDC_EXTENSION 101
#define IDC_DESCRIPTION 102
#define IDM_OVERLAPPED    100
#define IDM_POPUP         101
#define IDM_CHILD         102
#define IDM_WIZARD        200
#define IDM_HASHELP       201
#define IDM_MODELESS      202
#define IDM_MULTILINETABS 203
#define IDM_NOAPPLYNOW    204
#define IDM_PROPTITLE     205
#define IDM_RTLREADING    206

// Dialog template IDs

// Icon IDs
#define PAGE1	101
#define PAGE2	102
#define PAGE3	103
#define PAGE4	104
#define PAGE5	105
#define PAGE6	106
#define PAGE7	107
#define PAGE8	108

// Private message
#define PM_CREATEWINDOW   WM_APP

#include "svrConfig.h"

// Property Sheet Functions (in SHEET.CPP)
BOOL CreatePropertySheet (HWND hwndParent);

// Property Page Functions
UINT CALLBACK HTTPPageProc (HWND, UINT, LPPROPSHEETPAGE);
BOOL CALLBACK HTTPDlgProc (HWND, UINT, WPARAM, LPARAM);
UINT CALLBACK CGIPageProc (HWND, UINT, LPPROPSHEETPAGE);
BOOL CALLBACK CGIDlgProc (HWND, UINT, WPARAM, LPARAM);
UINT CALLBACK ProcessesPageProc (HWND, UINT, LPPROPSHEETPAGE);
BOOL CALLBACK ProcessesDlgProc (HWND, UINT, WPARAM, LPARAM);
UINT CALLBACK LoggingPageProc (HWND, UINT, LPPROPSHEETPAGE);
BOOL CALLBACK LoggingDlgProc (HWND, UINT, WPARAM, LPARAM);
UINT CALLBACK PathsPageProc (HWND, UINT, LPPROPSHEETPAGE);
BOOL CALLBACK PathsDlgProc (HWND, UINT, WPARAM, LPARAM);
UINT CALLBACK UsersPageProc (HWND, UINT, LPPROPSHEETPAGE);
BOOL CALLBACK UsersDlgProc (HWND, UINT, WPARAM, LPARAM);
UINT CALLBACK GroupsPageProc (HWND, UINT, LPPROPSHEETPAGE);
BOOL CALLBACK GroupsDlgProc (HWND, UINT, WPARAM, LPARAM);
UINT CALLBACK MIMEPageProc (HWND, UINT, LPPROPSHEETPAGE);
BOOL CALLBACK MIMEDlgProc (HWND, UINT, WPARAM, LPARAM);



extern HWND hwndMain;
extern HINSTANCE hInst;
extern BOOL sht1, sht2, sht3, sht4, sht5, sht6, sht7, sht8;

extern TsavantData savantData;
extern tDirInfo **dirInfo;
extern UserInfo **userInfo;
extern GroupInfo *groupInfo;
extern tMIMEInfo **MIMEinfo;

extern int dirsToRead;
extern int usersToRead, dirsToRead, MIMEToRead;


