/*
* Global constant and structure definitions
*/


#include <windows.h>

#define IDM_CONFIG  1001
#define IDM_SHUTDOWN  1002
#define IDM_HELP  1003
#define IDM_ABOUT   1004
#define IDM_STATUSBAR 1005
#define IDD_LISTVIEW 1006

#define PROGRAM_ICON 101


typedef	enum{
	MP_STATUS_ERROR			= 0,
	MP_STATUS_PATH_FOUND	= 1,
	MP_STATUS_NO_ACCESS		= 2,
	MP_STATUS_FORBIDDEN		= 3,
	MP_STATUS_REDIRECT		= 4
}MP_STATUS_T;

typedef	enum{
	SCRIPT_TYPE_NONE		= 0,
	SCRIPT_TYPE_CGI		= 2,
	SCRIPT_TYPE_WINCGI	= 3,
	SCRIPT_TYPE_ISAPI		= 4
}SCRIPT_TYPE_T;


typedef	enum{
	AUTH_LOC_ANYWHERE	= 0,
	AUTH_LOC_CLASSA		= 1,
	AUTH_LOC_CLASSB		= 2,
	AUTH_LOC_CLASSC		= 3,
	AUTH_LOC_CLASSD		= 4,
}AUTH_LOC_T;

#define TrayMsg        WM_USER+69
											//system tray context message ID

#define HTTP_SERVER_MSG WM_USER + 23
											//server context message ID

#define HTTP_TIMER_ID 23			//ID for timer process

#define REG_MAX_SERVER_NAME 200	//maximum length of server name


//Length constants for REQ_INFO_T
#define REQ_METHOD_LEN           24
#define REQ_URL_LEN             512
#define REQ_VERSION_LEN          24
#define REQ_DATA_LEN             48
#define ReqMIMEVerStrLen          24
#define ReqPragmaStrLen          128
#define ReqAuthorizationStrLen   512
#define ReqFromStrLen            128
#define ReqIfModSinceStrLen       48
#define ReqRefererStrLen         512
#define ReqUserAgentStrLen       256
#define ReqContentEncodingStrLen 128
#define ReqContentTypeStrLen     128
#define ReqContentLengthStrLen    48
#define ReqAcceptStrLen          512
#define ReqAcceptLangStrLen       48
#define ReqConnectionStrLen       24
#define ReqAuthorizedUserStrLen   48
#define REQ_PATH_INFO_LEN        512
#define REQ_PATH_TRANSLATED_LEN  512
#define REQ_SCRIPT_NAME_LEN      512
											//constants for lengths of requestFields

#define MAX_OTHER_HEADERS 50		//maximum number of additional header fields

#define NETIO_MAX_LINE			1000			//max number of lines to xfer in a socket


typedef	struct RequestThreadMessageT
{
	int				ThreadId;
	HANDLE			GoEventHnd;
	HANDLE			FreeEventHnd;
	
	BOOL			Shutdown;
	BOOL			CloseHandles;
	
	SOCKADDR_IN	ClientSockAddr;
	SOCKET			ClientSocket;
	int				AddrLen;
}THREAD_STATUS_T;


struct RequestHeaderT
{
	char *Var;
	char *Val;
};//structure for response to header request


//structure for file request info fieldsstruct REQ_INFO_T
typedef	struct	REQ_INFO_T
{
	char				MethodStr[REQ_METHOD_LEN];
	char				URIStr[REQ_URL_LEN];
	
	char				VersionStr[REQ_VERSION_LEN];
	char				DateStr[REQ_DATA_LEN];
	char				MIMEVerStr[ReqMIMEVerStrLen];
	char				PragmaStr[ReqPragmaStrLen];
	char				AuthorizationStr[ReqAuthorizationStrLen];
	char				FromStr[ReqFromStrLen];
	char				IfModSinceStr[ReqIfModSinceStrLen];
	char				RefererStr[ReqRefererStrLen];
	char				UserAgentStr[ReqUserAgentStrLen];
	
	char				ContentEncodingStr[ReqContentEncodingStrLen];
	char				ContentTypeStr[ReqContentTypeStrLen];
	char				ContentLengthStr[ReqContentLengthStrLen];
	
	char				AcceptStr[ReqAcceptStrLen];
	char				AcceptLangStr[ReqAcceptLangStrLen];
	char				ConnectionStr[ReqConnectionStrLen];
	
	DWORD			ContentLength;
	BYTE			*Content;
	
	char				AuthorizedUserStr[ReqAuthorizedUserStrLen];
	char				PathInfoStr[REQ_PATH_INFO_LEN];
	char				PathTranslatedStr[REQ_PATH_TRANSLATED_LEN];
	char				ScriptNameStr[REQ_SCRIPT_NAME_LEN];
	
	int				NumOtherHeaders;
	RequestHeaderT	OtherHeaders[MAX_OTHER_HEADERS];
}REQ_INFO_T;

typedef	struct	_PARSED_REQ
{
	BOOL			bAllowDirList;

	SCRIPT_TYPE_T	scriptType;
	AUTH_LOC_T		authLocType;

	char 			szURI[MAX_PATH]; /* part before ? in URI */
	char				szQuery[MAX_PATH];	/* part after ? in URI */
		
	char				szFilePath[MAX_PATH];
	char				szRemoteRealm[MAX_PATH];
	char				szLocalRealm[MAX_PATH];
	
}PARSED_REQ;

typedef	struct THREAD_INFO_T
{
	int				ThreadNum;
	BYTE			*IOBuffer;
	int				IOBufferSize;
	SOCKET			ClientSocket;
	SOCKADDR_IN	ClientSockAddr;
	int				AddrLen;
	BOOL			KeepAlive;

	PARSED_REQ		parsedReq;
}THREAD_INFO_T;



