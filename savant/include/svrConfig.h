
#ifndef	__SVR_CONFIG_H__
#define	__SVR_CONFIG_H__

struct TsavantData
{
	char szDNS[151];
	char szPort[6];
	char szIndex[21];
	char szErrorMsgPath[201];
	char szCGITempPipe[201];
	char szInitialProcesses[6];
	char szMaxProcesses[6];
	char szFreeProcesses[6];
	char szProcessCompactPeriod[6];
	char szProcessCompactLaziness[6];
	char szPathToStoreLogs[201];
	char szGeneralLogEnabled[2];
	char szGeneralLogLookup[2];
	char szGeneralLogFile[201];
	char szHitEnabled[2];
	char szHitRecordConnections[2];
	char szHitRecordKB[2];
	char szHitRecordFiles[2];
	char szHitLogFile[201];
	char szReferenceEnabled[2];
	char szReferenceLogFile[201];
	char szNumDirs[7];
	char szNumUsers[7];
	char szNumGroups[7];
	char szNumMIME[7];
};


struct tDirInfo
{
	char HTTPname[51];
	char FATname[201];
	char allowList[2];
	char scriptType[11];
	char authUser[31];
	char authLocation[31];
};


typedef	struct UserInfo
{
	struct UserInfo	*next;
	
	char		name[31];
	char		password[31];
}USER_T;


typedef	struct GroupInfo
{
	struct GroupInfo	*next;
	
	char		name[31];
	
	int		numMembers;
	char **members;
	USER_T	*users;
}GROUP_T;

struct tUser
{
  char *NameStr;
  char *PasswordStr;
};


struct tGroup
{
  char *NameStr;
  int NumMembers;
  char **Members;
};


struct tCacheEntry
{
  char EncodedAuthInfo[300];
  char AuthUserStr[50];
  char UserStr[50];
};


struct tMIMEInfo
{
	char extension[6];
	char description[128];
};

#define	DEFAULT_DIR		"d:\\work\\webserver\\savant\\wwwroot\\"

#define	SET_DEFAULT_DIR( dirName) \
		{SNPRINTF(dirName, MAX_PATH, "%s", DEFAULT_DIR);}

typedef	struct _RUN_CONFIG
{
	BOOL ComLogConvertIP, CntLogEnabled, CntLogCountFiles, CntLogCountConnects;
	BOOL ScriptDNS, CntLogCountKBytes, RefLogEnabled, ComLogEnabled;

	char		ErrorMsgDirStr[MAX_PATH];
	char		LogDirStr[MAX_PATH];
	char		TempDirStr[MAX_PATH];

	char		ComLogFileNameStr[MAX_PATH];
	char		IndexFileNameStr[MAX_PATH];
	
	char		RefLogFileNameStr[MAX_PATH];
	char		CntLogFileNameStr[MAX_PATH];

	int		InitNumThreads;
	int		MaxNumThreads;
	int		NumThreadsKeepFree;
	int		ThreadCompactLaziness;

	WORD	PortNum;
	UINT	ThreadCompactPeriod;

	char		ServerNameStr[MAX_PATH];
}RUNNING_CONFIG;


typedef	struct _STATUS
{
	int	numProcesses;
	int	totalNumProcesses;
	
	int	currentThreadNumber;

	int	totalConnections;
	int	totalSendKBytes;		/* kilo */
	int	totalSendFiles;
	
	int	totalRxKBytes;		/* kilo */
}STATUS_T;

typedef	struct	_SERVER
{
	RUNNING_CONFIG		cfg;

	GROUP_T				*group;


	SOCKET			serverSocket;
	HWND			msgWindow;
	UINT			watchDogID;

	STATUS_T			status;
}HTTP_SERVICE;


#ifdef	MINGW
	#define	SNPRINTF		snprintf
#else
//	#define	SNPRINTF		_snprintf
//	#define	SNPRINTF		_snprintf_s
#define	SNPRINTF(msg, size, format,...) \
	_snprintf(msg, size, format, ##__VA_ARGS__)
	
#define	GETS(msg)	\
			fgets(msg, sizeof(msg), stdin)
#endif

#if 1
#define	DEBUG_MSG( format ,...) \
	{char msg[512]; \
	SNPRINTF(msg, sizeof(msg), format, __VA_ARGS__ ); \
	logDebug(msg);}

#define	TRACE()		logDebug(__FILE__ " "__FUNCTION__"() : %d line\n", __LINE__ )

//	WOLFSSL_MSG(msg);} 
#else
	SNPRINTF(msg, sizeof(msg), format, ##__VA_ARGS__ ); \
#define	DEBUG_MSG( format ,...) \
	{char msg[512]; va_list args; \
  		va_start(args, format);	\
	SNPRINTF(msg, sizeof(msg), format, args); \
	printf(msg); \
	OutputDebugString(msg);} 

#define	TRACE()

#endif

void logDebug(char *format, ...);

#define	PROGRAM_CONFIG		TEXT("SAVCFG.EXE")

#define	ERR_REGISTER_NOT_FOUND			"Corrupted Registry - See the Errors & Troubleshooting section of the help file."

#define	ERR_REGISTER_ERR					""

#define	HANDLER_REGISTER_ERR() \
    {MessageBox(hwndMain, ERR_REGISTER_NOT_FOUND, "Registry Error", MB_OK | MB_ICONERROR); return;}

#define	DEBUG_REGISTER_ERR() \
    {logDebug( ERR_REGISTER_NOT_FOUND); return;}


#define INIT_THREAD_STACK_SIZE 16384
#define FIRST_THREAD_ID 1000
#define LAST_THREAD_ID  1999


#define MAX_HTTP_FIELD_NAME_LEN 128
#define MAX_HTTP_FIELD_LEN 1024
#define GH_ERROR           -1

#define IO_BUFFER_SIZE				16384

#define GH_UNKNOWN_VERSION		0
#define GH_SIMPLE_REQUEST			1
#define GH_10_REQUEST				2



#define	TIME_OF_WATCHDOG			2 * 60 * 1000
#define	TIME_OF_SHUTDOWN			30 * 1000


#define	SERVER_NAME() 			cfg->ServerNameStr

#define	PORT_NUM()				cfg->PortNum

#define	ERROE_MSG_PATH()  		cfg->ErrorMsgDirStr

//Returns directory for temporary CGI process files
#define	SERVER_TEMP_DIR()		cfg->TempDirStr


//Gets configuration info for the common log
#define CMN_LOG_FLAGS(enabled, fileName, lookUpIP) \
{	enabled = cfg->ComLogEnabled; fileName =cfg->ComLogFileNameStr; \
	lookUpIP = cfg->ComLogConvertIP; }

//Gets configuration info for the count log
#define	COUNT_LOG_FLAGS( countFiles, countConnects, countKBytes) \
{	countFiles = cfg->CntLogCountFiles; countConnects = cfg->CntLogCountConnects; \
	countKBytes = cfg->CntLogCountKBytes; }

//Gets configuration info for reference log
#define	REFERENCE_FLAGS(enabled, fileName) \
{	enabled = cfg->RefLogEnabled; fileName =cfg->RefLogFileNameStr; }


#define	STATUS_PROCESS_INCREASE() \
	http->status.totalNumProcesses ++

#define	STATUS_CONNECTIONS_COUNT() \
	http->status.totalConnections++ 


//HTTPLogCountEntry
#define	STATUS_SENDOUT_INFO(uriStr, dateStr, size) \
		{	http->status.totalSendKBytes += size/1024; http->status.totalSendFiles++; }

extern	HTTP_SERVICE	httpService;
extern	HTTP_SERVICE	*http;
extern	RUNNING_CONFIG		*cfg;


#endif

