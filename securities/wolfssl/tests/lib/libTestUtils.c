
#include "libTest.h"


/* do back x number of directories */
void ChangeDirBack(int x)
{
#ifdef USE_WINDOWS_API 
	char path[MAX_PATH];

	if (x == 1)
		strncpy(path, "..\\", MAX_PATH);
	else if (x == 2)
		strncpy(path, "..\\..\\", MAX_PATH);
	else if (x == 3)
		strncpy(path, "..\\..\\..\\", MAX_PATH);
	else if (x == 4)
		strncpy(path, "..\\..\\..\\..\\", MAX_PATH);
	else
		strncpy(path, ".\\", MAX_PATH);

	SetCurrentDirectoryA(path);
#elif defined(WOLFSSL_MDK_ARM)
    /* KEIL-RL File System does not support relative directry */
#elif defined(WOLFSSL_TIRTOS)
#else
    char path[MAX_PATH];

    if (x == 1)
        strncpy(path, "../", MAX_PATH);
    else if (x == 2)
        strncpy(path, "../../", MAX_PATH);
    else if (x == 3)
        strncpy(path, "../../../", MAX_PATH);
    else if (x == 4)
        strncpy(path, "../../../../", MAX_PATH);
    else
        strncpy(path, "./", MAX_PATH);
    
    if (chdir(path) < 0)
        printf("chdir to %s failed\n", path);
#endif	
}

/* does current dir contain str */
int CurrentDir(const char* str)
{
#ifdef USE_WINDOWS_API 
	char  path[MAX_PATH];
	char* baseName;

	GetCurrentDirectoryA(sizeof(path), path);

	baseName = strrchr(path, '\\');
	if (baseName)
		baseName++;
	else
		baseName = path;

	if (strstr(baseName, str))
		return 1;

	return 0;
#elif defined(WOLFSSL_MDK_ARM)
    /* KEIL-RL File System does not support relative directry */
#elif defined(WOLFSSL_TIRTOS)
#else
	char  path[MAX_PATH];
	char* baseName;

	if (getcwd(path, sizeof(path)) == NULL) {
		printf("no current dir?\n");
		return 0;
	}

	baseName = strrchr(path, '/');
	if (baseName)
		baseName++;
	else
		baseName = path;

	if (strstr(baseName, str))
		return 1;

	return 0;
#endif /* USE_WINDOWS_API */
}


void err_sys(const char* fmt, ...)
{
#if 0
//	wolfSslDebug("wolfSSL error: " );
	wolfSslDebug( fmt, ##__VA_ARGS__);
#else
	va_list argp; 
	static char debugStr[1024];


	va_start (argp, fmt);
	vsprintf(debugStr, fmt, argp);

	printf( debugStr);

	va_end (argp); 
#endif
	exit(EXIT_FAILURE);
}

int myoptind = 0;
char* myoptarg = NULL;

int mygetopt(int argc, char** argv, const char* optstring)
{
	static char* next = NULL;

	char  c;
	char* cp;

	if (myoptind == 0)
		next = NULL;   /* we're starting new/over */

	if (next == NULL || *next == '\0')
	{
		if (myoptind == 0)
			myoptind++;

		if (myoptind >= argc || argv[myoptind][0] != '-' ||argv[myoptind][1] == '\0')
		{
			myoptarg = NULL;
			if (myoptind < argc)
				myoptarg = argv[myoptind];

			return -1;
		}

		if (strcmp(argv[myoptind], "--") == 0)
		{
			myoptind++;
			myoptarg = NULL;

			if (myoptind < argc)
				myoptarg = argv[myoptind];

			return -1;
		}

		next = argv[myoptind];
		next++;                  /* skip - */
		myoptind++;
	}

	c  = *next++;
	/* The C++ strchr can return a different value */
	cp = (char*)strchr(optstring, c);

	if (cp == NULL || c == ':') 
		return '?';

	cp++;

	if (*cp == ':') {
		if (*next != '\0') {
			myoptarg = next;
			next     = NULL;
		}
		else if (myoptind < argc) {
			myoptarg = argv[myoptind];
			myoptind++;
		}
		else 
			return '?';
	}

	return c;
}



#ifdef USE_WINDOWS_API 
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
double current_time()
{
	static int init = 0;
	static LARGE_INTEGER freq;

	LARGE_INTEGER count;

	if (!init) {
		QueryPerformanceFrequency(&freq);
		init = 1;
	}

	QueryPerformanceCounter(&count);

	return (double)count.QuadPart / freq.QuadPart;
}

#elif defined(WOLFSSL_TIRTOS)
extern double current_time();
#else

#if !defined(WOLFSSL_MDK_ARM)
#include <sys/time.h>
double current_time(void)
{
	struct timeval tv;
	gettimeofday(&tv, 0);

	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}
#endif

#endif /* USE_WINDOWS_API */

