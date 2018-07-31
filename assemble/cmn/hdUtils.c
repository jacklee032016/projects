#include "hdAsm.h"
#include <windows.h>

int calculateCPUSpeed(void)
{
	U64 timerFirst, timerSecond;
	const DWORD dwDelay = 500;

	// We want absolute maximum priority
	DWORD dwPriorityClass = GetPriorityClass(GetCurrentProcess());
	int nPriority = GetThreadPriority(GetCurrentThread());
	SetPriorityClass(GetCurrentProcess(),REALTIME_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_TIME_CRITICAL);
	Sleep(0);	// Give up the rest of our timeslice so we don't get a context switch

	timerFirst = cpuInfoRdtsc();

	// Sleep for a while
	Sleep(dwDelay);

	// Get the elapsed time
	timerSecond = cpuInfoRdtsc();

	// Reset priority and get speed
	SetThreadPriority(GetCurrentThread(),nPriority);
	SetPriorityClass(GetCurrentProcess(),dwPriorityClass);
	return (timerSecond-timerFirst)/ (1000*dwDelay);
}

float ProcSpeedCalc()
{
/*
RdTSC:
It's the Pentium instruction "ReaD Time Stamp Counter". It measures the
number of clock cycles that have passed since the processor was reset, as a
64-bit number. That's what the <CODE>_emit</CODE> lines do.*/
#define RdTSC __asm _emit 0x0f __asm _emit 0x31

// variables for the clock-cycles:
__int64 cyclesStart = 0, cyclesStop = 0;
// variables for the High-Res Preformance Counter:
unsigned __int64 nCtr = 0, nFreq = 0, nCtrStop = 0;


    // retrieve performance-counter frequency per second:
    if(!QueryPerformanceFrequency((LARGE_INTEGER *) &nFreq)) return 0;

    // retrieve the current value of the performance counter:
    QueryPerformanceCounter((LARGE_INTEGER *) &nCtrStop);

    // add the frequency to the counter-value:
    nCtrStop += nFreq;

#if 0
    _asm
        {// retrieve the clock-cycles for the start value:
            RdTSC
            mov DWORD PTR cyclesStart, eax
            mov DWORD PTR [cyclesStart + 4], edx
        }

        do{
        // retrieve the value of the performance counter
        // until 1 sec has gone by:
             QueryPerformanceCounter((LARGE_INTEGER *) &nCtr);
          }while (nCtr < nCtrStop);

    _asm
        {// retrieve again the clock-cycles after 1 sec. has gone by:
            RdTSC
            mov DWORD PTR cyclesStop, eax
            mov DWORD PTR [cyclesStop + 4], edx
        }
#endif

// stop-start is speed in Hz divided by 1,000,000 is speed in MHz
return    ((float)cyclesStop-(float)cyclesStart) / 1000000;
}

#if 0
char *ProcSpeedRead()
{
	CString sMHz;
	char Buffer[_MAX_PATH];
	DWORD BufSize = _MAX_PATH;
	DWORD dwMHz = _MAX_PATH;
	HKEY hKey;

	// open the key where the proc speed is hidden:
	long lError = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                        0,
                        KEY_READ,
                        &hKey);
    
    if(lError != ERROR_SUCCESS)
      {// if the key is not found, tell the user why:
           FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
                         NULL,
                         lError,
                         0,
                         Buffer,
                         _MAX_PATH,
                         0);
               AfxMessageBox(Buffer);
           return "N/A";
       }

        // query the key:
        RegQueryValueEx(hKey, "~MHz", NULL, NULL, (LPBYTE) &dwMHz, &BufSize);

	// convert the DWORD to a CString:
	sMHz.Format("%i", dwMHz);

	return sMHz;
}
#endif

