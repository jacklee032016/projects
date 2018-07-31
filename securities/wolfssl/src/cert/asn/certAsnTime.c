#include "cmnCrypto.h"

#ifndef NO_ASN

/******************************************************************
* utils function of get current time with type of time_t in different platform
******************************************************************/
#ifdef _WIN32_WCE
/* no time() or gmtime() even though in time.h header?? */
#include <windows.h>
time_t time(time_t* timer)
{
    SYSTEMTIME     sysTime;
    FILETIME       fTime;
    ULARGE_INTEGER intTime;
    time_t         localTime;

    if (timer == NULL)
        timer = &localTime;

    GetSystemTime(&sysTime);
    SystemTimeToFileTime(&sysTime, &fTime);

    XMEMCPY(&intTime, &fTime, sizeof(FILETIME));
    /* subtract EPOCH */
    intTime.QuadPart -= 0x19db1ded53e8000;
    /* to secs */
    intTime.QuadPart /= 10000000;
    *timer = (time_t)intTime.QuadPart;

    return *timer;
}

#endif /*  _WIN32_WCE */
#if defined( _WIN32_WCE ) || defined( USER_TIME )

struct tm* gmtime(const time_t* timer)
{
    #define YEAR0          1900
    #define EPOCH_YEAR     1970
    #define SECS_DAY       (24L * 60L * 60L)
    #define LEAPYEAR(year) (!((year) % 4) && (((year) % 100) || !((year) %400)))
    #define YEARSIZE(year) (LEAPYEAR(year) ? 366 : 365)

    static const int _ytab[2][12] =
    {
        {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
        {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
    };

    static struct tm st_time;
    struct tm* ret = &st_time;
    time_t secs = *timer;
    unsigned long dayclock, dayno;
    int year = EPOCH_YEAR;

    dayclock = (unsigned long)secs % SECS_DAY;
    dayno    = (unsigned long)secs / SECS_DAY;

    ret->tm_sec  = (int) dayclock % 60;
    ret->tm_min  = (int)(dayclock % 3600) / 60;
    ret->tm_hour = (int) dayclock / 3600;
    ret->tm_wday = (int) (dayno + 4) % 7;        /* day 0 a Thursday */

    while(dayno >= (unsigned long)YEARSIZE(year)) {
        dayno -= YEARSIZE(year);
        year++;
    }

    ret->tm_year = year - YEAR0;
    ret->tm_yday = (int)dayno;
    ret->tm_mon  = 0;

    while(dayno >= (unsigned long)_ytab[LEAPYEAR(year)][ret->tm_mon]) {
        dayno -= _ytab[LEAPYEAR(year)][ret->tm_mon];
        ret->tm_mon++;
    }

    ret->tm_mday  = (int)++dayno;
    ret->tm_isdst = 0;

    return ret;
}

#endif /* _WIN32_WCE  || USER_TIME */


#ifdef HAVE_RTP_SYS

#define YEAR0          1900

struct tm* my_gmtime(const time_t* timer)       /* has a gmtime() but hangs */
{
    static struct tm st_time;
    struct tm* ret = &st_time;

    DC_RTC_CALENDAR cal;
    dc_rtc_time_get(&cal, TRUE);

    ret->tm_year  = cal.year - YEAR0;       /* gm starts at 1900 */
    ret->tm_mon   = cal.month - 1;          /* gm starts at 0 */
    ret->tm_mday  = cal.day;
    ret->tm_hour  = cal.hour;
    ret->tm_min   = cal.minute;
    ret->tm_sec   = cal.second;

    return ret;
}

#endif /* HAVE_RTP_SYS */


#if defined(MICROCHIP_TCPIP_V5) || defined(MICROCHIP_TCPIP)

/*
 * time() is just a stub in Microchip libraries. We need our own
 * implementation. Use SNTP client to get seconds since epoch.
 */
time_t pic32_time(time_t* timer)
{
#ifdef MICROCHIP_TCPIP_V5
    DWORD sec = 0;
#else
    uint32_t sec = 0;
#endif
    time_t localTime;

    if (timer == NULL)
        timer = &localTime;

#ifdef MICROCHIP_MPLAB_HARMONY
    sec = TCPIP_SNTP_UTCSecondsGet();
#else
    sec = SNTPGetUTCSeconds();
#endif
    *timer = (time_t) sec;

    return *timer;
}

#endif /* MICROCHIP_TCPIP */


#ifdef FREESCALE_MQX

time_t mqx_time(time_t* timer)
{
    time_t localTime;
    TIME_STRUCT time_s;

    if (timer == NULL)
        timer = &localTime;

    _time_get(&time_s);
    *timer = (time_t) time_s.SECONDS;

    return *timer;
}

/* CodeWarrior GCC toolchain only has gmtime_r(), no gmtime() */
struct tm* mqx_gmtime(const time_t* clock, struct tm* tmpTime)
{
    return gmtime_r(clock, tmpTime);
}

#endif /* FREESCALE_MQX */

#ifdef WOLFSSL_TIRTOS
time_t XTIME(time_t * timer)
{
    time_t sec = 0;

    sec = (time_t) Seconds_get();

    if (timer != NULL)
        *timer = sec;

    return sec;
}
#endif /* WOLFSSL_TIRTOS */


#ifndef NO_TIME_H

/* to the second */
static int __dateGreaterThan(const struct tm* a, const struct tm* b)
{
	if (a->tm_year > b->tm_year)
		return 1;

	if (a->tm_year == b->tm_year && a->tm_mon > b->tm_mon)
		return 1;

	if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon && a->tm_mday > b->tm_mday)
		return 1;

	if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
		a->tm_mday == b->tm_mday && a->tm_hour > b->tm_hour)
		return 1;

	if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
		a->tm_mday == b->tm_mday && a->tm_hour == b->tm_hour &&
		a->tm_min > b->tm_min)
		return 1;

	if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
		a->tm_mday == b->tm_mday && a->tm_hour == b->tm_hour &&
		a->tm_min  == b->tm_min  && a->tm_sec > b->tm_sec)
		return 1;

	return 0; /* false */
}


static INLINE int __dateLessThan(const struct tm* a, const struct tm* b)
{
	return __dateGreaterThan(b,a);
}


/* like atoi but only use first byte */
/* Make sure before and after dates are valid */
int ValidateDate(const byte* date, byte format, int dateType)
{
    time_t ltime;
    struct tm  certTime;
    struct tm* localTime;
    struct tm* tmpTime = NULL;
    int    i = 0;

#if defined(FREESCALE_MQX) || defined(TIME_OVERRIDES)
    struct tm tmpTimeStorage;
    tmpTime = &tmpTimeStorage;
#else
    (void)tmpTime;
#endif

    ltime = XTIME(0);
    XMEMSET(&certTime, 0, sizeof(certTime));

    if (format == ASN_UTC_TIME) {
        if (btoi(date[0]) >= 5)
            certTime.tm_year = 1900;
        else
            certTime.tm_year = 2000;
    }
    else  { /* format == GENERALIZED_TIME */
        certTime.tm_year += btoi(date[i++]) * 1000;
        certTime.tm_year += btoi(date[i++]) * 100;
    }

    /* adjust tm_year, tm_mon */
    GetTime((int*)&certTime.tm_year, date, &i); certTime.tm_year -= 1900;
    GetTime((int*)&certTime.tm_mon,  date, &i); certTime.tm_mon  -= 1;
    GetTime((int*)&certTime.tm_mday, date, &i);
    GetTime((int*)&certTime.tm_hour, date, &i);
    GetTime((int*)&certTime.tm_min,  date, &i);
    GetTime((int*)&certTime.tm_sec,  date, &i);

        if (date[i] != 'Z') {     /* only Zulu supported for this profile */
        WOLFSSL_MSG("Only Zulu time supported for this profile");
        return 0;
    }

    localTime = XGMTIME(&ltime, tmpTime);

    if (dateType == BEFORE) {
        if (__dateLessThan(localTime, &certTime))
            return 0;
    }
    else
    {
        if (__dateGreaterThan(localTime, &certTime))
            return 0;
    }
    return 1;
}

#endif /* NO_TIME_H */


#endif

