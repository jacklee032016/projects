
#include "libTest.h"


#ifdef USE_WOLFSSL_MEMORY

typedef struct memoryStats {
	size_t totalAllocs;     /* number of allocations */
	size_t totalBytes;      /* total number of bytes allocated */
	size_t peakBytes;       /* concurrent max bytes */
	size_t currentBytes;    /* total current bytes in use */
} memoryStats;

typedef struct memHint {
	size_t thisSize;      /* size of this memory */
	void*  thisMemory;    /* actual memory for user */
} memHint;

typedef struct memoryTrack {
	union {
		memHint hint;
		byte    alignit[16];   /* make sure we have strong alignment */
	} u;
} memoryTrack;

#if defined(WOLFSSL_TRACK_MEMORY)
#define DO_MEM_STATS
static memoryStats ourMemStats;
#endif

static void	*_trackMalloc(size_t sz)
{
	memoryTrack* mt;

	if (sz == 0)
		return NULL;

	mt = (memoryTrack*)malloc(sizeof(memoryTrack) + sz);
	if (mt == NULL)
		return NULL;

	mt->u.hint.thisSize   = sz;
	mt->u.hint.thisMemory = (byte*)mt + sizeof(memoryTrack);

#ifdef DO_MEM_STATS
	ourMemStats.totalAllocs++;
	ourMemStats.totalBytes   += sz;
	ourMemStats.currentBytes += sz;
	if (ourMemStats.currentBytes > ourMemStats.peakBytes)
		ourMemStats.peakBytes = ourMemStats.currentBytes;
#endif

	return mt->u.hint.thisMemory;
}


static void _trackFree(void* ptr)
{
	memoryTrack* mt;

	if (ptr == NULL)
		return;

	mt = (memoryTrack*)ptr;
	--mt;   /* same as minus sizeof(memoryTrack), removes header */

#ifdef DO_MEM_STATS 
	ourMemStats.currentBytes -= mt->u.hint.thisSize; 
#endif

	free(mt);
}


static void	*_trackRealloc(void* ptr, size_t sz)
{
	void* ret = _trackMalloc(sz);

	if (ptr)
	{
		/* if realloc is bigger, don't overread old ptr */
		memoryTrack* mt = (memoryTrack*)ptr;
		--mt;  /* same as minus sizeof(memoryTrack), removes header */

		if (mt->u.hint.thisSize < sz)
			sz = mt->u.hint.thisSize;
	}

	if (ret && ptr)
		memcpy(ret, ptr, sz);

	if (ret)
		_trackFree(ptr);

	return ret;
}

void InitMemoryTracker(void) 
{
	if (wolfSSL_SetAllocators(_trackMalloc, _trackFree, _trackRealloc) != 0)
		err_sys("wolfSSL SetAllocators failed for track memory");

#ifdef DO_MEM_STATS
	ourMemStats.totalAllocs  = 0;
	ourMemStats.totalBytes   = 0;
	ourMemStats.peakBytes    = 0;
	ourMemStats.currentBytes = 0;
#endif
}

void ShowMemoryTracker(void) 
{
#ifdef DO_MEM_STATS 
	printf("total   Allocs = %9lu\n", (unsigned long)ourMemStats.totalAllocs);
	printf("total   Bytes  = %9lu\n", (unsigned long)ourMemStats.totalBytes);
	printf("peak    Bytes  = %9lu\n", (unsigned long)ourMemStats.peakBytes);
	printf("current Bytes  = %9lu\n", (unsigned long)ourMemStats.currentBytes);
#endif
}
#endif /* USE_WOLFSSL_MEMORY */



 void StackTrap(void)
{
#ifdef STACK_TRAP
/* good settings
   --enable-debug --disable-shared C_EXTRA_FLAGS="-DUSER_TIME -DTFM_TIMING_RESISTANT -DPOSITIVE_EXP_ONLY -DSTACK_TRAP"*/
#ifdef HAVE_STACK_SIZE
    /* client only for now, setrlimit will fail if pthread_create() called */
    /* STACK_SIZE does pthread_create() on client */
    #error "can't use STACK_TRAP with STACK_SIZE, setrlimit will fail"
#endif /* HAVE_STACK_SIZE */
	struct rlimit  rl;
	if (getrlimit(RLIMIT_STACK, &rl) != 0)
		err_sys("getrlimit failed");
	
	printf("rlim_cur = %llu\n", rl.rlim_cur);
	rl.rlim_cur = 1024*21;  /* adjust trap size here */

	if (setrlimit(RLIMIT_STACK, &rl) != 0)
	{
		perror("setrlimit");
		err_sys("setrlimit failed");
	}
#else /* STACK_TRAP */
#endif /* STACK_TRAP */
}


int myDateCb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
	char buffer[WOLFSSL_MAX_ERROR_SZ];
	(void)preverify;

	printf("In verification callback, error = %d, %s\n", store->error, wolfSSL_ERR_error_string(store->error, buffer));
	printf("Subject's domain name is %s\n", store->domain);

	if (store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E)
	{
		printf("Overriding cert date error as example for bad clock testing\n");
		return 1;
	}
	printf("Cert error is not date error, not overriding\n");

	return 0;
}


void showPeer(WOLFSSL* ssl)
{
	WOLFSSL_CIPHER* cipher;
#ifdef KEEP_PEER_CERT
	WOLFSSL_X509* peer = wolfSSL_get_peer_certificate(ssl);
	if (peer)
		ShowX509(peer, "peer's cert info:");
	else
		printf("peer has no cert!\n");
#endif

	printf("SSL version is %s\n", wolfSSL_get_version(ssl));

	cipher = wolfSSL_get_current_cipher(ssl);
	printf("SSL cipher suite is %s\n", wolfSSL_CIPHER_get_name(cipher));

#if defined(SESSION_CERTS) //&& defined(SHOW_CERTS)
	{
		WOLFSSL_X509_CHAIN* chain = wolfSSL_get_peer_chain(ssl);
		int                count = wolfSSL_get_chain_count(chain);
		int i;

		for (i = 0; i < count; i++) {
			int length;
			unsigned char buffer[3072];
			WOLFSSL_X509* chainX509;

			wolfSSL_get_chain_cert_pem(chain,i,buffer, sizeof(buffer), &length);
			buffer[length] = 0;
			printf("cert %d has length %d data = \n%s\n", i, length, buffer);

			chainX509 = wolfSSL_get_chain_X509(chain, i);
			if (chainX509)
				ShowX509(chainX509, "session cert info:");
			else
				printf("get_chain_X509 failed\n");
			
			wolfSSL_FreeX509(chainX509);
		}
	}
#endif

	(void)ssl;
}

