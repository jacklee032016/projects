/* client.c
 */

#include <libTest.h>

typedef struct _Client_Cfg
{
	int    version;
	char		*host;
	char		*domain;
	word16		port;
	
	int    usePsk;
	int    useAnon;
	int    sendGET;
	int    benchmark;
	int    doDTLS;
	int    matchName;
	int    doPeerCheck;
	int    nonBlocking;
	int    resumeSession;
	int    wc_shutdown;
	int    disableCRL;
	int    externalTest;
	int    ret;
	int    scr;    /* allow secure renegotiation */
	int    forceScr;    /* force client initiaed scr */
	int    trackMemory;
	int    useClientCert;
	int    fewerPackets;
	int    atomicUser;
	int    pkCallbacks;
	int    overrideDateErrors;
	int    minDhKeyBits;
	char		*cipherList;
	char		*verifyCert;
	char		*ourCert;
	char		*ourKey;

#ifdef HAVE_OCSP
	int		useOcsp;
	char		*ocspUrl;
#endif

#ifdef HAVE_SNI
	char		*sniHostName;
#endif
#ifdef HAVE_MAX_FRAGMENT
	byte		maxFragment;
#endif
#ifdef HAVE_TRUNCATED_HMAC
	byte		truncatedHMAC;
#endif
}Client_Cfg;

#ifdef WOLFSSL_CALLBACKS
Timeval timeout;

int handShakeCB(HandShakeInfo* info)
{
	(void)info;
	return 0;
}

int timeoutCB(TimeoutInfo* info)
{
	(void)info;
	return 0;
}
#endif


#ifdef HAVE_SESSION_TICKET
int sessionTicketCB(WOLFSSL* ssl, const unsigned char* ticket, int ticketSz, void* ctx)
{
	(void)ssl;
	(void)ticket;
	printf("Session Ticket CB: ticketSz = %d, ctx = %s\n", ticketSz, (char*)ctx);
	return 0;
}
#endif


static void Usage(void)
{
    printf("client "    LIBWOLFSSL_VERSION_STRING
           " NOTE: All files relative to wolfSSL home dir\n");
    printf("-?          Help, print this usage\n");
    printf("-h <host>   Host to connect to, default %s\n", wolfSSLIP);
    printf("-p <num>    Port to connect on, not 0, default %d\n", wolfSSLPort);
    printf("-v <num>    SSL version [0-3], SSLv3(0) - TLS1.2(3)), default %d\n", CLIENT_DEFAULT_VERSION);
    printf("-l <str>    Cipher list\n");
    printf("-c <file>   Certificate file,           default %s\n", cliCert);
    printf("-k <file>   Key file,                   default %s\n", cliKey);
    printf("-A <file>   Certificate Authority file, default %s\n", caCert);
#ifndef NO_DH
    printf("-Z <num>    Minimum DH key bits,        default %d\n", DEFAULT_MIN_DHKEY_BITS);
#endif
    printf("-b <num>    Benchmark <num> connections and print stats\n");
    printf("-s          Use pre Shared keys\n");
    printf("-t          Track wolfSSL memory use\n");
    printf("-d          Disable peer checks\n");
    printf("-D          Override Date Errors example\n");
    printf("-g          Send server HTTP GET\n");
    printf("-u          Use UDP DTLS,"     " add -v 2 for DTLSv1 (default), -v 3 for DTLSv1.2\n");
    printf("-m          Match domain name in cert\n");
    printf("-N          Use Non-blocking sockets\n");
    printf("-r          Resume session\n");
    printf("-w          Wait for bidirectional shutdown\n");
#ifdef HAVE_SECURE_RENEGOTIATION
    printf("-R          Allow Secure Renegotiation\n");
    printf("-i          Force client Initiated Secure Renegotiation\n");
#endif
    printf("-f          Fewer packets/group messages\n");
    printf("-x          Disable client cert/key loading\n");
    printf("-X          Driven by eXternal test case\n");
#ifdef SHOW_SIZES
    printf("-z          Print structure sizes\n");
#endif
#ifdef HAVE_SNI
    printf("-S <str>    Use Host Name Indication\n");
#endif
#ifdef HAVE_MAX_FRAGMENT
    printf("-L <num>    Use Maximum Fragment Length [1-5]\n");
#endif
#ifdef HAVE_TRUNCATED_HMAC
    printf("-T          Use Truncated HMAC\n");
#endif
#ifdef HAVE_OCSP
    printf("-o          Perform OCSP lookup on peer certificate\n");
    printf("-O <url>    Perform OCSP lookup using <url> as responder\n");
#endif
#ifdef ATOMIC_USER
    printf("-U          Atomic User Record Layer Callbacks\n");
#endif
#ifdef HAVE_PK_CALLBACKS 
    printf("-P          Public Key Callbacks\n");
#endif
#ifdef HAVE_ANON
    printf("-a          Anonymous client\n");
#endif
#ifdef HAVE_CRL
    printf("-C          Disable CRL\n");
#endif
}


WOLFSSL_CTX *clientConfig(Client_Cfg *cfg, func_args *args)
{
	int     argc = ((func_args*)args)->argc;
	char**  argv = ((func_args*)args)->argv;
	int    ch;
	WOLFSSL_METHOD	*method  = NULL;
	WOLFSSL_CTX	*ctx = NULL;

	WOLFSSL_ENTER();

	XMEMSET(cfg, 0, sizeof(Client_Cfg));
	cfg->minDhKeyBits  = DEFAULT_MIN_DHKEY_BITS;
	cfg->version = CLIENT_INVALID_VERSION;
	cfg->verifyCert = caCert;
	cfg->ourCert    = cliCert;
	cfg->ourKey     = cliKey;
	cfg->host   = (char*)wolfSSLIP;
	cfg->domain = "www.wolfssl.com";
	cfg->port   = wolfSSLPort;
	
	while ((ch = mygetopt(argc, argv, "?gdDusmNrwRitfxXUPCh:p:v:l:A:c:k:Z:b:zS:L:ToO:a")) != -1)
	{
//		printf("'%c'::", ch);
		switch (ch)
		{
			case '?' :
				Usage();
				exit(EXIT_SUCCESS);

			case 'g' :
				cfg->sendGET = 1;
				break;

			case 'd' :
				cfg->doPeerCheck = 0;
				break;

			case 'D' :
				cfg->overrideDateErrors = 1;
				break;

			case 'C' :
#ifdef HAVE_CRL
				cfg->disableCRL = 1;
#endif
				break;

			case 'u' :
				cfg->doDTLS  = 1;
				break;

			case 's' :
				cfg->usePsk = 1;
				break;

			case 't' :
#ifdef USE_WOLFSSL_MEMORY
				cfg->trackMemory = 1;
#endif
				break;

			case 'm' :
				cfg->matchName = 1;
				break;

			case 'x' :
				cfg->useClientCert = 0;
				break;

			case 'X' :
				cfg->externalTest = 1;
				break;

			case 'f' :
				cfg->fewerPackets = 1;
				break;

			case 'U' :
#ifdef ATOMIC_USER
				cfg->atomicUser = 1;
#endif
				break;

			case 'P' :
#ifdef HAVE_PK_CALLBACKS 
				cfg->pkCallbacks = 1;
#endif
				break;

			case 'h' :
				cfg->host   = myoptarg;
				cfg->domain = myoptarg;
				break;

			case 'p' :
				cfg->port = (word16)atoi(myoptarg);
#if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
				if (cfg->port == 0)
					err_sys("port number cannot be 0");
#endif
				break;

			case 'v' :
				cfg->version = atoi(myoptarg);
				if (cfg->version < 0 || cfg->version > 3) {
					Usage();
					exit(MY_EX_USAGE);
				}
				break;

			case 'l' :
				cfg->cipherList = myoptarg;
				break;

			case 'A' :
				cfg->verifyCert = myoptarg;
				break;

			case 'c' :
				cfg->ourCert = myoptarg;
				break;

			case 'k' :
				cfg->ourKey = myoptarg;
				break;

			case 'Z' :
#ifndef NO_DH
				cfg->minDhKeyBits = atoi(myoptarg);
				if (cfg->minDhKeyBits <= 0 || cfg->minDhKeyBits > 16000) {
					Usage();
					exit(MY_EX_USAGE);
				}
#endif
			break;

			case 'b' :
				cfg->benchmark = atoi(myoptarg);
				if (cfg->benchmark < 0 || cfg->benchmark > 1000000) {
					Usage();
					exit(MY_EX_USAGE);
				}
				break;

			case 'N' :
				cfg->nonBlocking = 1;
				break;

			case 'r' :
				cfg->resumeSession = 1;
				break;

			case 'w' :
				cfg->wc_shutdown = 1;
				break;

			case 'R' :
#ifdef HAVE_SECURE_RENEGOTIATION
				cfg->scr = 1;
#endif
				break;

			case 'i' :
#ifdef HAVE_SECURE_RENEGOTIATION
				cfg->scr      = 1;
				cfg->forceScr = 1;
#endif
				break;

			case 'z' :
#ifndef WOLFSSL_LEANPSK
				wolfSSL_GetObjectSize();
#endif
				break;

			case 'S' :
#ifdef HAVE_SNI
				cfg->sniHostName = myoptarg;
#endif
				break;

			case 'L' :
#ifdef HAVE_MAX_FRAGMENT
				cfg->maxFragment = atoi(myoptarg);
				if (cfg->maxFragment < WOLFSSL_MFL_2_9 ||	cfg->maxFragment > WOLFSSL_MFL_2_13)
				{
					Usage();
					exit(MY_EX_USAGE);
				}
#endif
				break;

			case 'T' :
#ifdef HAVE_TRUNCATED_HMAC
				cfg->truncatedHMAC = 1;
#endif
				break;

			case 'o' :
#ifdef HAVE_OCSP
				cfg->useOcsp = 1;
#endif
				break;

			case 'O' :
#ifdef HAVE_OCSP
				cfg->useOcsp = 1;
				cfg->ocspUrl = myoptarg;
#endif
				break;

			case 'a' :
#ifdef HAVE_ANON
				cfg->useAnon = 1;
#endif
			break;

			default:
				Usage();
				exit(MY_EX_USAGE);
		}
	}

	myoptind = 0;      /* reset for test cases */

	/* sort out DTLS versus TLS versions */
	if (cfg->version == CLIENT_INVALID_VERSION) {
		if (cfg->doDTLS)
			cfg->version = CLIENT_DTLS_DEFAULT_VERSION;
		else
			cfg->version = CLIENT_DEFAULT_VERSION;
	}
	else {
		if (cfg->doDTLS) {
			if (cfg->version == 3)
				cfg->version = -2;
			else
				cfg->version = -1;
		}
	}

	
	if (cfg->externalTest)
	{/* detect build cases that wouldn't allow test against wolfssl.com */
		int done = 0;

#ifdef NO_RSA
		done = 1;
#endif

#ifndef NO_PSK
		done = 1;
#endif

#ifdef NO_SHA
		done = 1;  /* external cert chain most likely has SHA */
#endif

		if (done) {
			printf("external test can't be run in this mode");
			((func_args*)args)->return_code = 0;
			exit(EXIT_SUCCESS);
		}
	}

#ifdef USE_WOLFSSL_MEMORY
    if (cfg->trackMemory)
        InitMemoryTracker(); 
#endif

	switch (cfg->version) {
#ifndef NO_OLD_TLS
		case 0:
			method = wolfSSLv3_client_method();
			break;

#ifndef NO_TLS
		case 1:
			method = wolfTLSv1_client_method();
			break;

		case 2:
			method = wolfTLSv1_1_client_method();
			break;
#endif /* NO_TLS */

#endif  /* NO_OLD_TLS */

#ifndef NO_TLS
		case 3:
			method = wolfTLSv1_2_client_method();
			break;
#endif

#ifdef WOLFSSL_DTLS
#ifndef NO_OLD_TLS
		case -1:
			method = wolfDTLSv1_client_method();
			break;
#endif

		case -2:
			method = wolfDTLSv1_2_client_method();
			break;
#endif

		default:
		err_sys("Bad SSL version");
		break;
	}

	if (method == NULL)
		err_sys("unable to get method");

	ctx = wolfSSL_CTX_new(method);

	WOLFSSL_LEAVE_2();
	
	return ctx;
}

int clientContextConfig(Client_Cfg *cfg, WOLFSSL_CTX *ctx)
{
	WOLFSSL_ENTER();
	
	if (cfg->cipherList)
	{
		if (wolfSSL_CTX_set_cipher_list(ctx, cfg->cipherList) != SSL_SUCCESS)
			err_sys("client can't set cipher list 1");
	}
	
#ifdef WOLFSSL_LEANPSK
	cfg->usePsk = 1;
#endif

#if defined(NO_RSA) && !defined(HAVE_ECC)
	cfg->usePsk = 1;
#endif

	if (cfg->fewerPackets)
		wolfSSL_CTX_set_group_messages(ctx);

#ifndef NO_DH
	wolfSSL_CTX_SetMinDhKey_Sz(ctx, (word16)cfg->minDhKeyBits);
#endif

	if (cfg->usePsk)
	{
#ifndef NO_PSK
		wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
		if (cfg->cipherList == NULL) {
			const char *defaultCipherList;
#if defined(HAVE_AESGCM) && !defined(NO_DH)
			defaultCipherList = "DHE-PSK-AES128-GCM-SHA256";
#elif defined(HAVE_NULL_CIPHER)
			defaultCipherList = "PSK-NULL-SHA256";
#else
			defaultCipherList = "PSK-AES128-CBC-SHA256";
#endif
			printf("defaultCipherList : %s\n", defaultCipherList);
			if (wolfSSL_CTX_set_cipher_list(ctx,defaultCipherList)	!=SSL_SUCCESS)
				err_sys("client can't set cipher list 2");
		}
#endif
		cfg->useClientCert = 0;
	}

	if (cfg->useAnon) {
#ifdef HAVE_ANON
		if (cfg->cipherList == NULL) {
			wolfSSL_CTX_allow_anon_cipher(ctx);
			if (wolfSSL_CTX_set_cipher_list(ctx,"ADH-AES128-SHA") != SSL_SUCCESS)
				err_sys("client can't set cipher list 4");
		}
#endif
		cfg->useClientCert = 0;
	}

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
	wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

#if defined(WOLFSSL_SNIFFER)
	if (cfg->cipherList == NULL) {
		/* don't use EDH, can't sniff tmp keys */
		if (wolfSSL_CTX_set_cipher_list(ctx, "AES256-SHA256") != SSL_SUCCESS) {
			err_sys("client can't set cipher list 3");
		}
	}
#endif

#ifdef HAVE_OCSP
	if (cfg->useOcsp) {
		if (cfg->ocspUrl != NULL) {
			wolfSSL_CTX_SetOCSP_OverrideURL(ctx, cfg->ocspUrl);
			wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_NO_NONCE | WOLFSSL_OCSP_URL_OVERRIDE);
		}
		else
			wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_NO_NONCE);
	}
#endif

#ifdef USER_CA_CB
	wolfSSL_CTX_SetCACb(ctx, CaCb);
#endif

#ifdef VERIFY_CALLBACK
	wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, myVerify);
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
	if (cfg->useClientCert)
	{
		if (wolfSSL_CTX_use_certificate_chain_file(ctx, cfg->ourCert) != SSL_SUCCESS)
			err_sys("can't load client cert file, check file and run from wolfSSL home dir");

		if (wolfSSL_CTX_use_PrivateKey_file(ctx, cfg->ourKey, SSL_FILETYPE_PEM) != SSL_SUCCESS)
			err_sys("can't load client private key file, check file and run from wolfSSL home dir");
	}

	if (!cfg->usePsk && !cfg->useAnon) 
	{
		/* added CA */
		if (wolfSSL_CTX_load_verify_locations(ctx, cfg->verifyCert,0) != SSL_SUCCESS)
			err_sys("can't load ca file, Please run from wolfSSL home dir");
#ifdef HAVE_ECC
		/* load ecc verify too, echoserver uses it by default w/ ecc */
		if (wolfSSL_CTX_load_verify_locations(ctx, eccCert, 0) != SSL_SUCCESS)
			err_sys("can't load ecc ca file, Please run from wolfSSL home dir");
#endif /* HAVE_ECC */
	}
#endif /* !NO_FILESYSTEM && !NO_CERTS */

#if !defined(NO_CERTS)
	if (!cfg->usePsk && !cfg->useAnon && cfg->doPeerCheck == 0)
		wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
	if (!cfg->usePsk && !cfg->useAnon && cfg->overrideDateErrors == 1)
		wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, myDateCb);
#endif

#ifdef HAVE_CAVIUM
	wolfSSL_CTX_UseCavium(ctx, CAVIUM_DEV_ID);
#endif

#ifdef HAVE_SNI
	if (cfg->sniHostName)
		if (wolfSSL_CTX_UseSNI(ctx, 0, cfg->sniHostName, XSTRLEN(cfg->sniHostName)) != SSL_SUCCESS)
			err_sys("UseSNI failed");
#endif

#ifdef HAVE_MAX_FRAGMENT
	if (cfg->maxFragment)
		if (wolfSSL_CTX_UseMaxFragment(ctx, cfg->maxFragment) != SSL_SUCCESS)
			err_sys("UseMaxFragment failed");
#endif

#ifdef HAVE_TRUNCATED_HMAC
	if (cfg->truncatedHMAC)
		if (wolfSSL_CTX_UseTruncatedHMAC(ctx) != SSL_SUCCESS)
			err_sys("UseTruncatedHMAC failed");
#endif

#ifdef HAVE_SESSION_TICKET
	if (wolfSSL_CTX_UseSessionTicket(ctx) != SSL_SUCCESS)
		err_sys("UseSessionTicket failed");
#endif

	WOLFSSL_LEAVE_2();
	
	return 0;
}



int clientBenchMark(Client_Cfg *cfg, WOLFSSL_CTX *ctx)
{
	SOCKET_T	sockfd = NULL;
	WOLFSSL		*ssl = NULL;

	WOLFSSL_ENTER();

	if (cfg->benchmark)
	{
		/* time passed in number of connects give average */
		int times = cfg->benchmark;
		int loops = cfg->resumeSession ? 2 : 1;
		int i = 0;
		WOLFSSL_SESSION* benchSession = NULL;

		while (loops--)
		{
			int benchResume = cfg->resumeSession && loops == 0;
			double start = current_time(), avg;

			for (i = 0; i < times; i++)
			{
				tcp_connect(&sockfd, cfg->host, cfg->port, cfg->doDTLS);

				ssl = wolfSSL_new(ctx);
				if (benchResume)
					wolfSSL_set_session(ssl, benchSession);
				
				wolfSSL_set_fd(ssl, sockfd);
				
				if (wolfSSL_connect(ssl) != SSL_SUCCESS)
					err_sys("SSL_connect failed");

				wolfSSL_shutdown(ssl);
				
				if (i == (times-1) && cfg->resumeSession) {
					benchSession = wolfSSL_get_session(ssl);
				}
				
				wolfSSL_free(ssl);
				CloseSocket(sockfd);
			}
			
			avg = current_time() - start;
			avg /= times;
			avg *= 1000;   /* milliseconds */
			if (benchResume)
				printf("wolfSSL_resume  avg took: %8.3f milliseconds\n", avg);
			else
				printf("wolfSSL_connect avg took: %8.3f milliseconds\n", avg);
		}

		wolfSSL_CTX_free(ctx);
//		((func_args*)args)->return_code = 0;

		exit(EXIT_SUCCESS);
	}


	WOLFSSL_LEAVE_2();
	
	return 0;
}

	SOCKET_T sockfd = 0;



static void NonBlockingSSL_Connect(WOLFSSL* ssl)
{
#ifndef WOLFSSL_CALLBACKS
	int ret = wolfSSL_connect(ssl);
#else
	int ret = wolfSSL_connect_ex(ssl, handShakeCB, timeoutCB, timeout);
#endif
	int error = wolfSSL_get_error(ssl, 0);
	SOCKET_T sockfd = (SOCKET_T)wolfSSL_get_fd(ssl);
	int select_ret;

	while (ret != SSL_SUCCESS && (error == SSL_ERROR_WANT_READ ||error == SSL_ERROR_WANT_WRITE))
	{
		int currTimeout = 1;

		if (error == SSL_ERROR_WANT_READ)
			printf("... client would read block\n");
		else
			printf("... client would write block\n");

#ifdef WOLFSSL_DTLS
		currTimeout = wolfSSL_dtls_get_current_timeout(ssl);
#endif
		select_ret = tcp_select(sockfd, currTimeout);

		if ((select_ret == TEST_RECV_READY) || (select_ret == TEST_ERROR_READY))
		{
#ifndef WOLFSSL_CALLBACKS
			ret = wolfSSL_connect(ssl);
#else
			ret = wolfSSL_connect_ex(ssl,handShakeCB,timeoutCB,timeout);
#endif
			error = wolfSSL_get_error(ssl, 0);
		}
		else if (select_ret == TEST_TIMEOUT && !wolfSSL_dtls(ssl))
		{
			error = SSL_ERROR_WANT_READ;
		}
#ifdef WOLFSSL_DTLS
		else if (select_ret == TEST_TIMEOUT && wolfSSL_dtls(ssl) && wolfSSL_dtls_got_timeout(ssl) >= 0)
		{
			error = SSL_ERROR_WANT_READ;
		}
#endif
		else
		{
			error = SSL_FATAL_ERROR;
		}
	}

	if (ret != SSL_SUCCESS)
		err_sys("SSL_connect failed");
}


int	clientSslConnectionInit(Client_Cfg *cfg, WOLFSSL_CTX *ctx, WOLFSSL *ssl)
{

	WOLFSSL_ENTER();

	if (cfg->doDTLS)
	{
		SOCKADDR_IN_T addr;
		build_addr(&addr, cfg->host, cfg->port, 1);
		wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr));
		tcp_socket(&sockfd, 1); /* UDP: no connection is needed */
	}
	else
	{
		tcp_connect(&sockfd, cfg->host, cfg->port, 0);
	}

#ifdef HAVE_POLY1305
	/* use old poly to connect with google server */
	if (!XSTRNCMP(cfg->domain, "www.google.com", 14)) {
		if (wolfSSL_use_old_poly(ssl, 1) != 0)
			err_sys("unable to set to old poly");
	}
#endif

	wolfSSL_set_fd(ssl, sockfd);

#ifdef HAVE_CRL
	if (cfg->disableCRL == 0)
	{
		if (wolfSSL_EnableCRL(ssl, WOLFSSL_CRL_CHECKALL) != SSL_SUCCESS)
			err_sys("can't enable crl check");
		if (wolfSSL_LoadCRL(ssl, crlPemDir, SSL_FILETYPE_PEM, 0) != SSL_SUCCESS)
			err_sys("can't load crl, check crlfile and date validity");
		if (wolfSSL_SetCRL_Cb(ssl, CRL_CallBack) != SSL_SUCCESS)
			err_sys("can't set crl callback");
	}
#endif

#ifdef HAVE_SECURE_RENEGOTIATION
	if (cfg->scr)
	{
		if (wolfSSL_UseSecureRenegotiation(ssl) != SSL_SUCCESS)
			err_sys("can't enable secure renegotiation");
	}
#endif

#ifdef ATOMIC_USER
	if (cfg->atomicUser)
		SetupAtomicUser(ctx, ssl);
#endif

#ifdef HAVE_PK_CALLBACKS
	if (cfg->pkCallbacks)
		SetupPkCallbacks(ctx, ssl);
#endif

	if (cfg->matchName && cfg->doPeerCheck)
		wolfSSL_check_domain_name(ssl, cfg->domain);

#ifndef WOLFSSL_CALLBACKS
	if (cfg->nonBlocking)
	{
		TRACE();
		wolfSSL_set_using_nonblock(ssl, 1);
		tcp_set_nonblocking(&sockfd);
		NonBlockingSSL_Connect(ssl);
	}
	else if (wolfSSL_connect(ssl) != SSL_SUCCESS)
	{
		/* see note at top of README */
		int  err = wolfSSL_get_error(ssl, 0);
		char buffer[WOLFSSL_MAX_ERROR_SZ];
		printf("err = %d, %s\n", err,  wolfSSL_ERR_error_string(err, buffer));
		err_sys("SSL_connect failed");
		/* if you're getting an error here  */
	}
#else
	TRACE();
	timeout.tv_sec  = 2;
	timeout.tv_usec = 0;
	NonBlockingSSL_Connect(ssl);  /* will keep retrying on timeout */
#endif


	WOLFSSL_LEAVE_2();
	
	exit(-1);
	return 0;
}

int	clientSslConnectionRw(Client_Cfg *cfg, WOLFSSL *ssl)
{
	char msg[32] = "hello wolfssl!";   /* GET may make bigger */
	char reply[80];
	int  input;
	int  msgSz = (int)strlen(msg);
	

	WOLFSSL_ENTER();

	if (cfg->sendGET)
	{
		printf("SSL connect ok, sending GET...\n");
		msgSz = 28;
		strncpy(msg, "GET /index.html HTTP/1.0\r\n\r\n", msgSz);
		msg[msgSz] = '\0';
	}
	
	if (wolfSSL_write(ssl, msg, msgSz) != msgSz)
		err_sys("SSL_write failed");

	input = wolfSSL_read(ssl, reply, sizeof(reply)-1);
	if (input > 0)
	{
		reply[input] = 0;
		printf("Server response: %s\n", reply);

		if (cfg->sendGET)
		{  /* get html */
			while (1)
			{
				input = wolfSSL_read(ssl, reply, sizeof(reply)-1);
				if (input > 0)
				{
					reply[input] = 0;
					printf("%s\n", reply);
				}
				else
					break;
			}
		}
	}
	else if (input < 0)
	{
		int readErr = wolfSSL_get_error(ssl, 0);
		if (readErr != SSL_ERROR_WANT_READ)
			err_sys("wolfSSL_read failed");
	}


	WOLFSSL_LEAVE_2();
	
	return 0;
}

int	clientSslConnectionShutdown(Client_Cfg *cfg, WOLFSSL *ssl)
{

	WOLFSSL_ENTER();

	if (cfg->doDTLS == 0)
	{ /* don't send alert after "break" command */
		cfg->ret = wolfSSL_shutdown(ssl);
		if (cfg->wc_shutdown && cfg->ret == SSL_SHUTDOWN_NOT_DONE)
			wolfSSL_shutdown(ssl);    /* bidirectional shutdown */
	}
	
#ifdef ATOMIC_USER
	if (cfg->atomicUser)
		FreeAtomicUser(ssl);
#endif

	wolfSSL_free(ssl);
	CloseSocket(sockfd);


	WOLFSSL_LEAVE_2();
	
	return 0;
}

int clientSslConnectionResume(Client_Cfg *cfg, WOLFSSL *sslResume, WOLFSSL_SESSION *session)
{
	char msg[32] = "hello wolfssl!";   /* GET may make bigger */
	char reply[80];
	int  input;
	int  msgSz = (int)strlen(msg);
	char         resumeMsg[] = "resuming wolfssl!";
	int          resumeSz    = sizeof(resumeMsg);
	

	WOLFSSL_ENTER();

#ifndef NO_SESSION_CACHE
	if (cfg->resumeSession)
	{
		if (cfg->doDTLS)
		{
			SOCKADDR_IN_T addr;
#ifdef USE_WINDOWS_API 
			Sleep(500);
#elif defined(WOLFSSL_TIRTOS)
			Task_sleep(1);
#else
			sleep(1);
#endif
			build_addr(&addr, cfg->host, cfg->port, 1);
			wolfSSL_dtls_set_peer(sslResume, &addr, sizeof(addr));
			tcp_socket(&sockfd, 1);
		}
		else
		{
			tcp_connect(&sockfd, cfg->host, cfg->port, 0);
		}
		
		wolfSSL_set_fd(sslResume, sockfd);
#ifdef HAVE_SECURE_RENEGOTIATION
		if (cfg->scr)
		{
			if (wolfSSL_UseSecureRenegotiation(sslResume) != SSL_SUCCESS)
				err_sys("can't enable secure renegotiation");
		}
#endif
		wolfSSL_set_session(sslResume, session);
#ifdef HAVE_SESSION_TICKET
		wolfSSL_set_SessionTicket_cb(sslResume, sessionTicketCB,  (void*)"resumed session");
#endif

		showPeer(sslResume);

#ifndef WOLFSSL_CALLBACKS
		if (cfg->nonBlocking)
		{
			wolfSSL_set_using_nonblock(sslResume, 1);
			tcp_set_nonblocking(&sockfd);
			NonBlockingSSL_Connect(sslResume);
		}
		else if (wolfSSL_connect(sslResume) != SSL_SUCCESS)
			err_sys("SSL resume failed");
#else
		timeout.tv_sec  = 2;
		timeout.tv_usec = 0;
		NonBlockingSSL_Connect(ssl);  /* will keep retrying on timeout */
#endif

		if (wolfSSL_session_reused(sslResume))
			printf("reused session id\n");
		else
			printf("didn't reuse session id!!!\n");

		if (wolfSSL_write(sslResume, resumeMsg, resumeSz) != resumeSz)
			err_sys("SSL_write failed");

		if (cfg->nonBlocking) {
		/* give server a chance to bounce a message back to client */
#ifdef USE_WINDOWS_API
			Sleep(500);
#elif defined(WOLFSSL_TIRTOS)
			Task_sleep(1);
#else
			sleep(1);
#endif
		}

		input = wolfSSL_read(sslResume, reply, sizeof(reply)-1);
		if (input > 0) {
			reply[input] = 0;
			printf("Server resume response: %s\n", reply);
		}

		/* try to send session break */
		wolfSSL_write(sslResume, msg, msgSz); 

		cfg->ret = wolfSSL_shutdown(sslResume);
		if (cfg->wc_shutdown && cfg->ret == SSL_SHUTDOWN_NOT_DONE)
			wolfSSL_shutdown(sslResume);    /* bidirectional shutdown */

		wolfSSL_free(sslResume);
		CloseSocket(sockfd);
	}
	
#endif /* NO_SESSION_CACHE */

	WOLFSSL_LEAVE_2();
	
	return 0;
}

THREAD_RETURN WOLFSSL_THREAD clientTest(void* args)
{
	WOLFSSL_CTX		*ctx = 0;
	WOLFSSL				*ssl = 0;

	WOLFSSL				*sslResume = 0;
	WOLFSSL_SESSION	*session = 0;
	
	char         resumeMsg[] = "resuming wolfssl!";
	int          resumeSz    = sizeof(resumeMsg);


	Client_Cfg  _cfg, *cfg;


	WOLFSSL_ENTER();

	cfg = &_cfg;

#ifdef NO_RSA
	cfg->verifyCert = (char*)eccCert;
	cfg->ourCert    = (char*)cliEccCert;
	cfg->ourKey     = (char*)cliEccKey;
#endif

	StackTrap();

	ctx = clientConfig( cfg, args);
	((func_args*)args)->return_code = -1; /* error state */

	if (ctx == NULL)
		err_sys("unable to get ctx");

	clientContextConfig(cfg, ctx);

	clientBenchMark(cfg, ctx);
	
    
#if defined(WOLFSSL_MDK_ARM)
	wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
#endif
    
	ssl = wolfSSL_new(ctx);
	if (ssl == NULL)
		err_sys("unable to get SSL object");
	
#ifdef HAVE_SESSION_TICKET
	wolfSSL_set_SessionTicket_cb(ssl, sessionTicketCB, (void*)"initial session");
#endif

	clientSslConnectionInit( cfg, ctx, ssl);
	
	showPeer(ssl);

#ifdef HAVE_SECURE_RENEGOTIATION
	if (cfg->scr && cfg->forceScr)
	{
		if (cfg->nonBlocking)
		{
			printf("not doing secure renegotiation on example with nonblocking yet");
		}
		else
		{
			if (wolfSSL_Rehandshake(ssl) != SSL_SUCCESS)
			{
				int  err = wolfSSL_get_error(ssl, 0);
				char buffer[WOLFSSL_MAX_ERROR_SZ];
				printf("err = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
				err_sys("wolfSSL_Rehandshake failed");
			}
		}
	}
#endif /* HAVE_SECURE_RENEGOTIATION */

	clientSslConnectionRw( cfg, ssl);

#ifndef NO_SESSION_CACHE
	if (cfg->resumeSession) {
		session   = wolfSSL_get_session(ssl);
		sslResume = wolfSSL_new(ctx);
	}
#endif

	clientSslConnectionShutdown( cfg, ssl);


	clientSslConnectionResume( cfg, sslResume, session);

	wolfSSL_CTX_free(ctx);

	((func_args*)args)->return_code = 0;

#ifdef USE_WOLFSSL_MEMORY
	if (cfg->trackMemory)
		ShowMemoryTracker();
#endif /* USE_WOLFSSL_MEMORY */

#if !defined(WOLFSSL_TIRTOS)
	return 0;
#endif
}



/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

#ifdef HAVE_CAVIUM
        int ret = OpenNitroxDevice(CAVIUM_DIRECT, CAVIUM_DEV_ID);
        if (ret != 0)
            err_sys("Cavium OpenNitroxDevice failed");
#endif /* HAVE_CAVIUM */

        StartTCP();

        args.argc = argc;
        args.argv = argv;

#if defined(DEBUG_WOLFSSL) && !defined(WOLFSSL_MDK_SHELL) && !defined(STACK_TRAP)
        wolfSSL_Debugging_ON();
#endif
        if (CurrentDir("_build"))
            ChangeDirBack(1);
        else if (CurrentDir("client"))
            ChangeDirBack(2);
        else if (CurrentDir("Debug") || CurrentDir("Release"))
            ChangeDirBack(3);
  
#ifdef HAVE_STACK_SIZE
        StackSizeCheck(&args, client_test);
#else 
        clientTest(&args);
#endif

        wolfSSL_Cleanup();

#ifdef HAVE_CAVIUM
        CspShutdown(CAVIUM_DEV_ID);
#endif
        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */

