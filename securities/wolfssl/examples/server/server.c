/* server.c
 */

#include <libTest.h>

#ifdef WOLFSSL_CALLBACKS
Timeval srvTo;

int srvHandShakeCB(HandShakeInfo* info)
{
	(void)info;
	return 0;
}


int srvTimeoutCB(TimeoutInfo* info)
{
	(void)info;
	return 0;
}
#endif

#ifndef NO_HANDSHAKE_DONE_CB
int myHsDoneCb(WOLFSSL* ssl, void* user_ctx)
{
	(void)user_ctx;
	(void)ssl;

	printf("Notified HandShake done\n");

	/* return negative number to end TLS connection now */
	return 0;
}
#endif

typedef	struct 
{
	int			idx;
	int			version;
	int			doCliCertCheck;
	int			useAnyAddr;
	word16		port;
	int			usePsk;
	int			useAnon;
	int			doDTLS;
	int			needDH;
	int			useNtruKey;
	int			nonBlocking;
	int			trackMemory;
	int			fewerPackets;
	int			pkCallbacks;
	int			serverReadyFile;
	int			wc_shutdown;
	int			resume;
	int			minDhKeyBits;
	int			ret;
	
	char			*cipherList;
	const char	*verifyCert;
	
	const char	*ourCert;
	const char	*ourKey;
	const char	*ourDhParam;

#ifdef HAVE_SNI
	char			*sniHostName;
#endif

#ifdef HAVE_OCSP
	int			useOcsp;
	char			*ocspUrl;
#endif
}SERVER_CONFIG;


static void Usage(void)
{
	printf("server "    LIBWOLFSSL_VERSION_STRING " NOTE: All files relative to wolfSSL home dir\n");
	printf("-?          Help, print this usage\n");
	printf("-p <num>    Port to listen on, not 0, default %d\n", wolfSSLPort);
	printf("-v <num>    SSL version [0-3], SSLv3(0) - TLS1.2(3)), default %d\n", SERVER_DEFAULT_VERSION);
	printf("-l <str>    Cipher list\n");
	printf("-c <file>   Certificate file,           default %s\n", svrCert);
	printf("-k <file>   Key file,                   default %s\n", svrKey);
	printf("-A <file>   Certificate Authority file, default %s\n", cliCert);
#ifndef NO_DH
	printf("-D <file>   Diffie-Hellman Params file, default %s\n", dhParam);
	printf("-Z <num>    Minimum DH key bits,        default %d\n", DEFAULT_MIN_DHKEY_BITS);
#endif
	printf("-d          Disable client cert check\n");
	printf("-b          Bind to any interface instead of localhost only\n");
	printf("-s          Use pre Shared keys\n");
	printf("-t          Track wolfSSL memory use\n");
	printf("-u          Use UDP DTLS,"	" add -v 2 for DTLSv1 (default), -v 3 for DTLSv1.2\n");
	printf("-f          Fewer packets/group messages\n");
	printf("-R          Create server ready file, for external monitor\n");
	printf("-r          Allow one client Resumption\n");
	printf("-N          Use Non-blocking sockets\n");
	printf("-S <str>    Use Host Name Indication\n");
	printf("-w          Wait for bidirectional shutdown\n");
#ifdef HAVE_OCSP
	printf("-o          Perform OCSP lookup on peer certificate\n");
	printf("-O <url>    Perform OCSP lookup using <url> as responder\n");
#endif
#ifdef HAVE_PK_CALLBACKS 
	printf("-P          Public Key Callbacks\n");
#endif
#ifdef HAVE_ANON
	printf("-a          Anonymous server\n");
#endif
}


WOLFSSL_CTX *serverConfiguration(SERVER_CONFIG *cfg, func_args *args)
{
	int    argc = ((func_args*)args)->argc;
	char** argv = ((func_args*)args)->argv;
	int    ch;
	WOLFSSL_METHOD* method = 0;
	WOLFSSL_CTX*    ctx    = 0;

	XMEMSET(cfg, 0, sizeof(SERVER_CONFIG));
	
	cfg->version = SERVER_DEFAULT_VERSION;
	cfg->doCliCertCheck = 1;
	cfg->port = wolfSSLPort;
	cfg->minDhKeyBits = DEFAULT_MIN_DHKEY_BITS;

	cfg->verifyCert = cliCert;
	cfg->ourCert    = svrCert;
	cfg->ourKey     = svrKey;
	cfg->ourDhParam = dhParam;
	


#ifdef NO_RSA
	cfg->verifyCert = (char*)cliEccCert;
	cfg->ourCert    = (char*)eccCert;
	cfg->ourKey     = (char*)eccKey;
#endif
	while ((ch = mygetopt(argc, argv, "?dbstnNufrRawPp:v:l:A:c:k:Z:S:oO:D:")) != -1)
	{
		switch (ch)
		{
			case '?' :
				Usage();
				exit(EXIT_SUCCESS);

			case 'd' :
				cfg->doCliCertCheck = 0;
				break;

			case 'b' :
				cfg->useAnyAddr = 1;
				break;

			case 's' :
				cfg->usePsk = 1;
				break;

			case 't' :
#ifdef USE_WOLFSSL_MEMORY
				cfg->trackMemory = 1;
#endif
				break;

			case 'n' :
				cfg->useNtruKey = 1;
				break;

			case 'u' :
				cfg->doDTLS  = 1;
				break;

			case 'f' :
				cfg->fewerPackets = 1;
				break;

			case 'R' :
				cfg->serverReadyFile = 1;
				break;

			case 'r' :
#ifndef NO_SESSION_CACHE
				cfg->resume = 1;
#endif
				break;

			case 'P' :
#ifdef HAVE_PK_CALLBACKS 
				cfg->pkCallbacks = 1;
#endif
				break;

			case 'p' :
				cfg->port = (word16)atoi(myoptarg);
#if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
				if (cfg->port == 0)
				    err_sys("port number cannot be 0");
#endif
				break;

			case 'w' :
				cfg->wc_shutdown = 1;
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

			case 'D' :
#ifndef NO_DH
				cfg->ourDhParam = myoptarg;
#endif
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

			case 'N':
				cfg->nonBlocking = 1;
				break;

			case 'S' :
#ifdef HAVE_SNI
				cfg->sniHostName = myoptarg;
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
	if (cfg->version == CLIENT_INVALID_VERSION)
	{
		if (cfg->doDTLS)
			cfg->version = CLIENT_DTLS_DEFAULT_VERSION;
		else
			cfg->version = CLIENT_DEFAULT_VERSION;
	}
	else
	{
		if (cfg->doDTLS)
		{
			if (cfg->version == 3)
				cfg->version = -2;
			else
				cfg->version = -1;
		}
	}

#ifdef USE_WOLFSSL_MEMORY
	if (cfg->trackMemory)
		InitMemoryTracker(); 
#endif

	switch (cfg->version)
	{
#ifndef NO_OLD_TLS
		case 0:
		method = wolfSSLv3_server_method();
		break;

#ifndef NO_TLS
		case 1:
		method = wolfTLSv1_server_method();
		break;


		case 2:
		method = wolfTLSv1_1_server_method();
		break;

#endif
#endif

#ifndef NO_TLS
		case 3:
		method = wolfTLSv1_2_server_method();
		break;
#endif

#ifdef WOLFSSL_DTLS
#ifndef NO_OLD_TLS
		case -1:
		method = wolfDTLSv1_server_method();
		break;
#endif

		case -2:
		method = wolfDTLSv1_2_server_method();
		break;
#endif

		default:
		err_sys("Bad SSL version");
	}

	if (method == NULL)
		err_sys("unable to get method");


	ctx = wolfSSL_CTX_new( method);
	if (ctx == NULL)
		err_sys("unable to get ctx");
	
	return 0;
}


static void NonBlockingSSL_Accept(WOLFSSL *ssl)
{
#ifndef WOLFSSL_CALLBACKS
	int ret = wolfSSL_accept(ssl);
#else
	int ret = wolfSSL_accept_ex(ssl, srvHandShakeCB, srvTimeoutCB, srvTo);
#endif
	int error = wolfSSL_get_error(ssl, 0);
	SOCKET_T sockfd = (SOCKET_T)wolfSSL_get_fd(ssl);
	int select_ret;

	while (ret != SSL_SUCCESS && (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE))
	{
		int currTimeout = 1;

		if (error == SSL_ERROR_WANT_READ)
			printf("... server would read block\n");
		else
			printf("... server would write block\n");

#ifdef WOLFSSL_DTLS
		currTimeout = wolfSSL_dtls_get_current_timeout(ssl);
#endif
		select_ret = tcp_select(sockfd, currTimeout);

		if ((select_ret == TEST_RECV_READY) || (select_ret == TEST_ERROR_READY))
		{
#ifndef WOLFSSL_CALLBACKS
			ret = wolfSSL_accept(ssl);
#else
			ret = wolfSSL_accept_ex(ssl, srvHandShakeCB, srvTimeoutCB, srvTo);
#endif
			error = wolfSSL_get_error(ssl, 0);
		}
		else if (select_ret == TEST_TIMEOUT && !wolfSSL_dtls(ssl)) {
			error = SSL_ERROR_WANT_READ;
		}
#ifdef CYASSL_DTLS
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
		err_sys("SSL_accept failed");
}


THREAD_RETURN WOLFSSL_THREAD server_test(void* args)
{
	SOCKET_T sockfd   = 0;
	SOCKET_T clientfd = 0;
	char   msg[] = "I hear you fa shizzle!";
	char   input[80];


	SERVER_CONFIG _cfg, *cfg;
	WOLFSSL_CTX 	*ctx;
	WOLFSSL			*ssl;

	cfg = &_cfg;

	((func_args*)args)->return_code = -1; /* error state */

	ctx = serverConfiguration(cfg, args);

#ifdef CYASSL_TIRTOS
	fdOpenSession(Task_self());
#endif

#if defined(HAVE_SESSION_TICKET) && defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
	if (TicketInit() != 0)
		err_sys("unable to setup Session Ticket Key context");
	wolfSSL_CTX_set_TicketEncCb(ctx, myTicketEncCb);
#endif

	if (cfg->cipherList)
	{
		DEBUG_MSG("Cipher List: %s\n", cfg->cipherList);
		if (wolfSSL_CTX_set_cipher_list( ctx,  cfg->cipherList) != SSL_SUCCESS)
			err_sys("server can't set cipher list 1");
	}

#ifdef WOLFSSL_LEANPSK
	cfg->usePsk = 1;
#endif

#if defined(NO_RSA) && !defined(HAVE_ECC)
	cfg->usePsk = 1;
#endif

	if (cfg->fewerPackets)
		wolfSSL_CTX_set_group_messages(ctx);

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
	wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
	if (!cfg->usePsk && !cfg->useAnon)
	{
		if(wolfSSL_CTX_use_certificate_file(ctx, cfg->ourCert, SSL_FILETYPE_PEM) != SSL_SUCCESS)
			err_sys("can't load server cert file, check file and run from wolfSSL home dir");
	}
#endif

#ifndef NO_DH
	wolfSSL_CTX_SetMinDhKey_Sz(ctx, (word16)cfg->minDhKeyBits);
#endif

#ifdef HAVE_NTRU
	if (cfg->useNtruKey)
	{
		if (wolfSSL_CTX_use_NTRUPrivateKey_file(ctx, cfg->ourKey) != SSL_SUCCESS)
			err_sys("can't load ntru key file, Please run from wolfSSL home dir");
	}
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
	if (!cfg->useNtruKey && !cfg->usePsk && !cfg->useAnon)
	{
		DEBUG_MSG("Load server private key: %s\n", cfg->ourKey);
		if (wolfSSL_CTX_use_PrivateKey_file(ctx, cfg->ourKey, SSL_FILETYPE_PEM) != SSL_SUCCESS)
			err_sys("can't load server private key file, check file and run from wolfSSL home dir");
	}
#endif

	if (cfg->usePsk) {
#ifndef NO_PSK
		wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
		wolfSSL_CTX_use_psk_identity_hint(ctx, "cyassl server");
		
		if (cfg->cipherList == NULL)
		{
			const char *defaultCipherList;
#if defined(HAVE_AESGCM) && !defined(NO_DH)
			defaultCipherList = "DHE-PSK-AES128-GCM-SHA256";
			cfg->needDH = 1;
#elif defined(HAVE_NULL_CIPHER)
			defaultCipherList = "PSK-NULL-SHA256";
#else
			defaultCipherList = "PSK-AES128-CBC-SHA256";
#endif
			if (wolfSSL_CTX_set_cipher_list(ctx, defaultCipherList) != SSL_SUCCESS)
				err_sys("server can't set cipher list 2");
		}
#endif
	}

	if (cfg->useAnon) {
#ifdef HAVE_ANON
		wolfSSL_CTX_allow_anon_cipher(ctx);
		if (cfg->cipherList == NULL)
		{
			if (wolfSSL_CTX_set_cipher_list(ctx, "ADH-AES128-SHA") != SSL_SUCCESS)
				err_sys("server can't set cipher list 4");
		}
#endif
	}

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
	/* if not using PSK, verify peer with certs */
	if (cfg->doCliCertCheck && cfg->usePsk == 0 && cfg->useAnon == 0)
	{
		DEBUG_MSG("Load CA file: %s\n", cfg->verifyCert);
		
		wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |SSL_VERIFY_FAIL_IF_NO_PEER_CERT,0);
		if (wolfSSL_CTX_load_verify_locations(ctx, cfg->verifyCert, 0) != SSL_SUCCESS)
			err_sys("can't load ca file, Please run from wolfSSL home dir");
	}
#endif

#if defined(WOLFSSL_SNIFFER)
	/* don't use EDH, can't sniff tmp keys */
	if (cfg->cipherList == NULL)
	{
		DEBUG_MSG("set cipher list: %s\n", "AES256-SHA256");
		if (wolfSSL_CTX_set_cipher_list(ctx, "AES256-SHA256") != SSL_SUCCESS)
			err_sys("server can't set cipher list 3");
	}
#endif

#ifdef HAVE_SNI
	if (cfg->sniHostName)
	if (wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, cfg->sniHostName, XSTRLEN(cfg->sniHostName)) != SSL_SUCCESS)
		err_sys("UseSNI failed");
#endif

	while (1)
	{  /* allow resume option */
		if (cfg->resume > 1)
		{  /* already did listen, just do accept */
			if (cfg->doDTLS == 0)
			{
				SOCKADDR_IN_T client;
				socklen_t client_len = sizeof(client);
				clientfd = accept(sockfd, (struct sockaddr*)&client, (ACCEPT_THIRD_T)&client_len);
			}
			else
			{
				tcp_listen(&sockfd, &cfg->port, cfg->useAnyAddr, cfg->doDTLS);
				clientfd = udp_read_connect(sockfd);
			}
#ifdef USE_WINDOWS_API
			if (clientfd == INVALID_SOCKET)
				err_sys("tcp accept failed");
#else
			if (clientfd == -1)
				err_sys("tcp accept failed");
#endif
		}
		
		DEBUG_MSG("Receive new connection\n");

		ssl = wolfSSL_new(ctx);
		if (ssl == NULL)
			err_sys("unable to get SSL");

#ifndef NO_HANDSHAKE_DONE_CB
		wolfSSL_SetHsDoneCb(ssl, myHsDoneCb, NULL);
#endif

#ifdef HAVE_CRL
		wolfSSL_EnableCRL(ssl, 0);
		wolfSSL_LoadCRL(ssl, crlPemDir, SSL_FILETYPE_PEM, WOLFSSL_CRL_MONITOR | WOLFSSL_CRL_START_MON);
		wolfSSL_SetCRL_Cb(ssl, CRL_CallBack);
#endif

#ifdef HAVE_OCSP
		if (cfg->useOcsp)
		{
			if (cfg->ocspUrl != NULL)
			{
				wolfSSL_CTX_SetOCSP_OverrideURL(ctx, cfg->ocspUrl);
				wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_NO_NONCE | WOLFSSL_OCSP_URL_OVERRIDE);
			}
			else
				wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_NO_NONCE);
		}
#endif

#ifdef HAVE_PK_CALLBACKS
		if (cfg->pkCallbacks)
			SetupPkCallbacks(ctx, ssl);
#endif

		if (cfg->resume < 2) {  /* do listen and accept : ????? */
			tcp_accept(&sockfd, &clientfd, (func_args*)args, cfg->port, cfg->useAnyAddr, cfg->doDTLS, cfg->serverReadyFile);
		}

		wolfSSL_set_fd(ssl, clientfd);
		if (cfg->usePsk == 0 || cfg->useAnon == 1 || cfg->cipherList != NULL || cfg->needDH == 1)
		{
#if !defined(NO_FILESYSTEM) && !defined(NO_DH) && !defined(NO_ASN)
			wolfSSL_SetTmpDH_file(ssl, cfg->ourDhParam, SSL_FILETYPE_PEM);
#elif !defined(NO_DH)
			SetDH(ssl);  /* repick suites with DHE, higher priority than PSK */
#endif
		}

#ifndef WOLFSSL_CALLBACKS
		if (cfg->nonBlocking)
		{
			wolfSSL_set_using_nonblock(ssl, 1);
			tcp_set_nonblocking(&clientfd);
			NonBlockingSSL_Accept(ssl);
		}
		else if (wolfSSL_accept(ssl) != SSL_SUCCESS)
		{
			char buffer[WOLFSSL_MAX_ERROR_SZ];
			
			int err = wolfSSL_get_error(ssl, 0);
			printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
			err_sys("SSL_accept failed");
		}
#else
		NonBlockingSSL_Accept(ssl);
#endif
		showPeer(ssl);

		cfg->idx = wolfSSL_read(ssl, input, sizeof(input)-1);
		if (cfg->idx > 0) {
			input[cfg->idx] = 0;
			printf("Client message: %s\n", input);
		}
		else if (cfg->idx < 0) {
			int readErr = wolfSSL_get_error(ssl, 0);
			if (readErr != SSL_ERROR_WANT_READ)
				err_sys("SSL_read failed");
		}

		if (wolfSSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
			err_sys("SSL_write failed");

#if defined(WOLFSSL_MDK_SHELL) && defined(HAVE_MDK_RTX)
		os_dly_wait(500) ;
#elif defined (WOLFSSL_TIRTOS)
		Task_yield();
#endif

		if (cfg->doDTLS == 0)
		{
			cfg->ret = wolfSSL_shutdown(ssl);
			if (cfg->wc_shutdown && cfg->ret == SSL_SHUTDOWN_NOT_DONE)
				wolfSSL_shutdown(ssl);    /* bidirectional shutdown */
		}
		
		wolfSSL_Free(ssl);
		if (cfg->resume == 1) {
			CloseSocket(clientfd);
			cfg->resume++;           /* only do one resume for testing */
			continue;
		}
		break;  /* out of while loop, done with normal and resume option */
	}
	
	wolfSSL_CTX_free(ctx);

	CloseSocket(clientfd);
	CloseSocket(sockfd);
	((func_args*)args)->return_code = 0;


#if defined(NO_MAIN_DRIVER) && defined(HAVE_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
	wc_ecc_fp_free();  /* free per thread cache */
#endif

#ifdef USE_WOLFSSL_MEMORY
	if (cfg->trackMemory)
		ShowMemoryTracker();
#endif

#ifdef WOLFSSL_TIRTOS
	fdCloseSession(Task_self());
#endif

#if defined(HAVE_SESSION_TICKET) && defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
	TicketCleanup();
#endif

#ifndef WOLFSSL_TIRTOS
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

	wolfSSL_Init();
#if defined(DEBUG_CYASSL) && !defined(WOLFSSL_MDK_SHELL)
	wolfSSL_Debugging_ON();
#endif
	if (CurrentDir("_build"))
		ChangeDirBack(1);
	else if (CurrentDir("server"))
		ChangeDirBack(2);
	else if (CurrentDir("Debug") || CurrentDir("Release"))
		ChangeDirBack(3);

#ifdef HAVE_STACK_SIZE
	StackSizeCheck(&args, server_test);
#else 
	server_test(&args);
#endif

	wolfSSL_Cleanup();

#ifdef HAVE_CAVIUM
	CspShutdown(CAVIUM_DEV_ID);
#endif
	return args.return_code;
}

#endif /* NO_MAIN_DRIVER */


