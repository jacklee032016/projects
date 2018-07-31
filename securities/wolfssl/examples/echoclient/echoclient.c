/* echoclient.c
 */

#include <libTest.h>

void echoclient_test(void* args)
{
	SOCKET_T sockfd = 0;

	FILE* fin   = stdin  ;
	FILE* fout = stdout;

	int inCreated  = 0;
	int outCreated = 0;

	char msg[1024];
	char reply[1024+1];

	WOLFSSL_METHOD* method = 0;
	WOLFSSL_CTX*    ctx    = 0;
	WOLFSSL*        ssl    = 0;

	int doDTLS = 0;
	int doPSK = 0;
	int sendSz;
	int argc    = 0;
	char** argv = 0;
	word16 port = wolfSSLPort;

	((func_args*)args)->return_code = -1; /* error state */

#ifndef WOLFSSL_MDK_SHELL
	argc = ((func_args*)args)->argc;
	argv = ((func_args*)args)->argv;
#endif

	if (argc >= 2) {
		fin  = fopen(argv[1], "r"); 
		inCreated = 1;
	}
	if (argc >= 3) {
		fout = fopen(argv[2], "w");
		outCreated = 1;
	}

	if (!fin)  err_sys("can't open input file");
	if (!fout) err_sys("can't open output file");

#ifdef WOLFSSL_DTLS
	doDTLS  = 1;
#endif

#ifdef WOLFSSL_LEANPSK 
	doPSK = 1;
#endif

#if defined(NO_RSA) && !defined(HAVE_ECC)
	doPSK = 1;
#endif

#if defined(NO_MAIN_DRIVER) && !defined(USE_WINDOWS_API) && !defined(WOLFSSL_MDK_SHELL)
	port = ((func_args*)args)->signal->port;
#endif

#if defined(WOLFSSL_DTLS)
	method  = DTLSv1_2_client_method();
#elif  !defined(NO_TLS)
	method = wolfSSLv23_client_method();
#else
	method = wolfSSLv3_client_method();
#endif
	ctx    = wolfSSL_CTX_new(method);

#ifndef NO_FILESYSTEM
#ifndef NO_RSA
	if (wolfSSL_CTX_load_verify_locations(ctx, caCert, 0) != SSL_SUCCESS)
		err_sys("can't load ca file, Please run from wolfSSL home dir");
#endif
#ifdef HAVE_ECC
	if (wolfSSL_CTX_load_verify_locations(ctx, eccCert, 0) != SSL_SUCCESS)
		err_sys("can't load ca file, Please run from wolfSSL home dir");
#endif
#elif !defined(NO_CERTS)
	if (!doPSK)
		load_buffer(ctx, caCert, CYASSL_CA);
#endif

#if defined(CYASSL_SNIFFER)
	/* don't use EDH, can't sniff tmp keys */
	wolfSSL_CTX_set_cipher_list(ctx, "AES256-SHA");
#endif

	if (doPSK) {
#ifndef NO_PSK
		const char *defaultCipherList;

		wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
#ifdef HAVE_NULL_CIPHER
		defaultCipherList = "PSK-NULL-SHA256";
#else
		defaultCipherList = "PSK-AES128-CBC-SHA256";
#endif
		if (wolfSSL_CTX_set_cipher_list(ctx,defaultCipherList) !=SSL_SUCCESS)
			err_sys("client can't set cipher list 2");
#endif
	}

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
	wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

#if defined(CYASSL_MDK_ARM)
	wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
#endif

	ssl = wolfSSL_new(ctx);

	if (doDTLS) {
		SOCKADDR_IN_T addr;
		build_addr(&addr, wolfSSLIP, port, 1);
		wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr));
		tcp_socket(&sockfd, 1);
	}
	else {
		tcp_connect(&sockfd, wolfSSLIP, port, 0);
	}

	wolfSSL_set_fd(ssl, sockfd);
#if defined(USE_WINDOWS_API) && defined(CYASSL_DTLS) && defined(NO_MAIN_DRIVER)
	/* let echoserver bind first, TODO: add Windows signal like pthreads does */
	Sleep(100);
#endif

	if (wolfSSL_connect(ssl) != SSL_SUCCESS) err_sys("SSL_connect failed");

	while (fgets(msg, sizeof(msg), fin) != 0)
	{
		sendSz = (int)strlen(msg);

		if (wolfSSL_write(ssl, msg, sendSz) != sendSz)
			err_sys("SSL_write failed");

		if (strncmp(msg, "quit", 4) == 0) {
			fputs("sending server shutdown command: quit!\n", fout);
			break;
		}

		if (strncmp(msg, "break", 5) == 0) {
			fputs("sending server session close: break!\n", fout);
			break;
		}

#ifndef WOLFSSL_MDK_SHELL
		while (sendSz)
		{
			int got;
			if ( (got =wolfSSL_read(ssl, reply, sizeof(reply)-1)) > 0)
			{
				reply[got] = 0;
				fputs(reply, fout);
				fflush(fout) ;
				sendSz -= got;
			}
			else
				break;
		}
#else
		{
			int got;
			if ( (got = wolfSSL_read(ssl, reply, sizeof(reply)-1)) > 0)
			{
				reply[got] = 0;
				fputs(reply, fout);
				fflush(fout) ;
				sendSz -= got;
			}
		}
#endif
	}


#ifdef WOLFSSL_DTLS
	strncpy(msg, "break", 6);
	sendSz = (int)strlen(msg);
	/* try to tell server done */
	wolfSSL_write(ssl, msg, sendSz);
#else
	wolfSSL_shutdown(ssl);
#endif

	wolfSSL_free(ssl);
	wolfSSL_CTX_free(ctx);

	fflush(fout);
	if (inCreated)  fclose(fin);
	if (outCreated) fclose(fout);

	CloseSocket(sockfd);
	((func_args*)args)->return_code = 0; 
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
	wolfSSL_Debugging_ON();
#if defined(DEBUG_WOLFSSL) && !defined(WOLFSSL_MDK_SHELL)
	wolfSSL_Debugging_ON();
#endif

#ifndef WOLFSSL_TIRTOS
	if (CurrentDir("echoclient"))
		ChangeDirBack(2);
	else if (CurrentDir("Debug") || CurrentDir("Release"))
		ChangeDirBack(3);
#endif
	echoclient_test(&args);

	wolfSSL_Cleanup();

#ifdef HAVE_CAVIUM
	CspShutdown(CAVIUM_DEV_ID);
#endif
	return args.return_code;
}
        
#endif /* NO_MAIN_DRIVER */


