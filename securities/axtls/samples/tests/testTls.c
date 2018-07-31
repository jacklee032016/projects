
#include "ecp.h"

static void clientBasicTest(int svrPort)
{
	int client_fd;
	SSL *ssl = NULL;
	uint8_t buf[16*1024]={"GET / HTTP/1.1\r\n\r\n"};
	unsigned char *readData= NULL;
	SSL_CTX *ctx;
	int ret = 0;


	TRACE();
	ctx = ssl_ctx_new(SSL_DISPLAY_ALL, SSL_DEFAULT_CLNT_SESS);
	if(! ctx)
	{
		return;
	}
	TRACE();
	
	if (ssl_obj_load(ctx, SSL_OBJ_X509_CACERT, CERT_HOME_DIR"ecpCA.1024.x509.pem", NULL))
	{
		AX_LOG("Load CA cert failed");
		goto error;
	}

	if ((client_fd = client_socket_init("127.0.0.1", svrPort)) < 0)
	{
		AX_LOG("socket failed\n");
		goto error;
	}

	AX_LOG("Socket is %d\n", client_fd);
	ssl = ssl_client_new(ctx, client_fd, NULL, 0);
	if(!ssl)
	{
		AX_LOG("SSL init failed\n");
		goto error;
	}

	AX_LOG("SSL initialized successfully!\n");
	/* check the return status */
	if (ssl_handshake_status(ssl) < 0)
	{
		ssl_display_error(ssl_handshake_status(ssl));
		goto error;
	}

	ret = ssl_write(ssl, buf, strlen(buf));
	if(ret!= strlen(buf))
	{
		AX_LOG("Write error: %d bytes wroten\n", ret);
		ssl_display_error(ret);
		goto error;
	}

	AX_LOG("SSL write \"%s\" OK!\n", buf);
	AX_LOG("SSL read.....\n");
	while ((ret = ssl_read(ssl, &readData)) == SSL_OK);
	if (ret > SSL_OK)
	{
		memcpy(buf, readData, ret > sizeof(buf)? sizeof(buf): ret);
	}
	AX_LOG("SSL read \"%s\" OK!\n", buf);

#if 0
	ret = ssl_read(ssl, &readData);
	if(ret< 0)
	{
		ssl_display_error(ret);
		goto error;
	}
	
	if(ret == SSL_OK)
	{
		AX_LOG("TEST Client: the handshaking stage is successful (but not yet complete)\n");
		ret = ssl_read(ssl, &readData);
		if(ret< 0)
		{
			ssl_display_error(ret);
			goto error;
		}
	}
	
	if(readData)
		AX_LOG("read data:\"%s\"\n", readData);
#endif

error:
	if(ssl)
	{
		ssl_free(ssl);
	}
	
	ssl_ctx_free(ctx);
	SOCKET_CLOSE(client_fd);

	/* exit this thread */
}

#if 0
static int special_read(struct connstruct *cn, void *buf, size_t count)
{
	int res;

	if (cn->is_ssl)
	{
		uint8_t *read_buf;
		if ((res = ssl_read(cn->ssl, &read_buf)) > SSL_OK)
		{
			memcpy(buf, read_buf, res > (int)count ? count : res);
		}
	}
	else
		res = SOCKET_READ(cn->networkdesc, buf, count);

	return res;
}
#endif


static int serverBasicTest(int port, const char *cert, const char *private_key, const char *ca_cert, const char *passwd)
{
	int server_fd, ret = 0;
	SSL_CTX *ssl_ctx = NULL;
	struct sockaddr_in client_addr;
	uint8_t *read_buf;
	socklen_t clnt_len = sizeof(client_addr);
	int axtls_option = SSL_DISPLAY_ALL;

	if (private_key)
	{
		axtls_option |= SSL_NO_DEFAULT_KEY;
	}

	if ((server_fd = server_socket_init(port)) < 0)
	{
		goto error;
	}

	if ((ssl_ctx = ssl_ctx_new(axtls_option, SSL_DEFAULT_SVR_SESS)) == NULL)
	{
		ret = SSL_ERROR_INVALID_KEY;
		goto error;
	}

	if (private_key)
	{
		int obj_type = SSL_OBJ_RSA_KEY;

		if (strstr(private_key, ".p8"))
			obj_type = SSL_OBJ_PKCS8;
		else if (strstr(private_key, ".p12"))
			obj_type = SSL_OBJ_PKCS12;

		if (ssl_obj_load(ssl_ctx, obj_type, private_key, passwd))
		{
			ret = SSL_ERROR_INVALID_KEY;
			goto error;
		}
	}

	if (cert)/* test chaining */
	{
		if ((ret = ssl_obj_load(ssl_ctx, SSL_OBJ_X509_CERT, cert, NULL)) != SSL_OK)
			goto error;
	}

	if (ca_cert)/* test adding certificate authorities */
	{
		if ((ret = ssl_obj_load(ssl_ctx, SSL_OBJ_X509_CACERT, ca_cert, NULL)) != SSL_OK)
			goto error;
	}

	for (;;)
	{
		int client_fd, size = 0; 
		SSL *ssl;

		/* Wait for a client to connect */
		if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &clnt_len)) < 0)
		{
			ret = SSL_ERROR_SOCK_SETUP_FAILURE;
			goto error;
		}

		/* we are ready to go */
		ssl = ssl_server_new(ssl_ctx, client_fd);
		while ((size = ssl_read(ssl, &read_buf)) == SSL_OK);

		if (size == SSL_CLOSE_NOTIFY)
		{
			/* do nothing */ 
		}
		else if (size < SSL_OK) /* got some alert or something nasty */
		{
			ret = size;

			if (ret == SSL_ERROR_CONN_LOST)
				continue;

			break;  /* we've got a problem */
		}
		else /* looks more promising */
		{
			char buf[1024] = "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY BGCOLOR=\"#ffffff\">"
				"Simple SSL Server(Zhijie Li, Nov.21,2015</BODY></HTML>)";
			
			printf("SSL server read \"%s\" passed\n",(char *)read_buf );
			TTY_FLUSH();

			
			ret = ssl_write(ssl, buf, strlen(buf));
			AX_LOG("Write : %d bytes wroten\n", ret);
			if(ret!= strlen(buf))
			{
				ssl_display_error(ret);
				goto error;
			}
			break;
		}

		ssl_free(ssl);
	}

	SOCKET_CLOSE(server_fd);

error:
	if(ssl_ctx)
	{
		TRACE();
		ssl_ctx_free(ssl_ctx);
	}
	
	return ret;
}


int main(int argc, char *argv[])
{
	int ret = 1;
	int fd;

#ifdef WIN32
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSAStartup(wVersionRequested, &wsaData);
	fd = _open("test_result.txt", O_WRONLY|O_TEMPORARY|O_CREAT, _S_IWRITE);
#else
	fd = open("/dev/null", O_WRONLY);   /* write stderr to /dev/null */
	signal(SIGPIPE, SIG_IGN);           /* ignore pipe errors */
#endif
//	dup2(fd, 2);

	if(argc == 1)
		clientBasicTest(SSL_PORT_HTTP);
	else
	{
//		serverBasicTest(SSL_PORT_HTTP, CERT_HOME_DIR"ecpServer.1024.x509.pem", 
//			CERT_HOME_DIR"ecpServer.1024.key.pem", CERT_HOME_DIR"ecpCa.1024.x509.pem", NULL);
		serverBasicTest(SSL_PORT_HTTP, NULL,NULL, CERT_HOME_DIR"ecpCa.1024.x509.pem", NULL);

	}
	return 0;
}

