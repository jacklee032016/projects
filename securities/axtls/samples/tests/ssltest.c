
#include "ecp.h"

int	g_port =19001;

/**************************************************************************
 * SSL Basic Testing (test a big packet handshake)
 **************************************************************************/
static uint8_t basic_buf[256*1024];

static void do_basic(void)
{
    int client_fd;
    SSL *ssl_clnt;
    SSL_CTX *ssl_clnt_ctx = ssl_ctx_new(DEFAULT_CLNT_OPTION, SSL_DEFAULT_CLNT_SESS);
    usleep(200000);           /* allow server to start */

    if ((client_fd = client_socket_init(g_port)) < 0)
        goto error;

    if (ssl_obj_load(ssl_clnt_ctx, SSL_OBJ_X509_CACERT, CERT_HOME_DIR"axTLS.ca_x509.cer", NULL))
        goto error;

    ssl_clnt = ssl_client_new(ssl_clnt_ctx, client_fd, NULL, 0);

    /* check the return status */
    if (ssl_handshake_status(ssl_clnt) < 0)
    {
        ssl_display_error(ssl_handshake_status(ssl_clnt));
        goto error;
    }

    ssl_write(ssl_clnt, basic_buf, sizeof(basic_buf));
    ssl_free(ssl_clnt);

error:
    ssl_ctx_free(ssl_clnt_ctx);
    SOCKET_CLOSE(client_fd);

    /* exit this thread */
}

static int SSL_basic_test(void)
{
	int server_fd, client_fd, ret = 0, size = 0, offset = 0;
	SSL_CTX *ssl_svr_ctx = NULL;
	struct sockaddr_in client_addr;
	uint8_t *read_buf;
	socklen_t clnt_len = sizeof(client_addr);
	SSL *ssl_svr;
#ifndef WIN32
	pthread_t thread;
#endif
	memset(basic_buf, 0xA5, sizeof(basic_buf)/2);
	memset(&basic_buf[sizeof(basic_buf)/2], 0x5A, sizeof(basic_buf)/2);

	if ((server_fd = server_socket_init(g_port)) < 0)
		goto error;

	ssl_svr_ctx = ssl_ctx_new(DEFAULT_SVR_OPTION, SSL_DEFAULT_SVR_SESS);

#ifndef WIN32
	pthread_create(&thread, NULL, (void *(*)(void *))do_basic, NULL);
	pthread_detach(thread);
#else
	CreateThread(NULL, 1024, (LPTHREAD_START_ROUTINE)do_basic, NULL, 0, NULL);
#endif

    /* Wait for a client to connect */
	if ((client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &clnt_len)) < 0)
	{
		ret = SSL_ERROR_SOCK_SETUP_FAILURE;
		goto error;
	}

	/* we are ready to go */
	ssl_svr = ssl_server_new(ssl_svr_ctx, client_fd);
    
	do
	{
		while ((size = ssl_read(ssl_svr, &read_buf)) == SSL_OK);

		if (size < SSL_OK) /* got some alert or something nasty */
		{
			ssl_display_error(size);
			ret = size;
			break;
		}
		else /* looks more promising */
		{
			if (memcmp(read_buf, &basic_buf[offset], size) != 0)
			{
				ret = SSL_NOT_OK;
				break;
			}
		}

		offset += size;
	} while (offset < sizeof(basic_buf));

	printf(ret == SSL_OK && offset == sizeof(basic_buf) ? "SSL basic test passed\n" :"SSL basic test failed\n");
	TTY_FLUSH();

	ssl_free(ssl_svr);
	SOCKET_CLOSE(server_fd);
	SOCKET_CLOSE(client_fd);

error:
	ssl_ctx_free(ssl_svr_ctx);
	return ret;
}

/*
 * SSL unblocked case
 */
static void do_unblocked(void)
{
    int client_fd;
    SSL *ssl_clnt;
    SSL_CTX *ssl_clnt_ctx = ssl_ctx_new(DEFAULT_CLNT_OPTION,SSL_DEFAULT_CLNT_SESS |SSL_CONNECT_IN_PARTS);
    usleep(200000);           /* allow server to start */

    if ((client_fd = client_socket_init(g_port)) < 0)
        goto error;

    {
#ifdef WIN32
        u_long argp = 1;
        ioctlsocket(client_fd, FIONBIO, &argp);
#else
        int flags = fcntl(client_fd, F_GETFL, NULL);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
#endif
    }

    if (ssl_obj_load(ssl_clnt_ctx, SSL_OBJ_X509_CACERT, 
                                        CERT_HOME_DIR"axTLS.ca_x509.cer", NULL))
        goto error;

    ssl_clnt = ssl_client_new(ssl_clnt_ctx, client_fd, NULL, 0);

    while (ssl_handshake_status(ssl_clnt) != SSL_OK)
    {
        if (ssl_read(ssl_clnt, NULL) < 0)
        {
            ssl_display_error(ssl_handshake_status(ssl_clnt));
            goto error;
        }
    }

    ssl_write(ssl_clnt, basic_buf, sizeof(basic_buf));
    ssl_free(ssl_clnt);

error:
    ssl_ctx_free(ssl_clnt_ctx);
    SOCKET_CLOSE(client_fd);

    /* exit this thread */
}

static int SSL_unblocked_test(void)
{
    int server_fd, client_fd, ret = 0, size = 0, offset = 0;
    SSL_CTX *ssl_svr_ctx = NULL;
    struct sockaddr_in client_addr;
    uint8_t *read_buf;
    socklen_t clnt_len = sizeof(client_addr);
    SSL *ssl_svr;
#ifndef WIN32
    pthread_t thread;
#endif
    memset(basic_buf, 0xA5, sizeof(basic_buf)/2);
    memset(&basic_buf[sizeof(basic_buf)/2], 0x5A, sizeof(basic_buf)/2);

    if ((server_fd = server_socket_init(g_port)) < 0)
        goto error;

    ssl_svr_ctx = ssl_ctx_new(DEFAULT_SVR_OPTION, SSL_DEFAULT_SVR_SESS);

#ifndef WIN32
    pthread_create(&thread, NULL,(void *(*)(void *))do_unblocked, NULL);
    pthread_detach(thread);
#else
    CreateThread(NULL, 1024, (LPTHREAD_START_ROUTINE)do_unblocked, NULL, 0, NULL);
#endif

    /* Wait for a client to connect */
    if ((client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &clnt_len)) < 0)
    {
        ret = SSL_ERROR_SOCK_SETUP_FAILURE;
        goto error;
    }
    
    /* we are ready to go */
    ssl_svr = ssl_server_new(ssl_svr_ctx, client_fd);
    
    do
    {
        while ((size = ssl_read(ssl_svr, &read_buf)) == SSL_OK);

        if (size < SSL_OK) /* got some alert or something nasty */
        {
            ssl_display_error(size);
            ret = size;
            break;
        }
        else /* looks more promising */
        {
            if (memcmp(read_buf, &basic_buf[offset], size) != 0)
            {
                ret = SSL_NOT_OK;
                break;
            }
        }

        offset += size;
    } while (offset < sizeof(basic_buf));

    printf(ret == SSL_OK && offset == sizeof(basic_buf) ? 
                            "SSL unblocked test passed\n" :
                            "SSL unblocked test failed\n");
    TTY_FLUSH();

    ssl_free(ssl_svr);
    SOCKET_CLOSE(server_fd);
    SOCKET_CLOSE(client_fd);

error:
    ssl_ctx_free(ssl_svr_ctx);
    return ret;
}

#if !defined(WIN32) && defined(CONFIG_SSL_CTX_MUTEXING)
/**************************************************************************
 * Multi-Threading Tests
 *
 **************************************************************************/
#define NUM_THREADS         100

typedef struct
{
    SSL_CTX *ssl_clnt_ctx;
    int port;
    int thread_id;
} multi_t;

void do_multi_clnt(multi_t *multi_data)
{
    int res = 1, client_fd, i;
    SSL *ssl = NULL;
    char tmp[5];

    if ((client_fd = client_socket_init(multi_data->port)) < 0)
        goto client_test_exit;

    usleep(200000);
    ssl = ssl_client_new(multi_data->ssl_clnt_ctx, client_fd, NULL, 0);

    if ((res = ssl_handshake_status(ssl)))
    {
        printf("Client ");
        ssl_display_error(res);
        goto client_test_exit;
    }

    sprintf(tmp, "%d\n", multi_data->thread_id);
    for (i = 0; i < 10; i++)
        ssl_write(ssl, (uint8_t *)tmp, strlen(tmp)+1);

client_test_exit:
    ssl_free(ssl);
    SOCKET_CLOSE(client_fd);
    free(multi_data);
}

void do_multi_svr(SSL *ssl)
{
    uint8_t *read_buf;
    int *res_ptr = malloc(sizeof(int));
    int res;

    for (;;)
    {
        res = ssl_read(ssl, &read_buf);

        /* kill the client */
        if (res != SSL_OK)
        {
            if (res == SSL_ERROR_CONN_LOST)
            {
                SOCKET_CLOSE(ssl->client_fd);
                ssl_free(ssl);
                break;
            }
            else if (res > 0)
            {
                /* do nothing */
            }
            else /* some problem */
            {
                printf("Server ");
                ssl_display_error(res);
                goto error;
            }
        }
    }

    res = SSL_OK;
error:
    *res_ptr = res;
    pthread_exit(res_ptr);
}

int multi_thread_test(void)
{
    int server_fd = -1;
    SSL_CTX *ssl_server_ctx;
    SSL_CTX *ssl_clnt_ctx;
    pthread_t clnt_threads[NUM_THREADS];
    pthread_t svr_threads[NUM_THREADS];
    int i, res = 0;
    struct sockaddr_in client_addr;
    socklen_t clnt_len = sizeof(client_addr);

    printf("Do multi-threading test (takes a minute)\n");

    ssl_server_ctx = ssl_ctx_new(DEFAULT_SVR_OPTION, SSL_DEFAULT_SVR_SESS);
    ssl_clnt_ctx = ssl_ctx_new(DEFAULT_CLNT_OPTION, SSL_DEFAULT_CLNT_SESS);

    if (ssl_obj_load(ssl_clnt_ctx, SSL_OBJ_X509_CACERT, 
                                        CERT_HOME_DIR"axTLS.ca_x509.cer", NULL))
        goto error;

    if ((server_fd = server_socket_init(g_port)) < 0)
        goto error;

    for (i = 0; i < NUM_THREADS; i++)
    {
        multi_t *multi_data = (multi_t *)malloc(sizeof(multi_t));
        multi_data->ssl_clnt_ctx = ssl_clnt_ctx;
        multi_data->port = g_port;
        multi_data->thread_id = i+1;
        pthread_create(&clnt_threads[i], NULL,  (void *(*)(void *))do_multi_clnt, (void *)multi_data);
        pthread_detach(clnt_threads[i]);
    }

    for (i = 0; i < NUM_THREADS; i++)
    { 
        SSL *ssl_svr;
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &clnt_len);

        if (client_fd < 0)
            goto error;

        ssl_svr = ssl_server_new(ssl_server_ctx, client_fd);

        pthread_create(&svr_threads[i], NULL, (void *(*)(void *))do_multi_svr, (void *)ssl_svr);
    }

    /* make sure we've run all of the threads */
    for (i = 0; i < NUM_THREADS; i++)
    {
        void *thread_res;
        pthread_join(svr_threads[i], &thread_res);

        if (*((int *)thread_res) != 0)
            res = 1;

        free(thread_res);
    } 

    if (res) 
        goto error;

    printf("Multi-thread test passed (%d)\n", NUM_THREADS);
error:
    ssl_ctx_free(ssl_server_ctx);
    ssl_ctx_free(ssl_clnt_ctx);
    SOCKET_CLOSE(server_fd);
    return res;
}
#endif /* !defined(WIN32) && defined(CONFIG_SSL_CTX_MUTEXING) */ 

/**************************************************************************
 * Header issue
 **************************************************************************/
#define	TEST_HEADER 0
#if TEST_HEADER 
static void do_header_issue(void)
{
    char axtls_buf[2048];
#ifndef WIN32
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
#endif
    sprintf(axtls_buf, "./axssl s_client -connect localhost:%d", g_port);
    SYSTEM(axtls_buf);
}


static int header_issue(void)
{
    FILE *f = fopen(CERT_HOME_DIR"header_issue.dat", "r");
    int server_fd = -1, client_fd = -1, ret = 1;
    uint8_t buf[2048];
    int size = 0;
    struct sockaddr_in client_addr;
    socklen_t clnt_len = sizeof(client_addr);
#ifndef WIN32
    pthread_t thread;
#endif

    if (f == NULL || (server_fd = server_socket_init(g_port)) < 0)
        goto error;

#ifndef WIN32
    pthread_create(&thread, NULL, (void *(*)(void *))do_header_issue, NULL);
    pthread_detach(thread);
#else
    CreateThread(NULL, 1024, (LPTHREAD_START_ROUTINE)do_header_issue, NULL, 0, NULL);
#endif
    if ((client_fd = accept(server_fd,(struct sockaddr *) &client_addr, &clnt_len)) < 0)
    {
        ret = SSL_ERROR_SOCK_SETUP_FAILURE;
        goto error;
    }

    size = fread(buf, 1, sizeof(buf), f);
    if (SOCKET_WRITE(client_fd, buf, size) < 0)
    {
        ret = SSL_ERROR_SOCK_SETUP_FAILURE;
        goto error;
    }

    usleep(200000);

    ret = 0;
error:
    fclose(f);
    SOCKET_CLOSE(client_fd);
    SOCKET_CLOSE(server_fd);
    TTY_FLUSH();
    SYSTEM("killall axssl");
    return ret;
}
#endif

/**************************************************************************
 * main()
 *
 **************************************************************************/
int main(int argc, char *argv[])
{
	int ret = 1;
	int fd;

#ifdef WIN32
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSAStartup(wVersionRequested, &wsaData);
	fd = _open("test_result.txt", O_WRONLY|O_TEMPORARY|O_CREAT, _S_IWRITE);
	dup2(fd, 2);                        /* write stderr to this file */
#else
	fd = open("/dev/null", O_WRONLY);   /* write stderr to /dev/null */
	signal(SIGPIPE, SIG_IGN);           /* ignore pipe errors */
	dup2(fd, 2);
#endif

    /* can't do testing in this mode */
#if defined CONFIG_SSL_GENERATE_X509_CERT
	printf("Error: Must compile with default key/certificates\n");
	exit(1);
#endif

//	TEST_NO_ARGUMENT(testCrypto, ret);

//	TEST_NO_ARGUMENT(cert_tests, ret);


#if !defined(WIN32) && defined(CONFIG_SSL_CTX_MUTEXING)
	TEST_NO_ARGUMENT(multi_thread_test, ret);
#endif

	TEST_NO_ARGUMENT(SSL_basic_test, ret);
#if 0

    SYSTEM("sh "CERT_HOME_DIR"killopenssl.sh");

	TEST_NO_ARGUMENT(SSL_unblocked_test, ret);

    SYSTEM("sh "CERT_HOME_DIR"killopenssl.sh");

	TEST_NO_ARGUMENT(SSL_client_tests, ret);

    SYSTEM("sh "CERT_HOME_DIR"killopenssl.sh");
    SYSTEM("sh "CERT_HOME_DIR"killgnutls.sh");

	TEST_NO_ARGUMENT(SSL_server_tests, ret);


    SYSTEM("sh "CERT_HOME_DIR"killopenssl.sh");

#if	TEST_HEADER
	TEST_NO_ARGUMENT(header_issue, ret);
#endif
#endif

    ret = 0;        /* all ok */
    printf("**** ALL TESTS PASSED ****\n"); TTY_FLUSH();
cleanup:

    if (ret)
        printf("Error: Some tests failed!\n");

    close(fd);
    return ret;
}

