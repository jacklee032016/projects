
#include "ecp.h"

/**************************************************************************
 * SSL Client Testing
 *
 **************************************************************************/
typedef struct
{
    uint8_t session_id[SSL_SESSION_ID_SIZE];
#ifndef WIN32
    pthread_t server_thread;
#endif
    int start_server;
    int stop_server;
    int do_reneg;
} CLNT_SESSION_RESUME_CTX;

typedef struct
{
    const char *testname;
    const char *openssl_option;
    int do_gnutls;
} server_t;


static void do_server(server_t *svr)
{
    char openssl_buf[2048];
#ifndef WIN32
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
#endif
    if (svr->do_gnutls)
    {
        sprintf(openssl_buf, "gnutls-serv -p %d --quiet %s ", g_port, svr->openssl_option);
    }
    else
    {
        sprintf(openssl_buf, "openssl s_server -tls1 -accept %d -quiet %s ", g_port, svr->openssl_option);
    }

    SYSTEM(openssl_buf);
}


static int SSL_client_test(
        const char *test,
        SSL_CTX **ssl_ctx,
        const char *openssl_option, 
        CLNT_SESSION_RESUME_CTX *sess_resume,
        uint32_t client_options,
        const char *private_key,
        const char *password,
        const char *cert)
{
    server_t server_data;
    SSL *ssl = NULL;
    int client_fd = -1;
    uint8_t *session_id = NULL;
    int ret = 1;
#ifndef WIN32
    pthread_t thread;
#endif

    server_data.do_gnutls = strstr(test, "GNUTLS") != NULL;

    if (sess_resume == NULL || sess_resume->start_server)
    {
        g_port++;
        server_data.openssl_option = openssl_option;

#ifndef WIN32
        pthread_create(&thread, NULL, 
                (void *(*)(void *))do_server, (void *)&server_data);
        pthread_detach(thread);
#else
        CreateThread(NULL, 1024, (LPTHREAD_START_ROUTINE)do_server, 
            (LPVOID)&server_data, 0, NULL);
#endif
    }
    
    usleep(200000);           /* allow server to start */

    if (*ssl_ctx == NULL)
    {
        if (private_key)
        {
            client_options |= SSL_NO_DEFAULT_KEY;
        }

        if ((*ssl_ctx = ssl_ctx_new(
                            client_options, SSL_DEFAULT_CLNT_SESS)) == NULL)
        {
            ret = SSL_ERROR_INVALID_KEY;
            goto client_test_exit;
        }

        if (private_key)
        {
            int obj_type = SSL_OBJ_RSA_KEY;

            if (strstr(private_key, ".p8"))
                obj_type = SSL_OBJ_PKCS8;
            else if (strstr(private_key, ".p12"))
                obj_type = SSL_OBJ_PKCS12;

            if (ssl_obj_load(*ssl_ctx, obj_type, private_key, password))
            {
                ret = SSL_ERROR_INVALID_KEY;
                goto client_test_exit;
            }
        }

        if (cert)                  
        {
            if ((ret = ssl_obj_load(*ssl_ctx, 
                            SSL_OBJ_X509_CERT, cert, NULL)) != SSL_OK)
            {
                printf("could not add cert %s (%d)\n", cert, ret);
                TTY_FLUSH();
                goto client_test_exit;
            }
        }

        if (ssl_obj_load(*ssl_ctx, SSL_OBJ_X509_CACERT, 
                CERT_HOME_DIR"axTLS.ca_x509.cer", NULL))
        {
            printf("could not add cert auth\n"); TTY_FLUSH();
            goto client_test_exit;
        }
    }
    
    if (sess_resume && !sess_resume->start_server) 
    {
        session_id = sess_resume->session_id;
    }

    if ((client_fd = client_socket_init(g_port)) < 0)
    {
        printf("could not start socket on %d\n", g_port); TTY_FLUSH();
        goto client_test_exit;
    }

    ssl = ssl_client_new(*ssl_ctx, client_fd, session_id, sizeof(session_id));

    /* check the return status */
    if ((ret = ssl_handshake_status(ssl)))
        goto client_test_exit;

    /* renegotiate client */
    if (sess_resume && sess_resume->do_reneg) 
    {
        if (ssl_renegotiate(ssl) == -TLS_ALERT_NO_RENEGOTIATION) 
            ret = 0;
        else
            ret = -TLS_ALERT_NO_RENEGOTIATION;

        goto client_test_exit;
    }

    if (sess_resume)
    {
        memcpy(sess_resume->session_id, 
                ssl_get_session_id(ssl), SSL_SESSION_ID_SIZE);
    }

    if (IS_SET_SSL_FLAG(SSL_SERVER_VERIFY_LATER) && 
                                            (ret = ssl_verify_cert(ssl)))
    {
        goto client_test_exit;
    }

    ssl_write(ssl, (uint8_t *)"hello world\n", 13);
    if (sess_resume)
    {
        const uint8_t *sess_id = ssl_get_session_id(ssl);
        int i;

        printf("    Session-ID: ");
        for (i = 0; i < SSL_SESSION_ID_SIZE; i++)
        {
            printf("%02X", sess_id[i]);
        }
        printf("\n");
        TTY_FLUSH();
    }

    ret = 0;

client_test_exit:
    ssl_free(ssl);
    SOCKET_CLOSE(client_fd);
    usleep(200000);           /* allow openssl to say something */

    if (sess_resume)
    {
        if (sess_resume->stop_server)
        {
            ssl_ctx_free(*ssl_ctx);
            *ssl_ctx = NULL;
        }
        else if (sess_resume->start_server)
        {
#ifndef WIN32
           sess_resume->server_thread = thread;
#endif
        }
    }
    else
    {
        ssl_ctx_free(*ssl_ctx);
        *ssl_ctx = NULL;
    }

    if (ret == 0)
    {
        printf("SSL client test \"%s\" passed\n", test);
        TTY_FLUSH();
    }

    return ret;
}


int SSL_client_tests(void)
{
    int ret =  -1;
    SSL_CTX *ssl_ctx = NULL;
    CLNT_SESSION_RESUME_CTX sess_resume;
    memset(&sess_resume, 0, sizeof(CLNT_SESSION_RESUME_CTX));

    sess_resume.start_server = 1;
    printf("### starting client tests\n");
   
    if ((ret = SSL_client_test("512 bit key", 
                    &ssl_ctx,
                    "-cert "CERT_HOME_DIR"axTLS.x509_512.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_512.pem", &sess_resume, 
                    DEFAULT_CLNT_OPTION, NULL, NULL, NULL)))
        goto cleanup;

    /* all the session id's should match for session resumption */
    sess_resume.start_server = 0;
    if ((ret = SSL_client_test("Client session resumption #1", 
                    &ssl_ctx, NULL, &sess_resume, 
                    DEFAULT_CLNT_OPTION, NULL, NULL, NULL)))
        goto cleanup;

    // no client renegotiation
    sess_resume.do_reneg = 1;
    // test relies on openssl killing the call
    if ((ret = SSL_client_test("Client renegotiation", 
                    &ssl_ctx, NULL, &sess_resume, 
                    DEFAULT_CLNT_OPTION, NULL, NULL, NULL)))
        goto cleanup;
    sess_resume.do_reneg = 0;

    sess_resume.stop_server = 1;
    if ((ret = SSL_client_test("Client session resumption #2", 
                    &ssl_ctx, NULL, &sess_resume, 
                    DEFAULT_CLNT_OPTION, NULL, NULL, NULL)))
        goto cleanup;

    if ((ret = SSL_client_test("1024 bit key", 
                    &ssl_ctx,
                    "-cert "CERT_HOME_DIR"axTLS.x509_1024.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_1024.pem", NULL,
                    DEFAULT_CLNT_OPTION, NULL, NULL, NULL)))
        goto cleanup;

    if ((ret = SSL_client_test("2048 bit key", 
                    &ssl_ctx,
                    "-cert "CERT_HOME_DIR"axTLS.x509_2048.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_2048.pem",  NULL,
                    DEFAULT_CLNT_OPTION, NULL, NULL, NULL)))
        goto cleanup;

    if ((ret = SSL_client_test("4096 bit key", 
                    &ssl_ctx,
                    "-cert "CERT_HOME_DIR"axTLS.x509_4096.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_4096.pem", NULL,
                    DEFAULT_CLNT_OPTION, NULL, NULL, NULL)))
        goto cleanup;

    if ((ret = SSL_client_test("Server cert chaining", 
                    &ssl_ctx,
                    "-cert "CERT_HOME_DIR"axTLS.x509_device.pem "
                    "-key "CERT_HOME_DIR"axTLS.device_key.pem "
                    "-CAfile "CERT_HOME_DIR"axTLS.x509_512.pem ", NULL,
                    DEFAULT_CLNT_OPTION, NULL, NULL, NULL)))
        goto cleanup;

    /* Check the server can verify the client */
    if ((ret = SSL_client_test("Client peer authentication",
                    &ssl_ctx,
                    "-cert "CERT_HOME_DIR"axTLS.x509_2048.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_2048.pem "
                    "-CAfile "CERT_HOME_DIR"axTLS.ca_x509.pem "
                    "-verify 1 ", NULL, DEFAULT_CLNT_OPTION, 
                    CERT_HOME_DIR"axTLS.key_1024", NULL,
                    CERT_HOME_DIR"axTLS.x509_1024.cer")))
        goto cleanup;

    /* Should get an "ERROR" from openssl (as the handshake fails as soon as
     * the certificate verification fails) */
    if ((ret = SSL_client_test("Error: Expired cert (verify now)",
                    &ssl_ctx,
                    "-cert "CERT_HOME_DIR"axTLS.x509_bad_after.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_512.pem", NULL,
                    DEFAULT_CLNT_OPTION, NULL, NULL, NULL)) != 
                            SSL_X509_ERROR(X509_VFY_ERROR_EXPIRED))
    {
        printf("*** Error: %d\n", ret);
        goto cleanup;
    }

    printf("SSL client test \"Expired cert (verify now)\" passed\n");

    /* There is no "ERROR" from openssl */
    if ((ret = SSL_client_test("Error: Expired cert (verify later)", 
                    &ssl_ctx,
                    "-cert "CERT_HOME_DIR"axTLS.x509_bad_after.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_512.pem", NULL,
                    DEFAULT_CLNT_OPTION|SSL_SERVER_VERIFY_LATER, NULL, 
                    NULL, NULL)) != SSL_X509_ERROR(X509_VFY_ERROR_EXPIRED))
    {
        printf("*** Error: %d\n", ret); TTY_FLUSH();
        goto cleanup;
    }

    printf("SSL client test \"Expired cert (verify later)\" passed\n");

    /* invalid cert type */
    if ((ret = SSL_client_test("Error: Invalid certificate type", 
                    &ssl_ctx,
                    "-cert "CERT_HOME_DIR"axTLS.x509_2048.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_2048.pem "
                    "-CAfile "CERT_HOME_DIR"axTLS.ca_x509.pem "
                    "-verify 1 ", NULL, DEFAULT_CLNT_OPTION, 
                    CERT_HOME_DIR"axTLS.x509_1024.cer", NULL,
                    CERT_HOME_DIR"axTLS.x509_1024.cer")) 
                            != SSL_ERROR_INVALID_KEY)
    {
        printf("*** Error: %d\n", ret); TTY_FLUSH();
        goto cleanup;
    }

    printf("SSL client test \"Invalid certificate type\" passed\n");

    if ((ret = SSL_client_test("GNUTLS client", 
                    &ssl_ctx,
                    "--x509certfile "CERT_HOME_DIR"axTLS.x509_1024.pem "
                    "--x509keyfile "CERT_HOME_DIR"axTLS.key_1024.pem -q", NULL,
                    DEFAULT_CLNT_OPTION, NULL, NULL, NULL)))
        goto cleanup;

    ret = 0;

cleanup:
    if (ret)
    {
        ssl_display_error(ret);
        printf("Error: A client test failed\n");
        SYSTEM("sh "CERT_HOME_DIR"killopenssl.sh");
        SYSTEM("sh "CERT_HOME_DIR"killgnutls.sh");
        exit(1);
    }
    else
    {
        printf("All client tests passed\n"); TTY_FLUSH();
    }

    ssl_ctx_free(ssl_ctx);
    return ret;
}

