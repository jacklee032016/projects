
#include "ecp.h"
typedef struct
{
    /* not used as yet */
    int dummy;
} SVR_CTX;

typedef struct
{
    const char *testname;
    const char *openssl_option;
} client_t;


static void do_client(client_t *clnt)
{
    char openssl_buf[2048];
    usleep(200000);           /* allow server to start */

    /* show the session ids in the reconnect test */
    if (strcmp(clnt->testname, "Session Reuse") == 0)
    {
        sprintf(openssl_buf, "echo \"hello client\" | openssl s_client -tls1 "
            "-connect localhost:%d %s 2>&1 | grep \"Session-ID:\"", 
            g_port, clnt->openssl_option);
    }
    else if (strstr(clnt->testname, "GNUTLS") == NULL)
    {
        sprintf(openssl_buf, "echo \"hello client\" | openssl s_client -tls1 "
#ifdef WIN32
            "-connect localhost:%d -quiet %s",
#else
            "-connect localhost:%d -quiet %s > /dev/null 2>&1",
#endif
        g_port, clnt->openssl_option);
    }
    else /* gnutls */
    {
        sprintf(openssl_buf, "echo \"hello client\" | gnutls-cli "
#ifdef WIN32
            "-p %d %s 127.0.0.1",
#else
            "-p %d %s 127.0.0.1 > /dev/null 2>&1",
#endif
        g_port, clnt->openssl_option);
    }

    SYSTEM(openssl_buf);
}


int SSL_server_tests(void)
{
    int ret = -1;
    struct stat stat_buf;
    SVR_CTX svr_test_ctx;
    memset(&svr_test_ctx, 0, sizeof(SVR_CTX));

    printf("### starting server tests\n"); TTY_FLUSH();

    /* Go through the algorithms */

    /* 
     * TLS1 client hello 
     */
    if ((ret = SSL_server_test("TLSv1", "-cipher RC4-SHA -tls1", 
                    NULL, NULL, NULL, NULL, NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;

    /*
     * AES128-SHA
     */
    if ((ret = SSL_server_test("AES256-SHA", "-cipher AES128-SHA", 
                    DEFAULT_CERT, NULL, DEFAULT_KEY, NULL, NULL,
                    DEFAULT_SVR_OPTION)))
        goto cleanup;

    /*
     * AES256-SHA
     */
    if ((ret = SSL_server_test("AES256-SHA", "-cipher AES128-SHA", 
                    DEFAULT_CERT, NULL, DEFAULT_KEY, NULL, NULL,
                    DEFAULT_SVR_OPTION)))
        goto cleanup;

    /*
     * RC4-SHA
     */
    if ((ret = SSL_server_test("RC4-SHA", "-cipher RC4-SHA", 
                DEFAULT_CERT, NULL, DEFAULT_KEY, NULL, NULL,
                DEFAULT_SVR_OPTION)))
        goto cleanup;

    /*
     * RC4-MD5
     */
    if ((ret = SSL_server_test("RC4-MD5", "-cipher RC4-MD5", 
                DEFAULT_CERT, NULL, DEFAULT_KEY, NULL, NULL,
                DEFAULT_SVR_OPTION)))
        goto cleanup;

    /*
     * Session Reuse
     * all the session id's should match for session resumption.
     */
    if ((ret = SSL_server_test("Session Reuse",   "-cipher RC4-SHA -reconnect", 
                    DEFAULT_CERT, NULL, DEFAULT_KEY, NULL, NULL,
                    DEFAULT_SVR_OPTION)))
        goto cleanup;

    /* 
     * 512 bit RSA key 
     */
    if ((ret = SSL_server_test("512 bit key", 
                    "-cipher RC4-SHA", 
                    CERT_HOME_DIR"axTLS.x509_512.cer", NULL, 
                    CERT_HOME_DIR"axTLS.key_512",
                    NULL, NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;

    /* 
     * 1024 bit RSA key (check certificate chaining)
     */
    if ((ret = SSL_server_test("1024 bit key", 
                    "-cipher RC4-SHA",
                    CERT_HOME_DIR"axTLS.x509_1024.cer", NULL, 
                    CERT_HOME_DIR"axTLS.key_1024",
                    NULL, NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;

    /* 
     * 1042 bit RSA key (check certificate chaining)
     */
    if ((ret = SSL_server_test("1042 bit key", 
                    "-cipher RC4-SHA",
                    CERT_HOME_DIR"axTLS.x509_1042.cer", NULL, 
                    CERT_HOME_DIR"axTLS.key_1042",
                    NULL, NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;
    /* 
     * 2048 bit RSA key 
     */
    if ((ret = SSL_server_test("2048 bit key", 
                    "-cipher RC4-SHA",
                    CERT_HOME_DIR"axTLS.x509_2048.cer", NULL, 
                    CERT_HOME_DIR"axTLS.key_2048",
                    NULL, NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;

    /* 
     * 4096 bit RSA key 
     */
    if ((ret = SSL_server_test("4096 bit key", 
                    "-cipher RC4-SHA",
                    CERT_HOME_DIR"axTLS.x509_4096.cer", NULL, 
                    CERT_HOME_DIR"axTLS.key_4096",
                    NULL, NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;

    /* 
     * Client Verification
     */
    if ((ret = SSL_server_test("Client Verification", 
                    "-cipher RC4-SHA -tls1 "
                    "-cert "CERT_HOME_DIR"axTLS.x509_2048.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_2048.pem ",
                    NULL, NULL, NULL, 
                    CERT_HOME_DIR"axTLS.ca_x509.cer", NULL,
                    DEFAULT_SVR_OPTION|SSL_CLIENT_AUTHENTICATION)))
        goto cleanup;

    /* this test should fail */
    if (stat(CERT_HOME_DIR"axTLS.x509_bad_before.pem", &stat_buf) >= 0)
    {
        if ((ret = SSL_server_test("Error: Bad Before Cert", 
                    "-cipher RC4-SHA -tls1 "
                    "-cert "CERT_HOME_DIR"axTLS.x509_bad_before.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_512.pem ",
                    NULL, NULL, NULL, 
                    CERT_HOME_DIR"axTLS.ca_x509.cer", NULL,
                    DEFAULT_SVR_OPTION|SSL_CLIENT_AUTHENTICATION)) !=
                            SSL_X509_ERROR(X509_VFY_ERROR_NOT_YET_VALID))
            goto cleanup;

        printf("SSL server test \"%s\" passed\n", "Bad Before Cert");
        TTY_FLUSH();
    }

    /* this test should fail */
    if ((ret = SSL_server_test("Error: Bad After Cert", 
                    "-cipher RC4-SHA -tls1 "
                    "-cert "CERT_HOME_DIR"axTLS.x509_bad_after.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_512.pem ",
                    NULL, NULL, NULL, 
                    CERT_HOME_DIR"axTLS.ca_x509.cer", NULL,
                    DEFAULT_SVR_OPTION|SSL_CLIENT_AUTHENTICATION)) !=
                            SSL_X509_ERROR(X509_VFY_ERROR_EXPIRED))
        goto cleanup;

    printf("SSL server test \"%s\" passed\n", "Bad After Cert");
    TTY_FLUSH();

    /*
     * No trusted cert
     */
    if ((ret = SSL_server_test("Error: No trusted certificate", 
                    "-cipher RC4-SHA -tls1 "
                    "-cert "CERT_HOME_DIR"axTLS.x509_512.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_512.pem ",
                    NULL, NULL, NULL, 
                    NULL, NULL,
                    DEFAULT_SVR_OPTION|SSL_CLIENT_AUTHENTICATION)) !=
                            SSL_X509_ERROR(X509_VFY_ERROR_NO_TRUSTED_CERT))
        goto cleanup;

    printf("SSL server test \"%s\" passed\n", "No trusted certificate");
    TTY_FLUSH();

    /*
     * Self-signed (from the server)
     */
    if ((ret = SSL_server_test("Error: Self-signed certificate (from server)", 
                    "-cipher RC4-SHA -tls1 "
                    "-cert "CERT_HOME_DIR"axTLS.x509_512.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_512.pem "
                    "-CAfile "CERT_HOME_DIR"axTLS.ca_x509.pem ",
                    NULL, NULL, NULL, 
                    NULL, NULL,
                    DEFAULT_SVR_OPTION|SSL_CLIENT_AUTHENTICATION)) !=
                            SSL_X509_ERROR(X509_VFY_ERROR_SELF_SIGNED))
        goto cleanup;

    printf("SSL server test \"%s\" passed\n", 
                            "Self-signed certificate (from server)");
    TTY_FLUSH();

    /*
     * Self-signed (from the client)
     */
    if ((ret = SSL_server_test("Self-signed certificate (from client)", 
                    "-cipher RC4-SHA -tls1 "
                    "-cert "CERT_HOME_DIR"axTLS.x509_512.pem "
                    "-key "CERT_HOME_DIR"axTLS.key_512.pem ",
                    NULL, NULL, NULL, 
                    CERT_HOME_DIR"axTLS.ca_x509.cer",
                    NULL,
                    DEFAULT_SVR_OPTION|SSL_CLIENT_AUTHENTICATION)))
        goto cleanup;

    /* 
     * Key in PEM format
     */
    if ((ret = SSL_server_test("Key in PEM format",
                    "-cipher RC4-SHA", 
                    CERT_HOME_DIR"axTLS.x509_512.cer", NULL, 
                    CERT_HOME_DIR"axTLS.key_512.pem", NULL,
                    NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;

    /* 
     * Cert in PEM format
     */
    if ((ret = SSL_server_test("Cert in PEM format", 
                    "-cipher RC4-SHA", 
                    CERT_HOME_DIR"axTLS.x509_512.pem", NULL, 
                    CERT_HOME_DIR"axTLS.key_512.pem", NULL,
                    NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;

    /* 
     * Cert chain in PEM format
     */
    if ((ret = SSL_server_test("Cert chain in PEM format", 
                    "-cipher RC4-SHA", 
                    CERT_HOME_DIR"axTLS.x509_device.pem", 
                    NULL, CERT_HOME_DIR"axTLS.device_key.pem",
                    CERT_HOME_DIR"axTLS.ca_x509.pem", NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;

    /* 
     * AES128 Encrypted key 
     */
    if ((ret = SSL_server_test("AES128 encrypted key", 
                    "-cipher RC4-SHA", 
                    CERT_HOME_DIR"axTLS.x509_aes128.pem", NULL, 
                    CERT_HOME_DIR"axTLS.key_aes128.pem",
                    NULL, "abcd", DEFAULT_SVR_OPTION)))
        goto cleanup;

    /* 
     * AES256 Encrypted key 
     */
    if ((ret = SSL_server_test("AES256 encrypted key", 
                    "-cipher RC4-SHA", 
                    CERT_HOME_DIR"axTLS.x509_aes256.pem", NULL, 
                    CERT_HOME_DIR"axTLS.key_aes256.pem",
                    NULL, "abcd", DEFAULT_SVR_OPTION)))
        goto cleanup;

    /* 
     * AES128 Encrypted invalid key 
     */
    if ((ret = SSL_server_test("AES128 encrypted invalid key", 
                    "-cipher RC4-SHA", 
                    CERT_HOME_DIR"axTLS.x509_aes128.pem", NULL, 
                    CERT_HOME_DIR"axTLS.key_aes128.pem",
                    NULL, "xyz", DEFAULT_SVR_OPTION)) != SSL_ERROR_INVALID_KEY)
        goto cleanup;

    printf("SSL server test \"%s\" passed\n", "AES128 encrypted invalid key");
    TTY_FLUSH();

    /*
     * PKCS#8 key (encrypted)
     */
    if ((ret = SSL_server_test("pkcs#8 encrypted", "-cipher RC4-SHA", 
                DEFAULT_CERT, NULL, CERT_HOME_DIR"axTLS.encrypted.p8", 
                NULL, "abcd", DEFAULT_SVR_OPTION)))
        goto cleanup;

    /*
     * PKCS#8 key (unencrypted DER format)
     */
    if ((ret = SSL_server_test("pkcs#8 DER unencrypted", "-cipher RC4-SHA", 
                DEFAULT_CERT, NULL, CERT_HOME_DIR"axTLS.unencrypted.p8", 
                NULL, NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;

    /*
     * PKCS#8 key (unencrypted PEM format)
     */
    if ((ret = SSL_server_test("pkcs#8 PEM unencrypted", "-cipher RC4-SHA", 
                DEFAULT_CERT, NULL, CERT_HOME_DIR"axTLS.unencrypted_pem.p8", 
                NULL, NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;

    /*
     * PKCS#12 key/certificate
     */
    if ((ret = SSL_server_test("pkcs#12 with CA", "-cipher RC4-SHA", 
                NULL, NULL, CERT_HOME_DIR"axTLS.withCA.p12", 
                NULL, "abcd", DEFAULT_SVR_OPTION)))
        goto cleanup;

    if ((ret = SSL_server_test("pkcs#12 no CA", "-cipher RC4-SHA", 
                DEFAULT_CERT, NULL, CERT_HOME_DIR"axTLS.withoutCA.p12", 
                NULL, "abcd", DEFAULT_SVR_OPTION)))
        goto cleanup;

    /* 
     * GNUTLS
     */
    if ((ret = SSL_server_test("GNUTLS client", 
                    "",
                    CERT_HOME_DIR"axTLS.x509_1024.cer", NULL, 
                    CERT_HOME_DIR"axTLS.key_1024",
                    NULL, NULL, DEFAULT_SVR_OPTION)))
        goto cleanup;
    ret = 0;
    return ret;
}

