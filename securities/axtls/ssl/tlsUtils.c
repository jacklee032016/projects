
#include "tls.h"


/*
 * Retrieve various parameters about the SSL engine.
 */
EXP_FUNC int STDCALL ssl_get_config(int offset)
{
    switch (offset)
    {
        /* return the appropriate build mode */
        case SSL_BUILD_MODE:
#if defined(CONFIG_SSL_FULL_MODE)
            return SSL_BUILD_FULL_MODE;
#elif defined(CONFIG_SSL_ENABLE_CLIENT)
            return SSL_BUILD_ENABLE_CLIENT;
#elif defined(CONFIG_ENABLE_VERIFICATION)
            return SSL_BUILD_ENABLE_VERIFICATION;
#elif defined(CONFIG_SSL_SERVER_ONLY )
            return SSL_BUILD_SERVER_ONLY;
#else 
            return SSL_BUILD_SKELETON_MODE;
#endif

        case SSL_MAX_CERT_CFG_OFFSET:
            return CONFIG_SSL_MAX_CERTS;

#ifdef CONFIG_SSL_CERT_VERIFICATION
        case SSL_MAX_CA_CERT_CFG_OFFSET:
            return CONFIG_X509_MAX_CA_CERTS;
#endif
#ifdef CONFIG_SSL_HAS_PEM
        case SSL_HAS_PEM:
            return 1;
#endif
        default:
            return 0;
    }
}


/**
 * Debugging routine to display SSL handshaking stuff.
 */
#ifdef CONFIG_SSL_FULL_MODE
/**
 * Debugging routine to display SSL states.
 */
void DISPLAY_STATE(SSL *ssl, int is_send, uint8_t state, int not_ok)
{
	const char *str;

	if (!IS_SET_SSL_FLAG(SSL_DISPLAY_STATES))
		return;

	printf(not_ok ? "Error - invalid State:\t" : "State:\t");
	printf(is_send ? "sending " : "receiving ");

	switch (state)
	{
		case HS_HELLO_REQUEST:
		str = "Hello Request (0)";
		break;

		case HS_CLIENT_HELLO:
		str = "Client Hello (1)";
		break;

		case HS_SERVER_HELLO:
		str = "Server Hello (2)";
		break;

		case HS_CERTIFICATE:
		str = "Certificate (11)";
		break;

		case HS_SERVER_KEY_XCHG:
		str = "Certificate Request (12)";
		break;

		case HS_CERT_REQ:
		str = "Certificate Request (13)";
		break;

		case HS_SERVER_HELLO_DONE:
		str = "Server Hello Done (14)";
		break;

		case HS_CERT_VERIFY:
		str = "Certificate Verify (15)";
		break;

		case HS_CLIENT_KEY_XCHG:
		str = "Client Key Exchange (16)";
		break;

		case HS_FINISHED:
		str = "Finished (20)";
		break;

		default:
		str = "Error (Unknown)";

		break;
	}

	printf("%s\n", str);
	TTY_FLUSH();
}

/**
 * Debugging routine to display RSA objects
 */
void DISPLAY_RSA(SSL *ssl, const RSA_CTX *rsa_ctx)
{
	if (!IS_SET_SSL_FLAG(SSL_DISPLAY_RSA))
		return;

	RSA_print(rsa_ctx);
	TTY_FLUSH();
}


/**
 * Debugging routine to display SSL handshaking errors.
 */
EXP_FUNC void STDCALL ssl_display_error(int error_code)
{
	if (error_code == SSL_OK)
	{
		printf("No Error in SSL\n");
		return;
	}

	printf("Error: ");

	/* X509 error? */
	if (error_code < SSL_X509_OFFSET)
	{
		printf("%s\n", x509_display_error(error_code - SSL_X509_OFFSET));
		return;
	}

	/* SSL alert error code */
	if (error_code > SSL_ERROR_CONN_LOST)
	{
		printf("SSL error %d\n", -error_code);
		return;
	}

	switch (error_code)
	{
		case SSL_ERROR_DEAD:
			printf("connection dead");
			break;

		case SSL_ERROR_INVALID_HANDSHAKE:
			printf("invalid handshake");
			break;

		case SSL_ERROR_INVALID_PROT_MSG:
			printf("invalid protocol message");
			break;

		case SSL_ERROR_INVALID_HMAC:
			printf("invalid mac");
			break;

		case SSL_ERROR_INVALID_VERSION:
			printf("invalid version");
			break;

		case SSL_ERROR_INVALID_SESSION:
			printf("invalid session");
			break;

		case SSL_ERROR_NO_CIPHER:
			printf("no cipher");
			break;

		case SSL_ERROR_CONN_LOST:
			printf("connection lost");
			break;

		case SSL_ERROR_BAD_CERTIFICATE:
			printf("bad certificate");
			break;

		case SSL_ERROR_INVALID_KEY:
			printf("invalid key");
			break;

		case SSL_ERROR_FINISHED_INVALID:
			printf("finished invalid");
			break;

		case SSL_ERROR_NO_CERT_DEFINED:
			printf("no certificate defined");
			break;

		case SSL_ERROR_NO_CLIENT_RENOG:
			printf("client renegotiation not supported");
			break;

		case SSL_ERROR_NOT_SUPPORTED:
			printf("Option not supported");
			break;

		default:
			printf("undefined as yet - %d", error_code);
			break;
	}

	printf("\n");
	TTY_FLUSH();
}


void ecpDebugDumpAlert(SSL *ssl, TLS_ALERT_HEADER *header, int isRx)
{
	if (!IS_SET_SSL_FLAG(SSL_DISPLAY_STATES))
		return;

	printf("%s %s Alert: ", (isRx==0)?"Send":"Received", (header->level==TLS_ALERT_LEVEL_WARNING)?"Warning":"Fatal");

	switch (header->description)
	{
		case TLS_ALERT_CLOSE_NOTIFY:
			printf("close notify");
			break;

		case TLS_ALERT_INVALID_VERSION:
			printf("invalid version");
			break;

		case TLS_ALERT_BAD_CERTIFICATE:
			printf("bad certificate");
			break;

		case TLS_ALERT_UNEXPECTED_MESSAGE:
			printf("unexpected message");
			break;

		case TLS_ALERT_BAD_RECORD_MAC:
			printf("bad record mac");
			break;

		case TLS_ALERT_HANDSHAKE_FAILURE:
			printf("handshake failure");
			break;

		case TLS_ALERT_ILLEGAL_PARAMETER:
			printf("illegal parameter");
			break;

		case TLS_ALERT_DECODE_ERROR:
			printf("decode error");
			break;

		case TLS_ALERT_DECRYPT_ERROR:
			printf("decrypt error");
			break;

		case TLS_ALERT_NO_RENEGOTIATION:
			printf("no renegotiation");
			break;

		default:
			printf("alert - (unknown %d)", header->description);
			break;
	}

	printf("\n");
	TTY_FLUSH();
}
#endif /* CONFIG_SSL_FULL_MODE */

/**
 * Return the version of this library.
 */
EXP_FUNC const char  * STDCALL ssl_version()
{
	static const char * axtls_version = AXTLS_VERSION;
	return axtls_version;
}


const char *ecpTlsHandshakeName(HAND_SHAKE_T hst)
{
	switch (hst)
	{
		case HS_HELLO_REQUEST:
			return "HELLO REQ";
			break;
		case HS_CLIENT_HELLO:
			return "CLIENT HELLO";
			break;
		case HS_SERVER_HELLO:
			return "SERVER HELLO";
			break;
		case HS_CERTIFICATE:
			return "CERTIFICATE";
			break;
		case HS_SERVER_KEY_XCHG:
			return "SERVER_KEY_XCHG";
			break;
		case HS_CERT_REQ:
			return "CERT REQ";
			break;
		case HS_SERVER_HELLO_DONE:
			return "SERVER_HELLO_DONE";
			break;
		case HS_CERT_VERIFY:
			return "CERT_VERIFY";
			break;
		case HS_CLIENT_KEY_XCHG:
			return "CLIENT_KEY_XCHG";
			break;
		case HS_FINISHED:
		default:	
			return "FINISHED";
			break;
			
	}

	return "UNKNOWN HS";
}


const char *ecpTlsProtocolName(TLS_CNT_TYPE protocol)
{
	switch (protocol)
	{
		case TLS_CNT_CHANGE_CIPHER_SPEC:
			return "CHANGE_CIPHER_SPEC";
			break;
		case TLS_CNT_ALERT:
			return "ALERT_PROTOCOL";
			break;
		case TLS_CNT_HANDSHAKE:
			return "HANDSHAKE_PROTOCOL";
			break;
		case TLS_CNT_APP_DATA:
		default:	
			return "APP_DATA";
			break;
			
	}

	return "UNKNOWN CNT Type";
}

