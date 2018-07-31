/*
* Error info in SSL protocol level
*/

#include "cmnSsl.h"


const char* __error_reason_string(unsigned long e)
{
#ifdef NO_ERROR_STRINGS
	(void)e;
#else

	int error = (int)e;
	/* pass to wolfCrypt */
	if (error < MAX_CODE_E && error > MIN_CODE_E)
	{
		return wc_GetErrorString(error);
	}

	switch (error)
	{

		case UNSUPPORTED_SUITE :
		return "unsupported cipher suite";

		case INPUT_CASE_ERROR :
		return "input state error";

		case PREFIX_ERROR :
		return "bad index to key rounds";

		case MEMORY_ERROR :
		return "out of memory";

		case VERIFY_FINISHED_ERROR :
		return "verify problem on finished";

		case VERIFY_MAC_ERROR :
		return "verify mac problem";

		case PARSE_ERROR :
		return "parse error on header";

		case SIDE_ERROR :
		return "wrong client/server type";

		case NO_PEER_CERT :
		return "peer didn't send cert";

		case UNKNOWN_HANDSHAKE_TYPE :
		return "weird handshake type";

		case SOCKET_ERROR_E :
		return "error state on socket";

		case SOCKET_NODATA :
		return "expected data, not there";

		case INCOMPLETE_DATA :
		return "don't have enough data to complete task";

		case UNKNOWN_RECORD_TYPE :
		return "unknown type in record hdr";

		case DECRYPT_ERROR :
		return "error during decryption";

		case FATAL_ERROR :
		return "revcd alert fatal error";

		case ENCRYPT_ERROR :
		return "error during encryption";

		case FREAD_ERROR :
		return "fread problem";

		case NO_PEER_KEY :
		return "need peer's key";

		case NO_PRIVATE_KEY :
		return "need the private key";

		case NO_DH_PARAMS :
		return "server missing DH params";

		case RSA_PRIVATE_ERROR :
		return "error during rsa priv op";

		case MATCH_SUITE_ERROR :
		return "can't match cipher suite";

		case BUILD_MSG_ERROR :
		return "build message failure";

		case BAD_HELLO :
		return "client hello malformed";

		case DOMAIN_NAME_MISMATCH :
		return "peer subject name mismatch";

		case WANT_READ :
		case SSL_ERROR_WANT_READ :
		return "non-blocking socket wants data to be read";

		case NOT_READY_ERROR :
		return "handshake layer not ready yet, complete first";

		case PMS_VERSION_ERROR :
		return "premaster secret version mismatch error";

		case VERSION_ERROR :
		return "record layer version error";

		case WANT_WRITE :
		case SSL_ERROR_WANT_WRITE :
		return "non-blocking socket write buffer full";

		case BUFFER_ERROR :
		return "malformed buffer input error";

		case VERIFY_CERT_ERROR :
		return "verify problem on certificate";

		case VERIFY_SIGN_ERROR :
		return "verify problem based on signature";

		case CLIENT_ID_ERROR :
		return "psk client identity error";

		case SERVER_HINT_ERROR:
		return "psk server hint error";

		case PSK_KEY_ERROR:
		return "psk key callback error";

		case NTRU_KEY_ERROR:
		return "NTRU key error";

		case NTRU_DRBG_ERROR:
		return "NTRU drbg error";

		case NTRU_ENCRYPT_ERROR:
		return "NTRU encrypt error";

		case NTRU_DECRYPT_ERROR:
		return "NTRU decrypt error";

		case ZLIB_INIT_ERROR:
		return "zlib init error";

		case ZLIB_COMPRESS_ERROR:
		return "zlib compress error";

		case ZLIB_DECOMPRESS_ERROR:
		return "zlib decompress error";

		case GETTIME_ERROR:
		return "gettimeofday() error";

		case GETITIMER_ERROR:
		return "getitimer() error";

		case SIGACT_ERROR:
		return "sigaction() error";

		case SETITIMER_ERROR:
		return "setitimer() error";

		case LENGTH_ERROR:
		return "record layer length error";

		case PEER_KEY_ERROR:
		return "cant decode peer key";

		case ZERO_RETURN:
		case SSL_ERROR_ZERO_RETURN:
		return "peer sent close notify alert";

		case ECC_CURVETYPE_ERROR:
		return "Bad ECC Curve Type or unsupported";

		case ECC_CURVE_ERROR:
		return "Bad ECC Curve or unsupported";

		case ECC_PEERKEY_ERROR:
		return "Bad ECC Peer Key";

		case ECC_MAKEKEY_ERROR:
		return "ECC Make Key failure";

		case ECC_EXPORT_ERROR:
		return "ECC Export Key failure";

		case ECC_SHARED_ERROR:
		return "ECC DHE shared failure";

		case NOT_CA_ERROR:
		return "Not a CA by basic constraint error";

		case BAD_PATH_ERROR:
		return "Bad path for opendir error";

		case BAD_CERT_MANAGER_ERROR:
		return "Bad Cert Manager error";

		case OCSP_CERT_REVOKED:
		return "OCSP Cert revoked";

		case CRL_CERT_REVOKED:
		return "CRL Cert revoked";

		case CRL_MISSING:
		return "CRL missing, not loaded";

		case MONITOR_RUNNING_E:
		return "CRL monitor already running";

		case THREAD_CREATE_E:
		return "Thread creation problem";

		case OCSP_NEED_URL:
		return "OCSP need URL";

		case OCSP_CERT_UNKNOWN:
		return "OCSP Cert unknown";

		case OCSP_LOOKUP_FAIL:
		return "OCSP Responder lookup fail";

		case MAX_CHAIN_ERROR:
		return "Maximum Chain Depth Exceeded";

		case COOKIE_ERROR:
		return "DTLS Cookie Error";

		case SEQUENCE_ERROR:
		return "DTLS Sequence Error";

		case SUITES_ERROR:
		return "Suites Pointer Error";

		case SSL_NO_PEM_HEADER:
		return "No PEM Header Error";

		case OUT_OF_ORDER_E:
		return "Out of order message, fatal";

		case BAD_KEA_TYPE_E:
		return "Bad KEA type found";

		case SANITY_CIPHER_E:
		return "Sanity check on ciphertext failed";

		case RECV_OVERFLOW_E:
		return "Receive callback returned more than requested";

		case GEN_COOKIE_E:
		return "Generate Cookie Error";

		case NO_PEER_VERIFY:
		return "Need peer certificate verify Error";

		case FWRITE_ERROR:
		return "fwrite Error";

		case CACHE_MATCH_ERROR:
		return "Cache restore header match Error";

		case UNKNOWN_SNI_HOST_NAME_E:
		return "Unrecognized host name Error";

		case KEYUSE_SIGNATURE_E:
		return "Key Use digitalSignature not set Error";

		case KEYUSE_ENCIPHER_E:
		return "Key Use keyEncipherment not set Error";

		case EXTKEYUSE_AUTH_E:
		return "Ext Key Use server/client auth not set Error";

		case SEND_OOB_READ_E:
		return "Send Callback Out of Bounds Read Error";

		case SECURE_RENEGOTIATION_E:
		return "Invalid Renegotiation Error";

		case SESSION_TICKET_LEN_E:
		return "Session Ticket Too Long Error";

		case SESSION_TICKET_EXPECT_E:
		return "Session Ticket Error";

		case SCR_DIFFERENT_CERT_E:
		return "Peer sent different cert during SCR";

		case SESSION_SECRET_CB_E:
		return "Session Secret Callback Error";

		case NO_CHANGE_CIPHER_E:
		return "Finished received from peer before Change Cipher Error";

		case SANITY_MSG_E:
		return "Sanity Check on message order Error";

		case DUPLICATE_MSG_E:
		return "Duplicate HandShake message Error";

		case SNI_UNSUPPORTED:
		return "Protocol version does not support SNI Error";

		case SOCKET_PEER_CLOSED_E:
		return "Peer closed underlying transport Error";

		case BAD_TICKET_KEY_CB_SZ:
		return "Bad user session ticket key callback Size Error";

		case BAD_TICKET_MSG_SZ:
		return "Bad session ticket message Size Error";

		case BAD_TICKET_ENCRYPT:
		return "Bad user ticket callback encrypt Error";

		case DH_KEY_SIZE_E:
		return "DH key too small Error";

		default :
		return "unknown error number";
	}
#endif /* NO_ERROR_STRINGS */

	return "no support for error strings built in";

}

int wolfSSL_get_error(WOLFSSL* ssl, int ret)
{
	if (ret > 0)
		return SSL_ERROR_NONE;
	if (ssl == NULL)
		return BAD_FUNC_ARG;

	/* make sure converted types are handled in SetErrorString() too */
	if (ssl->error == WANT_READ)
		return SSL_ERROR_WANT_READ;         /* convert to OpenSSL type */
	else if (ssl->error == WANT_WRITE)
		return SSL_ERROR_WANT_WRITE;        /* convert to OpenSSL type */
	else if (ssl->error == ZERO_RETURN)
		return SSL_ERROR_ZERO_RETURN;       /* convert to OpenSSL type */
	return ssl->error;
}


char* wolfSSL_ERR_error_string(unsigned long errNumber, char* data)
{
	static const char* msg = "Please supply a buffer for error string";

	if (data) {
		XSTRNCPY(data, __error_reason_string((int)errNumber), WOLFSSL_MAX_ERROR_SZ);
		return data;
	}

	return (char*)msg;
}


void wolfSSL_ERR_error_string_n(unsigned long e, char* buf, unsigned long len)
{
	WOLFSSL_ENTER();
	if (len >= WOLFSSL_MAX_ERROR_SZ)
		wolfSSL_ERR_error_string(e, buf);
	else
	{
		char tmp[WOLFSSL_MAX_ERROR_SZ];

		WOLFSSL_MSG("Error buffer too short, truncating");
		if (len) {
			wolfSSL_ERR_error_string(e, tmp);
			XMEMCPY(buf, tmp, len-1);
			buf[len-1] = '\0';
		}
	}
}

unsigned long wolfSSL_ERR_peek_error(void)
{
	return 0;
}


int wolfSSL_ERR_GET_REASON(int err)
{
	(void)err;
	return 0;
}



