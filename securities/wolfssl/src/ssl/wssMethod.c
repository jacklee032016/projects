/* tls.c
 */

#include "cmnSsl.h"


void InitSSL_Method(WOLFSSL_METHOD* method, ProtocolVersion pv)
{
    method->version    = pv;
    method->side       = WOLFSSL_CLIENT_END;
    method->downgrade  = 0;
}


#ifndef NO_TLS

#ifndef NO_OLD_TLS
/* ? return a structure, not a pointer in stack ??? */
ProtocolVersion MakeTLSv1(void)
{
	ProtocolVersion pv;
	pv.major = SSLv3_MAJOR;
	pv.minor = TLSv1_MINOR;

	return pv;
}

/* ? return a structure, not a pointer in stack ??? */
ProtocolVersion MakeTLSv1_1(void)
{
	ProtocolVersion pv;
	pv.major = SSLv3_MAJOR;
	pv.minor = TLSv1_1_MINOR;

	return pv;
}
#endif

/* ? return a structure, not a pointer in stack ??? */
ProtocolVersion MakeTLSv1_2(void)
{
	ProtocolVersion pv;
	pv.major = SSLv3_MAJOR;
	pv.minor = TLSv1_2_MINOR;

	return pv;
}


#ifndef NO_WOLFSSL_CLIENT

#ifndef NO_OLD_TLS
WOLFSSL_METHOD* wolfTLSv1_client_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0,	DYNAMIC_TYPE_METHOD);
	if (method)
		InitSSL_Method(method, MakeTLSv1());
	return method;
}


WOLFSSL_METHOD* wolfTLSv1_1_client_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0,	DYNAMIC_TYPE_METHOD);
	if (method)
		InitSSL_Method(method, MakeTLSv1_1());
	return method;
}
#endif /* !NO_OLD_TLS */


#ifndef NO_SHA256   /* can't use without SHA256 */
WOLFSSL_METHOD* wolfTLSv1_2_client_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0, DYNAMIC_TYPE_METHOD);
	if (method)
		InitSSL_Method(method, MakeTLSv1_2());
	return method;
}
#endif


WOLFSSL_METHOD* wolfSSLv23_client_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0, DYNAMIC_TYPE_METHOD);
	if (method) {
#ifndef NO_SHA256         /* 1.2 requires SHA256 */
		InitSSL_Method(method, MakeTLSv1_2());
#else
		InitSSL_Method(method, MakeTLSv1_1());
#endif
#ifndef NO_OLD_TLS
		method->downgrade = 1;
#endif
	}
	return method;
}

#endif /* NO_WOLFSSL_CLIENT */


#ifndef NO_WOLFSSL_SERVER
#ifndef NO_OLD_TLS
WOLFSSL_METHOD* wolfTLSv1_server_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0, DYNAMIC_TYPE_METHOD);
	if (method) {
		InitSSL_Method(method, MakeTLSv1());
		method->side = WOLFSSL_SERVER_END;
	}
	return method;
}

WOLFSSL_METHOD* wolfTLSv1_1_server_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0, DYNAMIC_TYPE_METHOD);
	if (method) {
		InitSSL_Method(method, MakeTLSv1_1());
		method->side = WOLFSSL_SERVER_END;
	}
	return method;
}

#endif /* !NO_OLD_TLS */

#ifndef NO_SHA256   /* can't use without SHA256 */
WOLFSSL_METHOD* wolfTLSv1_2_server_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0, DYNAMIC_TYPE_METHOD);
	if (method) {
		InitSSL_Method(method, MakeTLSv1_2());
		method->side = WOLFSSL_SERVER_END;
	}
	return method;
}
#endif


WOLFSSL_METHOD* wolfSSLv23_server_method(void)
{
	WOLFSSL_METHOD* method =(WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0, DYNAMIC_TYPE_METHOD);
	if (method) {
#ifndef NO_SHA256         /* 1.2 requires SHA256 */
		InitSSL_Method(method, MakeTLSv1_2());
#else
		InitSSL_Method(method, MakeTLSv1_1());
#endif
		method->side      = WOLFSSL_SERVER_END;
#ifndef NO_OLD_TLS
		method->downgrade = 1;
#endif /* !NO_OLD_TLS */
	}
	return method;
}

#endif /* NO_WOLFSSL_SERVER */

#endif  /* NO_TLS */


/* SSL and DTLS */
#ifndef NO_OLD_TLS

ProtocolVersion MakeSSLv3(void)
{
	ProtocolVersion pv;
	pv.major = SSLv3_MAJOR;
	pv.minor = SSLv3_MINOR;

	return pv;
}
#endif
#ifdef WOLFSSL_DTLS

ProtocolVersion MakeDTLSv1(void)
{
	ProtocolVersion pv;
	pv.major = DTLS_MAJOR;
	pv.minor = DTLS_MINOR;

	return pv;
}

ProtocolVersion MakeDTLSv1_2(void)
{
	ProtocolVersion pv;
	pv.major = DTLS_MAJOR;
	pv.minor = DTLSv1_2_MINOR;

	return pv;
}
#endif

#ifndef NO_WOLFSSL_CLIENT

#ifndef NO_OLD_TLS

WOLFSSL_METHOD* wolfSSLv3_client_method(void)
{
	WOLFSSL_METHOD* method =  (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0,	DYNAMIC_TYPE_METHOD);
	if (method)
		InitSSL_Method(method, MakeSSLv3());
	return method;
}
#endif


#ifdef WOLFSSL_DTLS


#ifndef NO_OLD_TLS
WOLFSSL_METHOD* wolfDTLSv1_client_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0,DYNAMIC_TYPE_METHOD);
	if (method)
		InitSSL_Method(method, MakeDTLSv1());
	return method;
}
#endif  /* NO_OLD_TLS */

WOLFSSL_METHOD* wolfDTLSv1_2_client_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0, DYNAMIC_TYPE_METHOD);
	if (method)
		InitSSL_Method(method, MakeDTLSv1_2());
	return method;
}

#endif /* WOLFSSL_DTLS */


/* please see note at top of README if you get an error from connect */
int wolfSSL_connect(WOLFSSL* ssl)
{
	int neededState;

	WOLFSSL_ENTER();

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif

	if (ssl->options.side != WOLFSSL_CLIENT_END)
	{
		WOLFSSL_ERROR(ssl->error = SIDE_ERROR);
		return SSL_FATAL_ERROR;
	}

#ifdef WOLFSSL_DTLS
	if (ssl->version.major == DTLS_MAJOR)
	{
		ssl->options.dtls   = 1;
		ssl->options.tls    = 1;
		ssl->options.tls1_1 = 1;

		if (DtlsPoolInit(ssl) != 0)
		{
			ssl->error = MEMORY_ERROR;
			WOLFSSL_ERROR(ssl->error);
			return SSL_FATAL_ERROR;
		}
	}
#endif

	if (ssl->buffers.outputBuffer.length > 0)
	{
		if ( (ssl->error = SendBuffered(ssl)) == 0)
		{
			ssl->options.connectState++;
			WOLFSSL_MSG("connect state: Advanced from buffered send");
		}
		else
		{
			WOLFSSL_ERROR(ssl->error);
			return SSL_FATAL_ERROR;
		}
	}

	switch (ssl->options.connectState)
	{

		case CONNECT_BEGIN :
			/* always send client hello first */
			if ( (ssl->error = SendClientHello(ssl)) != 0)
			{
				WOLFSSL_ERROR(ssl->error);
				return SSL_FATAL_ERROR;
			}
			ssl->options.connectState = CLIENT_HELLO_SENT;
			WOLFSSL_MSG("connect state: CLIENT_HELLO_SENT");

		case CLIENT_HELLO_SENT :
			neededState = ssl->options.resuming ? SERVER_FINISHED_COMPLETE : SERVER_HELLODONE_COMPLETE;
#ifdef WOLFSSL_DTLS
			/* In DTLS, when resuming, we can go straight to FINISHED,
			* or do a cookie exchange and then skip to FINISHED, assume
			* we need the cookie exchange first. */
			if (ssl->options.dtls)
				neededState = SERVER_HELLOVERIFYREQUEST_COMPLETE;
#endif
			/* get response */
			while (ssl->options.serverState < neededState)
			{
				if ( (ssl->error = ProcessReply(ssl)) < 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
				/* if resumption failed, reset needed state */
				else if (neededState == SERVER_FINISHED_COMPLETE)
					if (!ssl->options.resuming) {
						if (!ssl->options.dtls)
							neededState = SERVER_HELLODONE_COMPLETE;
						else
							neededState = SERVER_HELLOVERIFYREQUEST_COMPLETE;
					}
			}

			ssl->options.connectState = HELLO_AGAIN;
			WOLFSSL_MSG("connect state: HELLO_AGAIN");

		case HELLO_AGAIN :
			if (ssl->options.certOnly)
				return SSL_SUCCESS;

#ifdef WOLFSSL_DTLS
			if (ssl->options.dtls)
			{
				/* re-init hashes, exclude first hello and verify request */
#ifndef NO_OLD_TLS
				wc_InitMd5(&ssl->hsHashes->hashMd5);
				if ( (ssl->error = wc_InitSha(&ssl->hsHashes->hashSha)) != 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
#endif
				if (IsAtLeastTLSv1_2(ssl))
				{
#ifndef NO_SHA256
					if ( (ssl->error = wc_InitSha256(&ssl->hsHashes->hashSha256)) != 0) {
						WOLFSSL_ERROR(ssl->error);
						return SSL_FATAL_ERROR;
					}
#endif
#ifdef WOLFSSL_SHA384
					if ( (ssl->error = wc_InitSha384(&ssl->hsHashes->hashSha384)) != 0) {
						WOLFSSL_ERROR(ssl->error);
						return SSL_FATAL_ERROR;
					}
#endif
#ifdef WOLFSSL_SHA512
					if ( (ssl->error = wc_InitSha512( &ssl->hsHashes->hashSha512)) != 0) {
						WOLFSSL_ERROR(ssl->error);
						return SSL_FATAL_ERROR;
					}
#endif
				}
				if ( (ssl->error = SendClientHello(ssl)) != 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
			}
#endif

			ssl->options.connectState = HELLO_AGAIN_REPLY;
			WOLFSSL_MSG("connect state: HELLO_AGAIN_REPLY");

		case HELLO_AGAIN_REPLY :
#ifdef WOLFSSL_DTLS
			if (ssl->options.dtls) {
				neededState = ssl->options.resuming ? SERVER_FINISHED_COMPLETE : SERVER_HELLODONE_COMPLETE;

				/* get response */
				while (ssl->options.serverState < neededState) {
					if ( (ssl->error = ProcessReply(ssl)) < 0) {
						WOLFSSL_ERROR(ssl->error);
						return SSL_FATAL_ERROR;
					}
					/* if resumption failed, reset needed state */
					else if (neededState == SERVER_FINISHED_COMPLETE)
						if (!ssl->options.resuming)
							neededState = SERVER_HELLODONE_COMPLETE;
				}
			}
#endif

			ssl->options.connectState = FIRST_REPLY_DONE;
			WOLFSSL_MSG("connect state: FIRST_REPLY_DONE");

		case FIRST_REPLY_DONE :
#ifndef NO_CERTS
			if (ssl->options.sendVerify) {
				if ( (ssl->error = SendCertificate(ssl)) != 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
				WOLFSSL_MSG("sent: certificate");
			}

#endif
			ssl->options.connectState = FIRST_REPLY_FIRST;
			WOLFSSL_MSG("connect state: FIRST_REPLY_FIRST");

		case FIRST_REPLY_FIRST :
			if (!ssl->options.resuming) {
				if ( (ssl->error = SendClientKeyExchange(ssl)) != 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
				WOLFSSL_MSG("sent: client key exchange");
			}

			ssl->options.connectState = FIRST_REPLY_SECOND;
			WOLFSSL_MSG("connect state: FIRST_REPLY_SECOND");

		case FIRST_REPLY_SECOND :
#ifndef NO_CERTS
			if (ssl->options.sendVerify) {
				if ( (ssl->error = SendCertificateVerify(ssl)) != 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
				WOLFSSL_MSG("sent: certificate verify");
			}
#endif
			ssl->options.connectState = FIRST_REPLY_THIRD;
			WOLFSSL_MSG("connect state: FIRST_REPLY_THIRD");

		case FIRST_REPLY_THIRD :
			if ( (ssl->error = SendChangeCipher(ssl)) != 0) {
				WOLFSSL_ERROR(ssl->error);
				return SSL_FATAL_ERROR;
			}
			WOLFSSL_MSG("sent: change cipher spec");
			ssl->options.connectState = FIRST_REPLY_FOURTH;
			WOLFSSL_MSG("connect state: FIRST_REPLY_FOURTH");

		case FIRST_REPLY_FOURTH :
			if ( (ssl->error = SendFinished(ssl)) != 0) {
				WOLFSSL_ERROR(ssl->error);
				return SSL_FATAL_ERROR;
			}
			WOLFSSL_MSG("sent: finished");
			ssl->options.connectState = FINISHED_DONE;
			WOLFSSL_MSG("connect state: FINISHED_DONE");

		case FINISHED_DONE :
			/* get response */
			while (ssl->options.serverState < SERVER_FINISHED_COMPLETE)
				if ( (ssl->error = ProcessReply(ssl)) < 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}

			ssl->options.connectState = SECOND_REPLY_DONE;
			WOLFSSL_MSG("connect state: SECOND_REPLY_DONE");

		case SECOND_REPLY_DONE:
#ifndef NO_HANDSHAKE_DONE_CB
			if (ssl->hsDoneCb) {
				int cbret = ssl->hsDoneCb(ssl, ssl->hsDoneCtx);
				if (cbret < 0) {
					ssl->error = cbret;
					WOLFSSL_MSG("HandShake Done Cb don't continue error");
					return SSL_FATAL_ERROR;
				}
			}
#endif /* NO_HANDSHAKE_DONE_CB */
			FreeHandshakeResources(ssl);
			WOLFSSL_LEAVE( SSL_SUCCESS);
			return SSL_SUCCESS;

		default:
			WOLFSSL_MSG("Unknown connect state ERROR");
			return SSL_FATAL_ERROR; /* unknown connect state */
	}
}

#ifndef NO_WOLFSSL_CLIENT
/* connect enough to get peer cert chain */
int wolfSSL_connect_cert(WOLFSSL* ssl)
{
    int  ret;

    if (ssl == NULL)
        return SSL_FAILURE;

    ssl->options.certOnly = 1;
    ret = wolfSSL_connect(ssl);
    ssl->options.certOnly   = 0;

    return ret;
}
#endif

#endif /* NO_WOLFSSL_CLIENT */


/* server only parts */
#ifndef NO_WOLFSSL_SERVER

#ifndef NO_OLD_TLS
WOLFSSL_METHOD* wolfSSLv3_server_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0,	DYNAMIC_TYPE_METHOD);
	if (method) {
		InitSSL_Method(method, MakeSSLv3());
		method->side = WOLFSSL_SERVER_END;
	}
	return method;
}
#endif


#ifdef WOLFSSL_DTLS

#ifndef NO_OLD_TLS
WOLFSSL_METHOD* wolfDTLSv1_server_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),0, DYNAMIC_TYPE_METHOD);
	if (method) {
		InitSSL_Method(method, MakeDTLSv1());
		method->side = WOLFSSL_SERVER_END;
	}
	return method;
}
#endif /* NO_OLD_TLS */

WOLFSSL_METHOD* wolfDTLSv1_2_server_method(void)
{
	WOLFSSL_METHOD* method = (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 0, DYNAMIC_TYPE_METHOD);
	if (method) {
		InitSSL_Method(method, MakeDTLSv1_2());
		method->side = WOLFSSL_SERVER_END;
	}
	return method;
}
#endif


int wolfSSL_accept(WOLFSSL* ssl)
{
	byte havePSK = 0;
	byte haveAnon = 0;
	WOLFSSL_ENTER();

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif

#ifndef NO_PSK
	havePSK = ssl->options.havePSK;
#endif
	(void)havePSK;

#ifdef HAVE_ANON
	haveAnon = ssl->options.haveAnon;
#endif
	(void)haveAnon;

	if (ssl->options.side != WOLFSSL_SERVER_END) {
		WOLFSSL_ERROR(ssl->error = SIDE_ERROR);
		return SSL_FATAL_ERROR;
	}

#ifndef NO_CERTS
	/* in case used set_accept_state after init */
	if (!havePSK && !haveAnon && (ssl->buffers.certificate.buffer == NULL ||ssl->buffers.key.buffer == NULL)) {
		WOLFSSL_MSG("accept error: don't have server cert and key");
		ssl->error = NO_PRIVATE_KEY;
		WOLFSSL_ERROR(ssl->error);
		return SSL_FATAL_ERROR;
	}
#endif

#ifdef WOLFSSL_DTLS
	if (ssl->version.major == DTLS_MAJOR) {
		ssl->options.dtls   = 1;
		ssl->options.tls    = 1;
		ssl->options.tls1_1 = 1;

		if (DtlsPoolInit(ssl) != 0) {
			ssl->error = MEMORY_ERROR;
			WOLFSSL_ERROR(ssl->error);
			return SSL_FATAL_ERROR;
		}
	}
#endif

	if (ssl->buffers.outputBuffer.length > 0) {
		if ( (ssl->error = SendBuffered(ssl)) == 0) {
			ssl->options.acceptState++;
			WOLFSSL_MSG("accept state: Advanced from buffered send");
		}
		else {
			WOLFSSL_ERROR(ssl->error);
			return SSL_FATAL_ERROR;
		}
	}

	switch (ssl->options.acceptState)
	{

		case ACCEPT_BEGIN :
			/* get response */
			while (ssl->options.clientState < CLIENT_HELLO_COMPLETE)
				if ( (ssl->error = ProcessReply(ssl)) < 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
			ssl->options.acceptState = ACCEPT_CLIENT_HELLO_DONE;
			WOLFSSL_MSG("accept state ACCEPT_CLIENT_HELLO_DONE");

		case ACCEPT_CLIENT_HELLO_DONE :
#ifdef WOLFSSL_DTLS
			if (ssl->options.dtls)
				if ( (ssl->error = SendHelloVerifyRequest(ssl)) != 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
#endif
			ssl->options.acceptState = HELLO_VERIFY_SENT;
			WOLFSSL_MSG("accept state HELLO_VERIFY_SENT");

		case HELLO_VERIFY_SENT:
#ifdef WOLFSSL_DTLS
			if (ssl->options.dtls)
			{
				ssl->options.clientState = NULL_STATE;  /* get again */
				/* reset messages received */
				XMEMSET(&ssl->msgsReceived, 0, sizeof(ssl->msgsReceived));
				/* re-init hashes, exclude first hello and verify request */
#ifndef NO_OLD_TLS
				wc_InitMd5(&ssl->hsHashes->hashMd5);
				if ( (ssl->error = wc_InitSha(&ssl->hsHashes->hashSha)) != 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
#endif
				if (IsAtLeastTLSv1_2(ssl))
				{
#ifndef NO_SHA256
					if ( (ssl->error = wc_InitSha256(&ssl->hsHashes->hashSha256)) != 0) {
						WOLFSSL_ERROR(ssl->error);
						return SSL_FATAL_ERROR;
					}
#endif
#ifdef WOLFSSL_SHA384
					if ( (ssl->error = wc_InitSha384( &ssl->hsHashes->hashSha384)) != 0) {
						WOLFSSL_ERROR(ssl->error);
						return SSL_FATAL_ERROR;
					}
#endif
#ifdef WOLFSSL_SHA512
					if ( (ssl->error = wc_InitSha512( &ssl->hsHashes->hashSha512)) != 0) {
						WOLFSSL_ERROR(ssl->error);
						return SSL_FATAL_ERROR;
					}
#endif
				}

				while (ssl->options.clientState < CLIENT_HELLO_COMPLETE)
					if ( (ssl->error = ProcessReply(ssl)) < 0) {
						WOLFSSL_ERROR(ssl->error);
						return SSL_FATAL_ERROR;
					}
			}
#endif
			ssl->options.acceptState = ACCEPT_FIRST_REPLY_DONE;
			WOLFSSL_MSG("accept state ACCEPT_FIRST_REPLY_DONE");

		case ACCEPT_FIRST_REPLY_DONE :
			if ( (ssl->error = SendServerHello(ssl)) != 0) {
				WOLFSSL_ERROR(ssl->error);
				return SSL_FATAL_ERROR;
			}
			ssl->options.acceptState = SERVER_HELLO_SENT;
			WOLFSSL_MSG("accept state SERVER_HELLO_SENT");

		case SERVER_HELLO_SENT :
#ifndef NO_CERTS
			if (!ssl->options.resuming)
				if ( (ssl->error = SendCertificate(ssl)) != 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
#endif
			ssl->options.acceptState = CERT_SENT;
			WOLFSSL_MSG("accept state CERT_SENT");

		case CERT_SENT :
			if (!ssl->options.resuming)
				if ( (ssl->error = SendServerKeyExchange(ssl)) != 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
			ssl->options.acceptState = KEY_EXCHANGE_SENT;
			WOLFSSL_MSG("accept state KEY_EXCHANGE_SENT");

		case KEY_EXCHANGE_SENT :
#ifndef NO_CERTS
			if (!ssl->options.resuming)
				if (ssl->options.verifyPeer)
					if ( (ssl->error = SendCertificateRequest(ssl)) != 0) {
						WOLFSSL_ERROR(ssl->error);
						return SSL_FATAL_ERROR;
					}
#endif
			ssl->options.acceptState = CERT_REQ_SENT;
			WOLFSSL_MSG("accept state CERT_REQ_SENT");

		case CERT_REQ_SENT :
			if (!ssl->options.resuming)
				if ( (ssl->error = SendServerHelloDone(ssl)) != 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
			ssl->options.acceptState = SERVER_HELLO_DONE;
			WOLFSSL_MSG("accept state SERVER_HELLO_DONE");

		case SERVER_HELLO_DONE :
			if (!ssl->options.resuming) {
				while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE)
					if ( (ssl->error = ProcessReply(ssl)) < 0) {
						WOLFSSL_ERROR(ssl->error);
						return SSL_FATAL_ERROR;
					}
			}
			ssl->options.acceptState = ACCEPT_SECOND_REPLY_DONE;
			WOLFSSL_MSG("accept state  ACCEPT_SECOND_REPLY_DONE");

		case ACCEPT_SECOND_REPLY_DONE :
#ifdef HAVE_SESSION_TICKET
			if (ssl->options.createTicket) {
				if ( (ssl->error = SendTicket(ssl)) != 0) {
					WOLFSSL_ERROR(ssl->error);
					return SSL_FATAL_ERROR;
				}
			}
#endif /* HAVE_SESSION_TICKET */
			ssl->options.acceptState = TICKET_SENT;
			WOLFSSL_MSG("accept state  TICKET_SENT");

		case TICKET_SENT:
			if ( (ssl->error = SendChangeCipher(ssl)) != 0) {
			WOLFSSL_ERROR(ssl->error);
			return SSL_FATAL_ERROR;
			}
			ssl->options.acceptState = CHANGE_CIPHER_SENT;
			WOLFSSL_MSG("accept state  CHANGE_CIPHER_SENT");

		case CHANGE_CIPHER_SENT :
			if ( (ssl->error = SendFinished(ssl)) != 0) {
			WOLFSSL_ERROR(ssl->error);
			return SSL_FATAL_ERROR;
			}

			ssl->options.acceptState = ACCEPT_FINISHED_DONE;
			WOLFSSL_MSG("accept state ACCEPT_FINISHED_DONE");

		case ACCEPT_FINISHED_DONE :
			if (ssl->options.resuming)
			while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE)
			if ( (ssl->error = ProcessReply(ssl)) < 0) {
			WOLFSSL_ERROR(ssl->error);
			return SSL_FATAL_ERROR;
			}

			ssl->options.acceptState = ACCEPT_THIRD_REPLY_DONE;
			WOLFSSL_MSG("accept state ACCEPT_THIRD_REPLY_DONE");

		case ACCEPT_THIRD_REPLY_DONE :
#ifndef NO_HANDSHAKE_DONE_CB
			if (ssl->hsDoneCb) {
				int cbret = ssl->hsDoneCb(ssl, ssl->hsDoneCtx);
				if (cbret < 0) {
					ssl->error = cbret;
					WOLFSSL_MSG("HandShake Done Cb don't continue error");
					return SSL_FATAL_ERROR;
				}
			}
#endif /* NO_HANDSHAKE_DONE_CB */
			FreeHandshakeResources(ssl);
			WOLFSSL_LEAVE( SSL_SUCCESS);
			return SSL_SUCCESS;

		default :
			WOLFSSL_MSG("Unknown accept state ERROR");
			return SSL_FATAL_ERROR;
	}
}

#endif /* NO_WOLFSSL_SERVER */


