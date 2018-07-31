
#include "cmnSsl.h"

int wolfSSL_Init(void)
{
	int ret = SSL_SUCCESS;

	if (initRefCount == 0) {
#ifndef NO_SESSION_CACHE
		if (InitMutex(&session_mutex) != 0)
			ret = BAD_MUTEX_E;
#endif
		if (InitMutex(&count_mutex) != 0)
			ret = BAD_MUTEX_E;
	}
	
	if (ret == SSL_SUCCESS) {
		if (LockMutex(&count_mutex) != 0) {
			WOLFSSL_MSG("Bad Lock Mutex count");
			return BAD_MUTEX_E;
		}
		initRefCount++;
		UnLockMutex(&count_mutex);
	}

	return ret;
}


int wolfSSL_library_init(void)
{
	if (wolfSSL_Init() == SSL_SUCCESS)
		return SSL_SUCCESS;
	else
		return SSL_FATAL_ERROR;
}



int wolfSSL_Cleanup(void)
{
	int ret = SSL_SUCCESS;
	int release = 0;

	WOLFSSL_ENTER();

	if (initRefCount == 0)
		return ret;  /* possibly no init yet, but not failure either way */

	if (LockMutex(&count_mutex) != 0) {
		WOLFSSL_MSG("Bad Lock Mutex count");
		return BAD_MUTEX_E;
	}

	release = initRefCount-- == 1;
	if (initRefCount < 0)
		initRefCount = 0;

	UnLockMutex(&count_mutex);

	if (!release)
		return ret;

#ifndef NO_SESSION_CACHE
	if (FreeMutex(&session_mutex) != 0)
		ret = BAD_MUTEX_E;
#endif
	if (FreeMutex(&count_mutex) != 0)
		ret = BAD_MUTEX_E;

#if defined(HAVE_ECC) && defined(FP_ECC)
	wc_ecc_fp_free();
#endif

	return ret;
}


/* SSL_SUCCESS on ok */
int wolfSSL_shutdown(WOLFSSL* ssl)
{
	int  ret = SSL_FATAL_ERROR;
	byte tmp;
	WOLFSSL_ENTER();

	if (ssl == NULL)
		return SSL_FATAL_ERROR;

	if (ssl->options.quietShutdown) {
		WOLFSSL_MSG("quiet shutdown, no close notify sent");
		return SSL_SUCCESS;
	}

	/* try to send close notify, not an error if can't */
	if (!ssl->options.isClosed && !ssl->options.connReset && !ssl->options.sentNotify)
	{
		ssl->error = SendAlert(ssl, alert_warning, close_notify);
		if (ssl->error < 0) {
			WOLFSSL_ERROR(ssl->error);
			return SSL_FATAL_ERROR;
		}
		ssl->options.sentNotify = 1;  /* don't send close_notify twice */
		if (ssl->options.closeNotify)
			ret = SSL_SUCCESS;
		else
			ret = SSL_SHUTDOWN_NOT_DONE;

		WOLFSSL_LEAVE( ret);
		return ret;
	}

	/* call wolfSSL_shutdown again for bidirectional shudown */
	if (ssl->options.sentNotify && !ssl->options.closeNotify) {
		ret = wolfSSL_read(ssl, &tmp, 0);
		if (ret < 0) {
			WOLFSSL_ERROR(ssl->error);
			ret = SSL_FATAL_ERROR;
		}
		else if (ssl->options.closeNotify) {
			ssl->error = SSL_ERROR_SYSCALL;   /* simulate OpenSSL behavior */
			ret = SSL_SUCCESS;
		}
	}

	WOLFSSL_LEAVE( ret);

	return ret;
}


/* retrive alert history, SSL_SUCCESS on ok */
int wolfSSL_get_alert_history(WOLFSSL* ssl, WOLFSSL_ALERT_HISTORY *h)
{
	if (ssl && h) {
		*h = ssl->alert_history;
	}
	return SSL_SUCCESS;
}


/* return TRUE if current error is want read */
int wolfSSL_want_read(WOLFSSL* ssl)
{
	WOLFSSL_ENTER();
	if (ssl->error == WANT_READ)
		return 1;

	return 0;
}


/* return TRUE if current error is want write */
int wolfSSL_want_write(WOLFSSL* ssl)
{
	WOLFSSL_ENTER();
    if (ssl->error == WANT_WRITE)
        return 1;

    return 0;
}


/* don't free temporary arrays at end of handshake */
void wolfSSL_KeepArrays(WOLFSSL* ssl)
{
    if (ssl)
        ssl->options.saveArrays = 1;
}


/* user doesn't need temporary arrays anymore, Free */
void wolfSSL_FreeArrays(WOLFSSL* ssl)
{
    if (ssl && ssl->options.handShakeState == HANDSHAKE_DONE) {
        ssl->options.saveArrays = 0;
        FreeArrays(ssl, 1);
    }
}


const byte* wolfSSL_GetMacSecret(WOLFSSL* ssl, int verify)
{
    if (ssl == NULL)
        return NULL;

    if ( (ssl->options.side == WOLFSSL_CLIENT_END && !verify) ||
         (ssl->options.side == WOLFSSL_SERVER_END &&  verify) )
        return ssl->keys.client_write_MAC_secret;
    else
        return ssl->keys.server_write_MAC_secret;
}

/* current library version */
const char* wolfSSL_lib_version(void)
{
	return LIBWOLFSSL_VERSION_STRING;
}


/* current library version in hex */
word32 wolfSSL_lib_version_hex(void)
{
	return LIBWOLFSSL_VERSION_HEX;
}


WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD* method)
{
	WOLFSSL_CTX* ctx = NULL;

	if (initRefCount == 0)
		wolfSSL_Init(); /* user no longer forced to call Init themselves */

	if (method == NULL)
		return ctx;

	ctx = (WOLFSSL_CTX*) XMALLOC(sizeof(WOLFSSL_CTX), 0, DYNAMIC_TYPE_CTX);
	if (ctx) {
		if (InitSSL_Ctx(ctx, method) < 0) {
			WOLFSSL_MSG("Init CTX failed");
			wolfSSL_CTX_free(ctx);
			ctx = NULL;
		}
	}
	else {
		WOLFSSL_MSG("Alloc CTX failed, method freed");
		XFREE(method, NULL, DYNAMIC_TYPE_METHOD);
	}

	return ctx;
}


void wolfSSL_CTX_free(WOLFSSL_CTX* ctx)
{
	if (ctx)
		FreeSSL_Ctx(ctx);
}


WOLFSSL* wolfSSL_new(WOLFSSL_CTX* ctx)
{
	WOLFSSL* ssl = NULL;
	int ret = 0;

	if (ctx == NULL)
		return ssl;

	ssl = (WOLFSSL*) XMALLOC(sizeof(WOLFSSL), ctx->heap,DYNAMIC_TYPE_SSL);
	if (ssl)
	{
		if ( (ret = InitSSL(ssl, ctx)) < 0) {
			FreeSSL(ssl);
			ssl = 0;
		}
	}

	return ssl;
}


void wolfSSL_free(WOLFSSL* ssl)
{
	if (ssl)
		FreeSSL(ssl);
}

WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew(void)
{
	WOLFSSL_CERT_MANAGER* cm = NULL;

	cm = (WOLFSSL_CERT_MANAGER*) XMALLOC(sizeof(WOLFSSL_CERT_MANAGER), 0, DYNAMIC_TYPE_CERT_MANAGER);
	if (cm) {
		XMEMSET(cm, 0, sizeof(WOLFSSL_CERT_MANAGER));

		if (InitMutex(&cm->caLock) != 0) {
			WOLFSSL_MSG("Bad mutex init");
			wolfSSL_CertManagerFree(cm);
			return NULL;
		}
	}

	return cm;
}


void wolfSSL_CertManagerFree(WOLFSSL_CERT_MANAGER* cm)
{
	if (cm) {
#ifdef HAVE_CRL
		if (cm->crl)
			FreeCRL(cm->crl, 1);
#endif
#ifdef HAVE_OCSP
		if (cm->ocsp)
			FreeOCSP(cm->ocsp, 1);
#endif
		FreeSignerTable(cm->caTable, CA_TABLE_SIZE, NULL);
		FreeMutex(&cm->caLock);
		XFREE(cm, NULL, DYNAMIC_TYPE_CERT_MANAGER);
	}

}


/* Unload the CA signer list */
int wolfSSL_CertManagerUnloadCAs(WOLFSSL_CERT_MANAGER* cm)
{
    if (cm == NULL)
        return BAD_FUNC_ARG;

    if (LockMutex(&cm->caLock) != 0)
        return BAD_MUTEX_E;

    FreeSignerTable(cm->caTable, CA_TABLE_SIZE, NULL);

    UnLockMutex(&cm->caLock);


    return SSL_SUCCESS;
}



