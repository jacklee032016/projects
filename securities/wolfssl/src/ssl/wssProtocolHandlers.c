
#include "cmnSsl.h"


/* Secure Renegotiation */
#ifdef HAVE_SECURE_RENEGOTIATION
/* user is forcing ability to use secure renegotiation, we discourage it */
int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl)
{
    int ret = BAD_FUNC_ARG;

    if (ssl)
        ret = TLSX_UseSecureRenegotiation(&ssl->extensions);

    if (ret == SSL_SUCCESS) {
        TLSX* extension = TLSX_Find(ssl->extensions, SECURE_RENEGOTIATION);
        
        if (extension)
            ssl->secure_renegotiation = (SecureRenegotiation*)extension->data;
    }

    return ret;
}


/* do a secure renegotiation handshake, user forced, we discourage */
int wolfSSL_Rehandshake(WOLFSSL* ssl)
{
    int ret;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->secure_renegotiation == NULL) {
        WOLFSSL_MSG("Secure Renegotiation not forced on by user");
        return SECURE_RENEGOTIATION_E;
    }

    if (ssl->secure_renegotiation->enabled == 0) {
        WOLFSSL_MSG("Secure Renegotiation not enabled at extension level");
        return SECURE_RENEGOTIATION_E;
    }

    if (ssl->options.handShakeState != HANDSHAKE_DONE) {
        WOLFSSL_MSG("Can't renegotiate until previous handshake complete");
        return SECURE_RENEGOTIATION_E;
    }

#ifndef NO_FORCE_SCR_SAME_SUITE
    /* force same suite */
    if (ssl->suites) {
        ssl->suites->suiteSz = SUITE_LEN;
        ssl->suites->suites[0] = ssl->options.cipherSuite0;
        ssl->suites->suites[1] = ssl->options.cipherSuite;
    }
#endif

    /* reset handshake states */
    ssl->options.serverState = NULL_STATE;
    ssl->options.clientState = NULL_STATE;
    ssl->options.connectState  = CONNECT_BEGIN;
    ssl->options.acceptState   = ACCEPT_BEGIN;
    ssl->options.handShakeState = NULL_STATE;
    ssl->options.processReply  = 0;  /* TODO, move states in internal.h */

    XMEMSET(&ssl->msgsReceived, 0, sizeof(ssl->msgsReceived));

    ssl->secure_renegotiation->cache_status = SCR_CACHE_NEEDED;

#ifndef NO_OLD_TLS
#ifndef NO_MD5
    wc_InitMd5(&ssl->hsHashes->hashMd5);
#endif
#ifndef NO_SHA
    ret = wc_InitSha(&ssl->hsHashes->hashSha);
    if (ret !=0)
        return ret;
#endif
#endif /* NO_OLD_TLS */
#ifndef NO_SHA256
    ret = wc_InitSha256(&ssl->hsHashes->hashSha256);
    if (ret !=0)
        return ret;
#endif
#ifdef WOLFSSL_SHA384
    ret = wc_InitSha384(&ssl->hsHashes->hashSha384);
    if (ret !=0)
        return ret;
#endif
#ifdef WOLFSSL_SHA512
    ret = wc_InitSha512(&ssl->hsHashes->hashSha512);
    if (ret !=0)
        return ret;
#endif

    ret = wolfSSL_negotiate(ssl);
    return ret;
}
#endif /* HAVE_SECURE_RENEGOTIATION */

/* return underlyig connect or accept, SSL_SUCCESS on ok */
int wolfSSL_negotiate(WOLFSSL* ssl)
{
	int err = SSL_FATAL_ERROR;

	WOLFSSL_ENTER();
#ifndef NO_WOLFSSL_SERVER
	if (ssl->options.side == WOLFSSL_SERVER_END)
		err = wolfSSL_accept(ssl);
#endif

#ifndef NO_WOLFSSL_CLIENT
	if (ssl->options.side == WOLFSSL_CLIENT_END)
		err = wolfSSL_connect(ssl);
#endif

	WOLFSSL_LEAVE( err);

	return err;
}


