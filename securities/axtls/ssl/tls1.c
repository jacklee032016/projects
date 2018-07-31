/**
 * Common ssl/tlsv1 code to both the client and server implementations.
 */

#include "tls.h"

/* The session expiry time */
#define SSL_EXPIRY_TIME     (CONFIG_SSL_EXPIRY_TIME*3600)


/**
 * The server will pick the cipher based on the order that the order that the
 * ciphers are listed. This order is defined at compile time.
 */
#ifdef CONFIG_SSL_SKELETON_MODE
	const uint8_t ssl_prot_prefs[NUM_PROTOCOLS] = { CST_RC4_128_SHA };
#else

	const uint8_t ssl_prot_prefs[NUM_PROTOCOLS] = 
#ifdef CONFIG_SSL_PROT_LOW                  /* low security, fast speed */
	{ CST_RC4_128_SHA, CST_AES128_CBC_SHA, CST_AES256_CBC_SHA, CST_RC4_128_MD5 };
#elif CONFIG_SSL_PROT_MEDIUM                /* medium security, medium speed */
	{ CST_AES128_CBC_SHA, CST_AES256_CBC_SHA, CST_RC4_128_SHA, CST_RC4_128_MD5 };    
#else /* CONFIG_SSL_PROT_HIGH */            /* high security, low speed */
	{ CST_AES256_CBC_SHA, CST_AES128_CBC_SHA, CST_RC4_128_SHA, CST_RC4_128_MD5 };
#endif

static void session_free(SSL_SESSION *ssl_sessions[], int sess_index)
{
	if (ssl_sessions[sess_index])
	{
		free(ssl_sessions[sess_index]);
		ssl_sessions[sess_index] = NULL;
	}
}

#endif /* CONFIG_SSL_SKELETON_MODE */


/**
 * Establish a new client/server context.
 */
EXP_FUNC SSL_CTX *STDCALL ssl_ctx_new(uint32_t options, int num_sessions)
{
	SSL_CTX *ctx = (SSL_CTX *)calloc(1, sizeof (SSL_CTX));
	ctx->options = options;
	RNG_initialize();

#if 1
	if (load_key_certs(ctx) < 0)
	{
		free(ctx);  /* can't load our key/certificate pair, so die */
		return NULL;
	}
#endif

#ifndef CONFIG_SSL_SKELETON_MODE
	ctx->num_sessions = num_sessions;
#endif

	SSL_CTX_MUTEX_INIT(ctx->mutex);

#ifndef CONFIG_SSL_SKELETON_MODE
	if (num_sessions)
	{
		ctx->ssl_sessions = (SSL_SESSION **) calloc(1, num_sessions*sizeof(SSL_SESSION *));
	}
#endif

	return ctx;
}

/*
 * Remove a client/server context.
 */
EXP_FUNC void STDCALL ssl_ctx_free(SSL_CTX *ctx)
{
	SSL *ssl;
	int i;

	if (ctx == NULL)
		return;

	ssl = ctx->head;

	/* clear out all the ssl entries */
	while (ssl)
	{
		SSL *next = ssl->next;
		ssl_free(ssl);
		ssl = next;
	}

#ifndef CONFIG_SSL_SKELETON_MODE
	/* clear out all the sessions */
	for (i = 0; i < ctx->num_sessions; i++)
		session_free(ctx->ssl_sessions, i);

	free(ctx->ssl_sessions);
#endif

	i = 0;
	while (i < CONFIG_SSL_MAX_CERTS && ctx->certs[i].buf)
	{
		free(ctx->certs[i].buf);
		ctx->certs[i++].buf = NULL;
	}

#ifdef CONFIG_SSL_CERT_VERIFICATION
	remove_ca_certs(ctx->ca_cert_ctx);
#endif
	ctx->chain_length = 0;
	SSL_CTX_MUTEX_DESTROY(ctx->mutex);
	RSA_free(ctx->rsa_ctx);
	RNG_terminate();
	free(ctx);
}


/*
 * Get a new ssl context for a new connection.
 */
SSL *ssl_new(SSL_CTX *ctx, int client_fd)
{
	SSL *ssl = (SSL *)calloc(1, sizeof(SSL));
	ssl->ctx = ctx;
	ssl->need_bytes = SSL_RECORD_SIZE;      /* need a record */
	ssl->client_fd = client_fd;
	ssl->flag = SSL_NEED_RECORD;
	ssl->bm_data = ssl->bm_all_data+BM_RECORD_OFFSET; /* space at the start */
	ssl->hs_status = SSL_NOT_OK;            /* not connected */
#ifdef CONFIG_ENABLE_VERIFICATION
	ssl->ca_cert_ctx = ctx->ca_cert_ctx;
#endif
	disposable_new(ssl);

	/* a bit hacky but saves a few bytes of memory */
	ssl->flag |= ctx->options;
	SSL_CTX_LOCK(ctx->mutex);

	if (ctx->head == NULL)
	{
		ctx->head = ssl;
		ctx->tail = ssl;
	}
	else
	{
		ssl->prev = ctx->tail;
		ctx->tail->next = ssl;
		ctx->tail = ssl;
	}

	SSL_CTX_UNLOCK(ctx->mutex);
	return ssl;
}

/*
 * Free any used resources used by this connection.
 */
EXP_FUNC void STDCALL ssl_free(SSL *ssl)
{
	SSL_CTX *ctx;

	if (ssl == NULL)/* just ignore null pointers */
		return;

	/* only notify if we weren't notified first */
	/* spec says we must notify when we are dying */
	if (!IS_SET_SSL_FLAG(SSL_SENT_CLOSE_NOTIFY))
		send_alert(ssl, TLS_ALERT_CLOSE_NOTIFY);

	ctx = ssl->ctx;
	SSL_CTX_LOCK(ctx->mutex);

	/* adjust the server SSL list */
	if (ssl->prev)
		ssl->prev->next = ssl->next;
	else
		ctx->head = ssl->next;

	if (ssl->next)
		ssl->next->prev = ssl->prev;
	else
		ctx->tail = ssl->prev;

	SSL_CTX_UNLOCK(ctx->mutex);

	/* may already be free - but be sure */
	free(ssl->encrypt_ctx);
	free(ssl->decrypt_ctx);
	disposable_free(ssl);
#ifdef CONFIG_SSL_CERT_VERIFICATION
	x509_free(ssl->x509_ctx);
#endif

	free(ssl);
}


/**
 * Add a certificate to the certificate chain. buf: binary data, not coded in DER or PEM format
 */
int STDCALL add_cert(SSL_CTX *ctx, const uint8_t *buf, int len)
{
	int ret = SSL_ERROR_NO_CERT_DEFINED, i = 0;
	SSL_CERT *ssl_cert;
	X509 *_x509 = NULL;
	int offset;

	while (i < CONFIG_SSL_MAX_CERTS && ctx->certs[i].buf) 
		i++;

	if (i == CONFIG_SSL_MAX_CERTS) /* too many certs */
	{
#ifdef CONFIG_SSL_FULL_MODE
		AX_LOG("Error: maximum number of certs added (%d) - change of compile-time configuration required\n",
			CONFIG_SSL_MAX_CERTS);
#endif
		goto error;
	}

	/* x509 only used for error check */
	if ((ret = x509_new(buf, &offset, &_x509)))
		goto error;

#if defined (CONFIG_SSL_FULL_MODE)
	if (ctx->options & SSL_DISPLAY_CERTS)
		x509_print(_x509, NULL);
#endif

	AX_DEBUG("No.%d Cert of '%s' has been added\n", i, _x509->dn[X509_COMMON_NAME] );
	ssl_cert = &ctx->certs[i];
	ssl_cert->size = len;
	ssl_cert->buf = (uint8_t *)malloc(len);
	memcpy(ssl_cert->buf, buf, len);
	ctx->chain_length++;
	len -= offset;
	ret = SSL_OK;           /* ok so far */

	/* recurse? */
	if (len > 0)
	{
		ret = add_cert(ctx, &buf[offset], len);
	}

error:
	x509_free(_x509);        /* don't need anymore */
	return ret;
}


/*
 * Add a private key to a context.
 */
int add_private_key(SSL_CTX *ctx, SSLObjLoader *ssl_obj)
{
	int ret = SSL_OK;

	/* get the private key details */
	if (asn1_get_private_key(ssl_obj->buf, ssl_obj->len, &ctx->rsa_ctx))
	{
		ret = SSL_ERROR_INVALID_KEY;
		goto error;
	}

error:
	return ret;
}

#ifdef CONFIG_SSL_CERT_VERIFICATION
/**
 * Add a certificate authority. buf: binary data, not coded in DER or PEM format
 */
EXP_FUNC int STDCALL add_cert_auth(SSL_CTX *ctx, const uint8_t *buf, int len)
{
	int ret = X509_OK; /* ignore errors for now */
	int i = 0;
	CA_CERT *ca_cert_ctx;

	if (ctx->ca_cert_ctx == NULL)
		ctx->ca_cert_ctx = (CA_CERT *)calloc(1, sizeof(CA_CERT));

	ca_cert_ctx = ctx->ca_cert_ctx;

	while (i < CONFIG_X509_MAX_CA_CERTS && ca_cert_ctx->cert[i]) 
		i++;

	while (len > 0)
	{
		int offset;
		AX_DEBUG("No. %d CA Certs is adding...\n", i+1);
		if (i >= CONFIG_X509_MAX_CA_CERTS)
		{
#ifdef CONFIG_SSL_FULL_MODE
			AX_LOG("Error: maximum number of CA certs added (%d) - change of compile-time configuration required\n", CONFIG_X509_MAX_CA_CERTS);
#endif
			ret = X509_MAX_CERTS;
			break;
		}

		/* ignore the return code */
		if (x509_new(buf, &offset, &ca_cert_ctx->cert[i]) == X509_OK)
		{
#if defined (CONFIG_SSL_FULL_MODE)
			if (ctx->options & SSL_DISPLAY_CERTS)
				x509_print(ca_cert_ctx->cert[i], NULL);
#endif
		}

		i++;
		len -= offset;
	}

	return ret;
}


/*
 * Retrieve an X.509 distinguished name component
 */
EXP_FUNC const char * STDCALL ssl_get_cert_dn(const SSL *ssl, int component)
{
    if (ssl->x509_ctx == NULL)
        return NULL;

    switch (component)
    {
        case SSL_X509_CERT_COMMON_NAME:
            return ssl->x509_ctx->dn[X509_COMMON_NAME];

        case SSL_X509_CERT_ORGANIZATION:
            return ssl->x509_ctx->dn[X509_ORGANIZATION];

        case SSL_X509_CERT_ORGANIZATIONAL_NAME:       
            return ssl->x509_ctx->dn[X509_ORGANIZATIONAL_UNIT];

        case SSL_X509_CA_CERT_COMMON_NAME:
            return ssl->x509_ctx->caDn[X509_COMMON_NAME];

        case SSL_X509_CA_CERT_ORGANIZATION:
            return ssl->x509_ctx->caDn[X509_ORGANIZATION];

        case SSL_X509_CA_CERT_ORGANIZATIONAL_NAME:       
            return ssl->x509_ctx->caDn[X509_ORGANIZATIONAL_UNIT];

        default:
            return NULL;
    }
}

/*
 * Retrieve a "Subject Alternative Name" from a v3 certificate
 */
EXP_FUNC const char * STDCALL ssl_get_cert_subject_alt_dnsname(const SSL *ssl, int dnsindex)
{
    int i;

    if (ssl->x509_ctx == NULL || ssl->x509_ctx->subject_alt_dnsnames == NULL)
        return NULL;

    for (i = 0; i < dnsindex; ++i)
    {
        if (ssl->x509_ctx->subject_alt_dnsnames[i] == NULL)
            return NULL;
    }

    return ssl->x509_ctx->subject_alt_dnsnames[dnsindex];
}

#endif /* CONFIG_SSL_CERT_VERIFICATION */

/*
 * Find an ssl object based on the client's file descriptor.
 */
EXP_FUNC SSL * STDCALL ssl_find(SSL_CTX *ctx, int client_fd)
{
    SSL *ssl;

    SSL_CTX_LOCK(ctx->mutex);
    ssl = ctx->head;

    /* search through all the ssl entries */
    while (ssl)
    {
        if (ssl->client_fd == client_fd)
        {
            SSL_CTX_UNLOCK(ctx->mutex);
            return ssl;
        }

        ssl = ssl->next;
    }

    SSL_CTX_UNLOCK(ctx->mutex);
    return NULL;
}


/**
 * Create a blob of memory that we'll get rid of once the handshake is complete.
 */
void disposable_new(SSL *ssl)
{
	if (ssl->dc == NULL)
	{
		ssl->dc = (DISPOSABLE_CTX *)calloc(1, sizeof(DISPOSABLE_CTX));
		MD5_Init(&ssl->dc->md5_ctx);
		SHA1_Init(&ssl->dc->sha1_ctx);
	}
}

/**
 * Remove the temporary blob of memory.
 */
void disposable_free(SSL *ssl)
{
	if (ssl->dc)
	{
		free(ssl->dc->key_block);
		memset(ssl->dc, 0, sizeof(DISPOSABLE_CTX));
		free(ssl->dc);
		ssl->dc = NULL;
	}
}

#ifndef CONFIG_SSL_SKELETON_MODE     /* no session resumption in this mode */
/**
 * Find if an existing session has the same session id. If so, use the
 * master secret from this session for session resumption.
 */
SSL_SESSION *ssl_session_update(int max_sessions, SSL_SESSION *ssl_sessions[], 
        SSL *ssl, const uint8_t *session_id)
{
    time_t tm = time(NULL);
    time_t oldest_sess_time = tm;
    SSL_SESSION *oldest_sess = NULL;
    int i;

    /* no sessions? Then bail */
    if (max_sessions == 0)
        return NULL;

    SSL_CTX_LOCK(ssl->ctx->mutex);
    if (session_id)
    {
        for (i = 0; i < max_sessions; i++)
        {
            if (ssl_sessions[i])
            {
                /* kill off any expired sessions (including those in the future) */
                if ((tm > ssl_sessions[i]->conn_time + SSL_EXPIRY_TIME) ||(tm < ssl_sessions[i]->conn_time))
                {
                    session_free(ssl_sessions, i);
                    continue;
                }

                /* if the session id matches, it must still be less than the expiry time */
                if (memcmp(ssl_sessions[i]->session_id, session_id, SSL_SESSION_ID_SIZE) == 0)
                {
                    ssl->session_index = i;
                    memcpy(ssl->dc->master_secret, ssl_sessions[i]->master_secret, SSL_MASTER_SECRET_SIZE);
                    SET_SSL_FLAG(SSL_SESSION_RESUME);
                    SSL_CTX_UNLOCK(ssl->ctx->mutex);
                    return ssl_sessions[i];  /* a session was found */
                }
            }
        }
    }

    /* If we've got here, no matching session was found - so create one */
    for (i = 0; i < max_sessions; i++)
    {
        if (ssl_sessions[i] == NULL)
        {
            /* perfect, this will do */
            ssl_sessions[i] = (SSL_SESSION *)calloc(1, sizeof(SSL_SESSION));
            ssl_sessions[i]->conn_time = tm;
            ssl->session_index = i;
            SSL_CTX_UNLOCK(ssl->ctx->mutex);
            return ssl_sessions[i]; /* return the session object */
        }
        else if (ssl_sessions[i]->conn_time <= oldest_sess_time)
        {
            /* find the oldest session */
            oldest_sess_time = ssl_sessions[i]->conn_time;
            oldest_sess = ssl_sessions[i];
            ssl->session_index = i;
        }
    }

    /* ok, we've used up all of our sessions. So blow the oldest session away */
    oldest_sess->conn_time = tm;
    memset(oldest_sess->session_id, 0, sizeof(SSL_SESSION_ID_SIZE));
    memset(oldest_sess->master_secret, 0, sizeof(SSL_MASTER_SECRET_SIZE));
    SSL_CTX_UNLOCK(ssl->ctx->mutex);
    return oldest_sess;
}

/**
 * This ssl object doesn't want this session anymore.
 */
void kill_ssl_session(SSL_SESSION **ssl_sessions, SSL *ssl)
{
    SSL_CTX_LOCK(ssl->ctx->mutex);

    if (ssl->ctx->num_sessions)
    {
        session_free(ssl_sessions, ssl->session_index);
        ssl->session = NULL;
    }

    SSL_CTX_UNLOCK(ssl->ctx->mutex);
}
#endif /* CONFIG_SSL_SKELETON_MODE */

/*
 * Get the session id for a handshake. This will be a 32 byte sequence.
 */
EXP_FUNC const uint8_t * STDCALL ssl_get_session_id(const SSL *ssl)
{
    return ssl->session_id;
}

/*
 * Get the session id size for a handshake. 
 */
EXP_FUNC uint8_t STDCALL ssl_get_session_id_size(const SSL *ssl)
{
    return ssl->sess_id_size;
}

/*
 * Return the cipher id (in the SSL form).
 */
EXP_FUNC uint8_t STDCALL ssl_get_cipher_id(const SSL *ssl)
{
    return ssl->cipher;
}

/*
 * Return the status of the handshake, mainly used in unblocked SSL
 */
EXP_FUNC int STDCALL ssl_handshake_status(const SSL *ssl)
{
    return ssl->hs_status;
}


