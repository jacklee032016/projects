
#include "tls.h"


static const uint8_t g_hello_request[] = { HS_HELLO_REQUEST, 0, 0, 0 };
static const uint8_t g_chg_cipher_spec_pkt[] = { 1 };


/*
 * Sends the change cipher spec message. We have just read a finished message from the client.
 * first time, this content must be send in plaintext, so it is first called before set key
 */
int send_change_cipher_spec(SSL *ssl)
{
	int ret= send_packet(ssl, TLS_CNT_CHANGE_CIPHER_SPEC,  g_chg_cipher_spec_pkt, sizeof(g_chg_cipher_spec_pkt));
	if ( set_key_block(ssl, 1) < 0)
		return SSL_ERROR_INVALID_HANDSHAKE;

	if (ssl->cipher_info)
	{
		SET_SSL_FLAG(SSL_TX_ENCRYPTED);
//		SET_SSL_FLAG(SSL_TX_ENCRYPTED);
	}

	memset(ssl->write_sequence, 0, 8);

	return ret;
}


/**
 * Send an alert message.
 * Return 1 if the alert was an "error".
 */
int send_alert(SSL *ssl, int error_code)
{
	int alert_num = 0;
	int is_warning = 0;
	uint8_t buf[2];
	TLS_ALERT_HEADER header;
	header.level = TLS_ALERT_LEVEL_FATAL;

	/* Don't bother we're already dead */
	if (ssl->hs_status == SSL_ERROR_DEAD)
	{
		return SSL_ERROR_CONN_LOST;
	}

#ifdef CONFIG_SSL_FULL_MODE
	if (IS_SET_SSL_FLAG(SSL_DISPLAY_STATES))
		ssl_display_error(error_code);
#endif

	switch (error_code)
	{
		case TLS_ALERT_CLOSE_NOTIFY:
			header.level = TLS_ALERT_LEVEL_WARNING;
			header.description = TLS_ALERT_CLOSE_NOTIFY;
			break;

		case SSL_ERROR_CONN_LOST:       /* don't send alert just yet */
			header.level = TLS_ALERT_LEVEL_WARNING;
			break;

		case SSL_ERROR_INVALID_HANDSHAKE:
		case SSL_ERROR_INVALID_PROT_MSG:
			header.description = TLS_ALERT_HANDSHAKE_FAILURE;
			break;

		case SSL_ERROR_INVALID_HMAC:
		case SSL_ERROR_FINISHED_INVALID:
			header.description = TLS_ALERT_BAD_RECORD_MAC;
			break;

		case SSL_ERROR_INVALID_VERSION:
			header.description = TLS_ALERT_INVALID_VERSION;
			break;

		case SSL_ERROR_INVALID_SESSION:
		case SSL_ERROR_NO_CIPHER:
		case SSL_ERROR_INVALID_KEY:
			header.description = TLS_ALERT_ILLEGAL_PARAMETER;
			break;

		case SSL_ERROR_BAD_CERTIFICATE:
			header.description = TLS_ALERT_BAD_CERTIFICATE;
			break;

		case SSL_ERROR_NO_CLIENT_RENOG:
			header.description = TLS_ALERT_NO_RENEGOTIATION;
			break;

		default:
			/* a catch-all for any badly verified certificates */
			header.description = (error_code <= SSL_X509_OFFSET) ? TLS_ALERT_BAD_CERTIFICATE : TLS_ALERT_UNEXPECTED_MESSAGE;
			break;
	}

	send_packet(ssl, TLS_CNT_ALERT, (uint8_t *)&header, sizeof(TLS_ALERT_HEADER));
	ecpDebugDumpAlert(ssl, &header, 1);
	return (header.level == TLS_ALERT_LEVEL_WARNING) ? 0 : 1;
}


/**
 * Send a certificate.
 */
int send_certificate(SSL *ssl)
{
    int i = 0;
    uint8_t *buf = ssl->bm_data;
    int offset = 7;
    int chain_length;

    buf[0] = HS_CERTIFICATE;
    buf[1] = 0;
    buf[4] = 0;

    while (i < ssl->ctx->chain_length)
    {
        SSL_CERT *cert = &ssl->ctx->certs[i];
        buf[offset++] = 0;        
        buf[offset++] = cert->size >> 8;        /* cert 1 length */
        buf[offset++] = cert->size & 0xff;
        memcpy(&buf[offset], cert->buf, cert->size);
        offset += cert->size;
        i++;
    }

    chain_length = offset - 7;
    buf[5] = chain_length >> 8;        /* cert chain length */
    buf[6] = chain_length & 0xff;
    chain_length += 3;
    buf[2] = chain_length >> 8;        /* handshake length */
    buf[3] = chain_length & 0xff;
    ssl->bm_index = offset;
    return send_packet(ssl, TLS_CNT_HANDSHAKE, NULL, offset);
}



int send_finished(SSL *ssl)
{
	uint8_t buf[TLS_FINISHED_VERIFY_SIZE+4] = { HS_FINISHED, 0, 0, TLS_FINISHED_VERIFY_SIZE };

	/* now add the finished digest mac (12 bytes) */
	finished_digest(ssl, IS_SET_SSL_FLAG(SSL_IS_CLIENT)?TLS_FINISH_LABEL_CLIENT : TLS_FINISH_LABEL_SERVER, &buf[4]);

#ifndef CONFIG_SSL_SKELETON_MODE
	/* store in the session cache */
	if (!IS_SET_SSL_FLAG(SSL_SESSION_RESUME) && ssl->ctx->num_sessions)
	{
		memcpy(ssl->session->master_secret, ssl->dc->master_secret, SSL_MASTER_SECRET_SIZE);
	}
#endif

	return send_packet(ssl, TLS_CNT_HANDSHAKE,  buf, TLS_FINISHED_VERIFY_SIZE+4);
}

/* Process a finished message */
int process_finished(SSL *ssl, uint8_t *buf, int hs_len)
{
	int ret = SSL_OK;
	int is_client = IS_SET_SSL_FLAG(SSL_IS_CLIENT);
	int resume = IS_SET_SSL_FLAG(SSL_SESSION_RESUME);

	PARANOIA_CHECK(ssl->bm_index, TLS_FINISHED_VERIFY_SIZE+4);

	/* check that we all work before we continue */
	if (memcmp(ssl->dc->final_finish_mac, &buf[4], TLS_FINISHED_VERIFY_SIZE))
		return SSL_ERROR_FINISHED_INVALID;

	if ((!is_client && !resume) || (is_client && resume))
	{/* server send change_cipher and finished after rxing finished */
		if ((ret = send_change_cipher_spec(ssl)) == SSL_OK)
			ret = send_finished(ssl);
	}

	/* if we ever renegotiate */
	ssl->next_state = is_client ? HS_HELLO_REQUEST : HS_CLIENT_HELLO;  
	ssl->hs_status = ret;  /* set the final handshake status */

	error:
	return ret;
}


/**
 * Do some basic checking of data and then perform the appropriate handshaking.
 */
int do_handshake(SSL *ssl, uint8_t *buf, int read_len)
{
	int hs_len = (buf[2]<<8) + buf[3];
	uint8_t handshake_type = buf[0];
	int ret = SSL_OK;
	int is_client = IS_SET_SSL_FLAG(SSL_IS_CLIENT);

	/* some integrity checking on the handshake */
	PARANOIA_CHECK(read_len-SSL_HS_HDR_SIZE, hs_len);

	if (handshake_type != ssl->next_state)
	{
		/* handle a special case on the client */
		if (!is_client || handshake_type != HS_CERT_REQ ||ssl->next_state != HS_SERVER_HELLO_DONE)
		{
			ret = SSL_ERROR_INVALID_HANDSHAKE;
			goto error;
		}
	}

	hs_len += SSL_HS_HDR_SIZE;  /* adjust for when adding packets */
	ssl->bm_index = hs_len;     /* store the size and check later */

	DISPLAY_STATE(ssl, 0, handshake_type, 0);

	if (handshake_type != HS_CERT_VERIFY && handshake_type != HS_HELLO_REQUEST)
		add_packet(ssl, buf, hs_len); 

#if defined(CONFIG_SSL_ENABLE_CLIENT)
	ret = is_client ? do_clnt_handshake(ssl, handshake_type, buf, hs_len):do_svr_handshake(ssl, handshake_type, buf, hs_len);
#else
	ret = do_svr_handshake(ssl, handshake_type, buf, hs_len);
#endif

	/* just use recursion to get the rest */
	if (hs_len < read_len && ret == SSL_OK)
		ret = do_handshake(ssl, &buf[hs_len], read_len-hs_len);

error:
	return ret;
}


#ifdef CONFIG_SSL_CERT_VERIFICATION
/**
 * Authenticate a received certificate.
 */
EXP_FUNC int STDCALL ssl_verify_cert(const SSL *ssl)
{
	int ret;
	
	SSL_CTX_LOCK(ssl->ctx->mutex);

	x509_print(ssl->x509_ctx, ssl->ctx->ca_cert_ctx);

	ret = x509_verify(ssl->ctx->ca_cert_ctx, ssl->x509_ctx);
	SSL_CTX_UNLOCK(ssl->ctx->mutex);

	if (ret)/* modify into an SSL error type */
	{
		ret = SSL_X509_ERROR(ret);
	}

	return ret;
}

/**
 * Process a certificate message.
 */
int process_certificate(SSL *ssl, X509 **x509_ctx)
{
	int ret = SSL_OK;
	uint8_t *buf = &ssl->bm_data[ssl->dc->bm_proc_index];
	int pkt_size = ssl->bm_index;
	int cert_size, offset = 5;
	int total_cert_size = (buf[offset]<<8) + buf[offset+1];
	int is_client = IS_SET_SSL_FLAG(SSL_IS_CLIENT);
	X509 **chain = x509_ctx;
	offset += 2;

	PARANOIA_CHECK(total_cert_size, offset);

	while (offset < total_cert_size)
	{
		offset++;       /* skip empty char */
		cert_size = (buf[offset]<<8) + buf[offset+1];
		offset += 2;

		if (x509_new(&buf[offset], NULL, chain))
		{
			ret = SSL_ERROR_BAD_CERTIFICATE;
			goto error;
		}

		chain = &((*chain)->next);
		offset += cert_size;
	}

	PARANOIA_CHECK(pkt_size, offset);

	/* if we are client we can do the verify now or later */
	if (is_client && !IS_SET_SSL_FLAG(SSL_SERVER_VERIFY_LATER))
	{
		ret = ssl_verify_cert(ssl);
	}

	ssl->next_state = is_client ? HS_SERVER_HELLO_DONE : HS_CLIENT_KEY_XCHG;
	ssl->dc->bm_proc_index += offset;
	
error:
	return ret;
}

#endif /* CONFIG_SSL_CERT_VERIFICATION */

/* Force the client to perform its handshake again */
EXP_FUNC int STDCALL ssl_renegotiate(SSL *ssl)
{
	int ret = SSL_OK;

	disposable_new(ssl);
#ifdef CONFIG_SSL_ENABLE_CLIENT
	if (IS_SET_SSL_FLAG(SSL_IS_CLIENT))
	{
		ret = do_client_connect(ssl);
	}
	else
#endif
	{
		send_packet(ssl, TLS_CNT_HANDSHAKE, g_hello_request, sizeof(g_hello_request));
		SET_SSL_FLAG(SSL_NEED_RECORD);
	}

	return ret;
}

