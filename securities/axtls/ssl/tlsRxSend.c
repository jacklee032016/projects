
#include "tls.h"

/** 
 * Increment the read sequence number (as a 64 bit endian indepenent #)
 */     
static void increment_read_sequence(SSL *ssl)
{
	int i;

	for (i = 7; i >= 0; i--) 
	{       
		if (++ssl->read_sequence[i])
			break;
	}
}
            
/**
 * Increment the read sequence number (as a 64 bit endian indepenent #)
 */      
static void increment_write_sequence(SSL *ssl)
{        
	int i;                  

	for (i = 7; i >= 0; i--)
	{                       
		if (++ssl->write_sequence[i])
			break;
	}                       
}


/**
 * Work out the HMAC digest in a packet.
 */
static void add_hmac_digest(SSL *ssl, int mode, uint8_t *hmac_header,
        const uint8_t *buf, int buf_len, uint8_t *hmac_buf)
{
	int hmac_len = buf_len + 8 + SSL_RECORD_SIZE;
	uint8_t *t_buf = (uint8_t *)alloca(hmac_len+10);

	memcpy(t_buf, (mode == SSL_SERVER_WRITE || mode == SSL_CLIENT_WRITE) ? 
		ssl->write_sequence : ssl->read_sequence, 8);
	memcpy(&t_buf[8], hmac_header, SSL_RECORD_SIZE);
	memcpy(&t_buf[8+SSL_RECORD_SIZE], buf, buf_len);

	ssl->cipher_info->hmac(t_buf, hmac_len, (mode == SSL_SERVER_WRITE || mode == SSL_CLIENT_READ) ? 
		ssl->server_mac : ssl->client_mac, ssl->cipher_info->digest_size, hmac_buf);

#if 0
	print_blob(hmac_header, SSL_RECORD_SIZE, "record");
	print_blob( buf, buf_len, "buf");
	if (mode == SSL_SERVER_WRITE || mode == SSL_CLIENT_WRITE)
	{
		print_blob(ssl->write_sequence, 8, "write seq" );
	}
	else
	{
		print_blob(ssl->read_sequence, 8, "read seq");
	}

	if (mode == SSL_SERVER_WRITE || mode == SSL_CLIENT_READ)
	{
		print_blob(ssl->server_mac, ssl->cipher_info->digest_size, "server mac");
	}
	else
	{
		print_blob(ssl->client_mac, ssl->cipher_info->digest_size, "client mac" );
	}
	print_blob(hmac_buf, HASH_MD_LENGTH_SHA1, "hmac" );
#endif
}

/**
 * Verify that the digest of a packet is correct.
 */
static int verify_digest(SSL *ssl, int mode, const uint8_t *buf, int read_len)
{   
    uint8_t hmac_buf[HASH_MD_LENGTH_SHA1];
    int hmac_offset;
   
    if (ssl->cipher_info->padding_size)
    {
        int last_blk_size = buf[read_len-1], i;
        hmac_offset = read_len-last_blk_size-ssl->cipher_info->digest_size-1;

        /* guard against a timing attack - make sure we do the digest */
        if (hmac_offset < 0)
        {
            hmac_offset = 0;
        }
        else
        {
            /* already looked at last byte */
            for (i = 1; i < last_blk_size; i++)
            {
                if (buf[read_len-i] != last_blk_size)
                {
                    hmac_offset = 0;
                    break;
                }
            }
        }
    }
    else /* stream cipher */
    {
        hmac_offset = read_len - ssl->cipher_info->digest_size;

        if (hmac_offset < 0)
        {
            hmac_offset = 0;
        }
    }

    /* sanity check the offset */
    ssl->hmac_header[3] = hmac_offset >> 8;      /* insert size */
    ssl->hmac_header[4] = hmac_offset & 0xff;
    add_hmac_digest(ssl, mode, ssl->hmac_header, buf, hmac_offset, hmac_buf);

    if (memcmp(hmac_buf, &buf[hmac_offset], ssl->cipher_info->digest_size))
    {
        return SSL_ERROR_INVALID_HMAC;
    }

    return hmac_offset;
}


/**
 * Send a packet over the socket.
 */
static int send_raw_packet(SSL *ssl, TLS_CNT_TYPE protocol)
{
	uint8_t *rec_buf = ssl->bm_all_data;
	int pkt_size = SSL_RECORD_SIZE+ssl->bm_index;
	int sent = 0;
	int ret = SSL_OK;

	/* RECORDER layer header */
	rec_buf[0] = protocol;
	rec_buf[1] = 0x03;      /* version = 3.1 or higher */
	rec_buf[2] = ssl->version & 0x0f;
	/* length field */
	rec_buf[3] = ssl->bm_index >> 8;
	rec_buf[4] = ssl->bm_index & 0xff;

	DISPLAY_BYTES(ssl, ssl->bm_all_data, pkt_size, "sending %d bytes", pkt_size);

	while (sent < pkt_size)
	{
		ret = SOCKET_WRITE(ssl->client_fd, &ssl->bm_all_data[sent], pkt_size-sent);
		if (ret >= 0)
			sent += ret;
		else
		{
#ifdef WIN32
			if (GetLastError() != WSAEWOULDBLOCK)
#else
			if (errno != EAGAIN && errno != EWOULDBLOCK)
#endif
			{
				AX_LOG("System Error(socket write) : %s\n", getSystemErrorMsg() );
				return SSL_ERROR_CONN_LOST;
			}
		}

		/* keep going until the write buffer has some space */
		if (sent != pkt_size)
		{
			fd_set wfds;
			FD_ZERO(&wfds);
			FD_SET(ssl->client_fd, &wfds);

			/* block and wait for it */
			if (select(ssl->client_fd + 1, NULL, &wfds, NULL, NULL) < 0)
			{
				AX_LOG("System Error(select) : %s\n", getSystemErrorMsg() );
				return SSL_ERROR_CONN_LOST;
			}
		}
	}

	SET_SSL_FLAG(SSL_NEED_RECORD);  /* reset for next time */
	ssl->bm_index = 0;

	if (protocol != TLS_CNT_APP_DATA)  
	{/* always return SSL_OK during handshake */   
		ret = SSL_OK;
	}

	return ret;
}

/**
 * Send an encrypted packet with padding bytes if necessary.
 */
int send_packet(SSL *ssl, TLS_CNT_TYPE protocol, const uint8_t *in, int length)
{
	int ret, msg_length = 0;

	DISPLAY_BYTES(ssl, in, length, "send contentType: \"%s\"\n", ecpTlsProtocolName(protocol));
		
	/* if our state is bad, don't bother */
	if (ssl->hs_status == SSL_ERROR_DEAD)
	{
		AX_DEBUG("%s handshake is not send out at state ERROE_DEAD\n", ecpTlsProtocolName(protocol));
		return SSL_ERROR_CONN_LOST;
	}

	if (in) /* has the buffer already been initialised? */
	{
		memcpy(ssl->bm_data, in, length);
	}

	msg_length += length;

	if (IS_SET_SSL_FLAG(SSL_TX_ENCRYPTED))
	{
		int mode = IS_SET_SSL_FLAG(SSL_IS_CLIENT) ? SSL_CLIENT_WRITE : SSL_SERVER_WRITE;
		uint8_t hmac_header[SSL_RECORD_SIZE] = 
		{
			protocol, 
			0x03, /* version = 3.1 or higher */
			ssl->version & 0x0f,
			msg_length >> 8,
			msg_length & 0xff 
		};

		if (protocol == TLS_CNT_HANDSHAKE)
		{
			DISPLAY_STATE(ssl, 1, ssl->bm_data[0], 0);

			if (ssl->bm_data[0] != HS_HELLO_REQUEST)
			{
				add_packet(ssl, ssl->bm_data, msg_length);
			}
		}

		/* add the packet digest */
		add_hmac_digest(ssl, mode, hmac_header, ssl->bm_data, msg_length, &ssl->bm_data[msg_length]);
		msg_length += ssl->cipher_info->digest_size;

		/* add padding? */
		if (ssl->cipher_info->padding_size)
		{
			int last_blk_size = msg_length%ssl->cipher_info->padding_size;
			int pad_bytes = ssl->cipher_info->padding_size - last_blk_size;

			/* ensure we always have at least 1 padding byte */
			if (pad_bytes == 0)
				pad_bytes += ssl->cipher_info->padding_size;

			memset(&ssl->bm_data[msg_length], pad_bytes-1, pad_bytes);
			msg_length += pad_bytes;
		}

		DISPLAY_BYTES(ssl, ssl->bm_data, msg_length, "unencrypted write");
		increment_write_sequence(ssl);

		/* add the explicit IV for TLS1.1 */
		if (ssl->version >= SSL_PROTOCOL_VERSION1_1 && ssl->cipher_info->iv_size)
		{
			uint8_t iv_size = ssl->cipher_info->iv_size;
			uint8_t *t_buf = alloca(msg_length + iv_size);
			memcpy(t_buf + iv_size, ssl->bm_data, msg_length);
			if (get_random(iv_size, t_buf) < 0)
				return SSL_NOT_OK;

			msg_length += iv_size;
			memcpy(ssl->bm_data, t_buf, msg_length);
		}

		/* now encrypt the packet */
		ssl->cipher_info->encrypt(ssl->encrypt_ctx, ssl->bm_data, ssl->bm_data, msg_length);
	}
	else if (protocol == TLS_CNT_HANDSHAKE)
	{
		DISPLAY_STATE(ssl, 1, ssl->bm_data[0], 0);

		if (ssl->bm_data[0] != HS_HELLO_REQUEST)
		{
			add_packet(ssl, ssl->bm_data, length);
		}
	}

	ssl->bm_index = msg_length;
	if ((ret = send_raw_packet(ssl, protocol)) <= 0)
		return ret;

	return length;  /* just return what we wanted to send */
}


/**
 * Read the SSL connection.
 */
int basic_read(SSL *ssl, uint8_t **in_data)
{
	int ret = SSL_OK;
	int read_len, is_client = IS_SET_SSL_FLAG(SSL_IS_CLIENT);
	uint8_t *buf = ssl->bm_data;
	TLS_RECORD_HEADER *record = (TLS_RECORD_HEADER *)buf;

	read_len = SOCKET_READ(ssl->client_fd, &buf[ssl->bm_read_index],  ssl->need_bytes-ssl->got_bytes);
	if (read_len < 0) 
	{
#ifdef WIN32
		if (GetLastError() == WSAEWOULDBLOCK)
#else
		if (errno == EAGAIN || errno == EWOULDBLOCK)
#endif
			return 0;
	}

	/* connection has gone, so die */
	if (read_len <= 0)
	{
		ret = SSL_ERROR_CONN_LOST;
		ssl->hs_status = SSL_ERROR_DEAD;  /* make sure it stays dead */
		goto error;
	}

	DISPLAY_BYTES(ssl, &ssl->bm_data[ssl->bm_read_index], read_len, "received %d bytes", read_len);

	ssl->got_bytes += read_len;
	ssl->bm_read_index += read_len;

	/* haven't quite got what we want, so try again later */
	if (ssl->got_bytes < ssl->need_bytes)
		return SSL_OK;

	read_len = ssl->got_bytes;
	ssl->got_bytes = 0;

	if (IS_SET_SSL_FLAG(SSL_NEED_RECORD))
	{
		/* check for sslv2 "client hello" */
		if (buf[0] & 0x80 && buf[2] == 1)
		{
#ifdef CONFIG_SSL_ENABLE_V23_HANDSHAKE
			uint8_t version = (buf[3] << 4) + buf[4];
			DISPLAY_BYTES(ssl, buf, 5, "ssl2 record");

			/* should be v3.1 (TLSv1) or better  */
			ssl->version = ssl->client_version = version;

			if (version > SSL_PROTOCOL_VERSION_MAX)
			{/* use client's version */
				ssl->version = SSL_PROTOCOL_VERSION_MAX;
			}
			else if (version < SSL_PROTOCOL_MIN_VERSION)  
			{
				ret = SSL_ERROR_INVALID_VERSION;
				ssl_display_error(ret);
				return ret;
			}

			add_packet(ssl, &buf[2], 3);
			ret = process_sslv23_client_hello(ssl); 
#else
			AX_LOG("Error: no SSLv23 handshaking allowed\n"); TTY_FLUSH();
			ret = SSL_ERROR_NOT_SUPPORTED;
#endif
			goto error; /* not an error - just get out of here */
		}

		ssl->need_bytes = (buf[3] << 8) + buf[4];

		/* do we violate the spec with the message size?  */
		if (ssl->need_bytes > RT_MAX_PLAIN_LENGTH+RT_EXTRA-BM_RECORD_OFFSET)
		{
			ret = SSL_ERROR_INVALID_PROT_MSG;              
			goto error;
		}

		CLR_SSL_FLAG(SSL_NEED_RECORD);
		memcpy(ssl->hmac_header, buf, 3);       /* store for hmac */
		ssl->record_type = buf[0];
		goto error;                         /* no error, we're done */
	}

	/* for next time - just do it now in case of an error */
	SET_SSL_FLAG(SSL_NEED_RECORD);
	ssl->need_bytes = SSL_RECORD_SIZE;

	/* decrypt if we need to */
	if (IS_SET_SSL_FLAG(SSL_RX_ENCRYPTED))
	{
		ssl->cipher_info->decrypt(ssl->decrypt_ctx, buf, buf, read_len);

		if (ssl->version >= SSL_PROTOCOL_VERSION1_1 && ssl->cipher_info->iv_size)
		{
			buf += ssl->cipher_info->iv_size;
			read_len -= ssl->cipher_info->iv_size;
		}

		read_len = verify_digest(ssl, is_client ? SSL_CLIENT_READ : SSL_SERVER_READ, buf, read_len);
		/* does the hmac work? */
		if (read_len < 0)
		{
			ret = read_len;
			goto error;
		}

		DISPLAY_BYTES(ssl, buf, read_len, "decrypted");
		increment_read_sequence(ssl);
	}

	/* The main part of the SSL packet */
	switch (ssl->record_type)
	{
		case TLS_CNT_HANDSHAKE:
			if (ssl->dc != NULL)
			{
				ssl->dc->bm_proc_index = 0;
				ret = do_handshake(ssl, buf, read_len);
			}
			else /* no client renegotiation allowed */
			{
				ret = SSL_ERROR_NO_CLIENT_RENOG;              
				goto error;
			}
			break;

		case TLS_CNT_CHANGE_CIPHER_SPEC:
			if (ssl->next_state != HS_FINISHED)
			{
				ret = SSL_ERROR_INVALID_HANDSHAKE;
				goto error;
			}

			if (set_key_block(ssl, 0) < 0)
			{
				ret = SSL_ERROR_INVALID_HANDSHAKE;
				goto error;
			}

			/* all encrypted from now on */
			SET_SSL_FLAG(SSL_RX_ENCRYPTED);
			memset(ssl->read_sequence, 0, 8);
			break;

		case TLS_CNT_APP_DATA:
			if (in_data && ssl->hs_status == SSL_OK)
			{
				*in_data = buf;   /* point to the work buffer */
				(*in_data)[read_len] = 0;  /* null terminate just in case */
				ret = read_len;
			}
			else
				ret = SSL_ERROR_INVALID_PROT_MSG;
			break;

		case TLS_CNT_ALERT:
			/* return the alert # with alert bit set */
			if(buf[0] == TLS_ALERT_LEVEL_WARNING && buf[1] == TLS_ALERT_CLOSE_NOTIFY)
			{
				ret = SSL_CLOSE_NOTIFY;
				send_alert(ssl, TLS_ALERT_CLOSE_NOTIFY);
				SET_SSL_FLAG(SSL_SENT_CLOSE_NOTIFY);
			}
			else 
			{
				ret = -buf[1]; 
				ecpDebugDumpAlert(ssl, (TLS_ALERT_HEADER *)buf, 0);
			}

			break;

		default:
			ret = SSL_ERROR_INVALID_PROT_MSG;
			break;
	}

error:
	ssl->bm_read_index = 0;          /* reset to go again */

	if (ret < SSL_OK && in_data)/* if all wrong, then clear this buffer ptr */
		*in_data = NULL;

	return ret;
}


/*
 * Read the SSL connection and send any alerts for various errors.
 */
EXP_FUNC int STDCALL ssl_read(SSL *ssl, uint8_t **in_data)
{
	int ret = basic_read(ssl, in_data);

	/* check for return code so we can send an alert */
	if (ret < SSL_OK && ret != SSL_CLOSE_NOTIFY)
	{
		if (ret != SSL_ERROR_CONN_LOST)
		{
			send_alert(ssl, ret);
#ifndef CONFIG_SSL_SKELETON_MODE
			/* something nasty happened, so get rid of this session */
			kill_ssl_session(ssl->ctx->ssl_sessions, ssl);
#endif
		}
	}

	return ret;
}

/*
 * Write application data to the client
 */
EXP_FUNC int STDCALL ssl_write(SSL *ssl, const uint8_t *out_data, int out_len)
{
	int n = out_len, nw, i, tot = 0;

	/* maximum size of a TLS packet is around 16kB, so fragment */
	do 
	{
		nw = n;

		if (nw > RT_MAX_PLAIN_LENGTH)    /* fragment if necessary */
			nw = RT_MAX_PLAIN_LENGTH;

		if ((i = send_packet(ssl, TLS_CNT_APP_DATA, &out_data[tot], nw)) <= 0)
		{
			out_len = i;    /* an error */
			break;
		}

		tot += i;
		n -= i;
	} while (n > 0);

	return out_len;
}

