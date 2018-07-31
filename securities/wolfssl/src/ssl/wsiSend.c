
#include "cmnSsl.h"

/* only function which send data out */
int SendBuffered(WOLFSSL* ssl)
{
	if (ssl->ctx->CBIOSend == NULL) {
		WOLFSSL_MSG("Your IO Send callback is null, please set");
		return SOCKET_ERROR_E;
	}

	while (ssl->buffers.outputBuffer.length > 0)
	{
		int sent = ssl->ctx->CBIOSend(ssl, (char*)ssl->buffers.outputBuffer.buffer + ssl->buffers.outputBuffer.idx,
			(int)ssl->buffers.outputBuffer.length, ssl->IOCB_WriteCtx);
		if (sent < 0)
		{
			switch (sent)
			{
				case WOLFSSL_CBIO_ERR_WANT_WRITE:        /* would block */
					return WANT_WRITE;

				case WOLFSSL_CBIO_ERR_CONN_RST:          /* connection reset */
					ssl->options.connReset = 1;
					break;

				case WOLFSSL_CBIO_ERR_ISR:               /* interrupt */
				/* see if we got our timeout */
#ifdef WOLFSSL_CALLBACKS
					if (ssl->toInfoOn)
					{
						struct itimerval timeout;
						getitimer(ITIMER_REAL, &timeout);
						if (timeout.it_value.tv_sec == 0 && timeout.it_value.tv_usec == 0) {
							XSTRNCPY(ssl->timeoutInfo.timeoutName, "send() timeout", MAX_TIMEOUT_NAME_SZ);
							WOLFSSL_MSG("Got our timeout");
							return WANT_WRITE;
						}
					}
#endif
					continue;

				case WOLFSSL_CBIO_ERR_CONN_CLOSE: /* epipe / conn closed */
					ssl->options.connReset = 1;  /* treat same as reset */
					break;

				default:
					return SOCKET_ERROR_E;
			}

			return SOCKET_ERROR_E;
		}

		if (sent > (int)ssl->buffers.outputBuffer.length) {
			WOLFSSL_MSG("SendBuffered() out of bounds read");
			return SEND_OOB_READ_E;
		}

		ssl->buffers.outputBuffer.idx += sent;
		ssl->buffers.outputBuffer.length -= sent;
	}

	ssl->buffers.outputBuffer.idx = 0;

	if (ssl->buffers.outputBuffer.dynamicFlag)
		ShrinkOutputBuffer(ssl);

	return 0;
}



int SendChangeCipher(WOLFSSL* ssl)
{
	byte              *output;
	int                sendSz = RECORD_HEADER_SZ + ENUM_LEN;
	int                idx    = RECORD_HEADER_SZ;
	int                ret;

#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls) {
		sendSz += DTLS_RECORD_EXTRA;
		idx    += DTLS_RECORD_EXTRA;
	}
#endif

	/* are we in scr */
	if (ssl->keys.encryptionOn && ssl->options.handShakeDone) {
		sendSz += MAX_MSG_EXTRA;
	}

	/* check for avalaible size */
	if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
		return ret;

	/* get ouput buffer */
	output = ssl->buffers.outputBuffer.buffer +
	ssl->buffers.outputBuffer.length;

	AddRecordHeader(output, 1, change_cipher_spec, ssl);

	output[idx] = 1;             /* turn it on */

	if (ssl->keys.encryptionOn && ssl->options.handShakeDone) {
	byte input[ENUM_LEN];
	int  inputSz = ENUM_LEN;

	input[0] = 1;  /* turn it on */
	sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
	  change_cipher_spec);
	if (sendSz < 0)
	return sendSz;
	}

#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls) {
	if ((ret = DtlsPoolSave(ssl, output, sendSz)) != 0)
	return ret;
	}
#endif
#ifdef WOLFSSL_CALLBACKS
	if (ssl->hsInfoOn) AddPacketName("ChangeCipher", &ssl->handShakeInfo);
	if (ssl->toInfoOn)
	AddPacketInfo("ChangeCipher", &ssl->timeoutInfo, output, sendSz,
	ssl->heap);
#endif
	ssl->buffers.outputBuffer.length += sendSz;

	if (ssl->options.groupMessages)
	return 0;
#ifdef WOLFSSL_DTLS
	else if (ssl->options.dtls) {
	/* If using DTLS, force the ChangeCipherSpec message to be in the
	* same datagram as the finished message. */
	return 0;
	}
#endif
	else
	return SendBuffered(ssl);
	}



int SendFinished(WOLFSSL* ssl)
{
    int              sendSz,
                     finishedSz = ssl->options.tls ? TLS_FINISHED_SZ :
                                                     FINISHED_SZ;
    byte             input[FINISHED_SZ + DTLS_HANDSHAKE_HEADER_SZ];  /* max */
    byte            *output;
    Hashes*          hashes;
    int              ret;
    int              headerSz = HANDSHAKE_HEADER_SZ;
    int              outputSz;

    #ifdef WOLFSSL_DTLS
        word32 sequence_number = ssl->keys.dtls_sequence_number;
        word16 epoch           = ssl->keys.dtls_epoch;
    #endif

    /* setup encrypt keys */
    if ((ret = SetKeysSide(ssl, ENCRYPT_SIDE_ONLY)) != 0)
        return ret;

    /* check for available size */
    outputSz = sizeof(input) + MAX_MSG_EXTRA;
    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
        return ret;

    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            /* Send Finished message with the next epoch, but don't commit that
             * change until the other end confirms its reception. */
            headerSz += DTLS_HANDSHAKE_EXTRA;
            ssl->keys.dtls_epoch++;
            ssl->keys.dtls_sequence_number = 0;  /* reset after epoch change */
        }
    #endif

    /* get ouput buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    AddHandShakeHeader(input, finishedSz, finished, ssl);

    /* make finished hashes */
    hashes = (Hashes*)&input[headerSz];
    ret = BuildFinished(ssl, hashes,
                     ssl->options.side == WOLFSSL_CLIENT_END ? client : server);
    if (ret != 0) return ret;

#ifdef HAVE_SECURE_RENEGOTIATION
    if (ssl->secure_renegotiation) {
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            XMEMCPY(ssl->secure_renegotiation->client_verify_data, hashes,
                    TLS_FINISHED_SZ);
        else
            XMEMCPY(ssl->secure_renegotiation->server_verify_data, hashes,
                    TLS_FINISHED_SZ);
    }
#endif

    sendSz = BuildMessage(ssl, output, outputSz, input, headerSz + finishedSz,
                          handshake);
    if (sendSz < 0)
        return BUILD_MSG_ERROR;

    #ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        ssl->keys.dtls_epoch = epoch;
        ssl->keys.dtls_sequence_number = sequence_number;
    }
    #endif

    if (!ssl->options.resuming) {
#ifndef NO_SESSION_CACHE
        AddSession(ssl);    /* just try */
#endif
        if (ssl->options.side == WOLFSSL_SERVER_END) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
            #ifdef WOLFSSL_DTLS
                if (ssl->options.dtls) {
                    /* Other side will soon receive our Finished, go to next
                     * epoch. */
                    ssl->keys.dtls_epoch++;
                    ssl->keys.dtls_sequence_number = 1;
                }
            #endif
        }
    }
    else {
        if (ssl->options.side == WOLFSSL_CLIENT_END) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
            #ifdef WOLFSSL_DTLS
                if (ssl->options.dtls) {
                    /* Other side will soon receive our Finished, go to next
                     * epoch. */
                    ssl->keys.dtls_epoch++;
                    ssl->keys.dtls_sequence_number = 1;
                }
            #endif
        }
    }
    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            if ((ret = DtlsPoolSave(ssl, output, sendSz)) != 0)
                return ret;
        }
    #endif

    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Finished", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("Finished", &ssl->timeoutInfo, output, sendSz,
                          ssl->heap);
    #endif

    ssl->buffers.outputBuffer.length += sendSz;

    return SendBuffered(ssl);
}

#ifndef NO_CERTS
int SendCertificate(WOLFSSL* ssl)
{
    int    sendSz, length, ret = 0;
    word32 i = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
    word32 certSz, listSz;
    byte*  output = 0;

    if (ssl->options.usingPSK_cipher || ssl->options.usingAnon_cipher)
        return 0;  /* not needed */

    if (ssl->options.sendVerify == SEND_BLANK_CERT) {
        certSz = 0;
        length = CERT_HEADER_SZ;
        listSz = 0;
    }
    else {
        certSz = ssl->buffers.certificate.length;
        /* list + cert size */
        length = certSz + 2 * CERT_HEADER_SZ;
        listSz = certSz + CERT_HEADER_SZ;

        /* may need to send rest of chain, already has leading size(s) */
        if (ssl->buffers.certChain.buffer) {
            length += ssl->buffers.certChain.length;
            listSz += ssl->buffers.certChain.length;
        }
    }
    sendSz = length + RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
            i      += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
        }
    #endif

    if (ssl->keys.encryptionOn)
        sendSz += MAX_MSG_EXTRA;

    /* check for available size */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* get ouput buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    AddHeaders(output, length, certificate, ssl);

    /* list total */
    c32to24(listSz, output + i);
    i += CERT_HEADER_SZ;

    /* member */
    if (certSz) {
        c32to24(certSz, output + i);
        i += CERT_HEADER_SZ;
        XMEMCPY(output + i, ssl->buffers.certificate.buffer, certSz);
        i += certSz;

        /* send rest of chain? */
        if (ssl->buffers.certChain.buffer) {
            XMEMCPY(output + i, ssl->buffers.certChain.buffer,
                                ssl->buffers.certChain.length);
            i += ssl->buffers.certChain.length;
        }
    }

    if (ssl->keys.encryptionOn) {
        byte* input;
        int   inputSz = i - RECORD_HEADER_SZ; /* build msg adds rec hdr */

        input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (input == NULL)
            return MEMORY_E;

        XMEMCPY(input, output + RECORD_HEADER_SZ, inputSz);
        sendSz = BuildMessage(ssl, output, sendSz, input,inputSz,handshake);
        XFREE(input, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);

        if (sendSz < 0)
            return sendSz;
    } else {
        ret = HashOutput(ssl, output, sendSz, 0);
        if (ret != 0)
            return ret;
    }

    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            if ((ret = DtlsPoolSave(ssl, output, sendSz)) != 0)
                return ret;
        }
    #endif

    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Certificate", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("Certificate", &ssl->timeoutInfo, output, sendSz,
                           ssl->heap);
    #endif

    if (ssl->options.side == WOLFSSL_SERVER_END)
        ssl->options.serverState = SERVER_CERT_COMPLETE;

    ssl->buffers.outputBuffer.length += sendSz;
    if (ssl->options.groupMessages)
        return 0;
    else
        return SendBuffered(ssl);
}


int SendCertificateRequest(WOLFSSL* ssl)
{
    byte   *output;
    int    ret;
    int    sendSz;
    word32 i = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

    int  typeTotal = 1;  /* only 1 for now */
    int  reqSz = ENUM_LEN + typeTotal + REQ_HEADER_SZ;  /* add auth later */

    if (IsAtLeastTLSv1_2(ssl))
        reqSz += LENGTH_SZ + ssl->suites->hashSigAlgoSz;

    if (ssl->options.usingPSK_cipher || ssl->options.usingAnon_cipher)
        return 0;  /* not needed */

    sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + reqSz;

    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
            i      += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
        }
    #endif
    /* check for available size */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* get ouput buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    AddHeaders(output, reqSz, certificate_request, ssl);

    /* write to output */
    output[i++] = (byte)typeTotal;  /* # of types */
#ifdef HAVE_ECC
    if (ssl->options.cipherSuite0 == ECC_BYTE &&
                     ssl->specs.sig_algo == ecc_dsa_sa_algo) {
        output[i++] = ecdsa_sign;
    } else
#endif /* HAVE_ECC */
    {
        output[i++] = rsa_sign;
    }

    /* supported hash/sig */
    if (IsAtLeastTLSv1_2(ssl)) {
        c16toa(ssl->suites->hashSigAlgoSz, &output[i]);
        i += LENGTH_SZ;

        XMEMCPY(&output[i],
                         ssl->suites->hashSigAlgo, ssl->suites->hashSigAlgoSz);
        i += ssl->suites->hashSigAlgoSz;
    }

    c16toa(0, &output[i]);  /* auth's */
    /* if add more to output, adjust i
    i += REQ_HEADER_SZ; */

    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            if ((ret = DtlsPoolSave(ssl, output, sendSz)) != 0)
                return ret;
        }
    #endif

    ret = HashOutput(ssl, output, sendSz, 0);
    if (ret != 0)
        return ret;

    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("CertificateRequest", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("CertificateRequest", &ssl->timeoutInfo, output,
                          sendSz, ssl->heap);
    #endif
    ssl->buffers.outputBuffer.length += sendSz;
    if (ssl->options.groupMessages)
        return 0;
    else
        return SendBuffered(ssl);
}
#endif /* !NO_CERTS */


int _sendData(WOLFSSL* ssl, const void* data, int sz)
{
	int sent = 0,  /* plainText size */
	sendSz,
	ret,
	dtlsExtra = 0;

	if (ssl->error == WANT_WRITE)
		ssl->error = 0;

	if (ssl->options.handShakeState != HANDSHAKE_DONE) {
		int err;
		WOLFSSL_MSG("handshake not complete, trying to finish");
		if ( (err = wolfSSL_negotiate(ssl)) != SSL_SUCCESS)
			return  err;
	}

	/* last time system socket output buffer was full, try again to send */
	if (ssl->buffers.outputBuffer.length > 0) {
		WOLFSSL_MSG("output buffer was full, trying to send again");
		if ( (ssl->error = SendBuffered(ssl)) < 0) {
			WOLFSSL_ERROR(ssl->error);
		if (ssl->error == SOCKET_ERROR_E && ssl->options.connReset)
			return 0;     /* peer reset */
		return ssl->error;
	}
	else
	{
		/* advance sent to previous sent + plain size just sent */
		sent = ssl->buffers.prevSent + ssl->buffers.plainSz;
		WOLFSSL_MSG("sent write buffered data");

		if (sent > sz) {
			WOLFSSL_MSG("error: write() after WANT_WRITE with short size");
			return ssl->error = BAD_FUNC_ARG;
		}
	}
	}

#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls) {
		dtlsExtra = DTLS_RECORD_EXTRA;
	}
#endif

	for (;;)
	{
#ifdef HAVE_MAX_FRAGMENT
		int   len = min(sz - sent, min(ssl->max_fragment, OUTPUT_RECORD_SIZE));
#else
		int   len = min(sz - sent, OUTPUT_RECORD_SIZE);
#endif
		byte* out;
		byte* sendBuffer = (byte*)data + sent;  /* may switch on comp */
		int   buffSz = len;                     /* may switch on comp */
		int   outputSz;
#ifdef HAVE_LIBZ
		byte  comp[MAX_RECORD_SIZE + MAX_COMP_EXTRA];
#endif

		if (sent == sz) break;

#ifdef WOLFSSL_DTLS
		if (ssl->options.dtls) {
			len    = min(len, MAX_UDP_SIZE);
			buffSz = len;
		}
#endif

		/* check for available size */
		outputSz = len + COMP_EXTRA + dtlsExtra + MAX_MSG_EXTRA;
		if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
			return ssl->error = ret;

		/* get ouput buffer */
		out = ssl->buffers.outputBuffer.buffer +
		ssl->buffers.outputBuffer.length;

#ifdef HAVE_LIBZ
		if (ssl->options.usingCompression) {
			buffSz = myCompress(ssl, sendBuffer, buffSz, comp, sizeof(comp));
			if (buffSz < 0) {
				return buffSz;
			}
			sendBuffer = comp;
		}
#endif
		sendSz = BuildMessage(ssl, out, outputSz, sendBuffer, buffSz, application_data);
		if (sendSz < 0)
			return BUILD_MSG_ERROR;

		ssl->buffers.outputBuffer.length += sendSz;

		if ( (ret = SendBuffered(ssl)) < 0) {
			WOLFSSL_ERROR(ret);
			/* store for next call if WANT_WRITE or user embedSend() that
			doesn't present like WANT_WRITE */
			ssl->buffers.plainSz  = len;
			ssl->buffers.prevSent = sent;
			if (ret == SOCKET_ERROR_E && ssl->options.connReset)
			return 0;  /* peer reset */
			return ssl->error = ret;
		}

		sent += len;

		/* only one message per attempt */
		if (ssl->options.partialWrite == 1) {
			WOLFSSL_MSG("Paritial Write on, only sending one record");
			break;
		}
	}

	return sent;
}



/* send alert message */
int SendAlert(WOLFSSL* ssl, int severity, int type)
{
	byte input[ALERT_SIZE];
	byte *output;
	int  sendSz;
	int  ret;
	int  outputSz;
	int  dtlsExtra = 0;

	/* if sendalert is called again for nonbloking */
	if (ssl->options.sendAlertState != 0) {
		ret = SendBuffered(ssl);
		if (ret == 0)
			ssl->options.sendAlertState = 0;
		return ret;
	}

#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls)
		dtlsExtra = DTLS_RECORD_EXTRA;
#endif

	/* check for available size */
	outputSz = ALERT_SIZE + MAX_MSG_EXTRA + dtlsExtra;
	if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
		return ret;

	/* get ouput buffer */
	output = ssl->buffers.outputBuffer.buffer +
	ssl->buffers.outputBuffer.length;

	input[0] = (byte)severity;
	input[1] = (byte)type;
	ssl->alert_history.last_tx.code = type;
	ssl->alert_history.last_tx.level = severity;
	if (severity == alert_fatal) {
		ssl->options.isClosed = 1;  /* Don't send close_notify */
	}

	/* only send encrypted alert if handshake actually complete, otherwise
	other side may not be able to handle it */
	if (ssl->keys.encryptionOn && ssl->options.handShakeDone)
		sendSz = BuildMessage(ssl, output, outputSz, input, ALERT_SIZE, alert);
	else {

		AddRecordHeader(output, ALERT_SIZE, alert, ssl);
		output += RECORD_HEADER_SZ;
#ifdef WOLFSSL_DTLS
		if (ssl->options.dtls)
			output += DTLS_RECORD_EXTRA;
#endif
		XMEMCPY(output, input, ALERT_SIZE);

		sendSz = RECORD_HEADER_SZ + ALERT_SIZE;
#ifdef WOLFSSL_DTLS
		if (ssl->options.dtls)
			sendSz += DTLS_RECORD_EXTRA;
#endif
	}
	if (sendSz < 0)
	return BUILD_MSG_ERROR;

#ifdef WOLFSSL_CALLBACKS
	if (ssl->hsInfoOn)
		AddPacketName("Alert", &ssl->handShakeInfo);
	if (ssl->toInfoOn)
		AddPacketInfo("Alert", &ssl->timeoutInfo, output, sendSz,ssl->heap);
#endif

	ssl->buffers.outputBuffer.length += sendSz;
	ssl->options.sendAlertState = 1;

	return SendBuffered(ssl);
}


int wolfSSL_write(WOLFSSL* ssl, const void* data, int sz)
{
	int ret;

	WOLFSSL_ENTER();
	if (ssl == NULL || data == NULL || sz < 0)
		return BAD_FUNC_ARG;

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif

	ret = _sendData(ssl, data, sz);

	WOLFSSL_LEAVE( ret);

	if (ret < 0)
		return SSL_FATAL_ERROR;
	else
		return ret;
}


