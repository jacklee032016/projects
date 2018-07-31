
#include "cmnSsl.h"


/* client only parts */
#ifndef NO_WOLFSSL_CLIENT

/* called when in state of CONNECT_BEGIN */
int SendClientHello(WOLFSSL* ssl)
{
	byte		*output;
	word32	length, idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
	int		sendSz;
	int		idSz = ssl->options.resuming ? ssl->session.sessionIDSz : 0;
	int		ret;

	if (ssl->suites == NULL) {
		WOLFSSL_MSG("Bad suites pointer in SendClientHello");
		return SUITES_ERROR;
	}

#ifdef HAVE_SESSION_TICKET
	if (ssl->options.resuming && ssl->session.ticketLen > 0)
	{
		SessionTicket* ticket;

		ticket = TLSX_SessionTicket_Create(0, ssl->session.ticket, ssl->session.ticketLen);
		if (ticket == NULL) return MEMORY_E;

		ret = TLSX_UseSessionTicket(&ssl->extensions, ticket);
		if (ret != SSL_SUCCESS) return ret;

		idSz = 0;
	}
#endif

	length = VERSION_SZ + RAN_LEN + idSz + ENUM_LEN + ssl->suites->suiteSz + SUITE_LEN + COMP_LEN + ENUM_LEN;

#ifdef HAVE_TLS_EXTENSIONS
	length += TLSX_GetRequestSize(ssl);
#else
	if (IsAtLeastTLSv1_2(ssl) && ssl->suites->hashSigAlgoSz) {
		length += ssl->suites->hashSigAlgoSz + HELLO_EXT_SZ;
	}
#endif
	sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls) {
		length += ENUM_LEN;   /* cookie */
		if (ssl->arrays->cookieSz != 0)
			length += ssl->arrays->cookieSz;
		sendSz  = length + DTLS_HANDSHAKE_HEADER_SZ + DTLS_RECORD_HEADER_SZ;
		idx    += DTLS_HANDSHAKE_EXTRA + DTLS_RECORD_EXTRA;
	}
#endif

	if (ssl->keys.encryptionOn)
		sendSz += MAX_MSG_EXTRA;

	/* check for available size */
	if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
		return ret;

	/* get ouput buffer */
	output = ssl->buffers.outputBuffer.buffer + ssl->buffers.outputBuffer.length;

	AddHeaders(output, length, HST_CLIENT_HELLO, ssl);

	/* client hello, first version */
	output[idx++] = ssl->version.major;
	output[idx++] = ssl->version.minor;
	ssl->chVersion = ssl->version;  /* store in case changed */

	/* then random */
	if (ssl->options.connectState == CONNECT_BEGIN)
	{
		ret = wc_RNG_GenerateBlock(ssl->rng, output + idx, RAN_LEN);
		if (ret != 0)
			return ret;

		/* store random */
		XMEMCPY(ssl->arrays->clientRandom, output + idx, RAN_LEN);
	}
	else
	{
#ifdef WOLFSSL_DTLS
		/* send same random on hello again */
		XMEMCPY(output + idx, ssl->arrays->clientRandom, RAN_LEN);
#endif
	}
	idx += RAN_LEN;

	/* then session id */
	output[idx++] = (byte)idSz;
	if (idSz) {
		XMEMCPY(output + idx, ssl->session.sessionID, ssl->session.sessionIDSz);
		idx += ssl->session.sessionIDSz;
	}

	/* then DTLS cookie */
#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls) {
		byte cookieSz = ssl->arrays->cookieSz;

		output[idx++] = cookieSz;
		if (cookieSz) {
			XMEMCPY(&output[idx], ssl->arrays->cookie, cookieSz);
			idx += cookieSz;
		}
	}
#endif
	/* then cipher suites */
	c16toa(ssl->suites->suiteSz, output + idx);
	idx += 2;
	XMEMCPY(output + idx, &ssl->suites->suites, ssl->suites->suiteSz);
	idx += ssl->suites->suiteSz;

	/* last, compression */
	output[idx++] = COMP_LEN;
	if (ssl->options.usingCompression)
		output[idx++] = ZLIB_COMPRESSION;
	else
		output[idx++] = NO_COMPRESSION;

#ifdef HAVE_TLS_EXTENSIONS
	idx += TLSX_WriteRequest(ssl, output + idx);

	(void)idx; /* suppress analyzer warning, keep idx current */
#else
	if (IsAtLeastTLSv1_2(ssl) && ssl->suites->hashSigAlgoSz)
	{
		int i;
		/* add in the extensions length */
		c16toa(HELLO_EXT_LEN + ssl->suites->hashSigAlgoSz, output + idx);
		idx += 2;

		c16toa(HELLO_EXT_SIG_ALGO, output + idx);
		idx += 2;
		c16toa(HELLO_EXT_SIGALGO_SZ+ssl->suites->hashSigAlgoSz, output+idx);
		idx += 2;
		c16toa(ssl->suites->hashSigAlgoSz, output + idx);
		idx += 2;

		for (i = 0; i < ssl->suites->hashSigAlgoSz; i++, idx++) {
			output[idx] = ssl->suites->hashSigAlgo[i];
		}
	}
#endif

	if (ssl->keys.encryptionOn) {
		byte* input;
		int   inputSz = idx - RECORD_HEADER_SZ; /* build msg adds rec hdr */

		input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
		if (input == NULL)
			return MEMORY_E;

		XMEMCPY(input, output + RECORD_HEADER_SZ, inputSz);
		sendSz = BuildMessage(ssl, output, sendSz, input,inputSz,handshake);
		XFREE(input, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);

		if (sendSz < 0)
			return sendSz;
	}
	else {
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

	ssl->options.clientState = CLIENT_HELLO_COMPLETE;

#ifdef WOLFSSL_CALLBACKS
	if (ssl->hsInfoOn)
		AddPacketName("ClientHello", &ssl->handShakeInfo);
	if (ssl->toInfoOn)
		AddPacketInfo("ClientHello", &ssl->timeoutInfo, output, sendSz, ssl->heap);
#endif

	ssl->buffers.outputBuffer.length += sendSz;

	return SendBuffered(ssl);
}


int DSH_CheckSessionId(WOLFSSL* ssl)
{
    int ret = 0;

#ifdef HAVE_SECRET_CALLBACK
    /* If a session secret callback exists, we are using that
     * key instead of the saved session key. */
    ret = ret || (ssl->sessionSecretCb != NULL);
#endif

#ifdef HAVE_SESSION_TICKET
    /* server may send blank ticket which may not be expected to indicate
     * exisiting one ok but will also be sending a new one */
    ret = ret || (ssl->session.ticketLen > 0);
#endif

    ret = ret ||
          (ssl->options.haveSessionId && XMEMCMP(ssl->arrays->sessionID,
                                      ssl->session.sessionID, ID_LEN) == 0);

    return ret;
}


/* Make sure client setup is valid for this suite, true on success */
int VerifyClientSuite(WOLFSSL* ssl)
{
    int  havePSK = 0;
    byte first   = ssl->options.cipherSuite0;
    byte second  = ssl->options.cipherSuite;

WOLFSSL_ENTER();

    #ifndef NO_PSK
        havePSK = ssl->options.havePSK;
    #endif

    if (CipherRequires(first, second, REQUIRES_PSK)) {
        WOLFSSL_MSG("Requires PSK");
        if (havePSK == 0) {
            WOLFSSL_MSG("Don't have PSK");
            return 0;
        }
    }

    return 1;  /* success */
}




#ifdef HAVE_ECC

static int CheckCurveId(int oid)
{
    int ret = 0;

    switch (oid) {
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC160)
        case WOLFSSL_ECC_SECP160R1:
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC192)
        case WOLFSSL_ECC_SECP192R1:
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC224)
        case WOLFSSL_ECC_SECP224R1:
#endif
#if defined(HAVE_ALL_CURVES) || !defined(NO_ECC256)
        case WOLFSSL_ECC_SECP256R1:
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC384)
        case WOLFSSL_ECC_SECP384R1:
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC521)
        case WOLFSSL_ECC_SECP521R1:
#endif
            break;

        default:
            ret = -1;
    }

    return ret;
}

#endif /* HAVE_ECC */


int SendClientKeyExchange(WOLFSSL* ssl)
{
#ifdef WOLFSSL_SMALL_STACK
    byte*  encSecret = NULL;
#else
    byte   encSecret[MAX_ENCRYPT_SZ];
#endif
    word32 encSz = 0;
    word32 idx = 0;
    int    ret = 0;
    byte   doUserRsa = 0;

    (void)doUserRsa;

#ifdef HAVE_PK_CALLBACKS
#ifndef NO_RSA
    if (ssl->ctx->RsaEncCb)
        doUserRsa = 1;
#endif /* NO_RSA */
#endif /*HAVE_PK_CALLBACKS */

#ifdef WOLFSSL_SMALL_STACK
    encSecret = (byte*)XMALLOC(MAX_ENCRYPT_SZ, NULL,
                                                   DYNAMIC_TYPE_TMP_BUFFER);
    if (encSecret == NULL)
        return MEMORY_E;
#endif

    switch (ssl->specs.kea) {
    #ifndef NO_RSA
        case rsa_kea:
            ret = wc_RNG_GenerateBlock(ssl->rng, ssl->arrays->preMasterSecret,  SECRET_LEN);
            if (ret != 0) {
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                return ret;
            }

            ssl->arrays->preMasterSecret[0] = ssl->chVersion.major;
            ssl->arrays->preMasterSecret[1] = ssl->chVersion.minor;
            ssl->arrays->preMasterSz = SECRET_LEN;

            if (ssl->peerRsaKey == NULL || ssl->peerRsaKeyPresent == 0) {
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                return NO_PEER_KEY;
            }

            if (doUserRsa) {
            #ifdef HAVE_PK_CALLBACKS
                #ifndef NO_RSA
                    encSz = MAX_ENCRYPT_SZ;
                    ret = ssl->ctx->RsaEncCb(ssl,
                                        ssl->arrays->preMasterSecret,
                                        SECRET_LEN,
                                        encSecret, &encSz,
                                        ssl->buffers.peerRsaKey.buffer,
                                        ssl->buffers.peerRsaKey.length,
                                        ssl->RsaEncCtx);
                #endif /* NO_RSA */
            #endif /*HAVE_PK_CALLBACKS */
            }
            else {
                ret = wc_RsaPublicEncrypt(ssl->arrays->preMasterSecret,
                             SECRET_LEN, encSecret, MAX_ENCRYPT_SZ,
                             ssl->peerRsaKey, ssl->rng);
                if (ret > 0) {
                    encSz = ret;
                    ret = 0;   /* set success to 0 */
                }
            }
            break;
    #endif
    #ifndef NO_DH
        case diffie_hellman_kea:
            {
                buffer  serverP   = ssl->buffers.serverDH_P;
                buffer  serverG   = ssl->buffers.serverDH_G;
                buffer  serverPub = ssl->buffers.serverDH_Pub;
            #ifdef WOLFSSL_SMALL_STACK
                byte*   priv = NULL;
            #else
                byte    priv[ENCRYPT_LEN];
            #endif
                word32  privSz = 0;
                DhKey   key;

                if (serverP.buffer == 0 || serverG.buffer == 0 ||
                                           serverPub.buffer == 0) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return NO_PEER_KEY;
                }

            #ifdef WOLFSSL_SMALL_STACK
                priv = (byte*)XMALLOC(ENCRYPT_LEN, NULL,
                                                   DYNAMIC_TYPE_TMP_BUFFER);
                if (priv == NULL) {
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return MEMORY_E;
                }
            #endif

                wc_InitDhKey(&key);
                ret = wc_DhSetKey(&key, serverP.buffer, serverP.length,
                               serverG.buffer, serverG.length);
                if (ret == 0)
                    /* for DH, encSecret is Yc, agree is pre-master */
                    ret = wc_DhGenerateKeyPair(&key, ssl->rng, priv, &privSz,
                                            encSecret, &encSz);
                if (ret == 0)
                    ret = wc_DhAgree(&key, ssl->arrays->preMasterSecret,
                                  &ssl->arrays->preMasterSz, priv, privSz,
                                  serverPub.buffer, serverPub.length);
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                wc_FreeDhKey(&key);
            }
            break;
    #endif /* NO_DH */
    #ifndef NO_PSK
        case psk_kea:
            {
                byte* pms = ssl->arrays->preMasterSecret;

                ssl->arrays->psk_keySz = ssl->options.client_psk_cb(ssl,
                    ssl->arrays->server_hint, ssl->arrays->client_identity,
                    MAX_PSK_ID_LEN, ssl->arrays->psk_key, MAX_PSK_KEY_LEN);
                if (ssl->arrays->psk_keySz == 0 ||
                    ssl->arrays->psk_keySz > MAX_PSK_KEY_LEN) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return PSK_KEY_ERROR;
                }
                encSz = (word32)XSTRLEN(ssl->arrays->client_identity);
                if (encSz > MAX_PSK_ID_LEN) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return CLIENT_ID_ERROR;
                }
                XMEMCPY(encSecret, ssl->arrays->client_identity, encSz);

                /* make psk pre master secret */
                /* length of key + length 0s + length of key + key */
                c16toa((word16)ssl->arrays->psk_keySz, pms);
                pms += 2;
                XMEMSET(pms, 0, ssl->arrays->psk_keySz);
                pms += ssl->arrays->psk_keySz;
                c16toa((word16)ssl->arrays->psk_keySz, pms);
                pms += 2;
                XMEMCPY(pms, ssl->arrays->psk_key, ssl->arrays->psk_keySz);
                ssl->arrays->preMasterSz = ssl->arrays->psk_keySz * 2 + 4;
                ForceZero(ssl->arrays->psk_key, ssl->arrays->psk_keySz);
                ssl->arrays->psk_keySz = 0; /* No further need */
            }
            break;
    #endif /* NO_PSK */
    #if !defined(NO_DH) && !defined(NO_PSK)
        case dhe_psk_kea:
            {
                byte* pms = ssl->arrays->preMasterSecret;
                byte* es  = encSecret;
                buffer  serverP   = ssl->buffers.serverDH_P;
                buffer  serverG   = ssl->buffers.serverDH_G;
                buffer  serverPub = ssl->buffers.serverDH_Pub;
            #ifdef WOLFSSL_SMALL_STACK
                byte*   priv = NULL;
            #else
                byte    priv[ENCRYPT_LEN];
            #endif
                word32  privSz = 0;
                word32  pubSz = 0;
                word32  esSz = 0;
                DhKey   key;

                if (serverP.buffer == 0 || serverG.buffer == 0 ||
                                           serverPub.buffer == 0) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return NO_PEER_KEY;
                }

                ssl->arrays->psk_keySz = ssl->options.client_psk_cb(ssl,
                     ssl->arrays->server_hint, ssl->arrays->client_identity,
                     MAX_PSK_ID_LEN, ssl->arrays->psk_key, MAX_PSK_KEY_LEN);
                if (ssl->arrays->psk_keySz == 0 ||
                                 ssl->arrays->psk_keySz > MAX_PSK_KEY_LEN) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return PSK_KEY_ERROR;
                }
                esSz = (word32)XSTRLEN(ssl->arrays->client_identity);

                if (esSz > MAX_PSK_ID_LEN) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return CLIENT_ID_ERROR;
                }

            #ifdef WOLFSSL_SMALL_STACK
                priv = (byte*)XMALLOC(ENCRYPT_LEN, NULL,
                                                   DYNAMIC_TYPE_TMP_BUFFER);
                if (priv == NULL) {
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return MEMORY_E;
                }
            #endif
                c16toa((word16)esSz, es);
                es += OPAQUE16_LEN;
                XMEMCPY(es, ssl->arrays->client_identity, esSz);
                es += esSz;
                encSz = esSz + OPAQUE16_LEN;

                wc_InitDhKey(&key);
                ret = wc_DhSetKey(&key, serverP.buffer, serverP.length,
                               serverG.buffer, serverG.length);
                if (ret == 0)
                    /* for DH, encSecret is Yc, agree is pre-master */
                    ret = wc_DhGenerateKeyPair(&key, ssl->rng, priv, &privSz,
                                            es + OPAQUE16_LEN, &pubSz);
                if (ret == 0)
                    ret = wc_DhAgree(&key, pms + OPAQUE16_LEN,
                                  &ssl->arrays->preMasterSz, priv, privSz,
                                  serverPub.buffer, serverPub.length);
                wc_FreeDhKey(&key);
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                if (ret != 0) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return ret;
                }

                c16toa((word16)pubSz, es);
                encSz += pubSz + OPAQUE16_LEN;
                c16toa((word16)ssl->arrays->preMasterSz, pms);
                ssl->arrays->preMasterSz += OPAQUE16_LEN;
                pms += ssl->arrays->preMasterSz;

                /* make psk pre master secret */
                /* length of key + length 0s + length of key + key */
                c16toa((word16)ssl->arrays->psk_keySz, pms);
                pms += OPAQUE16_LEN;
                XMEMCPY(pms, ssl->arrays->psk_key, ssl->arrays->psk_keySz);
                ssl->arrays->preMasterSz +=
                                      ssl->arrays->psk_keySz + OPAQUE16_LEN;
                ForceZero(ssl->arrays->psk_key, ssl->arrays->psk_keySz);
                ssl->arrays->psk_keySz = 0; /* No further need */
            }
            break;
    #endif /* !NO_DH && !NO_PSK */
    #ifdef HAVE_NTRU
        case ntru_kea:
            {
                word32 rc;
                word16 cipherLen = MAX_ENCRYPT_SZ;
                DRBG_HANDLE drbg;
                static uint8_t const wolfsslStr[] = {
                    'C', 'y', 'a', 'S', 'S', 'L', ' ', 'N', 'T', 'R', 'U'
                };

                ret = wc_RNG_GenerateBlock(ssl->rng,
                                  ssl->arrays->preMasterSecret, SECRET_LEN);
                if (ret != 0) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return ret;
                }

                ssl->arrays->preMasterSz = SECRET_LEN;

                if (ssl->peerNtruKeyPresent == 0) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return NO_PEER_KEY;
                }

                rc = ntru_crypto_drbg_instantiate(MAX_NTRU_BITS, wolfsslStr,
                                             sizeof(wolfsslStr), GetEntropy,
                                             &drbg);
                if (rc != DRBG_OK) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return NTRU_DRBG_ERROR;
                }

                rc = ntru_crypto_ntru_encrypt(drbg, ssl->peerNtruKeyLen,
                                              ssl->peerNtruKey,
                                              ssl->arrays->preMasterSz,
                                              ssl->arrays->preMasterSecret,
                                              &cipherLen, encSecret);
                ntru_crypto_drbg_uninstantiate(drbg);
                if (rc != NTRU_OK) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return NTRU_ENCRYPT_ERROR;
                }

                encSz = cipherLen;
                ret = 0;
            }
            break;
    #endif /* HAVE_NTRU */
    #ifdef HAVE_ECC
        case ecc_diffie_hellman_kea:
            {
                ecc_key  myKey;
                ecc_key* peerKey = NULL;
                word32   size = MAX_ENCRYPT_SZ;

                if (ssl->specs.static_ecdh) {
                    /* TODO: EccDsa is really fixed Ecc change naming */
                    if (!ssl->peerEccDsaKey || !ssl->peerEccDsaKeyPresent ||
                                               !ssl->peerEccDsaKey->dp) {
                    #ifdef WOLFSSL_SMALL_STACK
                        XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    #endif
                        return NO_PEER_KEY;
                    }
                    peerKey = ssl->peerEccDsaKey;
                }
                else {
                    if (!ssl->peerEccKey || !ssl->peerEccKeyPresent ||
                                            !ssl->peerEccKey->dp) {
                    #ifdef WOLFSSL_SMALL_STACK
                        XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    #endif
                        return NO_PEER_KEY;
                    }
                    peerKey = ssl->peerEccKey;
                }

                if (peerKey == NULL) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return NO_PEER_KEY;
                }

                wc_ecc_init(&myKey);
                ret = wc_ecc_make_key(ssl->rng, peerKey->dp->size, &myKey);
                if (ret != 0) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return ECC_MAKEKEY_ERROR;
                }

                /* precede export with 1 byte length */
                ret = wc_ecc_export_x963(&myKey, encSecret + 1, &size);
                encSecret[0] = (byte)size;
                encSz = size + 1;

                if (ret != 0)
                    ret = ECC_EXPORT_ERROR;
                else {
                    size = sizeof(ssl->arrays->preMasterSecret);
                    ret  = wc_ecc_shared_secret(&myKey, peerKey,
                                             ssl->arrays->preMasterSecret, &size);
                    if (ret != 0)
                        ret = ECC_SHARED_ERROR;
                }

                ssl->arrays->preMasterSz = size;
                wc_ecc_free(&myKey);
            }
            break;
    #endif /* HAVE_ECC */
        default:
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return ALGO_ID_E; /* unsupported kea */
    }

    if (ret == 0) {
        byte              *output;
        int                sendSz;
        word32             tlsSz = 0;

        if (ssl->options.tls || ssl->specs.kea == diffie_hellman_kea)
            tlsSz = 2;

        if (ssl->specs.kea == ecc_diffie_hellman_kea ||
            ssl->specs.kea == dhe_psk_kea)  /* always off */
            tlsSz = 0;

        sendSz = encSz + tlsSz + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
        idx    = HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                sendSz += DTLS_HANDSHAKE_EXTRA + DTLS_RECORD_EXTRA;
                idx    += DTLS_HANDSHAKE_EXTRA + DTLS_RECORD_EXTRA;
            }
        #endif

        if (ssl->keys.encryptionOn)
            sendSz += MAX_MSG_EXTRA;

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0) {
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return ret;
        }

        /* get ouput buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        AddHeaders(output, encSz + tlsSz, client_key_exchange, ssl);

        if (tlsSz) {
            c16toa((word16)encSz, &output[idx]);
            idx += 2;
        }
        XMEMCPY(output + idx, encSecret, encSz);
        idx += encSz;

        if (ssl->keys.encryptionOn) {
            byte* input;
            int   inputSz = idx-RECORD_HEADER_SZ; /* buildmsg adds rechdr */

            input = (byte*)XMALLOC(inputSz, ssl->heap,
                                   DYNAMIC_TYPE_TMP_BUFFER);
            if (input == NULL) {
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                return MEMORY_E;
            }

            XMEMCPY(input, output + RECORD_HEADER_SZ, inputSz);
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                  handshake);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
            if (sendSz < 0) {
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                return sendSz;
            }
        } else {
            ret = HashOutput(ssl, output, sendSz, 0);
            if (ret != 0) {
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                return ret;
            }
        }

        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                if ((ret = DtlsPoolSave(ssl, output, sendSz)) != 0) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    return ret;
                }
            }
        #endif

        #ifdef WOLFSSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName("ClientKeyExchange", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddPacketInfo("ClientKeyExchange", &ssl->timeoutInfo,
                              output, sendSz, ssl->heap);
        #endif

        ssl->buffers.outputBuffer.length += sendSz;

        if (ssl->options.groupMessages)
            ret = 0;
        else
            ret = SendBuffered(ssl);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(encSecret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret == 0 || ret == WANT_WRITE) {
        int tmpRet = MakeMasterSecret(ssl);
        if (tmpRet != 0)
            ret = tmpRet;   /* save WANT_WRITE unless more serious */
        ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;
    }
    /* No further need for PMS */
    ForceZero(ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);
    ssl->arrays->preMasterSz = 0;

    return ret;
}

#ifndef NO_CERTS
int SendCertificateVerify(WOLFSSL* ssl)
{
    byte              *output;
    int                sendSz = MAX_CERT_VERIFY_SZ, length, ret;
    word32             idx = 0;
    word32             sigOutSz = 0;
#ifndef NO_RSA
    RsaKey             key;
    int                initRsaKey = 0;
#endif
    int                usingEcc = 0;
#ifdef HAVE_ECC
    ecc_key            eccKey;
#endif

    (void)idx;

    if (ssl->options.sendVerify == SEND_BLANK_CERT)
        return 0;  /* sent blank cert, can't verify */

    if (ssl->keys.encryptionOn)
        sendSz += MAX_MSG_EXTRA;

    /* check for available size */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* get ouput buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    ret = BuildCertHashes(ssl, &ssl->hsHashes->certHashes);
    if (ret != 0)
        return ret;

#ifdef HAVE_ECC
    wc_ecc_init(&eccKey);
#endif
#ifndef NO_RSA
    ret = wc_InitRsaKey(&key, ssl->heap);
    if (ret == 0) initRsaKey = 1;
    if (ret == 0)
        ret = wc_RsaPrivateKeyDecode(ssl->buffers.key.buffer, &idx, &key,
                                  ssl->buffers.key.length);
    if (ret == 0)
        sigOutSz = wc_RsaEncryptSize(&key);
    else
#endif
    {
#ifdef HAVE_ECC
        WOLFSSL_MSG("Trying ECC client cert, RSA didn't work");

        idx = 0;
        ret = wc_EccPrivateKeyDecode(ssl->buffers.key.buffer, &idx, &eccKey,
                                  ssl->buffers.key.length);
        if (ret == 0) {
            WOLFSSL_MSG("Using ECC client cert");
            usingEcc = 1;
            sigOutSz = MAX_ENCODED_SIG_SZ;
        }
        else {
            WOLFSSL_MSG("Bad client cert type");
        }
#endif
    }
    if (ret == 0) {
        byte*  verify = (byte*)&output[RECORD_HEADER_SZ +
                                       HANDSHAKE_HEADER_SZ];
#ifndef NO_OLD_TLS
        byte*  signBuffer = ssl->hsHashes->certHashes.md5;
#else
        byte*  signBuffer = NULL;
#endif
        word32 signSz = FINISHED_SZ;
        word32 extraSz = 0;  /* tls 1.2 hash/sig */
#ifdef WOLFSSL_SMALL_STACK
        byte*  encodedSig = NULL;
#else
        byte   encodedSig[MAX_ENCODED_SIG_SZ];
#endif

#ifdef WOLFSSL_SMALL_STACK
        encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL,
                                                   DYNAMIC_TYPE_TMP_BUFFER);
        if (encodedSig == NULL) {
        #ifndef NO_RSA
            if (initRsaKey)
                wc_FreeRsaKey(&key);
        #endif
        #ifdef HAVE_ECC
            wc_ecc_free(&eccKey);
        #endif
            return MEMORY_E;
        }
#endif

        (void)encodedSig;
        (void)signSz;
        (void)signBuffer;

        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls)
                verify += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
        #endif
        length = sigOutSz;
        if (IsAtLeastTLSv1_2(ssl)) {
            verify[0] = ssl->suites->hashAlgo;
            verify[1] = usingEcc ? ecc_dsa_sa_algo : rsa_sa_algo;
            extraSz = HASH_SIG_SIZE;
        }

        if (usingEcc) {
#ifdef HAVE_ECC
            word32 localSz = MAX_ENCODED_SIG_SZ;
            word32 digestSz;
            byte*  digest;
            byte   doUserEcc = 0;
#ifndef NO_OLD_TLS
            /* old tls default */
            digestSz = SHA_DIGEST_SIZE;
            digest   = ssl->hsHashes->certHashes.sha;
#else
            /* new tls default */
            digestSz = SHA256_DIGEST_SIZE;
            digest   = ssl->hsHashes->certHashes.sha256;
#endif

            #ifdef HAVE_PK_CALLBACKS
                #ifdef HAVE_ECC
                    if (ssl->ctx->EccSignCb)
                        doUserEcc = 1;
                #endif /* HAVE_ECC */
            #endif /*HAVE_PK_CALLBACKS */

            if (IsAtLeastTLSv1_2(ssl)) {
                if (ssl->suites->hashAlgo == sha_mac) {
                    #ifndef NO_SHA
                        digest = ssl->hsHashes->certHashes.sha;
                        digestSz = SHA_DIGEST_SIZE;
                    #endif
                }
                else if (ssl->suites->hashAlgo == sha256_mac) {
                    #ifndef NO_SHA256
                        digest = ssl->hsHashes->certHashes.sha256;
                        digestSz = SHA256_DIGEST_SIZE;
                    #endif
                }
                else if (ssl->suites->hashAlgo == sha384_mac) {
                    #ifdef WOLFSSL_SHA384
                        digest = ssl->hsHashes->certHashes.sha384;
                        digestSz = SHA384_DIGEST_SIZE;
                    #endif
                }
                else if (ssl->suites->hashAlgo == sha512_mac) {
                    #ifdef WOLFSSL_SHA512
                        digest = ssl->hsHashes->certHashes.sha512;
                        digestSz = SHA512_DIGEST_SIZE;
                    #endif
                }
            }

            if (doUserEcc) {
            #ifdef HAVE_PK_CALLBACKS
                #ifdef HAVE_ECC
                    ret = ssl->ctx->EccSignCb(ssl, digest, digestSz,
                                    encodedSig, &localSz,
                                    ssl->buffers.key.buffer,
                                    ssl->buffers.key.length,
                                    ssl->EccSignCtx);
                #endif /* HAVE_ECC */
            #endif /*HAVE_PK_CALLBACKS */
            }
            else {
                ret = wc_ecc_sign_hash(digest, digestSz, encodedSig,
                                    &localSz, ssl->rng, &eccKey);
            }
            if (ret == 0) {
                length = localSz;
                c16toa((word16)length, verify + extraSz); /* prepend hdr */
                XMEMCPY(verify + extraSz + VERIFY_HEADER,encodedSig,length);
            }
#endif
        }
#ifndef NO_RSA
        else {
            byte doUserRsa = 0;

            #ifdef HAVE_PK_CALLBACKS
                if (ssl->ctx->RsaSignCb)
                    doUserRsa = 1;
            #endif /*HAVE_PK_CALLBACKS */

            if (IsAtLeastTLSv1_2(ssl)) {
                /*
                 * MSVC Compiler complains because it can not
                 * guarantee any of the conditionals will succeed in
                 * assigning a value before wc_EncodeSignature executes.
                 */
                byte* digest    = NULL;
                int   digestSz  = 0;
                int   typeH     = 0;
                int   didSet    = 0;

                if (ssl->suites->hashAlgo == sha_mac) {
                    #ifndef NO_SHA
                        digest   = ssl->hsHashes->certHashes.sha;
                        typeH    = SHAh;
                        digestSz = SHA_DIGEST_SIZE;
                        didSet   = 1;
                    #endif
                }
                else if (ssl->suites->hashAlgo == sha256_mac) {
                    #ifndef NO_SHA256
                        digest   = ssl->hsHashes->certHashes.sha256;
                        typeH    = SHA256h;
                        digestSz = SHA256_DIGEST_SIZE;
                        didSet   = 1;
                    #endif
                }
                else if (ssl->suites->hashAlgo == sha384_mac) {
                    #ifdef WOLFSSL_SHA384
                        digest   = ssl->hsHashes->certHashes.sha384;
                        typeH    = SHA384h;
                        digestSz = SHA384_DIGEST_SIZE;
                        didSet   = 1;
                    #endif
                }
                else if (ssl->suites->hashAlgo == sha512_mac) {
                    #ifdef WOLFSSL_SHA512
                        digest   = ssl->hsHashes->certHashes.sha512;
                        typeH    = SHA512h;
                        digestSz = SHA512_DIGEST_SIZE;
                        didSet   = 1;
                    #endif
                }

                if (didSet == 0) {
                    /* defaults */
                    #ifndef NO_OLD_TLS
                        digest = ssl->hsHashes->certHashes.sha;
                        digestSz = SHA_DIGEST_SIZE;
                        typeH = SHAh;
                    #else
                        digest = ssl->hsHashes->certHashes.sha256;
                        digestSz = SHA256_DIGEST_SIZE;
                        typeH = SHA256h;
                    #endif
                }

                signSz = wc_EncodeSignature(encodedSig, digest,digestSz,typeH);
                signBuffer = encodedSig;
            }

            c16toa((word16)length, verify + extraSz); /* prepend hdr */
            if (doUserRsa) {
            #ifdef HAVE_PK_CALLBACKS
                #ifndef NO_RSA
                    word32 ioLen = ENCRYPT_LEN;
                    ret = ssl->ctx->RsaSignCb(ssl, signBuffer, signSz,
                                        verify + extraSz + VERIFY_HEADER,
                                        &ioLen,
                                        ssl->buffers.key.buffer,
                                        ssl->buffers.key.length,
                                        ssl->RsaSignCtx);
                #endif /* NO_RSA */
            #endif /*HAVE_PK_CALLBACKS */
            }
            else {
                ret = wc_RsaSSL_Sign(signBuffer, signSz, verify + extraSz +
                              VERIFY_HEADER, ENCRYPT_LEN, &key, ssl->rng);
            }

            if (ret > 0)
                ret = 0;  /* RSA reset */
        }
#endif
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encodedSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

        if (ret == 0) {
            AddHeaders(output, length + extraSz + VERIFY_HEADER,
                       certificate_verify, ssl);

            sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + length +
                     extraSz + VERIFY_HEADER;

            #ifdef WOLFSSL_DTLS
                if (ssl->options.dtls) {
                    sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                }
            #endif

            if (ssl->keys.encryptionOn) {
                byte* input;
                int   inputSz = sendSz - RECORD_HEADER_SZ;
                                /* build msg adds rec hdr */
                input = (byte*)XMALLOC(inputSz, ssl->heap,
                                       DYNAMIC_TYPE_TMP_BUFFER);
                if (input == NULL)
                    ret = MEMORY_E;
                else {
                    XMEMCPY(input, output + RECORD_HEADER_SZ, inputSz);
                    sendSz = BuildMessage(ssl, output,
                                          MAX_CERT_VERIFY_SZ +MAX_MSG_EXTRA,
                                          input, inputSz, handshake);
                    XFREE(input, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);

                    if (sendSz < 0)
                        ret = sendSz;
                }
            } else {
                ret = HashOutput(ssl, output, sendSz, 0);
            }

            #ifdef WOLFSSL_DTLS
                if (ssl->options.dtls) {
                    if ((ret = DtlsPoolSave(ssl, output, sendSz)) != 0)
                        return ret;
                }
            #endif
        }
    }
#ifndef NO_RSA
    if (initRsaKey)
        wc_FreeRsaKey(&key);
#endif
#ifdef HAVE_ECC
    wc_ecc_free(&eccKey);
#endif

    if (ret == 0) {
        #ifdef WOLFSSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName("CertificateVerify", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddPacketInfo("CertificateVerify", &ssl->timeoutInfo, output, sendSz, ssl->heap);
        #endif
        ssl->buffers.outputBuffer.length += sendSz;
        if (ssl->options.groupMessages)
            return 0;
        else
            return SendBuffered(ssl);
    }
    else
        return ret;
}
#endif /* NO_CERTS */


#endif /* NO_WOLFSSL_CLIENT */

