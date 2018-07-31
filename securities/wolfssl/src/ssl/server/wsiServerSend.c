
#include "cmnSsl.h"

#ifndef NO_WOLFSSL_SERVER

    int SendServerHello(WOLFSSL* ssl)
    {
        byte              *output;
        word32             length, idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int                sendSz;
        int                ret;
        byte               sessIdSz = ID_LEN;

        length = VERSION_SZ + RAN_LEN
               + ID_LEN + ENUM_LEN
               + SUITE_LEN
               + ENUM_LEN;

#ifdef HAVE_TLS_EXTENSIONS
        length += TLSX_GetResponseSize(ssl);

    #ifdef HAVE_SESSION_TICKET
        if (ssl->options.useTicket && ssl->arrays->sessionIDSz == 0) {
            /* no session id */
            length  -= ID_LEN;
            sessIdSz = 0;
        }
    #endif /* HAVE_SESSION_TICKET */
#endif

        /* check for avalaible size */
        if ((ret = CheckAvailableSize(ssl, MAX_HELLO_SZ)) != 0)
            return ret;

        /* get ouput buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
        AddHeaders(output, length, server_hello, ssl);

        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                idx    += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
            }
        #endif
        /* now write to output */
            /* first version */
        output[idx++] = ssl->version.major;
        output[idx++] = ssl->version.minor;

            /* then random */
        if (!ssl->options.resuming) {
            ret = wc_RNG_GenerateBlock(ssl->rng, ssl->arrays->serverRandom,
                                                                       RAN_LEN);
            if (ret != 0)
                return ret;
        }

        XMEMCPY(output + idx, ssl->arrays->serverRandom, RAN_LEN);
        idx += RAN_LEN;

#ifdef SHOW_SECRETS
        {
            int j;
            printf("server random: ");
            for (j = 0; j < RAN_LEN; j++)
                printf("%02x", ssl->arrays->serverRandom[j]);
            printf("\n");
        }
#endif
            /* then session id */
        output[idx++] = sessIdSz;
        if (sessIdSz) {

            if (!ssl->options.resuming) {
                ret = wc_RNG_GenerateBlock(ssl->rng, ssl->arrays->sessionID,
                                           sessIdSz);
                if (ret != 0) return ret;
            }

            XMEMCPY(output + idx, ssl->arrays->sessionID, sessIdSz);
            idx += sessIdSz;
        }

            /* then cipher suite */
        output[idx++] = ssl->options.cipherSuite0;
        output[idx++] = ssl->options.cipherSuite;

            /* then compression */
        if (ssl->options.usingCompression)
            output[idx++] = ZLIB_COMPRESSION;
        else
            output[idx++] = NO_COMPRESSION;

            /* last, extensions */
#ifdef HAVE_TLS_EXTENSIONS
        TLSX_WriteResponse(ssl, output + idx);
#endif

        ssl->buffers.outputBuffer.length += sendSz;
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
                AddPacketName("ServerHello", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddPacketInfo("ServerHello", &ssl->timeoutInfo, output, sendSz,
                              ssl->heap);
        #endif

        ssl->options.serverState = SERVER_HELLO_COMPLETE;

        if (ssl->options.groupMessages)
            return 0;
        else
            return SendBuffered(ssl);
    }


#ifdef HAVE_ECC

    static byte SetCurveId(int size)
    {
        switch(size) {
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC160)
            case 20:
                return WOLFSSL_ECC_SECP160R1;
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC192)
            case 24:
                return WOLFSSL_ECC_SECP192R1;
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC224)
            case 28:
                return WOLFSSL_ECC_SECP224R1;
#endif
#if defined(HAVE_ALL_CURVES) || !defined(NO_ECC256)
            case 32:
                return WOLFSSL_ECC_SECP256R1;
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC384)
            case 48:
                return WOLFSSL_ECC_SECP384R1;
#endif
#if defined(HAVE_ALL_CURVES) || defined(HAVE_ECC521)
            case 66:
                return WOLFSSL_ECC_SECP521R1;
#endif
            default:
                return 0;
        }
    }

#endif /* HAVE_ECC */


    /* Make sure server cert/key are valid for this suite, true on success */
    static int VerifyServerSuite(WOLFSSL* ssl, word16 idx)
    {
        int  haveRSA = !ssl->options.haveStaticECC;
        int  havePSK = 0;
        byte first;
        byte second;

	WOLFSSL_ENTER();

        if (ssl->suites == NULL) {
            WOLFSSL_MSG("Suites pointer error");
            return 0;
        }

        first   = ssl->suites->suites[idx];
        second  = ssl->suites->suites[idx+1];

        #ifndef NO_PSK
            havePSK = ssl->options.havePSK;
        #endif

        if (ssl->options.haveNTRU)
            haveRSA = 0;

        if (CipherRequires(first, second, REQUIRES_RSA)) {
            WOLFSSL_MSG("Requires RSA");
            if (haveRSA == 0) {
                WOLFSSL_MSG("Don't have RSA");
                return 0;
            }
        }

        if (CipherRequires(first, second, REQUIRES_DHE)) {
            WOLFSSL_MSG("Requires DHE");
            if (ssl->options.haveDH == 0) {
                WOLFSSL_MSG("Don't have DHE");
                return 0;
            }
        }

        if (CipherRequires(first, second, REQUIRES_ECC_DSA)) {
            WOLFSSL_MSG("Requires ECCDSA");
            if (ssl->options.haveECDSAsig == 0) {
                WOLFSSL_MSG("Don't have ECCDSA");
                return 0;
            }
        }

        if (CipherRequires(first, second, REQUIRES_ECC_STATIC)) {
            WOLFSSL_MSG("Requires static ECC");
            if (ssl->options.haveStaticECC == 0) {
                WOLFSSL_MSG("Don't have static ECC");
                return 0;
            }
        }

        if (CipherRequires(first, second, REQUIRES_PSK)) {
            WOLFSSL_MSG("Requires PSK");
            if (havePSK == 0) {
                WOLFSSL_MSG("Don't have PSK");
                return 0;
            }
        }

        if (CipherRequires(first, second, REQUIRES_NTRU)) {
            WOLFSSL_MSG("Requires NTRU");
            if (ssl->options.haveNTRU == 0) {
                WOLFSSL_MSG("Don't have NTRU");
                return 0;
            }
        }

        if (CipherRequires(first, second, REQUIRES_RSA_SIG)) {
            WOLFSSL_MSG("Requires RSA Signature");
            if (ssl->options.side == WOLFSSL_SERVER_END &&
                                           ssl->options.haveECDSAsig == 1) {
                WOLFSSL_MSG("Don't have RSA Signature");
                return 0;
            }
        }

#ifdef HAVE_SUPPORTED_CURVES
        if (!TLSX_ValidateEllipticCurves(ssl, first, second)) {
            WOLFSSL_MSG("Don't have matching curves");
                return 0;
        }
#endif

        /* ECCDHE is always supported if ECC on */

        return 1;
    }


    int MatchSuite(WOLFSSL* ssl, Suites* peerSuites)
    {
        word16 i, j;

	WOLFSSL_ENTER();

        /* & 0x1 equivalent % 2 */
        if (peerSuites->suiteSz == 0 || peerSuites->suiteSz & 0x1)
            return MATCH_SUITE_ERROR;

        if (ssl->suites == NULL)
            return SUITES_ERROR;
        /* start with best, if a match we are good */
        for (i = 0; i < ssl->suites->suiteSz; i += 2)
            for (j = 0; j < peerSuites->suiteSz; j += 2)
                if (ssl->suites->suites[i]   == peerSuites->suites[j] &&
                    ssl->suites->suites[i+1] == peerSuites->suites[j+1] ) {

                    if (VerifyServerSuite(ssl, i)) {
                        int result;
                        WOLFSSL_MSG("Verified suite validity");
                        ssl->options.cipherSuite0 = ssl->suites->suites[i];
                        ssl->options.cipherSuite  = ssl->suites->suites[i+1];
                        result = SetCipherSpecs(ssl);
                        if (result == 0)
                            PickHashSigAlgo(ssl, peerSuites->hashSigAlgo,
                                                 peerSuites->hashSigAlgoSz);
                        return result;
                    }
                    else {
                        WOLFSSL_MSG("Could not verify suite validity, continue");
                    }
                }

        return MATCH_SUITE_ERROR;
    }


#ifdef OLD_HELLO_ALLOWED

    /* process old style client hello, deprecate? */
    int ProcessOldClientHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                              word32 inSz, word16 sz)
    {
        word32          idx = *inOutIdx;
        word16          sessionSz;
        word16          randomSz;
        word16          i, j;
        ProtocolVersion pv;
        Suites          clSuites;

        (void)inSz;
        WOLFSSL_MSG("Got old format client hello");
#ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("ClientHello", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddLateName("ClientHello", &ssl->timeoutInfo);
#endif

        /* manually hash input since different format */
#ifndef NO_OLD_TLS
#ifndef NO_MD5
        wc_Md5Update(&ssl->hsHashes->hashMd5, input + idx, sz);
#endif
#ifndef NO_SHA
        wc_ShaUpdate(&ssl->hsHashes->hashSha, input + idx, sz);
#endif
#endif
#ifndef NO_SHA256
        if (IsAtLeastTLSv1_2(ssl)) {
            int shaRet = wc_Sha256Update(&ssl->hsHashes->hashSha256,
                                         input + idx, sz);
            if (shaRet != 0)
                return shaRet;
        }
#endif

        /* does this value mean HST_CLIENT_HELLO? */
        idx++;

        /* version */
        pv.major = input[idx++];
        pv.minor = input[idx++];
        ssl->chVersion = pv;  /* store */

        if (ssl->version.minor > pv.minor) {
            byte haveRSA = 0;
            byte havePSK = 0;
            if (!ssl->options.downgrade) {
                WOLFSSL_MSG("Client trying to connect with lesser version");
                return VERSION_ERROR;
            }
            if (pv.minor < ssl->options.minDowngrade) {
                WOLFSSL_MSG("    version below minimum allowed, fatal error");
                return VERSION_ERROR;
            }
            if (pv.minor == SSLv3_MINOR) {
                /* turn off tls */
                WOLFSSL_MSG("    downgrading to SSLv3");
                ssl->options.tls    = 0;
                ssl->options.tls1_1 = 0;
                ssl->version.minor  = SSLv3_MINOR;
            }
            else if (pv.minor == TLSv1_MINOR) {
                WOLFSSL_MSG("    downgrading to TLSv1");
                /* turn off tls 1.1+ */
                ssl->options.tls1_1 = 0;
                ssl->version.minor  = TLSv1_MINOR;
            }
            else if (pv.minor == TLSv1_1_MINOR) {
                WOLFSSL_MSG("    downgrading to TLSv1.1");
                ssl->version.minor  = TLSv1_1_MINOR;
            }
#ifndef NO_RSA
            haveRSA = 1;
#endif
#ifndef NO_PSK
            havePSK = ssl->options.havePSK;
#endif

            InitSuites(ssl->suites, ssl->version, haveRSA, havePSK,
                       ssl->options.haveDH, ssl->options.haveNTRU,
                       ssl->options.haveECDSAsig, ssl->options.haveStaticECC,
                       ssl->options.side);
        }

        /* suite size */
        ato16(&input[idx], &clSuites.suiteSz);
        idx += 2;

        if (clSuites.suiteSz > MAX_SUITE_SZ)
            return BUFFER_ERROR;
        clSuites.hashSigAlgoSz = 0;

        /* session size */
        ato16(&input[idx], &sessionSz);
        idx += 2;

        if (sessionSz > ID_LEN)
            return BUFFER_ERROR;

        /* random size */
        ato16(&input[idx], &randomSz);
        idx += 2;

        if (randomSz > RAN_LEN)
            return BUFFER_ERROR;

        /* suites */
        for (i = 0, j = 0; i < clSuites.suiteSz; i += 3) {
            byte first = input[idx++];
            if (!first) { /* implicit: skip sslv2 type */
                XMEMCPY(&clSuites.suites[j], &input[idx], 2);
                j += 2;
            }
            idx += 2;
        }
        clSuites.suiteSz = j;

        /* session id */
        if (sessionSz) {
            XMEMCPY(ssl->arrays->sessionID, input + idx, sessionSz);
            ssl->arrays->sessionIDSz = (byte)sessionSz;
            idx += sessionSz;
            ssl->options.resuming = 1;
        }

        /* random */
        if (randomSz < RAN_LEN)
            XMEMSET(ssl->arrays->clientRandom, 0, RAN_LEN - randomSz);
        XMEMCPY(&ssl->arrays->clientRandom[RAN_LEN - randomSz], input + idx,
               randomSz);
        idx += randomSz;

        if (ssl->options.usingCompression)
            ssl->options.usingCompression = 0;  /* turn off */

        ssl->options.clientState = CLIENT_HELLO_COMPLETE;
        *inOutIdx = idx;

        ssl->options.haveSessionId = 1;
        /* _doClientHello uses same resume code */
        if (ssl->options.resuming) {  /* let's try */
            int ret = -1;
            WOLFSSL_SESSION* session = GetSession(ssl,
                                                  ssl->arrays->masterSecret);
            #ifdef HAVE_SESSION_TICKET
                if (ssl->options.useTicket == 1) {
                    session = &ssl->session;
                }
            #endif

            if (!session) {
                WOLFSSL_MSG("Session lookup for resume failed");
                ssl->options.resuming = 0;
            } else {
                if (MatchSuite(ssl, &clSuites) < 0) {
                    WOLFSSL_MSG("Unsupported cipher suite, OldClientHello");
                    return UNSUPPORTED_SUITE;
                }
                #ifdef SESSION_CERTS
                    ssl->session = *session; /* restore session certs. */
                #endif

                ret = wc_RNG_GenerateBlock(ssl->rng, ssl->arrays->serverRandom,
                                                                       RAN_LEN);
                if (ret != 0)
                    return ret;

                #ifdef NO_OLD_TLS
                    ret = DeriveTlsKeys(ssl);
                #else
                    #ifndef NO_TLS
                        if (ssl->options.tls)
                            ret = DeriveTlsKeys(ssl);
                    #endif
                        if (!ssl->options.tls)
                            ret = DeriveKeys(ssl);
                #endif
                ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;

                return ret;
            }
        }

        return MatchSuite(ssl, &clSuites);
    }

#endif /* OLD_HELLO_ALLOWED */


    int SendServerHelloDone(WOLFSSL* ssl)
    {
        byte              *output;
        int                sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int                ret;

        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls)
                sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
        #endif
        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get ouput buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        AddHeaders(output, 0, server_hello_done, ssl);

        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                if ((ret = DtlsPoolSave(ssl, output, sendSz)) != 0)
                    return 0;
            }
        #endif

        ret = HashOutput(ssl, output, sendSz, 0);
            if (ret != 0)
                return ret;

#ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("ServerHelloDone", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("ServerHelloDone", &ssl->timeoutInfo, output, sendSz,
                          ssl->heap);
#endif
        ssl->options.serverState = SERVER_HELLODONE_COMPLETE;

        ssl->buffers.outputBuffer.length += sendSz;

        return SendBuffered(ssl);
    }


#ifdef HAVE_SESSION_TICKET

#define WOLFSSL_TICKET_FIXED_SZ (WOLFSSL_TICKET_NAME_SZ + \
                WOLFSSL_TICKET_IV_SZ + WOLFSSL_TICKET_MAC_SZ + LENGTH_SZ)
#define WOLFSSL_TICKET_ENC_SZ (SESSION_TICKET_LEN - WOLFSSL_TICKET_FIXED_SZ)

    /* our ticket format */
    typedef struct InternalTicket {
        ProtocolVersion pv;                    /* version when ticket created */
        byte            suite[SUITE_LEN];      /* cipher suite when created */
        byte            msecret[SECRET_LEN];   /* master secret */
        word32          timestamp;             /* born on */
    } InternalTicket;

    /* fit within SESSION_TICKET_LEN */
    typedef struct ExternalTicket {
        byte key_name[WOLFSSL_TICKET_NAME_SZ];  /* key context name */
        byte iv[WOLFSSL_TICKET_IV_SZ];          /* this ticket's iv */
        byte enc_len[LENGTH_SZ];                /* encrypted length */
        byte enc_ticket[WOLFSSL_TICKET_ENC_SZ]; /* encrypted internal ticket */
        byte mac[WOLFSSL_TICKET_MAC_SZ];        /* total mac */
        /* !! if add to structure, add to TICKET_FIXED_SZ !! */
    } ExternalTicket;

    /* create a new session ticket, 0 on success */
    static int CreateTicket(WOLFSSL* ssl)
    {
        InternalTicket  it;
        ExternalTicket* et = (ExternalTicket*)ssl->session.ticket;
        int encLen;
        int ret;
        byte zeros[WOLFSSL_TICKET_MAC_SZ];   /* biggest cmp size */

        /* build internal */
        it.pv.major = ssl->version.major;
        it.pv.minor = ssl->version.minor;

        it.suite[0] = ssl->options.cipherSuite0;
        it.suite[1] = ssl->options.cipherSuite;

        XMEMCPY(it.msecret, ssl->arrays->masterSecret, SECRET_LEN);
        c32toa(LowResTimer(), (byte*)&it.timestamp);

        /* build external */
        XMEMCPY(et->enc_ticket, &it, sizeof(InternalTicket));

        /* encrypt */
        encLen = WOLFSSL_TICKET_ENC_SZ;  /* max size user can use */
        ret = ssl->ctx->ticketEncCb(ssl, et->key_name, et->iv, et->mac, 1,
                                    et->enc_ticket, sizeof(InternalTicket),
                                    &encLen, ssl->ctx->ticketEncCtx);
        if (ret == WOLFSSL_TICKET_RET_OK) {
            if (encLen < (int)sizeof(InternalTicket) ||
                encLen > WOLFSSL_TICKET_ENC_SZ) {
                WOLFSSL_MSG("Bad user ticket encrypt size");
                return BAD_TICKET_KEY_CB_SZ;
            }

            /* sanity checks on encrypt callback */

            /* internal ticket can't be the same if encrypted */
            if (XMEMCMP(et->enc_ticket, &it, sizeof(InternalTicket)) == 0) {
                WOLFSSL_MSG("User ticket encrypt didn't encrypt");
                return BAD_TICKET_ENCRYPT;
            }

            XMEMSET(zeros, 0, sizeof(zeros));

            /* name */
            if (XMEMCMP(et->key_name, zeros, WOLFSSL_TICKET_NAME_SZ) == 0) {
                WOLFSSL_MSG("User ticket encrypt didn't set name");
                return BAD_TICKET_ENCRYPT;
            }

            /* iv */
            if (XMEMCMP(et->iv, zeros, WOLFSSL_TICKET_IV_SZ) == 0) {
                WOLFSSL_MSG("User ticket encrypt didn't set iv");
                return BAD_TICKET_ENCRYPT;
            }

            /* mac */
            if (XMEMCMP(et->mac, zeros, WOLFSSL_TICKET_MAC_SZ) == 0) {
                WOLFSSL_MSG("User ticket encrypt didn't set mac");
                return BAD_TICKET_ENCRYPT;
            }

            /* set size */
            c16toa((word16)encLen, et->enc_len);
            ssl->session.ticketLen = (word16)(encLen + WOLFSSL_TICKET_FIXED_SZ);
            if (encLen < WOLFSSL_TICKET_ENC_SZ) {
                /* move mac up since whole enc buffer not used */
                XMEMMOVE(et->enc_ticket +encLen, et->mac,WOLFSSL_TICKET_MAC_SZ);
            }
        }

        return ret;
    }


    /* Parse ticket sent by client, returns callback return value */
    int DoClientTicket(WOLFSSL* ssl, const byte* input, word32 len)
    {
        ExternalTicket* et;
        InternalTicket* it;
        int             ret;
        int             outLen;
        word16          inLen;

        if (len > SESSION_TICKET_LEN ||
             len < (word32)(sizeof(InternalTicket) + WOLFSSL_TICKET_FIXED_SZ)) {
            return BAD_TICKET_MSG_SZ;
        }

        et = (ExternalTicket*)input;
        it = (InternalTicket*)et->enc_ticket;

        /* decrypt */
        ato16(et->enc_len, &inLen);
        if (inLen > (word16)(len - WOLFSSL_TICKET_FIXED_SZ)) {
            return BAD_TICKET_MSG_SZ;
        }
        outLen = inLen;   /* may be reduced by user padding */
        ret = ssl->ctx->ticketEncCb(ssl, et->key_name, et->iv,
                                    et->enc_ticket + inLen, 0,
                                    et->enc_ticket, inLen, &outLen,
                                    ssl->ctx->ticketEncCtx);
        if (ret == WOLFSSL_TICKET_RET_FATAL || ret < 0) return ret;
        if (outLen > inLen || outLen < (int)sizeof(InternalTicket)) {
            WOLFSSL_MSG("Bad user ticket decrypt len");
            return BAD_TICKET_KEY_CB_SZ;
        }

        /* get master secret */
        if (ret == WOLFSSL_TICKET_RET_OK || ret == WOLFSSL_TICKET_RET_CREATE)
            XMEMCPY(ssl->arrays->masterSecret, it->msecret, SECRET_LEN);

        return ret;
    }


    /* send Session Ticket */
    int SendTicket(WOLFSSL* ssl)
    {
        byte*              output;
        int                ret;
        int                sendSz;
        word32             length = SESSION_HINT_SZ + LENGTH_SZ;
        word32             idx    = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            length += DTLS_RECORD_EXTRA;
            idx    += DTLS_RECORD_EXTRA;
        }
    #endif

        if (ssl->options.createTicket) {
            ret = CreateTicket(ssl);
            if (ret != 0) return ret;
        }

        length += ssl->session.ticketLen;
        sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get ouput buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        AddHeaders(output, length, session_ticket, ssl);

        /* hint */
        c32toa(ssl->ctx->ticketHint, output + idx);
        idx += SESSION_HINT_SZ;

        /* length */
        c16toa(ssl->session.ticketLen, output + idx);
        idx += LENGTH_SZ;

        /* ticket */
        XMEMCPY(output + idx, ssl->session.ticket, ssl->session.ticketLen);
        /* idx += ssl->session.ticketLen; */

        ret = HashOutput(ssl, output, sendSz, 0);
        if (ret != 0) return ret;
        ssl->buffers.outputBuffer.length += sendSz;

        return SendBuffered(ssl);
    }

#endif /* HAVE_SESSION_TICKET */


#ifdef WOLFSSL_DTLS
    int SendHelloVerifyRequest(WOLFSSL* ssl)
    {
        byte* output;
        byte  cookieSz = COOKIE_SZ;
        int   length = VERSION_SZ + ENUM_LEN + cookieSz;
        int   idx    = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ;
        int   sendSz = length + idx;
        int   ret;

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get ouput buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        AddHeaders(output, length, hello_verify_request, ssl);

        output[idx++] =  ssl->chVersion.major;
        output[idx++] =  ssl->chVersion.minor;

        output[idx++] = cookieSz;
        if (ssl->ctx->CBIOCookie == NULL) {
            WOLFSSL_MSG("Your Cookie callback is null, please set");
            return COOKIE_ERROR;
        }
        if ((ret = ssl->ctx->CBIOCookie(ssl, output + idx, cookieSz,
                                        ssl->IOCB_CookieCtx)) < 0)
            return ret;

        ret = HashOutput(ssl, output, sendSz, 0);
        if (ret != 0)
            return ret;

#ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("HelloVerifyRequest", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("HelloVerifyRequest", &ssl->timeoutInfo, output,
                          sendSz, ssl->heap);
#endif
        ssl->options.serverState = SERVER_HELLOVERIFYREQUEST_COMPLETE;

        ssl->buffers.outputBuffer.length += sendSz;

        return SendBuffered(ssl);
    }
#endif

#endif /* NO_WOLFSSL_SERVER */

