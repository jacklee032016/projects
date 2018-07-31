

#include "cmnSsl.h"


#ifndef NO_OLD_TLS
static INLINE void Md5Rounds(int rounds, const byte* data, int sz)
{
	Md5 md5;
	int i;

	wc_InitMd5(&md5);

	for (i = 0; i < rounds; i++)
		wc_Md5Update(&md5, data, sz);
}

/* do a dummy sha round */
static INLINE void ShaRounds(int rounds, const byte* data, int sz)
{
	Sha sha;
	int i;

	wc_InitSha(&sha);  /* no error check on purpose, dummy round */

	for (i = 0; i < rounds; i++)
		wc_ShaUpdate(&sha, data, sz);
}
#endif


#ifndef NO_SHA256
static INLINE void Sha256Rounds(int rounds, const byte* data, int sz)
{
	Sha256 sha256;
	int i;

	wc_InitSha256(&sha256);  /* no error check on purpose, dummy round */

	for (i = 0; i < rounds; i++) {
		wc_Sha256Update(&sha256, data, sz);
		/* no error check on purpose, dummy round */
	}
}
#endif


#ifdef WOLFSSL_SHA384
static INLINE void _sha384Rounds(int rounds, const byte* data, int sz)
{
	Sha384 sha384;
	int i;

	wc_InitSha384(&sha384);  /* no error check on purpose, dummy round */

	for (i = 0; i < rounds; i++) {
		wc_Sha384Update(&sha384, data, sz);
		/* no error check on purpose, dummy round */
	}
}
#endif


#ifdef WOLFSSL_SHA512
static INLINE void _sha512Rounds(int rounds, const byte* data, int sz)
{
	Sha512 sha512;
	int i;

	wc_InitSha512(&sha512);  /* no error check on purpose, dummy round */

	for (i = 0; i < rounds; i++) {
		wc_Sha512Update(&sha512, data, sz);
		/* no error check on purpose, dummy round */
	}
}
#endif


#ifdef WOLFSSL_RIPEMD
static INLINE void RmdRounds(int rounds, const byte* data, int sz)
{
	RipeMd ripemd;
	int i;

	wc_InitRipeMd(&ripemd);

	for (i = 0; i < rounds; i++)
		wc_RipeMdUpdate(&ripemd, data, sz);
}
#endif


/* Do dummy rounds */
static INLINE void DoRounds(int type, int rounds, const byte* data, int sz)
{
	switch (type)
	{
		case no_mac :
			break;

#ifndef NO_OLD_TLS
#ifndef NO_MD5
		case md5_mac :
			Md5Rounds(rounds, data, sz);
			break;
#endif

#ifndef NO_SHA
		case sha_mac :
			ShaRounds(rounds, data, sz);
			break;
#endif
#endif

#ifndef NO_SHA256
		case sha256_mac :
			Sha256Rounds(rounds, data, sz);
			break;
#endif

#ifdef WOLFSSL_SHA384
		case sha384_mac :
			_sha384Rounds(rounds, data, sz);
			break;
#endif

#ifdef WOLFSSL_SHA512
		case sha512_mac :
			_sha512Rounds(rounds, data, sz);
			break;
#endif

#ifdef WOLFSSL_RIPEMD
		case rmd_mac :
			RmdRounds(rounds, data, sz);
			break;
#endif

		default:
			WOLFSSL_MSG("Bad round type");
			break;
	}
}


/* do number of compression rounds on dummy data */
static INLINE void _CompressRounds(WOLFSSL* ssl, int rounds, const byte* dummy)
{
	if (rounds)
		DoRounds(ssl->specs.mac_algorithm, rounds, dummy, COMPRESS_LOWER);
}


/* check all length bytes for the pad value, return 0 on success */
static int _PadCheck(const byte* a, byte pad, int length)
{
	int i;
	int compareSum = 0;

	for (i = 0; i < length; i++) {
		compareSum |= a[i] ^ pad;
	}

	return compareSum;
}


/* get compression extra rounds */
static INLINE int _GetRounds(int pLen, int padLen, int t)
{
	int  roundL1 = 1;  /* round up flags */
	int  roundL2 = 1;

	int L1 = COMPRESS_CONSTANT + pLen - t;
	int L2 = COMPRESS_CONSTANT + pLen - padLen - 1 - t;

	L1 -= COMPRESS_UPPER;
	L2 -= COMPRESS_UPPER;

	if ( (L1 % COMPRESS_LOWER) == 0)
		roundL1 = 0;
	if ( (L2 % COMPRESS_LOWER) == 0)
		roundL2 = 0;

	L1 /= COMPRESS_LOWER;
	L2 /= COMPRESS_LOWER;

	L1 += roundL1;
	L2 += roundL2;

	return L1 - L2;
}



/* timing resistant pad/verify check, return 0 on success */
static int _timingPadVerify(WOLFSSL* ssl, const byte* input, int padLen, int t, int pLen, int content)
{
    byte verify[MAX_DIGEST_SIZE];
    byte dmy[sizeof(WOLFSSL) >= MAX_PAD_SIZE ? 1 : MAX_PAD_SIZE] = {0};
    byte* dummy = sizeof(dmy) < MAX_PAD_SIZE ? (byte*) ssl : dmy;
    int  ret = 0;

    (void)dmy;

    if ( (t + padLen + 1) > pLen) {
        WOLFSSL_MSG("Plain Len not long enough for pad/mac");
        _PadCheck(dummy, (byte)padLen, MAX_PAD_SIZE);
        ssl->hmac(ssl, verify, input, pLen - t, content, 1); /* still compare */
        ConstantCompare(verify, input + pLen - t, t);

        return VERIFY_MAC_ERROR;
    }

    if (_PadCheck(input + pLen - (padLen + 1), (byte)padLen, padLen + 1) != 0) {
        WOLFSSL_MSG("_PadCheck failed");
        _PadCheck(dummy, (byte)padLen, MAX_PAD_SIZE - padLen - 1);
        ssl->hmac(ssl, verify, input, pLen - t, content, 1); /* still compare */
        ConstantCompare(verify, input + pLen - t, t);

        return VERIFY_MAC_ERROR;
    }

    _PadCheck(dummy, (byte)padLen, MAX_PAD_SIZE - padLen - 1);
    ret = ssl->hmac(ssl, verify, input, pLen - padLen - 1 - t, content, 1);

    _CompressRounds(ssl, _GetRounds(pLen, padLen, t), dummy);

    if (ConstantCompare(verify, input + (pLen - padLen - 1 - t), t) != 0) {
        WOLFSSL_MSG("Verify MAC compare failed");
        return VERIFY_MAC_ERROR;
    }

    if (ret != 0)
        return VERIFY_MAC_ERROR;
    return 0;
}


static INLINE int _verifyMac(WOLFSSL* ssl, const byte* input, word32 msgSz,
                            int content, word32* padSz)
{
    int    ivExtra = 0;
    int    ret;
    word32 pad     = 0;
    word32 padByte = 0;
#ifdef HAVE_TRUNCATED_HMAC
    word32 digestSz = ssl->truncated_hmac ? TRUNCATED_HMAC_SZ
                                          : ssl->specs.hash_size;
#else
    word32 digestSz = ssl->specs.hash_size;
#endif
    byte   verify[MAX_DIGEST_SIZE];

    if (ssl->specs.cipher_type == block) {
        if (ssl->options.tls1_1)
            ivExtra = ssl->specs.block_size;
        pad = *(input + msgSz - ivExtra - 1);
        padByte = 1;

        if (ssl->options.tls) {
            ret = _timingPadVerify(ssl, input, pad, digestSz, msgSz - ivExtra,
                                  content);
            if (ret != 0)
                return ret;
        }
        else {  /* sslv3, some implementations have bad padding, but don't
                 * allow bad read */
            int  badPadLen = 0;
            byte dmy[sizeof(WOLFSSL) >= MAX_PAD_SIZE ? 1 : MAX_PAD_SIZE] = {0};
            byte* dummy = sizeof(dmy) < MAX_PAD_SIZE ? (byte*) ssl : dmy;

            (void)dmy;

            if (pad > (msgSz - digestSz - 1)) {
                WOLFSSL_MSG("Plain Len not long enough for pad/mac");
                pad       = 0;  /* no bad read */
                badPadLen = 1;
            }
            _PadCheck(dummy, (byte)pad, MAX_PAD_SIZE);  /* timing only */
            ret = ssl->hmac(ssl, verify, input, msgSz - digestSz - pad - 1,
                            content, 1);
            if (ConstantCompare(verify, input + msgSz - digestSz - pad - 1,
                                digestSz) != 0)
                return VERIFY_MAC_ERROR;
            if (ret != 0 || badPadLen)
                return VERIFY_MAC_ERROR;
        }
    }
    else if (ssl->specs.cipher_type == stream) {
        ret = ssl->hmac(ssl, verify, input, msgSz - digestSz, content, 1);
        if (ConstantCompare(verify, input + msgSz - digestSz, digestSz) != 0){
            return VERIFY_MAC_ERROR;
        }
        if (ret != 0)
            return VERIFY_MAC_ERROR;
    }

    if (ssl->specs.cipher_type == aead) {
        *padSz = ssl->specs.aead_mac_size;
    }
    else {
        *padSz = digestSz + pad + padByte;
    }

    return 0;
}


/* check cipher text size for sanity */
static int _sanityCheckCipherText(WOLFSSL* ssl, word32 encryptSz)
{
#ifdef HAVE_TRUNCATED_HMAC
    word32 minLength = ssl->truncated_hmac ? TRUNCATED_HMAC_SZ
                                           : ssl->specs.hash_size;
#else
    word32 minLength = ssl->specs.hash_size; /* covers stream */
#endif

    if (ssl->specs.cipher_type == block) {
        if (encryptSz % ssl->specs.block_size) {
            WOLFSSL_MSG("Block ciphertext not block size");
            return SANITY_CIPHER_E;
        }

        minLength++;  /* pad byte */

        if (ssl->specs.block_size > minLength)
            minLength = ssl->specs.block_size;

        if (ssl->options.tls1_1)
            minLength += ssl->specs.block_size;  /* explicit IV */
    }
    else if (ssl->specs.cipher_type == aead) {
        minLength = ssl->specs.aead_mac_size;    /* authTag size */
        if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
           minLength += AEAD_EXP_IV_SZ;          /* explicit IV  */
    }

    if (encryptSz < minLength) {
        WOLFSSL_MSG("Ciphertext not minimum size");
        return SANITY_CIPHER_E;
    }

    return 0;
}


/* do all verify and sanity checks on record header */
static int _getRecordHeader(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                           RecordLayerHeader* rh, word16 *size)
{
    if (!ssl->options.dtls) {
#ifdef HAVE_FUZZER
        if (ssl->fuzzerCb)
            ssl->fuzzerCb(ssl, input + *inOutIdx, RECORD_HEADER_SZ, FUZZ_HEAD,
                    ssl->fuzzerCtx);
#endif
        XMEMCPY(rh, input + *inOutIdx, RECORD_HEADER_SZ);
        *inOutIdx += RECORD_HEADER_SZ;
        ato16(rh->length, size);
    }
    else {
#ifdef WOLFSSL_DTLS
        /* type and version in same sport */
        XMEMCPY(rh, input + *inOutIdx, ENUM_LEN + VERSION_SZ);
        *inOutIdx += ENUM_LEN + VERSION_SZ;
        ato16(input + *inOutIdx, &ssl->keys.dtls_state.curEpoch);
        *inOutIdx += 4; /* advance past epoch, skip first 2 seq bytes for now */
        ato32(input + *inOutIdx, &ssl->keys.dtls_state.curSeq);
        *inOutIdx += 4;  /* advance past rest of seq */
        ato16(input + *inOutIdx, size);
        *inOutIdx += LENGTH_SZ;
#ifdef HAVE_FUZZER
        if (ssl->fuzzerCb)
            ssl->fuzzerCb(ssl, input + *inOutIdx - LENGTH_SZ - 8 - ENUM_LEN -
                           VERSION_SZ, ENUM_LEN + VERSION_SZ + 8 + LENGTH_SZ,
                           FUZZ_HEAD, ssl->fuzzerCtx);
#endif
#endif
    }

    /* catch version mismatch */
    if (rh->pvMajor != ssl->version.major || rh->pvMinor != ssl->version.minor){
        if (ssl->options.side == WOLFSSL_SERVER_END &&
            ssl->options.acceptState == ACCEPT_BEGIN)
            WOLFSSL_MSG("Client attempting to connect with different version");
        else if (ssl->options.side == WOLFSSL_CLIENT_END &&
                                 ssl->options.downgrade &&
                                 ssl->options.connectState < FIRST_REPLY_DONE)
            WOLFSSL_MSG("Server attempting to accept with different version");
        else {
            WOLFSSL_MSG("SSL version error");
            return VERSION_ERROR;              /* only use requested version */
        }
    }

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        if (DtlsCheckWindow(&ssl->keys.dtls_state) != 1)
            return SEQUENCE_ERROR;
    }
#endif

    /* record layer length check */
#ifdef HAVE_MAX_FRAGMENT
    if (*size > (ssl->max_fragment + MAX_COMP_EXTRA + MAX_MSG_EXTRA)) {
        SendAlert(ssl, alert_fatal, record_overflow);
        return LENGTH_ERROR;
    }
#else
    if (*size > (MAX_RECORD_SIZE + MAX_COMP_EXTRA + MAX_MSG_EXTRA))
        return LENGTH_ERROR;
#endif

    /* verify record type here as well */
    switch (rh->type) {
        case handshake:
        case change_cipher_spec:
        case application_data:
        case alert:
            break;
        case no_type:
        default:
            WOLFSSL_MSG("Unknown Record Type");
            return UNKNOWN_RECORD_TYPE;
    }

    /* haven't decrypted this record yet */
    ssl->keys.decryptedCur = 0;

    return 0;
}



/* receive from socket. return bytes received, -1 on error */
static int __receive(WOLFSSL* ssl, byte* buf, word32 sz)
{
	int recvd;

	if (ssl->ctx->CBIORecv == NULL) {
		WOLFSSL_MSG("Your IO Recv callback is null, please set");
		return -1;
	}

retry:
	recvd = ssl->ctx->CBIORecv(ssl, (char *)buf, (int)sz, ssl->IOCB_ReadCtx);
	if (recvd < 0)
	{
		switch (recvd)
		{
			case WOLFSSL_CBIO_ERR_GENERAL:        /* general/unknown error */
				return -1;

			case WOLFSSL_CBIO_ERR_WANT_READ:      /* want read, would block */
				return WANT_READ;

			case WOLFSSL_CBIO_ERR_CONN_RST:       /* connection reset */
#ifdef USE_WINDOWS_API
				if (ssl->options.dtls) {
					goto retry;
				}
#endif
				ssl->options.connReset = 1;
				return -1;

			case WOLFSSL_CBIO_ERR_ISR:            /* interrupt */
			/* see if we got our timeout */
#ifdef WOLFSSL_CALLBACKS
				if (ssl->toInfoOn) {
					struct itimerval timeout;
					getitimer(ITIMER_REAL, &timeout);
					
					if (timeout.it_value.tv_sec == 0 && timeout.it_value.tv_usec == 0)
					{
						XSTRNCPY(ssl->timeoutInfo.timeoutName, "recv() timeout", MAX_TIMEOUT_NAME_SZ);
						WOLFSSL_MSG("Got our timeout");
						return WANT_READ;
					}
				}
#endif
				goto retry;

			case WOLFSSL_CBIO_ERR_CONN_CLOSE:     /* peer closed connection */
				ssl->options.isClosed = 1;
				return -1;

			case WOLFSSL_CBIO_ERR_TIMEOUT:
#ifdef WOLFSSL_DTLS
				if (DtlsPoolTimeout(ssl) == 0 && DtlsPoolSend(ssl) == 0)
					goto retry;
				else
#endif
				return -1;

			default:
				return recvd;
		}
	}
	return recvd;
}

static int _getInputData(WOLFSSL *ssl, word32 size)
{
	int in;
	int inSz;
	int maxLength;
	int usedLength;
	int dtlsExtra = 0;


	/* check max input length */
	usedLength = ssl->buffers.inputBuffer.length - ssl->buffers.inputBuffer.idx;
	maxLength  = ssl->buffers.inputBuffer.bufferSize - usedLength;
	inSz       = (int)(size - usedLength);      /* from last partial read */

#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls) {
		if (size < ssl->dtls_expected_rx)
			dtlsExtra = (int)(ssl->dtls_expected_rx - size);
		inSz = ssl->dtls_expected_rx;
	}
#endif

	if (inSz > maxLength) {
		if (GrowInputBuffer(ssl, size + dtlsExtra, usedLength) < 0)
			return MEMORY_E;
	}

	if (inSz <= 0)
		return BUFFER_ERROR;

	/* Put buffer data at start if not there */
	if (usedLength > 0 && ssl->buffers.inputBuffer.idx != 0)
		XMEMMOVE(ssl->buffers.inputBuffer.buffer, ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx, usedLength);

	/* remove processed data */
	ssl->buffers.inputBuffer.idx    = 0;
	ssl->buffers.inputBuffer.length = usedLength;

	/* read data from network */
	do
	{
		in = __receive(ssl, ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.length,inSz);
		if (in == -1)
			return SOCKET_ERROR_E;

		if (in == WANT_READ)
			return WANT_READ;

		if (in > inSz)
			return RECV_OVERFLOW_E;

		ssl->buffers.inputBuffer.length += in;
		inSz -= in;
	} while (ssl->buffers.inputBuffer.length < size);

	return 0;
}



/* process alert, return level */
static int _doAlert(WOLFSSL* ssl, byte* input, word32* inOutIdx, int* type, word32 totalSz)
{
	byte level;
	byte code;

#ifdef WOLFSSL_CALLBACKS
	if (ssl->hsInfoOn)
		AddPacketName("Alert", &ssl->handShakeInfo);
	if (ssl->toInfoOn)
	/* add record header back on to info + 2 byte level, data */
		AddPacketInfo("Alert", &ssl->timeoutInfo, input + *inOutIdx - RECORD_HEADER_SZ, 2 + RECORD_HEADER_SZ, ssl->heap);
#endif

	/* make sure can read the message */
	if (*inOutIdx + ALERT_SIZE > totalSz)
		return BUFFER_E;

	level = input[(*inOutIdx)++];
	code  = input[(*inOutIdx)++];
	ssl->alert_history.last_rx.code = code;
	ssl->alert_history.last_rx.level = level;
	*type = code;

	if (level == alert_fatal)
	{
		ssl->options.isClosed = 1;  /* Don't send close_notify */
	}

	WOLFSSL_MSG("Got alert");
	if (*type == close_notify) {
		WOLFSSL_MSG("    close notify");
		ssl->options.closeNotify = 1;
	}

	WOLFSSL_ERROR(*type);
	if (ssl->keys.encryptionOn) {
		if (*inOutIdx + ssl->keys.padSz > totalSz)
			return BUFFER_E;
		*inOutIdx += ssl->keys.padSz;
	}

	return level;
}

/* process input requests, return 0 is done, 1 is call again to complete, and negative number is error 
* It is called in wolfssl_connect in client end and woldSSL_accept in server end 
Used in both handshake phase and data phase
*/
int ProcessReply(WOLFSSL* ssl)
{
	int    ret = 0, type, readSz;
	int    atomicUser = 0;
	word32 startIdx = 0;
#ifdef WOLFSSL_DTLS
	int    used;
#endif

	WOLFSSL_ENTER();

#ifdef ATOMIC_USER
	if (ssl->ctx->DecryptVerifyCb)
		atomicUser = 1;
#endif

	if (ssl->error != 0 && ssl->error != WANT_READ && ssl->error != WANT_WRITE){
		WOLFSSL_MSG("ProcessReply retry in error state, not allowed");
		return ssl->error;
	}

	for (;;)
	{
		switch (ssl->options.processReply)
		{
			/* in the WOLFSSL_SERVER case, get the first byte for detecting old client hello */
			case doProcessInit:

				readSz = RECORD_HEADER_SZ;

#ifdef WOLFSSL_DTLS
				if (ssl->options.dtls)
					readSz = DTLS_RECORD_HEADER_SZ;
#endif

				/* get header or return error */
				if (!ssl->options.dtls) {
					if ((ret = _getInputData(ssl, readSz)) < 0)
						return ret;
				}
				else {
#ifdef WOLFSSL_DTLS
					/* read ahead may already have header */
					used = ssl->buffers.inputBuffer.length - ssl->buffers.inputBuffer.idx;
					if (used < readSz)
						if ((ret = _getInputData(ssl, readSz)) < 0)
							return ret;
#endif
				}

#ifdef OLD_HELLO_ALLOWED

				/* see if sending SSLv2 client hello */
				if ( ssl->options.side == WOLFSSL_SERVER_END && ssl->options.clientState == NULL_STATE &&
					ssl->buffers.inputBuffer.buffer[ssl->buffers.inputBuffer.idx]  != handshake)
				{
					byte b0, b1;

					ssl->options.processReply = runProcessOldClientHello;

					/* sanity checks before getting size at front */
					if (ssl->buffers.inputBuffer.buffer[ssl->buffers.inputBuffer.idx + 2] != OLD_HELLO_ID) {
						WOLFSSL_MSG("Not a valid old client hello");
						return PARSE_ERROR;
					}

					if (ssl->buffers.inputBuffer.buffer[ssl->buffers.inputBuffer.idx + 3] != SSLv3_MAJOR &&
						ssl->buffers.inputBuffer.buffer[ ssl->buffers.inputBuffer.idx + 3] != DTLS_MAJOR)
					{
						WOLFSSL_MSG("Not a valid version in old client hello");
						return PARSE_ERROR;
					}

					/* how many bytes need ProcessOldClientHello */
					b0 =	ssl->buffers.inputBuffer.buffer[ssl->buffers.inputBuffer.idx++];
					b1 =	ssl->buffers.inputBuffer.buffer[ssl->buffers.inputBuffer.idx++];
					ssl->curSize = (word16)(((b0 & 0x7f) << 8) | b1);
				}
				else {
					ssl->options.processReply = getRecordLayerHeader;
					continue;
				}

			/* in the WOLFSSL_SERVER case, run the old client hello */
			case runProcessOldClientHello:

				/* get sz bytes or return error */
				if (!ssl->options.dtls) {
					if ((ret = _getInputData(ssl, ssl->curSize)) < 0)
					return ret;
				}
				else {
#ifdef WOLFSSL_DTLS
					/* read ahead may already have */
					used = ssl->buffers.inputBuffer.length - ssl->buffers.inputBuffer.idx;
					if (used < ssl->curSize)
						if ((ret = _getInputData(ssl, ssl->curSize)) < 0)
							return ret;
#endif  /* WOLFSSL_DTLS */
				}

				ret = ProcessOldClientHello(ssl, ssl->buffers.inputBuffer.buffer, &ssl->buffers.inputBuffer.idx,
					ssl->buffers.inputBuffer.length - ssl->buffers.inputBuffer.idx,	ssl->curSize);
				if (ret < 0)
					return ret;
				else if (ssl->buffers.inputBuffer.idx == ssl->buffers.inputBuffer.length)
				{
					ssl->options.processReply = doProcessInit;
					return 0;
				}

#endif  /* OLD_HELLO_ALLOWED */

			/* get the record layer header */
			case getRecordLayerHeader:
				ret = _getRecordHeader(ssl, ssl->buffers.inputBuffer.buffer, &ssl->buffers.inputBuffer.idx, &ssl->curRL, &ssl->curSize);
#ifdef WOLFSSL_DTLS
				if (ssl->options.dtls && ret == SEQUENCE_ERROR) {
					ssl->options.processReply = doProcessInit;
					ssl->buffers.inputBuffer.length = 0;
					ssl->buffers.inputBuffer.idx = 0;
					continue;
				}
#endif
				if (ret != 0)
					return ret;

				ssl->options.processReply = getData;

			/* retrieve record layer data */
			case getData:
				/* get sz bytes or return error */
				if (!ssl->options.dtls) {
					if ((ret = _getInputData(ssl, ssl->curSize)) < 0)
						return ret;
				}
				else {
#ifdef WOLFSSL_DTLS
					/* read ahead may already have */
					used = ssl->buffers.inputBuffer.length -
					ssl->buffers.inputBuffer.idx;
					if (used < ssl->curSize)
						if ((ret = _getInputData(ssl, ssl->curSize)) < 0)
						return ret;
#endif
				}

				ssl->options.processReply = runProcessingOneMessage;
				startIdx = ssl->buffers.inputBuffer.idx;  /* in case > 1 msg per */

			/* the record layer is here */
			case runProcessingOneMessage:

#ifdef WOLFSSL_DTLS
			if (ssl->options.dtls && ssl->keys.dtls_state.curEpoch < ssl->keys.dtls_state.nextEpoch)
				ssl->keys.decryptedCur = 1;
#endif

			if (ssl->keys.encryptionOn && ssl->keys.decryptedCur == 0)
			{
				ret = _sanityCheckCipherText(ssl, ssl->curSize);
				if (ret < 0)
					return ret;

				if (atomicUser) {
#ifdef ATOMIC_USER
					ret = ssl->ctx->DecryptVerifyCb(ssl, ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
						ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
						ssl->curSize, ssl->curRL.type, 1, &ssl->keys.padSz, ssl->DecryptVerifyCtx);
					if (ssl->options.tls1_1 && ssl->specs.cipher_type == block)
						ssl->buffers.inputBuffer.idx += ssl->specs.block_size;
					
					/* go past TLSv1.1 IV */
					if (ssl->specs.cipher_type == aead && ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
						ssl->buffers.inputBuffer.idx += AEAD_EXP_IV_SZ;
#endif /* ATOMIC_USER */
				}
				else
				{
					ret = Decrypt(ssl, ssl->buffers.inputBuffer.buffer +	 ssl->buffers.inputBuffer.idx,
						ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx, ssl->curSize);
					if (ret < 0) {
						WOLFSSL_ERROR(ret);
						return DECRYPT_ERROR;
					}
					
					if (ssl->options.tls1_1 && ssl->specs.cipher_type == block)
						ssl->buffers.inputBuffer.idx += ssl->specs.block_size;
					
					/* go past TLSv1.1 IV */
					if (ssl->specs.cipher_type == aead &&  ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
						ssl->buffers.inputBuffer.idx += AEAD_EXP_IV_SZ;

					ret = _verifyMac(ssl, ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx, 
						ssl->curSize, ssl->curRL.type, &ssl->keys.padSz);
				}
				if (ret < 0) {
					WOLFSSL_ERROR(ret);
					return DECRYPT_ERROR;
				}
				ssl->keys.encryptSz    = ssl->curSize;
				ssl->keys.decryptedCur = 1;
			}

			if (ssl->options.dtls) {
#ifdef WOLFSSL_DTLS
				DtlsUpdateWindow(&ssl->keys.dtls_state);
#endif /* WOLFSSL_DTLS */
			}

			WOLFSSL_MSG("received record layer msg");

			switch (ssl->curRL.type)
			{
				case handshake :
					/* debugging in DoHandShakeMsg */
					if (!ssl->options.dtls) {
						ret = DoHandShakeMsg(ssl, ssl->buffers.inputBuffer.buffer,
							&ssl->buffers.inputBuffer.idx, ssl->buffers.inputBuffer.length);
					}
					else {
#ifdef WOLFSSL_DTLS
						ret = DoDtlsHandShakeMsg(ssl, ssl->buffers.inputBuffer.buffer,
							&ssl->buffers.inputBuffer.idx, ssl->buffers.inputBuffer.length);
#endif
					}
					if (ret != 0)
					return ret;
					break;

				case change_cipher_spec:
				WOLFSSL_MSG("got CHANGE CIPHER SPEC");
#ifdef WOLFSSL_CALLBACKS
				if (ssl->hsInfoOn)
				    AddPacketName("ChangeCipher", &ssl->handShakeInfo);
				/* add record header back on info */
				if (ssl->toInfoOn) {
				    AddPacketInfo("ChangeCipher", &ssl->timeoutInfo,
				        ssl->buffers.inputBuffer.buffer +
				        ssl->buffers.inputBuffer.idx - RECORD_HEADER_SZ,
				        1 + RECORD_HEADER_SZ, ssl->heap);
				    AddLateRecordHeader(&ssl->curRL, &ssl->timeoutInfo);
				}
#endif

				ret = SanityCheckMsgReceived(ssl, change_cipher_hs);
				if (ret != 0)
				return ret;

#ifdef HAVE_SESSION_TICKET
				if (ssl->options.side == WOLFSSL_CLIENT_END &&
				                          ssl->expect_session_ticket) {
				WOLFSSL_MSG("Expected session ticket missing");
				return SESSION_TICKET_EXPECT_E;
				}
#endif

				if (ssl->keys.encryptionOn && ssl->options.handShakeDone) {
				ssl->buffers.inputBuffer.idx += ssl->keys.padSz;
				ssl->curSize -= (word16) ssl->buffers.inputBuffer.idx;
				}

				if (ssl->curSize != 1) {
				WOLFSSL_MSG("Malicious or corrupted ChangeCipher msg");
				return LENGTH_ERROR;
				}
#ifndef NO_CERTS
				if (ssl->options.side == WOLFSSL_SERVER_END &&
				         ssl->options.verifyPeer &&
				         ssl->options.havePeerCert)
				    if (!ssl->options.havePeerVerify) {
				        WOLFSSL_MSG("client didn't send cert verify");
				        return NO_PEER_VERIFY;
				    }
#endif


				ssl->buffers.inputBuffer.idx++;
				ssl->keys.encryptionOn = 1;

				/* setup decrypt keys for following messages */
				if ((ret = SetKeysSide(ssl, DECRYPT_SIDE_ONLY)) != 0)
				return ret;

#ifdef WOLFSSL_DTLS
				if (ssl->options.dtls) {
				    DtlsPoolReset(ssl);
				    ssl->keys.dtls_state.nextEpoch++;
				    ssl->keys.dtls_state.nextSeq = 0;
				}
#endif

#ifdef HAVE_LIBZ
				if (ssl->options.usingCompression)
				    if ( (ret = InitStreams(ssl)) != 0)
				        return ret;
#endif
				ret = BuildFinished(ssl, &ssl->hsHashes->verifyHashes, ssl->options.side == WOLFSSL_CLIENT_END ?  server : client);
				if (ret != 0)
				return ret;
				break;

				case application_data:
					WOLFSSL_MSG("got app DATA");
					if ((ret = DoApplicationData(ssl, ssl->buffers.inputBuffer.buffer,	 &ssl->buffers.inputBuffer.idx))	!= 0) {
						WOLFSSL_ERROR(ret);
						return ret;
					}
				break;

				case alert:
					WOLFSSL_MSG("got ALERT!");
					ret = _doAlert(ssl, ssl->buffers.inputBuffer.buffer, &ssl->buffers.inputBuffer.idx, &type, ssl->buffers.inputBuffer.length);
					if (ret == alert_fatal)
						return FATAL_ERROR;
					else if (ret < 0)
						return ret;

					/* catch warnings that are handled as errors */
					if (type == close_notify)
						return ssl->error = ZERO_RETURN;

					if (type == decrypt_error)
						return FATAL_ERROR;
					break;

				default:
					WOLFSSL_ERROR(UNKNOWN_RECORD_TYPE);
					return UNKNOWN_RECORD_TYPE;
				}

			ssl->options.processReply = doProcessInit;

			/* input exhausted? */
			if (ssl->buffers.inputBuffer.idx == ssl->buffers.inputBuffer.length)
			return 0;

			/* more messages per record */
			else if ((ssl->buffers.inputBuffer.idx - startIdx) < ssl->curSize) {
			WOLFSSL_MSG("More messages in record");
#ifdef WOLFSSL_DTLS
			/* read-ahead but dtls doesn't bundle messages per record */
			if (ssl->options.dtls) {
				ssl->options.processReply = doProcessInit;
				continue;
			}
#endif
			ssl->options.processReply = runProcessingOneMessage;

			if (ssl->keys.encryptionOn) {
				WOLFSSL_MSG("Bundled encrypted messages, remove middle pad");
				ssl->buffers.inputBuffer.idx -= ssl->keys.padSz;
			}

			continue;
			}
			/* more records */
			else {
			WOLFSSL_MSG("More records in input");
			ssl->options.processReply = doProcessInit;
			continue;
			}

			default:
				WOLFSSL_MSG("Bad process input state, programming error");
				return INPUT_CASE_ERROR;
		}
	}
}


/* process input data : calling ProcessReply, called in ssl_read */
int __receiveData(WOLFSSL* ssl, byte* output, int sz, int peek)
{
	int size;

	WOLFSSL_ENTER();

	if (ssl->error == WANT_READ)
		ssl->error = 0;

	if (ssl->error != 0 && ssl->error != WANT_WRITE) {
		WOLFSSL_MSG("User calling wolfSSL_read in error state, not allowed");
		return ssl->error;
	}

	if (ssl->options.handShakeState != HANDSHAKE_DONE)
	{
		int err;
		WOLFSSL_MSG("Handshake not complete, trying to finish");
		if ( (err = wolfSSL_negotiate(ssl)) != SSL_SUCCESS)
			return  err;
	}

#ifdef HAVE_SECURE_RENEGOTIATION
startScr:
	if (ssl->secure_renegotiation && ssl->secure_renegotiation->startScr) {
		int err;
		ssl->secure_renegotiation->startScr = 0;  /* only start once */
		WOLFSSL_MSG("Need to start scr, server requested");
		if ( (err = wolfSSL_Rehandshake(ssl)) != SSL_SUCCESS)
			return  err;
	}
#endif

	while (ssl->buffers.clearOutputBuffer.length == 0)
	{
		if ( (ssl->error = ProcessReply(ssl)) < 0)
		{
			WOLFSSL_ERROR(ssl->error);
			if (ssl->error == ZERO_RETURN) 
			{
				WOLFSSL_MSG("Zero return, no more data coming");
				return 0;         /* no more data coming */
			}
			if (ssl->error == SOCKET_ERROR_E) {
				if (ssl->options.connReset || ssl->options.isClosed) {
					WOLFSSL_MSG("Peer reset or closed, connection done");
					ssl->error = SOCKET_PEER_CLOSED_E;
					WOLFSSL_ERROR(ssl->error);
					return 0;     /* peer reset or closed */
				}
			}
			return ssl->error;
		}
		
#ifdef HAVE_SECURE_RENEGOTIATION
		if (ssl->secure_renegotiation &&
			ssl->secure_renegotiation->startScr) {
			goto startScr;
		}
#endif
	}

	if (sz < (int)ssl->buffers.clearOutputBuffer.length)
		size = sz;
	else
		size = ssl->buffers.clearOutputBuffer.length;

	XMEMCPY(output, ssl->buffers.clearOutputBuffer.buffer, size);

	if (peek == 0) {
		ssl->buffers.clearOutputBuffer.length -= size;
		ssl->buffers.clearOutputBuffer.buffer += size;
	}

	if (ssl->buffers.clearOutputBuffer.length == 0 && ssl->buffers.inputBuffer.dynamicFlag)
		ShrinkInputBuffer(ssl, NO_FORCED_FREE);

	WOLFSSL_LEAVE( size);
	return size;
}



static int _read_internal(WOLFSSL* ssl, void* data, int sz, int peek)
{
	int ret;

	WOLFSSL_ENTER();

	if (ssl == NULL || data == NULL || sz < 0)
		return BAD_FUNC_ARG;

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls)
		ssl->dtls_expected_rx = max(sz + 100, MAX_MTU);
#endif

#ifdef HAVE_MAX_FRAGMENT
	ret = __receiveData(ssl, (byte*)data, min(sz, min(ssl->max_fragment, OUTPUT_RECORD_SIZE)), peek);
#else
	ret = __receiveData(ssl, (byte*)data, min(sz, OUTPUT_RECORD_SIZE), peek);
#endif

	WOLFSSL_LEAVE( ret);

	if (ret < 0)
		return SSL_FATAL_ERROR;
	else
		return ret;
}


int wolfSSL_peek(WOLFSSL* ssl, void* data, int sz)
{
	WOLFSSL_ENTER();
	return _read_internal(ssl, data, sz, TRUE);
}


int wolfSSL_read(WOLFSSL* ssl, void* data, int sz)
{
	WOLFSSL_ENTER();

	return _read_internal(ssl, data, sz, FALSE);
}


