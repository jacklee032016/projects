
#include "cmnSsl.h"

/*
* hello handler for both client and server
* it should be handled client and server respectively and every handler is drived by a state machine
*/


static int _doHelloRequest(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                                                    word32 size, word32 totalSz)
{
    (void)input;

    if (size) /* must be 0 */
        return BUFFER_ERROR;

    if (ssl->keys.encryptionOn) {
        /* access beyond input + size should be checked against totalSz */
        if (*inOutIdx + ssl->keys.padSz > totalSz)
            return BUFFER_E;

        *inOutIdx += ssl->keys.padSz;
    }

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        SendAlert(ssl, alert_fatal, unexpected_message); /* try */
        return FATAL_ERROR;
    }
#ifdef HAVE_SECURE_RENEGOTIATION
    else if (ssl->secure_renegotiation && ssl->secure_renegotiation->enabled) {
        ssl->secure_renegotiation->startScr = 1;
        return 0;
    }
#endif
    else {
        return SendAlert(ssl, alert_warning, no_renegotiation);
    }
}



static int _doHelloVerifyRequest(WOLFSSL* ssl, const byte* input, word32* inOutIdx, word32 size)
{
	ProtocolVersion pv;
	byte            cookieSz;
	word32          begin = *inOutIdx;

#ifdef WOLFSSL_CALLBACKS
	if (ssl->hsInfoOn) AddPacketName("HelloVerifyRequest",
	&ssl->handShakeInfo);
	if (ssl->toInfoOn) AddLateName("HelloVerifyRequest", &ssl->timeoutInfo);
#endif

#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls) {
		DtlsPoolReset(ssl);
	}
#endif

	if ((*inOutIdx - begin) + OPAQUE16_LEN + OPAQUE8_LEN > size)
		return BUFFER_ERROR;

	XMEMCPY(&pv, input + *inOutIdx, OPAQUE16_LEN);
	*inOutIdx += OPAQUE16_LEN;

	cookieSz = input[(*inOutIdx)++];

	if (cookieSz) {
		if ((*inOutIdx - begin) + cookieSz > size)
			return BUFFER_ERROR;

#ifdef WOLFSSL_DTLS
		if (cookieSz <= MAX_COOKIE_LEN) {
			XMEMCPY(ssl->arrays->cookie, input + *inOutIdx, cookieSz);
			ssl->arrays->cookieSz = cookieSz;
		}
#endif
		*inOutIdx += cookieSz;
	}

	ssl->options.serverState = SERVER_HELLOVERIFYREQUEST_COMPLETE;
	return 0;
}


static int _doServerHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx, word32 helloSz)
{
	byte            cs0;   /* cipher suite bytes 0, 1 */
	byte            cs1;
	ProtocolVersion pv;
	byte            compression;
	word32          i = *inOutIdx;
	word32          begin = i;

#ifdef WOLFSSL_CALLBACKS
	if (ssl->hsInfoOn) AddPacketName("ServerHello", &ssl->handShakeInfo);
	if (ssl->toInfoOn) AddLateName("ServerHello", &ssl->timeoutInfo);
#endif

	/* protocol version, random and session id length check */
	if (OPAQUE16_LEN + RAN_LEN + OPAQUE8_LEN > helloSz)
	return BUFFER_ERROR;

	/* protocol version */
	XMEMCPY(&pv, input + i, OPAQUE16_LEN);
	i += OPAQUE16_LEN;

	if (pv.minor > ssl->version.minor) {
	WOLFSSL_MSG("Server using higher version, fatal error");
	return VERSION_ERROR;
	}
	else if (pv.minor < ssl->version.minor) {
	WOLFSSL_MSG("server using lower version");

	if (!ssl->options.downgrade) {
	WOLFSSL_MSG("    no downgrade allowed, fatal error");
	return VERSION_ERROR;
	}
	if (pv.minor < ssl->options.minDowngrade) {
	WOLFSSL_MSG("    version below minimum allowed, fatal error");
	return VERSION_ERROR;
	}

#ifdef HAVE_SECURE_RENEGOTIATION
	if (ssl->secure_renegotiation &&
	                 ssl->secure_renegotiation->enabled &&
	                 ssl->options.handShakeDone) {
	WOLFSSL_MSG("Server changed version during scr");
	return VERSION_ERROR;
	}
#endif

	if (pv.minor == SSLv3_MINOR) {
	/* turn off tls */
	WOLFSSL_MSG("    downgrading to SSLv3");
	ssl->options.tls    = 0;
	ssl->options.tls1_1 = 0;
	ssl->version.minor  = SSLv3_MINOR;
	}
	else if (pv.minor == TLSv1_MINOR) {
	/* turn off tls 1.1+ */
	WOLFSSL_MSG("    downgrading to TLSv1");
	ssl->options.tls1_1 = 0;
	ssl->version.minor  = TLSv1_MINOR;
	}
	else if (pv.minor == TLSv1_1_MINOR) {
	WOLFSSL_MSG("    downgrading to TLSv1.1");
	ssl->version.minor  = TLSv1_1_MINOR;
	}
	}

	/* random */
	XMEMCPY(ssl->arrays->serverRandom, input + i, RAN_LEN);
	i += RAN_LEN;

	/* session id */
	ssl->arrays->sessionIDSz = input[i++];

	if (ssl->arrays->sessionIDSz > ID_LEN) {
	WOLFSSL_MSG("Invalid session ID size");
	ssl->arrays->sessionIDSz = 0;
	return BUFFER_ERROR;
	}
	else if (ssl->arrays->sessionIDSz) {
	if ((i - begin) + ssl->arrays->sessionIDSz > helloSz)
	return BUFFER_ERROR;

	XMEMCPY(ssl->arrays->sessionID, input + i,
	                              ssl->arrays->sessionIDSz);
	i += ssl->arrays->sessionIDSz;
	ssl->options.haveSessionId = 1;
	}


	/* suite and compression */
	if ((i - begin) + OPAQUE16_LEN + OPAQUE8_LEN > helloSz)
	return BUFFER_ERROR;

	cs0 = input[i++];
	cs1 = input[i++];

#ifdef HAVE_SECURE_RENEGOTIATION
	if (ssl->secure_renegotiation && ssl->secure_renegotiation->enabled &&
	                 ssl->options.handShakeDone) {
	if (ssl->options.cipherSuite0 != cs0 ||
	ssl->options.cipherSuite  != cs1) {
	WOLFSSL_MSG("Server changed cipher suite during scr");
	return MATCH_SUITE_ERROR;
	}
	}
#endif

	ssl->options.cipherSuite0 = cs0;
	ssl->options.cipherSuite  = cs1;
	compression = input[i++];

	if (compression != ZLIB_COMPRESSION && ssl->options.usingCompression) {
	WOLFSSL_MSG("Server refused compression, turning off");
	ssl->options.usingCompression = 0;  /* turn off if server refused */
	}

	*inOutIdx = i;

	/* tls extensions */
	if ( (i - begin) < helloSz) {
#ifdef HAVE_TLS_EXTENSIONS
	if (TLSX_SupportExtensions(ssl)) {
	int    ret = 0;
	word16 totalExtSz;

	if ((i - begin) + OPAQUE16_LEN > helloSz)
	return BUFFER_ERROR;

	ato16(&input[i], &totalExtSz);
	i += OPAQUE16_LEN;

	if ((i - begin) + totalExtSz > helloSz)
	return BUFFER_ERROR;

	if ((ret = TLSX_Parse(ssl, (byte *) input + i,
	                                  totalExtSz, 0, NULL)))
	return ret;

	i += totalExtSz;
	*inOutIdx = i;
	}
	else
#endif
	*inOutIdx = begin + helloSz; /* skip extensions */
	}

	ssl->options.serverState = SERVER_HELLO_COMPLETE;

	if (ssl->keys.encryptionOn) {
	*inOutIdx += ssl->keys.padSz;
	}

#ifdef HAVE_SECRET_CALLBACK
	if (ssl->sessionSecretCb != NULL) {
	int secretSz = SECRET_LEN, ret;
	ret = ssl->sessionSecretCb(ssl, ssl->session.masterSecret,
	                      &secretSz, ssl->sessionSecretCtx);
	if (ret != 0 || secretSz != SECRET_LEN)
	return SESSION_SECRET_CB_E;
	}
#endif /* HAVE_SECRET_CALLBACK */

	if (ssl->options.resuming) {
	if (DSH_CheckSessionId(ssl)) {
	if (SetCipherSpecs(ssl) == 0) {
	int ret = -1;

	XMEMCPY(ssl->arrays->masterSecret,
	    ssl->session.masterSecret, SECRET_LEN);
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
	ssl->options.serverState = SERVER_HELLODONE_COMPLETE;

	return ret;
	}
	else {
	WOLFSSL_MSG("Unsupported cipher suite, _doServerHello");
	return UNSUPPORTED_SUITE;
	}
	}
	else {
	WOLFSSL_MSG("Server denied resumption attempt");
	ssl->options.resuming = 0; /* server denied resumption try */
	}
	}
#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls) {
	DtlsPoolReset(ssl);
	}
#endif

	return SetCipherSpecs(ssl);
	}

#ifndef NO_CERTS
    /* just read in and ignore for now TODO: */
static int _doCertificateRequest(WOLFSSL* ssl, const byte* input, word32* inOutIdx, word32 size)
{
word16 len;
word32 begin = *inOutIdx;

#ifdef WOLFSSL_CALLBACKS
if (ssl->hsInfoOn)
AddPacketName("CertificateRequest", &ssl->handShakeInfo);
if (ssl->toInfoOn)
AddLateName("CertificateRequest", &ssl->timeoutInfo);
#endif

if ((*inOutIdx - begin) + OPAQUE8_LEN > size)
return BUFFER_ERROR;

len = input[(*inOutIdx)++];

if ((*inOutIdx - begin) + len > size)
return BUFFER_ERROR;

/* types, read in here */
*inOutIdx += len;

/* signature and hash signature algorithm */
if (IsAtLeastTLSv1_2(ssl)) {
if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
return BUFFER_ERROR;

ato16(input + *inOutIdx, &len);
*inOutIdx += OPAQUE16_LEN;

if ((*inOutIdx - begin) + len > size)
return BUFFER_ERROR;

PickHashSigAlgo(ssl, input + *inOutIdx, len);
*inOutIdx += len;
}

/* authorities */
if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
return BUFFER_ERROR;

ato16(input + *inOutIdx, &len);
*inOutIdx += OPAQUE16_LEN;

if ((*inOutIdx - begin) + len > size)
return BUFFER_ERROR;

while (len) {
word16 dnSz;

if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
return BUFFER_ERROR;

ato16(input + *inOutIdx, &dnSz);
*inOutIdx += OPAQUE16_LEN;

if ((*inOutIdx - begin) + dnSz > size)
return BUFFER_ERROR;

*inOutIdx += dnSz;
len -= OPAQUE16_LEN + dnSz;
}

/* don't send client cert or cert verify if user hasn't provided
cert and private key */
if (ssl->buffers.certificate.buffer && ssl->buffers.key.buffer)
ssl->options.sendVerify = SEND_CERT;
else if (IsTLS(ssl))
ssl->options.sendVerify = SEND_BLANK_CERT;

if (ssl->keys.encryptionOn)
*inOutIdx += ssl->keys.padSz;

return 0;
}
#endif /* !NO_CERTS */


static int _doServerKeyExchange(WOLFSSL* ssl, const byte* input, word32* inOutIdx, word32 size)
{
	word16 length = 0;
	word32 begin  = *inOutIdx;
	int    ret    = 0;
#define ERROR_OUT(err, eLabel) do { ret = err; goto eLabel; } while(0)

	(void)length; /* shut up compiler warnings */
	(void)begin;
	(void)ssl;
	(void)input;
	(void)size;
	(void)ret;

#ifdef WOLFSSL_CALLBACKS
	if (ssl->hsInfoOn)
		AddPacketName("ServerKeyExchange", &ssl->handShakeInfo);
	if (ssl->toInfoOn)
		AddLateName("ServerKeyExchange", &ssl->timeoutInfo);
#endif

#ifndef NO_PSK
	if (ssl->specs.kea == psk_kea) {

	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &length);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + length > size)
	return BUFFER_ERROR;

	XMEMCPY(ssl->arrays->server_hint, input + *inOutIdx,
	min(length, MAX_PSK_ID_LEN));

	ssl->arrays->server_hint[min(length, MAX_PSK_ID_LEN - 1)] = 0;
	*inOutIdx += length;

	return 0;
	}
#endif
#ifndef NO_DH
	if (ssl->specs.kea == diffie_hellman_kea)
	{
	/* p */
	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &length);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + length > size)
	return BUFFER_ERROR;

	if (length < ssl->options.minDhKeySz) {
	WOLFSSL_MSG("Server using a DH key that is too small");
	SendAlert(ssl, alert_fatal, handshake_failure);
	return DH_KEY_SIZE_E;
	}

	ssl->buffers.serverDH_P.buffer = (byte*) XMALLOC(length, ssl->heap,
	                                 DYNAMIC_TYPE_DH);

	if (ssl->buffers.serverDH_P.buffer)
	ssl->buffers.serverDH_P.length = length;
	else
	return MEMORY_ERROR;

	XMEMCPY(ssl->buffers.serverDH_P.buffer, input + *inOutIdx, length);
	*inOutIdx += length;

	ssl->options.dhKeySz = length;

	/* g */
	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &length);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + length > size)
	return BUFFER_ERROR;

	ssl->buffers.serverDH_G.buffer = (byte*) XMALLOC(length, ssl->heap,
	                                 DYNAMIC_TYPE_DH);

	if (ssl->buffers.serverDH_G.buffer)
	ssl->buffers.serverDH_G.length = length;
	else
	return MEMORY_ERROR;

	XMEMCPY(ssl->buffers.serverDH_G.buffer, input + *inOutIdx, length);
	*inOutIdx += length;

	/* pub */
	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &length);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + length > size)
	return BUFFER_ERROR;

	ssl->buffers.serverDH_Pub.buffer = (byte*) XMALLOC(length, ssl->heap,
	                                   DYNAMIC_TYPE_DH);

	if (ssl->buffers.serverDH_Pub.buffer)
	ssl->buffers.serverDH_Pub.length = length;
	else
	return MEMORY_ERROR;

	XMEMCPY(ssl->buffers.serverDH_Pub.buffer, input + *inOutIdx, length);
	*inOutIdx += length;
	}  /* dh_kea */
#endif /* NO_DH */

#ifdef HAVE_ECC
	if (ssl->specs.kea == ecc_diffie_hellman_kea)
	{
	byte b;

	if ((*inOutIdx - begin) + ENUM_LEN + OPAQUE16_LEN + OPAQUE8_LEN > size)
	return BUFFER_ERROR;

	b = input[(*inOutIdx)++];

	if (b != named_curve)
	return ECC_CURVETYPE_ERROR;

	*inOutIdx += 1;   /* curve type, eat leading 0 */
	b = input[(*inOutIdx)++];

	if (CheckCurveId(b) != 0) {
	return ECC_CURVE_ERROR;
	}

	length = input[(*inOutIdx)++];

	if ((*inOutIdx - begin) + length > size)
	return BUFFER_ERROR;

	if (ssl->peerEccKey == NULL) {
	/* alloc/init on demand */
	ssl->peerEccKey = (ecc_key*)XMALLOC(sizeof(ecc_key),
	                      ssl->ctx->heap, DYNAMIC_TYPE_ECC);
	if (ssl->peerEccKey == NULL) {
	WOLFSSL_MSG("PeerEccKey Memory error");
	return MEMORY_E;
	}
	wc_ecc_init(ssl->peerEccKey);
	} else if (ssl->peerEccKeyPresent) {  /* don't leak on reuse */
	wc_ecc_free(ssl->peerEccKey);
	ssl->peerEccKeyPresent = 0;
	wc_ecc_init(ssl->peerEccKey);
	}

	if (wc_ecc_import_x963(input + *inOutIdx, length, ssl->peerEccKey) != 0)
	return ECC_PEERKEY_ERROR;

	*inOutIdx += length;
	ssl->peerEccKeyPresent = 1;
	}
#endif /* HAVE_ECC */

#if !defined(NO_DH) && !defined(NO_PSK)
	if (ssl->specs.kea == dhe_psk_kea) {
	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &length);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + length > size)
	return BUFFER_ERROR;

	XMEMCPY(ssl->arrays->server_hint, input + *inOutIdx,
	min(length, MAX_PSK_ID_LEN));

	ssl->arrays->server_hint[min(length, MAX_PSK_ID_LEN - 1)] = 0;
	*inOutIdx += length;

	/* p */
	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &length);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + length > size)
	return BUFFER_ERROR;

	if (length < ssl->options.minDhKeySz) {
	WOLFSSL_MSG("Server using a DH key that is too small");
	SendAlert(ssl, alert_fatal, handshake_failure);
	return DH_KEY_SIZE_E;
	}

	ssl->buffers.serverDH_P.buffer = (byte*) XMALLOC(length, ssl->heap,
	                                 DYNAMIC_TYPE_DH);

	if (ssl->buffers.serverDH_P.buffer)
	ssl->buffers.serverDH_P.length = length;
	else
	return MEMORY_ERROR;

	XMEMCPY(ssl->buffers.serverDH_P.buffer, input + *inOutIdx, length);
	*inOutIdx += length;

	ssl->options.dhKeySz = length;

	/* g */
	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &length);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + length > size)
	return BUFFER_ERROR;

	ssl->buffers.serverDH_G.buffer = (byte*) XMALLOC(length, ssl->heap,
	                                 DYNAMIC_TYPE_DH);

	if (ssl->buffers.serverDH_G.buffer)
	ssl->buffers.serverDH_G.length = length;
	else
	return MEMORY_ERROR;

	XMEMCPY(ssl->buffers.serverDH_G.buffer, input + *inOutIdx, length);
	*inOutIdx += length;

	/* pub */
	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &length);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + length > size)
	return BUFFER_ERROR;

	ssl->buffers.serverDH_Pub.buffer = (byte*) XMALLOC(length, ssl->heap,
	                                   DYNAMIC_TYPE_DH);

	if (ssl->buffers.serverDH_Pub.buffer)
	ssl->buffers.serverDH_Pub.length = length;
	else
	return MEMORY_ERROR;

	XMEMCPY(ssl->buffers.serverDH_Pub.buffer, input + *inOutIdx, length);
	*inOutIdx += length;
	}
#endif /* !NO_DH || !NO_PSK */

#if !defined(NO_DH) || defined(HAVE_ECC)
	if (!ssl->options.usingAnon_cipher &&
	(ssl->specs.kea == ecc_diffie_hellman_kea ||
	ssl->specs.kea == diffie_hellman_kea))
	{
#ifndef NO_OLD_TLS
#ifdef WOLFSSL_SMALL_STACK
	Md5*    md5 = NULL;
	Sha*    sha = NULL;
#else
	Md5     md5[1];
	Sha     sha[1];
#endif
#endif
#ifndef NO_SHA256
#ifdef WOLFSSL_SMALL_STACK
	Sha256* sha256  = NULL;
	byte*   hash256 = NULL;
#else
	Sha256  sha256[1];
	byte    hash256[SHA256_DIGEST_SIZE];
#endif
#endif
#ifdef WOLFSSL_SHA384
#ifdef WOLFSSL_SMALL_STACK
	Sha384* sha384  = NULL;
	byte*   hash384 = NULL;
#else
	Sha384  sha384[1];
	byte    hash384[SHA384_DIGEST_SIZE];
#endif
#endif
#ifdef WOLFSSL_SHA512
#ifdef WOLFSSL_SMALL_STACK
	Sha512* sha512  = NULL;
	byte*   hash512 = NULL;
#else
	Sha512  sha512[1];
	byte    hash512[SHA512_DIGEST_SIZE];
#endif
#endif
#ifdef WOLFSSL_SMALL_STACK
	byte*   hash          = NULL;
	byte*   messageVerify = NULL;
#else
	byte    hash[FINISHED_SZ];
	byte    messageVerify[MAX_DH_SZ];
#endif
	byte    hashAlgo = sha_mac;
	byte    sigAlgo  = ssl->specs.sig_algo;
	word16  verifySz = (word16) (*inOutIdx - begin);

#ifndef NO_OLD_TLS
	byte doMd5 = 0;
	byte doSha = 0;
#endif
#ifndef NO_SHA256
	byte doSha256 = 0;
#endif
#ifdef WOLFSSL_SHA384
	byte doSha384 = 0;
#endif
#ifdef WOLFSSL_SHA512
	byte doSha512 = 0;
#endif

	(void)hash;
	(void)sigAlgo;
	(void)hashAlgo;

	/* save message for hash verify */
	if (verifySz > MAX_DH_SZ)
	ERROR_OUT(BUFFER_ERROR, done);

#ifdef WOLFSSL_SMALL_STACK
	messageVerify = (byte*)XMALLOC(MAX_DH_SZ, NULL,
	                               DYNAMIC_TYPE_TMP_BUFFER);
	if (messageVerify == NULL)
	ERROR_OUT(MEMORY_E, done);
#endif

	XMEMCPY(messageVerify, input + begin, verifySz);

	if (IsAtLeastTLSv1_2(ssl)) {
	byte setHash = 0;
	if ((*inOutIdx - begin) + ENUM_LEN + ENUM_LEN > size)
	ERROR_OUT(BUFFER_ERROR, done);

	hashAlgo = input[(*inOutIdx)++];
	sigAlgo  = input[(*inOutIdx)++];

	switch (hashAlgo) {
	case sha512_mac:
#ifdef WOLFSSL_SHA512
	doSha512 = 1;
	setHash  = 1;
#endif
	break;

	case sha384_mac:
#ifdef WOLFSSL_SHA384
	doSha384 = 1;
	setHash  = 1;
#endif
	break;

	case sha256_mac:
#ifndef NO_SHA256
	doSha256 = 1;
	setHash  = 1;
#endif
	break;

	case sha_mac:
#ifndef NO_OLD_TLS
	doSha = 1;
	setHash  = 1;
#endif
	break;

	default:
	ERROR_OUT(ALGO_ID_E, done);
	}

	if (setHash == 0) {
	ERROR_OUT(ALGO_ID_E, done);
	}

	} else {
	/* only using sha and md5 for rsa */
#ifndef NO_OLD_TLS
	doSha = 1;
	if (sigAlgo == rsa_sa_algo) {
	doMd5 = 1;
	}
#else
	ERROR_OUT(ALGO_ID_E, done);
#endif
	}

	/* signature */
	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	ERROR_OUT(BUFFER_ERROR, done);

	ato16(input + *inOutIdx, &length);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + length > size)
	ERROR_OUT(BUFFER_ERROR, done);

	/* inOutIdx updated at the end of the function */

	/* verify signature */
#ifdef WOLFSSL_SMALL_STACK
	hash = (byte*)XMALLOC(FINISHED_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (hash == NULL)
	ERROR_OUT(MEMORY_E, done);
#endif

#ifndef NO_OLD_TLS
	/* md5 */
#ifdef WOLFSSL_SMALL_STACK
	if (doMd5) {
	md5 = (Md5*)XMALLOC(sizeof(Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (md5 == NULL)
	ERROR_OUT(MEMORY_E, done);
	}
#endif
	if (doMd5) {
	wc_InitMd5(md5);
	wc_Md5Update(md5, ssl->arrays->clientRandom, RAN_LEN);
	wc_Md5Update(md5, ssl->arrays->serverRandom, RAN_LEN);
	wc_Md5Update(md5, messageVerify, verifySz);
	wc_Md5Final(md5, hash);
	}
	/* sha */
#ifdef WOLFSSL_SMALL_STACK
	if (doSha) {
	sha = (Sha*)XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (sha == NULL)
	ERROR_OUT(MEMORY_E, done);
	}
#endif
	if (doSha) {
	ret = wc_InitSha(sha);
	if (ret != 0) goto done;
	wc_ShaUpdate(sha, ssl->arrays->clientRandom, RAN_LEN);
	wc_ShaUpdate(sha, ssl->arrays->serverRandom, RAN_LEN);
	wc_ShaUpdate(sha, messageVerify, verifySz);
	wc_ShaFinal(sha, hash + MD5_DIGEST_SIZE);
	}
#endif

#ifndef NO_SHA256
#ifdef WOLFSSL_SMALL_STACK
	if (doSha256) {
	sha256 = (Sha256*)XMALLOC(sizeof(Sha256), NULL,
	                               DYNAMIC_TYPE_TMP_BUFFER);
	hash256 = (byte*)XMALLOC(SHA256_DIGEST_SIZE, NULL,
	                               DYNAMIC_TYPE_TMP_BUFFER);
	if (sha256 == NULL || hash256 == NULL)
	ERROR_OUT(MEMORY_E, done);
	}
#endif
	if (doSha256) {
	if (!(ret = wc_InitSha256(sha256))
	&&  !(ret = wc_Sha256Update(sha256, ssl->arrays->clientRandom,
	                RAN_LEN))
	&&  !(ret = wc_Sha256Update(sha256, ssl->arrays->serverRandom,
	                RAN_LEN))
	&&  !(ret = wc_Sha256Update(sha256, messageVerify, verifySz)))
	ret = wc_Sha256Final(sha256, hash256);
	if (ret != 0) goto done;
	}
#endif

#ifdef WOLFSSL_SHA384
#ifdef WOLFSSL_SMALL_STACK
	if (doSha384) {
	sha384 = (Sha384*)XMALLOC(sizeof(Sha384), NULL,
	                               DYNAMIC_TYPE_TMP_BUFFER);
	hash384 = (byte*)XMALLOC(SHA384_DIGEST_SIZE, NULL,
	                               DYNAMIC_TYPE_TMP_BUFFER);
	if (sha384 == NULL || hash384 == NULL)
	ERROR_OUT(MEMORY_E, done);
	}
#endif
	if (doSha384) {
	if (!(ret = wc_InitSha384(sha384))
	&&  !(ret = wc_Sha384Update(sha384, ssl->arrays->clientRandom,
	                RAN_LEN))
	&&  !(ret = wc_Sha384Update(sha384, ssl->arrays->serverRandom,
	                RAN_LEN))
	&&  !(ret = wc_Sha384Update(sha384, messageVerify, verifySz)))
	ret = wc_Sha384Final(sha384, hash384);
	if (ret != 0) goto done;
	}
#endif

#ifdef WOLFSSL_SHA512
#ifdef WOLFSSL_SMALL_STACK
	if (doSha512) {
	sha512 = (Sha512*)XMALLOC(sizeof(Sha512), NULL,
	                               DYNAMIC_TYPE_TMP_BUFFER);
	hash512 = (byte*)XMALLOC(SHA512_DIGEST_SIZE, NULL,
	                               DYNAMIC_TYPE_TMP_BUFFER);
	if (sha512 == NULL || hash512 == NULL)
	ERROR_OUT(MEMORY_E, done);
	}
#endif
	if (doSha512) {
	if (!(ret = wc_InitSha512(sha512))
	&&  !(ret = wc_Sha512Update(sha512, ssl->arrays->clientRandom,
	                RAN_LEN))
	&&  !(ret = wc_Sha512Update(sha512, ssl->arrays->serverRandom,
	                RAN_LEN))
	&&  !(ret = wc_Sha512Update(sha512, messageVerify, verifySz)))
	ret = wc_Sha512Final(sha512, hash512);
	if (ret != 0) goto done;
	}
#endif

#ifndef NO_RSA
	/* rsa */
	if (sigAlgo == rsa_sa_algo)
	{
	byte*  out        = NULL;
	byte   doUserRsa  = 0;
	word32 verifiedSz = 0;

#ifdef HAVE_PK_CALLBACKS
	if (ssl->ctx->RsaVerifyCb)
	doUserRsa = 1;
#endif /*HAVE_PK_CALLBACKS */

	if (ssl->peerRsaKey == NULL || !ssl->peerRsaKeyPresent)
	ERROR_OUT(NO_PEER_KEY, done);

	if (doUserRsa) {
#ifdef HAVE_PK_CALLBACKS
	verifiedSz = ssl->ctx->RsaVerifyCb(ssl,
	                         (byte *)input + *inOutIdx,
	                         length, &out,
	                         ssl->buffers.peerRsaKey.buffer,
	                         ssl->buffers.peerRsaKey.length,
	                         ssl->RsaVerifyCtx);
#endif /*HAVE_PK_CALLBACKS */
	}
	else
	verifiedSz = wc_RsaSSL_VerifyInline((byte *)input + *inOutIdx,
	                         length, &out, ssl->peerRsaKey);

	if (IsAtLeastTLSv1_2(ssl)) {
	word32 encSigSz;
#ifndef NO_OLD_TLS
	byte*  digest = &hash[MD5_DIGEST_SIZE];
	int    typeH = SHAh;
	int    digestSz = SHA_DIGEST_SIZE;
#else
	byte*  digest = hash256;
	int    typeH =  SHA256h;
	int    digestSz = SHA256_DIGEST_SIZE;
#endif
#ifdef WOLFSSL_SMALL_STACK
	byte*  encodedSig = NULL;
#else
	byte   encodedSig[MAX_ENCODED_SIG_SZ];
#endif

	if (hashAlgo == sha_mac) {
#ifndef NO_SHA
	digest   = &hash[MD5_DIGEST_SIZE];
	typeH    = SHAh;
	digestSz = SHA_DIGEST_SIZE;
#endif
	}
	else if (hashAlgo == sha256_mac) {
#ifndef NO_SHA256
	digest   = hash256;
	typeH    = SHA256h;
	digestSz = SHA256_DIGEST_SIZE;
#endif
	}
	else if (hashAlgo == sha384_mac) {
#ifdef WOLFSSL_SHA384
	digest   = hash384;
	typeH    = SHA384h;
	digestSz = SHA384_DIGEST_SIZE;
#endif
	}
	else if (hashAlgo == sha512_mac) {
#ifdef WOLFSSL_SHA512
	digest   = hash512;
	typeH    = SHA512h;
	digestSz = SHA512_DIGEST_SIZE;
#endif
	}

#ifdef WOLFSSL_SMALL_STACK
	encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL,
	                               DYNAMIC_TYPE_TMP_BUFFER);
	if (encodedSig == NULL)
	ERROR_OUT(MEMORY_E, done);
#endif

	if (digest == NULL)
	ERROR_OUT(ALGO_ID_E, done);
	encSigSz = wc_EncodeSignature(encodedSig, digest, digestSz,
	                      typeH);
	if (encSigSz != verifiedSz || !out || XMEMCMP(out, encodedSig,
	                min(encSigSz, MAX_ENCODED_SIG_SZ)) != 0)
	ret = VERIFY_SIGN_ERROR;

#ifdef WOLFSSL_SMALL_STACK
	XFREE(encodedSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
	if (ret != 0)
	goto done;
	}
	else if (verifiedSz != FINISHED_SZ || !out || XMEMCMP(out,
	                                hash, FINISHED_SZ) != 0)
	ERROR_OUT(VERIFY_SIGN_ERROR, done);
	} else
#endif
#ifdef HAVE_ECC
	/* ecdsa */
	if (sigAlgo == ecc_dsa_sa_algo) {
	int verify = 0;
#ifndef NO_OLD_TLS
	byte* digest = &hash[MD5_DIGEST_SIZE];
	word32 digestSz = SHA_DIGEST_SIZE;
#else
	byte* digest = hash256;
	word32 digestSz = SHA256_DIGEST_SIZE;
#endif
	byte doUserEcc = 0;

#ifdef HAVE_PK_CALLBACKS
	if (ssl->ctx->EccVerifyCb)
	doUserEcc = 1;
#endif

	if (!ssl->peerEccDsaKeyPresent)
	ERROR_OUT(NO_PEER_KEY, done);

	if (IsAtLeastTLSv1_2(ssl)) {
	if (hashAlgo == sha_mac) {
#ifndef NO_SHA
	digest   = &hash[MD5_DIGEST_SIZE];
	digestSz = SHA_DIGEST_SIZE;
#endif
	}
	else if (hashAlgo == sha256_mac) {
#ifndef NO_SHA256
	digest   = hash256;
	digestSz = SHA256_DIGEST_SIZE;
#endif
	}
	else if (hashAlgo == sha384_mac) {
#ifdef WOLFSSL_SHA384
	digest   = hash384;
	digestSz = SHA384_DIGEST_SIZE;
#endif
	}
	else if (hashAlgo == sha512_mac) {
#ifdef WOLFSSL_SHA512
	digest   = hash512;
	digestSz = SHA512_DIGEST_SIZE;
#endif
	}
	}
	if (doUserEcc) {
#ifdef HAVE_PK_CALLBACKS
	ret = ssl->ctx->EccVerifyCb(ssl, input + *inOutIdx, length,
	                    digest, digestSz,
	                    ssl->buffers.peerEccDsaKey.buffer,
	                    ssl->buffers.peerEccDsaKey.length,
	                    &verify, ssl->EccVerifyCtx);
#endif
	}
	else {
	ret = wc_ecc_verify_hash(input + *inOutIdx, length,
	         digest, digestSz, &verify, ssl->peerEccDsaKey);
	}
	if (ret != 0 || verify == 0)
	ERROR_OUT(VERIFY_SIGN_ERROR, done);
	}
	else
#endif /* HAVE_ECC */
	ERROR_OUT(ALGO_ID_E, done);

	/* signature length */
	*inOutIdx += length;

	ssl->options.serverState = SERVER_KEYEXCHANGE_COMPLETE;

	done:
#ifdef WOLFSSL_SMALL_STACK
#ifndef NO_OLD_TLS
	XFREE(md5,           NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(sha,           NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#ifndef NO_SHA256
	XFREE(sha256,        NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(hash256,       NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#ifdef WOLFSSL_SHA384
	XFREE(sha384,        NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(hash384,       NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#ifdef WOLFSSL_SHA512
	XFREE(sha512,        NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(hash512,       NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
	XFREE(hash,          NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(messageVerify, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
	if (ret != 0)
	return ret;
	}

	if (ssl->keys.encryptionOn) {
	*inOutIdx += ssl->keys.padSz;
	}

	return 0;
#else  /* !NO_DH or HAVE_ECC */
	return NOT_COMPILED_IN;  /* not supported by build */
#endif /* !NO_DH or HAVE_ECC */

#undef ERROR_OUT
	}

#ifdef HAVE_SESSION_TICKET
int _doSessionTicket(WOLFSSL* ssl, const byte* input, word32* inOutIdx, word32 size)
{
    word32 begin = *inOutIdx;
    word32 lifetime;
    word16 length;

    if (ssl->expect_session_ticket == 0) {
        WOLFSSL_MSG("Unexpected session ticket");
        return SESSION_TICKET_EXPECT_E;
    }

    if ((*inOutIdx - begin) + OPAQUE32_LEN > size)
        return BUFFER_ERROR;

    ato32(input + *inOutIdx, &lifetime);
    *inOutIdx += OPAQUE32_LEN;

    if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
        return BUFFER_ERROR;

    ato16(input + *inOutIdx, &length);
    *inOutIdx += OPAQUE16_LEN;

    if (length > sizeof(ssl->session.ticket))
        return SESSION_TICKET_LEN_E;

    if ((*inOutIdx - begin) + length > size)
        return BUFFER_ERROR;

    /* If the received ticket including its length is greater than
     * a length value, the save it. Otherwise, don't save it. */
    if (length > 0) {
        XMEMCPY(ssl->session.ticket, input + *inOutIdx, length);
        *inOutIdx += length;
        ssl->session.ticketLen = length;
        ssl->timeout = lifetime;
        if (ssl->session_ticket_cb != NULL) {
            ssl->session_ticket_cb(ssl,
                                   ssl->session.ticket, ssl->session.ticketLen,
                                   ssl->session_ticket_ctx);
        }
        /* Create a fake sessionID based on the ticket, this will
         * supercede the existing session cache info. */
        ssl->options.haveSessionId = 1;
        XMEMCPY(ssl->arrays->sessionID,
                                 ssl->session.ticket + length - ID_LEN, ID_LEN);
#ifndef NO_SESSION_CACHE
        AddSession(ssl);
#endif

    }
    else {
        ssl->session.ticketLen = 0;
    }

    if (ssl->keys.encryptionOn) {
        *inOutIdx += ssl->keys.padSz;
    }

    ssl->expect_session_ticket = 0;

    return 0;
}
#endif /* HAVE_SESSION_TICKET */


int DoFinished(WOLFSSL* ssl, const byte* input, word32* inOutIdx, word32 size, word32 totalSz, int sniff)
{
    word32 finishedSz = (ssl->options.tls ? TLS_FINISHED_SZ : FINISHED_SZ);

    if (finishedSz != size)
        return BUFFER_ERROR;

    /* check against totalSz */
    if (*inOutIdx + size + ssl->keys.padSz > totalSz)
        return BUFFER_E;

    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Finished", &ssl->handShakeInfo);
        if (ssl->toInfoOn) AddLateName("Finished", &ssl->timeoutInfo);
    #endif

    if (sniff == NO_SNIFF) {
        if (XMEMCMP(input + *inOutIdx, &ssl->hsHashes->verifyHashes,size) != 0){
            WOLFSSL_MSG("Verify finished error on hashes");
            return VERIFY_FINISHED_ERROR;
        }
    }

#ifdef HAVE_SECURE_RENEGOTIATION
    if (ssl->secure_renegotiation) {
        /* save peer's state */
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            XMEMCPY(ssl->secure_renegotiation->server_verify_data,
                    input + *inOutIdx, TLS_FINISHED_SZ);
        else
            XMEMCPY(ssl->secure_renegotiation->client_verify_data,
                    input + *inOutIdx, TLS_FINISHED_SZ);
    }
#endif

    /* force input exhaustion at ProcessReply consuming padSz */
    *inOutIdx += size + ssl->keys.padSz;

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        ssl->options.serverState = SERVER_FINISHED_COMPLETE;
        if (!ssl->options.resuming) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;

#ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                /* Other side has received our Finished, go to next epoch */
                ssl->keys.dtls_epoch++;
                ssl->keys.dtls_sequence_number = 1;
            }
#endif
        }
    }
    else {
        ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
        if (ssl->options.resuming) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;

#ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                /* Other side has received our Finished, go to next epoch */
                ssl->keys.dtls_epoch++;
                ssl->keys.dtls_sequence_number = 1;
            }
#endif
        }
    }

    return 0;
}



static int _doClientHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx, word32 helloSz)
{
	byte            b;
	ProtocolVersion pv;
	Suites          clSuites;
	word32          i = *inOutIdx;
	word32          begin = i;

#ifdef WOLFSSL_CALLBACKS
	if (ssl->hsInfoOn) AddPacketName("ClientHello", &ssl->handShakeInfo);
	if (ssl->toInfoOn) AddLateName("ClientHello", &ssl->timeoutInfo);
#endif

	/* protocol version, random and session id length check */
	if ((i - begin) + OPAQUE16_LEN + RAN_LEN + OPAQUE8_LEN > helloSz)
	return BUFFER_ERROR;

	/* protocol version */
	XMEMCPY(&pv, input + i, OPAQUE16_LEN);
	ssl->chVersion = pv;   /* store */
	i += OPAQUE16_LEN;

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
	/* turn off tls 1.1+ */
	WOLFSSL_MSG("    downgrading to TLSv1");
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

	/* random */
	XMEMCPY(ssl->arrays->clientRandom, input + i, RAN_LEN);
	i += RAN_LEN;

#ifdef SHOW_SECRETS
	{
	int j;
	printf("client random: ");
	for (j = 0; j < RAN_LEN; j++)
	printf("%02x", ssl->arrays->clientRandom[j]);
	printf("\n");
	}
#endif

	/* session id */
	b = input[i++];

	if (b == ID_LEN) {
	if ((i - begin) + ID_LEN > helloSz)
	return BUFFER_ERROR;

	XMEMCPY(ssl->arrays->sessionID, input + i, ID_LEN);
	ssl->arrays->sessionIDSz = ID_LEN;
	i += ID_LEN;
	ssl->options.resuming = 1; /* client wants to resume */
	WOLFSSL_MSG("Client wants to resume session");
	}
	else if (b) {
	WOLFSSL_MSG("Invalid session ID size");
	return BUFFER_ERROR; /* session ID nor 0 neither 32 bytes long */
	}

#ifdef WOLFSSL_DTLS
	/* cookie */
	if (ssl->options.dtls) {

	if ((i - begin) + OPAQUE8_LEN > helloSz)
	return BUFFER_ERROR;

	b = input[i++];

	if (b) {
	byte cookie[MAX_COOKIE_LEN];

	if (b > MAX_COOKIE_LEN)
	    return BUFFER_ERROR;

	if ((i - begin) + b > helloSz)
	    return BUFFER_ERROR;

	if (ssl->ctx->CBIOCookie == NULL) {
	    WOLFSSL_MSG("Your Cookie callback is null, please set");
	    return COOKIE_ERROR;
	}

	if ((ssl->ctx->CBIOCookie(ssl, cookie, COOKIE_SZ,
	                          ssl->IOCB_CookieCtx) != COOKIE_SZ)
	        || (b != COOKIE_SZ)
	        || (XMEMCMP(cookie, input + i, b) != 0)) {
	    return COOKIE_ERROR;
	}

	i += b;
	}
	}
#endif

	/* suites */
	if ((i - begin) + OPAQUE16_LEN > helloSz)
	return BUFFER_ERROR;

	ato16(&input[i], &clSuites.suiteSz);
	i += OPAQUE16_LEN;

	/* suites and compression length check */
	if ((i - begin) + clSuites.suiteSz + OPAQUE8_LEN > helloSz)
	return BUFFER_ERROR;

	if (clSuites.suiteSz > MAX_SUITE_SZ)
	return BUFFER_ERROR;

	XMEMCPY(clSuites.suites, input + i, clSuites.suiteSz);
	i += clSuites.suiteSz;
	clSuites.hashSigAlgoSz = 0;

	/* compression length */
	b = input[i++];

	if ((i - begin) + b > helloSz)
	return BUFFER_ERROR;

	if (ssl->options.usingCompression) {
	int match = 0;

	while (b--) {
	byte comp = input[i++];

	if (comp == ZLIB_COMPRESSION)
	match = 1;
	}

	if (!match) {
	WOLFSSL_MSG("Not matching compression, turning off");
	ssl->options.usingCompression = 0;  /* turn off */
	}
	}
	else
	i += b; /* ignore, since we're not on */

	*inOutIdx = i;

	/* tls extensions */
	if ((i - begin) < helloSz) {
#ifdef HAVE_TLS_EXTENSIONS
	if (TLSX_SupportExtensions(ssl))
	//				{
	//               int ret = 0;
#else
	if (IsAtLeastTLSv1_2(ssl))
#endif
	{
	int ret = 0;
	/* Process the hello extension. Skip unsupported. */
	word16 totalExtSz;

	if ((i - begin) + OPAQUE16_LEN > helloSz)
	return BUFFER_ERROR;

	ato16(&input[i], &totalExtSz);
	i += OPAQUE16_LEN;

	if ((i - begin) + totalExtSz > helloSz)
	return BUFFER_ERROR;

#ifdef HAVE_TLS_EXTENSIONS
	if ((ret = TLSX_Parse(ssl, (byte *) input + i,
	                                 totalExtSz, 1, &clSuites)))
	return ret;

	i += totalExtSz;
#else
	while (totalExtSz) {
	word16 extId, extSz;

	if (OPAQUE16_LEN + OPAQUE16_LEN > totalExtSz)
	    return BUFFER_ERROR;

	ato16(&input[i], &extId);
	i += OPAQUE16_LEN;
	ato16(&input[i], &extSz);
	i += OPAQUE16_LEN;

	if (OPAQUE16_LEN + OPAQUE16_LEN + extSz > totalExtSz)
	    return BUFFER_ERROR;

	if (extId == HELLO_EXT_SIG_ALGO) {
	    ato16(&input[i], &clSuites.hashSigAlgoSz);
	    i += OPAQUE16_LEN;

	    if (OPAQUE16_LEN + clSuites.hashSigAlgoSz > extSz)
	        return BUFFER_ERROR;

	    XMEMCPY(clSuites.hashSigAlgo, &input[i],
	        min(clSuites.hashSigAlgoSz, HELLO_EXT_SIGALGO_MAX));
	    i += clSuites.hashSigAlgoSz;

	    if (clSuites.hashSigAlgoSz > HELLO_EXT_SIGALGO_MAX)
	        clSuites.hashSigAlgoSz = HELLO_EXT_SIGALGO_MAX;
	}
	else
	    i += extSz;

	totalExtSz -= OPAQUE16_LEN + OPAQUE16_LEN + extSz;
	}
#endif
	*inOutIdx = i;
	}
	else
	*inOutIdx = begin + helloSz; /* skip extensions */
	}

	ssl->options.clientState   = CLIENT_HELLO_COMPLETE;
	ssl->options.haveSessionId = 1;

	/* ProcessOld uses same resume code */
	if (ssl->options.resuming && (!ssl->options.dtls ||
	ssl->options.acceptState == HELLO_VERIFY_SENT)) { /* let's try */
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
	}
	else {
	if (MatchSuite(ssl, &clSuites) < 0) {
	WOLFSSL_MSG("Unsupported cipher suite, ClientHello");
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


static int _doClientKeyExchange(WOLFSSL* ssl, byte* input, word32* inOutIdx, word32 size)
{
	int    ret = 0;
	word32 length = 0;
	byte*  out = NULL;
	word32 begin = *inOutIdx;

	(void)length; /* shut up compiler warnings */
	(void)out;
	(void)input;
	(void)size;
	(void)begin;

	if (ssl->options.side != WOLFSSL_SERVER_END) {
	WOLFSSL_MSG("Client received client keyexchange, attack?");
	WOLFSSL_ERROR(ssl->error = SIDE_ERROR);
	return SSL_FATAL_ERROR;
	}

	if (ssl->options.clientState < CLIENT_HELLO_COMPLETE) {
	WOLFSSL_MSG("Client sending keyexchange at wrong time");
	SendAlert(ssl, alert_fatal, unexpected_message);
	return OUT_OF_ORDER_E;
	}

#ifndef NO_CERTS
	if (ssl->options.verifyPeer && ssl->options.failNoCert)
	if (!ssl->options.havePeerCert) {
	WOLFSSL_MSG("client didn't present peer cert");
	return NO_PEER_CERT;
	}
#endif

#ifdef WOLFSSL_CALLBACKS
	if (ssl->hsInfoOn)
	AddPacketName("ClientKeyExchange", &ssl->handShakeInfo);
	if (ssl->toInfoOn)
	AddLateName("ClientKeyExchange", &ssl->timeoutInfo);
#endif

	switch (ssl->specs.kea) {
#ifndef NO_RSA
	case rsa_kea:
	{
	word32 idx = 0;
	RsaKey key;
	byte   doUserRsa = 0;

#ifdef HAVE_PK_CALLBACKS
	if (ssl->ctx->RsaDecCb)
	doUserRsa = 1;
#endif

	ret = wc_InitRsaKey(&key, ssl->heap);
	if (ret != 0) return ret;

	if (ssl->buffers.key.buffer)
	ret = wc_RsaPrivateKeyDecode(ssl->buffers.key.buffer, &idx,
	                 &key, ssl->buffers.key.length);
	else
	return NO_PRIVATE_KEY;

	if (ret == 0) {
	length = wc_RsaEncryptSize(&key);
	ssl->arrays->preMasterSz = SECRET_LEN;

	if (ssl->options.tls) {
	word16 check;

	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &check);
	*inOutIdx += OPAQUE16_LEN;

	if ((word32) check != length) {
	WOLFSSL_MSG("RSA explicit size doesn't match");
	wc_FreeRsaKey(&key);
	return RSA_PRIVATE_ERROR;
	}
	}

	if ((*inOutIdx - begin) + length > size) {
	WOLFSSL_MSG("RSA message too big");
	wc_FreeRsaKey(&key);
	return BUFFER_ERROR;
	}

	if (doUserRsa) {
#ifdef HAVE_PK_CALLBACKS
	ret = ssl->ctx->RsaDecCb(ssl,
	            input + *inOutIdx, length, &out,
	            ssl->buffers.key.buffer,
	            ssl->buffers.key.length,
	            ssl->RsaDecCtx);
#endif
	}
	else {
	ret = wc_RsaPrivateDecryptInline(input + *inOutIdx, length,
	                                        &out, &key);
	}

	*inOutIdx += length;

	if (ret == SECRET_LEN) {
	XMEMCPY(ssl->arrays->preMasterSecret, out, SECRET_LEN);
	if (ssl->arrays->preMasterSecret[0] !=
	                               ssl->chVersion.major
	|| ssl->arrays->preMasterSecret[1] !=
	                               ssl->chVersion.minor)
	ret = PMS_VERSION_ERROR;
	else
	ret = MakeMasterSecret(ssl);
	}
	else {
	ret = RSA_PRIVATE_ERROR;
	}
	}

	wc_FreeRsaKey(&key);
	}
	break;
#endif
#ifndef NO_PSK
	case psk_kea:
	{
	byte* pms = ssl->arrays->preMasterSecret;
	word16 ci_sz;

	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &ci_sz);
	*inOutIdx += OPAQUE16_LEN;

	if (ci_sz > MAX_PSK_ID_LEN)
	return CLIENT_ID_ERROR;

	if ((*inOutIdx - begin) + ci_sz > size)
	return BUFFER_ERROR;

	XMEMCPY(ssl->arrays->client_identity, input + *inOutIdx, ci_sz);
	*inOutIdx += ci_sz;

	ssl->arrays->client_identity[min(ci_sz, MAX_PSK_ID_LEN-1)] = 0;
	ssl->arrays->psk_keySz = ssl->options.server_psk_cb(ssl,
	ssl->arrays->client_identity, ssl->arrays->psk_key,
	MAX_PSK_KEY_LEN);

	if (ssl->arrays->psk_keySz == 0 ||
	           ssl->arrays->psk_keySz > MAX_PSK_KEY_LEN)
	return PSK_KEY_ERROR;

	/* make psk pre master secret */
	/* length of key + length 0s + length of key + key */
	c16toa((word16) ssl->arrays->psk_keySz, pms);
	pms += OPAQUE16_LEN;

	XMEMSET(pms, 0, ssl->arrays->psk_keySz);
	pms += ssl->arrays->psk_keySz;

	c16toa((word16) ssl->arrays->psk_keySz, pms);
	pms += OPAQUE16_LEN;

	XMEMCPY(pms, ssl->arrays->psk_key, ssl->arrays->psk_keySz);
	ssl->arrays->preMasterSz = ssl->arrays->psk_keySz * 2 + 4;

	ret = MakeMasterSecret(ssl);

	/* No further need for PSK */
	ForceZero(ssl->arrays->psk_key, ssl->arrays->psk_keySz);
	ssl->arrays->psk_keySz = 0;
	}
	break;
#endif /* NO_PSK */
#ifdef HAVE_NTRU
	case ntru_kea:
	{
	word16 cipherLen;
	word16 plainLen = sizeof(ssl->arrays->preMasterSecret);

	if (!ssl->buffers.key.buffer)
	return NO_PRIVATE_KEY;

	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &cipherLen);
	*inOutIdx += OPAQUE16_LEN;

	if (cipherLen > MAX_NTRU_ENCRYPT_SZ)
	return NTRU_KEY_ERROR;

	if ((*inOutIdx - begin) + cipherLen > size)
	return BUFFER_ERROR;

	if (NTRU_OK != ntru_crypto_ntru_decrypt(
	(word16) ssl->buffers.key.length,
	ssl->buffers.key.buffer, cipherLen,
	input + *inOutIdx, &plainLen,
	ssl->arrays->preMasterSecret))
	return NTRU_DECRYPT_ERROR;

	if (plainLen != SECRET_LEN)
	return NTRU_DECRYPT_ERROR;

	*inOutIdx += cipherLen;

	ssl->arrays->preMasterSz = plainLen;
	ret = MakeMasterSecret(ssl);
	}
	break;
#endif /* HAVE_NTRU */
#ifdef HAVE_ECC
	case ecc_diffie_hellman_kea:
	{
	if ((*inOutIdx - begin) + OPAQUE8_LEN > size)
	return BUFFER_ERROR;

	length = input[(*inOutIdx)++];

	if ((*inOutIdx - begin) + length > size)
	return BUFFER_ERROR;

	if (ssl->peerEccKey == NULL) {
	/* alloc/init on demand */
	ssl->peerEccKey = (ecc_key*)XMALLOC(sizeof(ecc_key),
	                  ssl->ctx->heap, DYNAMIC_TYPE_ECC);
	if (ssl->peerEccKey == NULL) {
	WOLFSSL_MSG("PeerEccKey Memory error");
	return MEMORY_E;
	}
	wc_ecc_init(ssl->peerEccKey);
	} else if (ssl->peerEccKeyPresent) {  /* don't leak on reuse */
	wc_ecc_free(ssl->peerEccKey);
	ssl->peerEccKeyPresent = 0;
	wc_ecc_init(ssl->peerEccKey);
	}

	if (wc_ecc_import_x963(input + *inOutIdx, length, ssl->peerEccKey))
	return ECC_PEERKEY_ERROR;

	*inOutIdx += length;
	ssl->peerEccKeyPresent = 1;

	length = sizeof(ssl->arrays->preMasterSecret);

	if (ssl->specs.static_ecdh) {
	ecc_key staticKey;
	word32 i = 0;

	wc_ecc_init(&staticKey);
	ret = wc_EccPrivateKeyDecode(ssl->buffers.key.buffer, &i,
	               &staticKey, ssl->buffers.key.length);

	if (ret == 0)
	ret = wc_ecc_shared_secret(&staticKey, ssl->peerEccKey,
	             ssl->arrays->preMasterSecret, &length);

	wc_ecc_free(&staticKey);
	}
	else {
	if (ssl->eccTempKeyPresent == 0) {
	WOLFSSL_MSG("Ecc ephemeral key not made correctly");
	ret = ECC_MAKEKEY_ERROR;
	} else {
	ret = wc_ecc_shared_secret(ssl->eccTempKey,ssl->peerEccKey,
	             ssl->arrays->preMasterSecret, &length);
	}
	}

	if (ret != 0)
	return ECC_SHARED_ERROR;

	ssl->arrays->preMasterSz = length;
	ret = MakeMasterSecret(ssl);
	}
	break;
#endif /* HAVE_ECC */
#ifndef NO_DH
	case diffie_hellman_kea:
	{
	word16 clientPubSz;
	DhKey  dhKey;

	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &clientPubSz);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + clientPubSz > size)
	return BUFFER_ERROR;

	wc_InitDhKey(&dhKey);
	ret = wc_DhSetKey(&dhKey, ssl->buffers.serverDH_P.buffer,
	           ssl->buffers.serverDH_P.length,
	           ssl->buffers.serverDH_G.buffer,
	           ssl->buffers.serverDH_G.length);
	if (ret == 0)
	ret = wc_DhAgree(&dhKey, ssl->arrays->preMasterSecret,
	             &ssl->arrays->preMasterSz,
	              ssl->buffers.serverDH_Priv.buffer,
	              ssl->buffers.serverDH_Priv.length,
	              input + *inOutIdx, clientPubSz);
	wc_FreeDhKey(&dhKey);

	*inOutIdx += clientPubSz;

	if (ret == 0)
	ret = MakeMasterSecret(ssl);
	}
	break;
#endif /* NO_DH */
#if !defined(NO_DH) && !defined(NO_PSK)
	case dhe_psk_kea:
	{
	byte* pms = ssl->arrays->preMasterSecret;
	word16 clientSz;
	DhKey  dhKey;

	/* Read in the PSK hint */
	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &clientSz);
	*inOutIdx += OPAQUE16_LEN;
	if (clientSz > MAX_PSK_ID_LEN)
	return CLIENT_ID_ERROR;

	if ((*inOutIdx - begin) + clientSz > size)
	return BUFFER_ERROR;

	XMEMCPY(ssl->arrays->client_identity,
	                       input + *inOutIdx, clientSz);
	*inOutIdx += clientSz;
	ssl->arrays->client_identity[min(clientSz, MAX_PSK_ID_LEN-1)] =
	                                                  0;

	/* Read in the DHE business */
	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &clientSz);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + clientSz > size)
	return BUFFER_ERROR;

	wc_InitDhKey(&dhKey);
	ret = wc_DhSetKey(&dhKey, ssl->buffers.serverDH_P.buffer,
	           ssl->buffers.serverDH_P.length,
	           ssl->buffers.serverDH_G.buffer,
	           ssl->buffers.serverDH_G.length);
	if (ret == 0)
	ret = wc_DhAgree(&dhKey, pms + OPAQUE16_LEN,
	              &ssl->arrays->preMasterSz,
	              ssl->buffers.serverDH_Priv.buffer,
	              ssl->buffers.serverDH_Priv.length,
	              input + *inOutIdx, clientSz);
	wc_FreeDhKey(&dhKey);

	*inOutIdx += clientSz;
	c16toa((word16)ssl->arrays->preMasterSz, pms);
	ssl->arrays->preMasterSz += OPAQUE16_LEN;
	pms += ssl->arrays->preMasterSz;

	/* Use the PSK hint to look up the PSK and add it to the
	* preMasterSecret here. */
	ssl->arrays->psk_keySz = ssl->options.server_psk_cb(ssl,
	ssl->arrays->client_identity, ssl->arrays->psk_key,
	MAX_PSK_KEY_LEN);

	if (ssl->arrays->psk_keySz == 0 ||
	           ssl->arrays->psk_keySz > MAX_PSK_KEY_LEN)
	return PSK_KEY_ERROR;

	c16toa((word16) ssl->arrays->psk_keySz, pms);
	pms += OPAQUE16_LEN;

	XMEMCPY(pms, ssl->arrays->psk_key, ssl->arrays->psk_keySz);
	ssl->arrays->preMasterSz +=
	              ssl->arrays->psk_keySz + OPAQUE16_LEN;
	if (ret == 0)
	ret = MakeMasterSecret(ssl);

	/* No further need for PSK */
	ForceZero(ssl->arrays->psk_key, ssl->arrays->psk_keySz);
	ssl->arrays->psk_keySz = 0;
	}
	break;
#endif /* !NO_DH && !NO_PSK */
	default:
	{
	WOLFSSL_MSG("Bad kea type");
	ret = BAD_KEA_TYPE_E;
	}
	break;
	}

	/* No further need for PMS */
	ForceZero(ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);
	ssl->arrays->preMasterSz = 0;

	if (ret == 0) {
	ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;
#ifndef NO_CERTS
	if (ssl->options.verifyPeer)
	ret = BuildCertHashes(ssl, &ssl->hsHashes->certHashes);
#endif
	}

	return ret;
	}

#if !defined(NO_RSA) || defined(HAVE_ECC)
static int _doCertificateVerify(WOLFSSL* ssl, byte* input, word32* inOutIdx, word32 size)
{
	word16      sz = 0;
	int         ret = VERIFY_CERT_ERROR;   /* start in error state */
	byte        hashAlgo = sha_mac;
	byte        sigAlgo = anonymous_sa_algo;
	word32      begin = *inOutIdx;

#ifdef WOLFSSL_CALLBACKS
	if (ssl->hsInfoOn)
	AddPacketName("CertificateVerify", &ssl->handShakeInfo);
	if (ssl->toInfoOn)
	AddLateName("CertificateVerify", &ssl->timeoutInfo);
#endif


	if (IsAtLeastTLSv1_2(ssl)) {
	if ((*inOutIdx - begin) + ENUM_LEN + ENUM_LEN > size)
	return BUFFER_ERROR;

	hashAlgo = input[(*inOutIdx)++];
	sigAlgo  = input[(*inOutIdx)++];
	}

	if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
	return BUFFER_ERROR;

	ato16(input + *inOutIdx, &sz);
	*inOutIdx += OPAQUE16_LEN;

	if ((*inOutIdx - begin) + sz > size || sz > ENCRYPT_LEN)
	return BUFFER_ERROR;

	/* RSA */
#ifndef NO_RSA
	if (ssl->peerRsaKey != NULL && ssl->peerRsaKeyPresent != 0) {
	byte* out       = NULL;
	int   outLen    = 0;
	byte  doUserRsa = 0;

#ifdef HAVE_PK_CALLBACKS
	if (ssl->ctx->RsaVerifyCb)
	doUserRsa = 1;
#endif /*HAVE_PK_CALLBACKS */

	WOLFSSL_MSG("Doing RSA peer cert verify");

	if (doUserRsa) {
#ifdef HAVE_PK_CALLBACKS
	outLen = ssl->ctx->RsaVerifyCb(ssl, input + *inOutIdx, sz,
	                &out,
	                ssl->buffers.peerRsaKey.buffer,
	                ssl->buffers.peerRsaKey.length,
	                ssl->RsaVerifyCtx);
#endif /*HAVE_PK_CALLBACKS */
	}
	else {
	outLen = wc_RsaSSL_VerifyInline(input + *inOutIdx, sz, &out,
	                                   ssl->peerRsaKey);
	}

	if (IsAtLeastTLSv1_2(ssl)) {
#ifdef WOLFSSL_SMALL_STACK
	byte*  encodedSig = NULL;
#else
	byte   encodedSig[MAX_ENCODED_SIG_SZ];
#endif
	word32 sigSz;
	byte*  digest = ssl->hsHashes->certHashes.sha;
	int    typeH = SHAh;
	int    digestSz = SHA_DIGEST_SIZE;

#ifdef WOLFSSL_SMALL_STACK
	encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL,
	                           DYNAMIC_TYPE_TMP_BUFFER);
	if (encodedSig == NULL)
	return MEMORY_E;
#endif

	if (sigAlgo != rsa_sa_algo) {
	WOLFSSL_MSG("Oops, peer sent RSA key but not in verify");
	}

	if (hashAlgo == sha256_mac) {
#ifndef NO_SHA256
	digest = ssl->hsHashes->certHashes.sha256;
	typeH    = SHA256h;
	digestSz = SHA256_DIGEST_SIZE;
#endif
	}
	else if (hashAlgo == sha384_mac) {
#ifdef WOLFSSL_SHA384
	digest = ssl->hsHashes->certHashes.sha384;
	typeH    = SHA384h;
	digestSz = SHA384_DIGEST_SIZE;
#endif
	}
	else if (hashAlgo == sha512_mac) {
#ifdef WOLFSSL_SHA512
	digest = ssl->hsHashes->certHashes.sha512;
	typeH    = SHA512h;
	digestSz = SHA512_DIGEST_SIZE;
#endif
	}

	sigSz = wc_EncodeSignature(encodedSig, digest, digestSz, typeH);

	if (outLen == (int)sigSz && out && XMEMCMP(out, encodedSig,
	               min(sigSz, MAX_ENCODED_SIG_SZ)) == 0)
	ret = 0; /* verified */

#ifdef WOLFSSL_SMALL_STACK
	XFREE(encodedSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
	}
	else {
	if (outLen == FINISHED_SZ && out && XMEMCMP(out,
	                &ssl->hsHashes->certHashes,
	                FINISHED_SZ) == 0) {
	ret = 0; /* verified */
	}
	}
	}
#endif
#ifdef HAVE_ECC
	if (ssl->peerEccDsaKeyPresent) {
	int verify =  0;
	int err    = -1;
	byte* digest = ssl->hsHashes->certHashes.sha;
	word32 digestSz = SHA_DIGEST_SIZE;
	byte doUserEcc = 0;

#ifdef HAVE_PK_CALLBACKS
	if (ssl->ctx->EccVerifyCb)
	doUserEcc = 1;
#endif

	WOLFSSL_MSG("Doing ECC peer cert verify");

	if (IsAtLeastTLSv1_2(ssl)) {
	if (sigAlgo != ecc_dsa_sa_algo) {
	WOLFSSL_MSG("Oops, peer sent ECC key but not in verify");
	}

	if (hashAlgo == sha256_mac) {
#ifndef NO_SHA256
	digest = ssl->hsHashes->certHashes.sha256;
	digestSz = SHA256_DIGEST_SIZE;
#endif
	}
	else if (hashAlgo == sha384_mac) {
#ifdef WOLFSSL_SHA384
	digest = ssl->hsHashes->certHashes.sha384;
	digestSz = SHA384_DIGEST_SIZE;
#endif
	}
	else if (hashAlgo == sha512_mac) {
#ifdef WOLFSSL_SHA512
	digest = ssl->hsHashes->certHashes.sha512;
	digestSz = SHA512_DIGEST_SIZE;
#endif
	}
	}

	if (doUserEcc) {
#ifdef HAVE_PK_CALLBACKS
	ret = ssl->ctx->EccVerifyCb(ssl, input + *inOutIdx, sz, digest,
	                digestSz,
	                ssl->buffers.peerEccDsaKey.buffer,
	                ssl->buffers.peerEccDsaKey.length,
	                &verify, ssl->EccVerifyCtx);
#endif
	}
	else {
	err = wc_ecc_verify_hash(input + *inOutIdx, sz, digest,
	             digestSz, &verify, ssl->peerEccDsaKey);
	}

	if (err == 0 && verify == 1)
	ret = 0; /* verified */
	}
#endif
	*inOutIdx += sz;

	if (ret == 0)
	ssl->options.havePeerVerify = 1;

	return ret;
	}
#endif /* !NO_RSA || HAVE_ECC */

static int DoHandShakeMsgType(WOLFSSL* ssl, byte* input, word32* inOutIdx, byte type, word32 size, word32 totalSz)
{
	int ret = 0;
	(void)totalSz;

	WOLFSSL_ENTER();

	/* make sure can read the message */
	if (*inOutIdx + size > totalSz)
		return INCOMPLETE_DATA;

	/* sanity check msg received */
	if ( (ret = SanityCheckMsgReceived(ssl, type)) != 0) {
		WOLFSSL_MSG("Sanity Check on handshake message type received failed");
		return ret;
	}

#ifdef WOLFSSL_CALLBACKS
	/* add name later, add on record and handshake header part back on */
	if (ssl->toInfoOn) {
		int add = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
		AddPacketInfo(0, &ssl->timeoutInfo, input + *inOutIdx - add, 	size + add, ssl->heap);
		AddLateRecordHeader(&ssl->curRL, &ssl->timeoutInfo);
	}
#endif

	if (ssl->options.handShakeState == HANDSHAKE_DONE && type != hello_request){
		WOLFSSL_MSG("HandShake message after handshake complete");
		SendAlert(ssl, alert_fatal, unexpected_message);
		return OUT_OF_ORDER_E;
	}

	if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->options.dtls == 0 &&
		ssl->options.serverState == NULL_STATE && type != server_hello) {
		WOLFSSL_MSG("First server message not server hello");
		SendAlert(ssl, alert_fatal, unexpected_message);
		return OUT_OF_ORDER_E;
	}

	if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->options.dtls &&
		type == server_hello_done && ssl->options.serverState < SERVER_HELLO_COMPLETE) {
		WOLFSSL_MSG("Server hello done received before server hello in DTLS");
		SendAlert(ssl, alert_fatal, unexpected_message);
		return OUT_OF_ORDER_E;
	}

	if (ssl->options.side == WOLFSSL_SERVER_END &&	ssl->options.clientState == NULL_STATE && type != HST_CLIENT_HELLO) {
		WOLFSSL_MSG("First client message not client hello");
		SendAlert(ssl, alert_fatal, unexpected_message);
		return OUT_OF_ORDER_E;
	}

	/* above checks handshake state */
	/* hello_request not hashed */
	if (type != hello_request) {
		ret = HashInput(ssl, input + *inOutIdx, size);
		if (ret != 0)
			return ret;
	}

	switch (type)
	{

		case hello_request:
			WOLFSSL_MSG("processing hello request");
			ret = _doHelloRequest(ssl, input, inOutIdx, size, totalSz);
			break;

#ifndef NO_WOLFSSL_CLIENT
		case hello_verify_request: /* only used in client */
			WOLFSSL_MSG("processing hello verify request");
			ret = _doHelloVerifyRequest(ssl, input,inOutIdx, size);
			break;

		case server_hello: /* only used in client */
			WOLFSSL_MSG("processing server hello");
			ret = _doServerHello(ssl, input, inOutIdx, size);
			break;

#ifndef NO_CERTS
		case certificate_request:
			WOLFSSL_MSG("processing certificate request");
			ret = _doCertificateRequest(ssl, input, inOutIdx, size);
			break;
#endif

		case server_key_exchange:
			WOLFSSL_MSG("processing server key exchange");
			ret = _doServerKeyExchange(ssl, input, inOutIdx, size);
			break;

#ifdef HAVE_SESSION_TICKET
		case session_ticket:
			WOLFSSL_MSG("processing session ticket");
			ret = _doSessionTicket(ssl, input, inOutIdx, size);
			break;
#endif /* HAVE_SESSION_TICKET */
#endif	/* NO_WOLFSSL_CLIENT */

#ifndef NO_CERTS
		case certificate:
			WOLFSSL_MSG("processing certificate");
			ret =  _doCertificate(ssl, input, inOutIdx, size);
			break;
#endif

		case server_hello_done:
			WOLFSSL_MSG("processing server hello done");
#ifdef WOLFSSL_CALLBACKS
			if (ssl->hsInfoOn)
				AddPacketName("ServerHelloDone", &ssl->handShakeInfo);
			if (ssl->toInfoOn)
				AddLateName("ServerHelloDone", &ssl->timeoutInfo);
#endif
			ssl->options.serverState = SERVER_HELLODONE_COMPLETE;
			if (ssl->keys.encryptionOn) {
				*inOutIdx += ssl->keys.padSz;
			}
			if (ssl->options.resuming) {
				WOLFSSL_MSG("Not resuming as thought");
				ssl->options.resuming = 0;
			}
			break;

		case finished:
			WOLFSSL_MSG("processing finished");
			ret = DoFinished(ssl, input, inOutIdx, size, totalSz, NO_SNIFF);
			break;

#ifndef NO_WOLFSSL_SERVER
		case HST_CLIENT_HELLO:
			WOLFSSL_MSG("processing client hello");
			ret = _doClientHello(ssl, input, inOutIdx, size);
			break;

		case client_key_exchange:
			WOLFSSL_MSG("processing client key exchange");
			ret = _doClientKeyExchange(ssl, input, inOutIdx, size);
			break;

#if !defined(NO_RSA) || defined(HAVE_ECC)
		case certificate_verify:
			WOLFSSL_MSG("processing certificate verify");
			ret = _doCertificateVerify(ssl, input, inOutIdx, size);
			break;
#endif /* !NO_RSA || HAVE_ECC */

#endif /* !NO_WOLFSSL_SERVER */

		default:
			WOLFSSL_MSG("Unknown handshake message type");
			ret = UNKNOWN_HANDSHAKE_TYPE;
			break;
	}

	WOLFSSL_LEAVE( ret);
	return ret;
}



static int _getHandShakeHeader(WOLFSSL* ssl, const byte* input, word32* inOutIdx,  byte *type, word32 *size, word32 totalSz)
{
	const byte *ptr = input + *inOutIdx;
	(void)ssl;

	*inOutIdx += HANDSHAKE_HEADER_SZ;
	if (*inOutIdx > totalSz)
		return BUFFER_E;

	*type = ptr[0];
	c24to32(&ptr[1], size);

	return 0;
}

int DoHandShakeMsg(WOLFSSL* ssl, byte* input, word32* inOutIdx, word32 totalSz)
{
	byte   type;
	word32 size;
	int    ret = 0;

	if (_getHandShakeHeader(ssl, input, inOutIdx, &type, &size, totalSz) != 0)
		return PARSE_ERROR;

	ret = DoHandShakeMsgType(ssl, input, inOutIdx, type, size, totalSz);

	WOLFSSL_LEAVE( ret);
	return ret;
}


