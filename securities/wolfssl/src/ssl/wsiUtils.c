
#include "cmnSsl.h"


#ifdef USE_WINDOWS_API

    word32 LowResTimer(void)
    {
        static int           init = 0;
        static LARGE_INTEGER freq;
        LARGE_INTEGER        count;

        if (!init) {
            QueryPerformanceFrequency(&freq);
            init = 1;
        }

        QueryPerformanceCounter(&count);

        return (word32)(count.QuadPart / freq.QuadPart);
    }

#elif defined(HAVE_RTP_SYS)

    #include "rtptime.h"

    word32 LowResTimer(void)
    {
        return (word32)rtp_get_system_sec();
    }


#elif defined(MICRIUM)

    word32 LowResTimer(void)
    {
        NET_SECURE_OS_TICK  clk;

        #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
            clk = NetSecure_OS_TimeGet();
        #endif
        return (word32)clk;
    }


#elif defined(MICROCHIP_TCPIP_V5)

    word32 LowResTimer(void)
    {
        return (word32) TickGet();
    }


#elif defined(MICROCHIP_TCPIP)

    #if defined(MICROCHIP_MPLAB_HARMONY)

        #include <system/tmr/sys_tmr.h>

        word32 LowResTimer(void)
        {
            return (word32) SYS_TMR_TickCountGet();
        }

    #else

        word32 LowResTimer(void)
        {
            return (word32) SYS_TICK_Get();
        }

    #endif

#elif defined(FREESCALE_MQX)

    word32 LowResTimer(void)
    {
        TIME_STRUCT mqxTime;

        _time_get_elapsed(&mqxTime);

        return (word32) mqxTime.SECONDS;
    }

#elif defined(WOLFSSL_TIRTOS)

    word32 LowResTimer(void)
    {
        return (word32) Seconds_get();
    }

#elif defined(USER_TICKS)
#if 0
    word32 LowResTimer(void)
    {
        /*
        write your own clock tick function if don't want time(0)
        needs second accuracy but doesn't have to correlated to EPOCH
        */
    }
#endif

#elif defined(TIME_OVERRIDES)

    /* use same asn time overrides unless user wants tick override above */

    #ifndef HAVE_TIME_T_TYPE
        typedef long time_t;
    #endif
    extern time_t XTIME(time_t * timer);

    word32 LowResTimer(void)
    {
        return (word32) XTIME(0);
    }

#else /* !USE_WINDOWS_API && !HAVE_RTP_SYS && !MICRIUM && !USER_TICKS */

    #include <time.h>

    word32 LowResTimer(void)
    {
        return (word32)time(0);
    }


#endif /* USE_WINDOWS_API */


/* add output to md5 and sha handshake hashes, exclude record header */
int HashOutput(WOLFSSL* ssl, const byte* output, int sz, int ivSz)
{
    const byte* adj = output + RECORD_HEADER_SZ + ivSz;
    sz -= RECORD_HEADER_SZ;

#ifdef HAVE_FUZZER
    if (ssl->fuzzerCb)
        ssl->fuzzerCb(ssl, output, sz, FUZZ_HASH, ssl->fuzzerCtx);
#endif
#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        adj += DTLS_RECORD_EXTRA;
        sz  -= DTLS_RECORD_EXTRA;
    }
#endif
#ifndef NO_OLD_TLS
#ifndef NO_SHA
    wc_ShaUpdate(&ssl->hsHashes->hashSha, adj, sz);
#endif
#ifndef NO_MD5
    wc_Md5Update(&ssl->hsHashes->hashMd5, adj, sz);
#endif
#endif

    if (IsAtLeastTLSv1_2(ssl)) {
        int ret;

#ifndef NO_SHA256
        ret = wc_Sha256Update(&ssl->hsHashes->hashSha256, adj, sz);
        if (ret != 0)
            return ret;
#endif
#ifdef WOLFSSL_SHA384
        ret = wc_Sha384Update(&ssl->hsHashes->hashSha384, adj, sz);
        if (ret != 0)
            return ret;
#endif
#ifdef WOLFSSL_SHA512
        ret = wc_Sha512Update(&ssl->hsHashes->hashSha512, adj, sz);
        if (ret != 0)
            return ret;
#endif
    }

    return 0;
}


/* add input to md5 and sha handshake hashes, include handshake header */
int HashInput(WOLFSSL* ssl, const byte* input, int sz)
{
    const byte* adj = input - HANDSHAKE_HEADER_SZ;
    sz += HANDSHAKE_HEADER_SZ;

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        adj -= DTLS_HANDSHAKE_EXTRA;
        sz  += DTLS_HANDSHAKE_EXTRA;
    }
#endif

#ifndef NO_OLD_TLS
#ifndef NO_SHA
    wc_ShaUpdate(&ssl->hsHashes->hashSha, adj, sz);
#endif
#ifndef NO_MD5
    wc_Md5Update(&ssl->hsHashes->hashMd5, adj, sz);
#endif
#endif

    if (IsAtLeastTLSv1_2(ssl)) {
        int ret;

#ifndef NO_SHA256
        ret = wc_Sha256Update(&ssl->hsHashes->hashSha256, adj, sz);
        if (ret != 0)
            return ret;
#endif
#ifdef WOLFSSL_SHA384
        ret = wc_Sha384Update(&ssl->hsHashes->hashSha384, adj, sz);
        if (ret != 0)
            return ret;
#endif
#ifdef WOLFSSL_SHA512
        ret = wc_Sha512Update(&ssl->hsHashes->hashSha512, adj, sz);
        if (ret != 0)
            return ret;
#endif
    }

    return 0;
}



int Encrypt(WOLFSSL* ssl, byte* out, const byte* input, word16 sz)
{
	int ret = 0;

	(void)out;
	(void)input;
	(void)sz;

	if (ssl->encrypt.setup == 0) {
		WOLFSSL_MSG("Encrypt ciphers not setup");
		return ENCRYPT_ERROR;
	}

#ifdef HAVE_FUZZER
	if (ssl->fuzzerCb)
		ssl->fuzzerCb(ssl, input, sz, FUZZ_ENCRYPT, ssl->fuzzerCtx);
#endif

	switch (ssl->specs.bulk_cipher_algorithm)
	{
#ifdef BUILD_ARC4
		case wolfssl_rc4:
			wc_Arc4Process(ssl->encrypt.arc4, out, input, sz);
			break;
#endif

#ifdef BUILD_DES3
		case wolfssl_triple_des:
			ret = wc_Des3_CbcEncrypt(ssl->encrypt.des3, out, input, sz);
			break;
#endif

#ifdef BUILD_AES
		case wolfssl_aes:
			ret = wc_AesCbcEncrypt(ssl->encrypt.aes, out, input, sz);
			break;
#endif

#ifdef BUILD_AESGCM
		case wolfssl_aes_gcm:
		{
			byte additional[AEAD_AUTH_DATA_SZ];
			byte nonce[AEAD_NONCE_SZ];
			const byte* additionalSrc = input - 5;

			XMEMSET(additional, 0, AEAD_AUTH_DATA_SZ);

			/* sequence number field is 64-bits, we only use 32-bits */
			c32toa(GetSEQIncrement(ssl, 0),  additional + AEAD_SEQ_OFFSET);

			/* Store the type, version. Unfortunately, they are in
			* the input buffer ahead of the plaintext. */
#ifdef WOLFSSL_DTLS
			if (ssl->options.dtls) {
				c16toa(ssl->keys.dtls_epoch, additional);
				additionalSrc -= DTLS_HANDSHAKE_EXTRA;
			}
#endif
			XMEMCPY(additional + AEAD_TYPE_OFFSET, additionalSrc, 3);

			/* Store the length of the plain text minus the explicit
			* IV length minus the authentication tag size. */
			c16toa(sz - AEAD_EXP_IV_SZ - ssl->specs.aead_mac_size, additional + AEAD_LEN_OFFSET);
			XMEMCPY(nonce,	 ssl->keys.aead_enc_imp_IV, AEAD_IMP_IV_SZ);
			XMEMCPY(nonce + AEAD_IMP_IV_SZ,  ssl->keys.aead_exp_IV, AEAD_EXP_IV_SZ);
			ret = wc_AesGcmEncrypt(ssl->encrypt.aes,	 out + AEAD_EXP_IV_SZ, input + AEAD_EXP_IV_SZ,
				sz - AEAD_EXP_IV_SZ - ssl->specs.aead_mac_size,  nonce, AEAD_NONCE_SZ,
				out + sz - ssl->specs.aead_mac_size,  ssl->specs.aead_mac_size, additional, AEAD_AUTH_DATA_SZ);
			if (ret == 0)
				AeadIncrementExpIV(ssl);
			ForceZero(nonce, AEAD_NONCE_SZ);
		}
		break;
#endif

#ifdef HAVE_AESCCM
		case wolfssl_aes_ccm:
		{
			byte additional[AEAD_AUTH_DATA_SZ];
			byte nonce[AEAD_NONCE_SZ];
			const byte* additionalSrc = input - 5;

			XMEMSET(additional, 0, AEAD_AUTH_DATA_SZ);

			/* sequence number field is 64-bits, we only use 32-bits */
			c32toa(GetSEQIncrement(ssl, 0), additional + AEAD_SEQ_OFFSET);

			/* Store the type, version. Unfortunately, they are in
			* the input buffer ahead of the plaintext. */
#ifdef WOLFSSL_DTLS
			if (ssl->options.dtls) {
				c16toa(ssl->keys.dtls_epoch, additional);
				additionalSrc -= DTLS_HANDSHAKE_EXTRA;
			}
#endif
			XMEMCPY(additional + AEAD_TYPE_OFFSET, additionalSrc, 3);

			/* Store the length of the plain text minus the explicit
			* IV length minus the authentication tag size. */
			c16toa(sz - AEAD_EXP_IV_SZ - ssl->specs.aead_mac_size, additional + AEAD_LEN_OFFSET);
			XMEMCPY(nonce, ssl->keys.aead_enc_imp_IV, AEAD_IMP_IV_SZ);
			XMEMCPY(nonce + AEAD_IMP_IV_SZ,  ssl->keys.aead_exp_IV, AEAD_EXP_IV_SZ);
			wc_AesCcmEncrypt(ssl->encrypt.aes, out + AEAD_EXP_IV_SZ, input + AEAD_EXP_IV_SZ,
				sz - AEAD_EXP_IV_SZ - ssl->specs.aead_mac_size, nonce, AEAD_NONCE_SZ,
				out + sz - ssl->specs.aead_mac_size, ssl->specs.aead_mac_size, additional, AEAD_AUTH_DATA_SZ);
			AeadIncrementExpIV(ssl);
			ForceZero(nonce, AEAD_NONCE_SZ);
		}
		break;
#endif

#ifdef HAVE_CAMELLIA
		case wolfssl_camellia:
			wc_CamelliaCbcEncrypt(ssl->encrypt.cam, out, input, sz);
			break;
#endif

#ifdef HAVE_HC128
		case wolfssl_hc128:
			ret = wc_Hc128_Process(ssl->encrypt.hc128, out, input, sz);
			break;
#endif

#ifdef BUILD_RABBIT
		case wolfssl_rabbit:
			ret = wc_RabbitProcess(ssl->encrypt.rabbit, out, input, sz);
			break;
#endif

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
		case wolfssl_chacha:
			ret = ChachaAEADEncrypt(ssl, out, input, sz);
			break;
#endif

#ifdef HAVE_NULL_CIPHER
		case wolfssl_cipher_null:
			if (input != out) {
			XMEMMOVE(out, input, sz);
			}
			break;
#endif

		default:
			WOLFSSL_MSG("wolfSSL Encrypt programming error");
			ret = ENCRYPT_ERROR;
	}

	return ret;
}



int Decrypt(WOLFSSL* ssl, byte* plain, const byte* input, word16 sz)
{
    int ret = 0;

    (void)plain;
    (void)input;
    (void)sz;

    if (ssl->decrypt.setup == 0) {
        WOLFSSL_MSG("Decrypt ciphers not setup");
        return DECRYPT_ERROR;
    }

    switch (ssl->specs.bulk_cipher_algorithm) {
        #ifdef BUILD_ARC4
            case wolfssl_rc4:
                wc_Arc4Process(ssl->decrypt.arc4, plain, input, sz);
                break;
        #endif

        #ifdef BUILD_DES3
            case wolfssl_triple_des:
                ret = wc_Des3_CbcDecrypt(ssl->decrypt.des3, plain, input, sz);
                break;
        #endif

        #ifdef BUILD_AES
            case wolfssl_aes:
                ret = wc_AesCbcDecrypt(ssl->decrypt.aes, plain, input, sz);
                break;
        #endif

        #ifdef BUILD_AESGCM
            case wolfssl_aes_gcm:
            {
                byte additional[AEAD_AUTH_DATA_SZ];
                byte nonce[AEAD_NONCE_SZ];

                XMEMSET(additional, 0, AEAD_AUTH_DATA_SZ);

                /* sequence number field is 64-bits, we only use 32-bits */
                c32toa(GetSEQIncrement(ssl, 1), additional + AEAD_SEQ_OFFSET);

                #ifdef WOLFSSL_DTLS
                    if (ssl->options.dtls)
                        c16toa(ssl->keys.dtls_state.curEpoch, additional);
                #endif

                additional[AEAD_TYPE_OFFSET] = ssl->curRL.type;
                additional[AEAD_VMAJ_OFFSET] = ssl->curRL.pvMajor;
                additional[AEAD_VMIN_OFFSET] = ssl->curRL.pvMinor;

                c16toa(sz - AEAD_EXP_IV_SZ - ssl->specs.aead_mac_size,
                                        additional + AEAD_LEN_OFFSET);
                XMEMCPY(nonce, ssl->keys.aead_dec_imp_IV, AEAD_IMP_IV_SZ);
                XMEMCPY(nonce + AEAD_IMP_IV_SZ, input, AEAD_EXP_IV_SZ);
                if (wc_AesGcmDecrypt(ssl->decrypt.aes,
                            plain + AEAD_EXP_IV_SZ,
                            input + AEAD_EXP_IV_SZ,
                                sz - AEAD_EXP_IV_SZ - ssl->specs.aead_mac_size,
                            nonce, AEAD_NONCE_SZ,
                            input + sz - ssl->specs.aead_mac_size,
                            ssl->specs.aead_mac_size,
                            additional, AEAD_AUTH_DATA_SZ) < 0) {
                    SendAlert(ssl, alert_fatal, bad_record_mac);
                    ret = VERIFY_MAC_ERROR;
                }
                ForceZero(nonce, AEAD_NONCE_SZ);
            }
            break;
        #endif

        #ifdef HAVE_AESCCM
            case wolfssl_aes_ccm:
            {
                byte additional[AEAD_AUTH_DATA_SZ];
                byte nonce[AEAD_NONCE_SZ];

                XMEMSET(additional, 0, AEAD_AUTH_DATA_SZ);

                /* sequence number field is 64-bits, we only use 32-bits */
                c32toa(GetSEQIncrement(ssl, 1), additional + AEAD_SEQ_OFFSET);

                #ifdef WOLFSSL_DTLS
                    if (ssl->options.dtls)
                        c16toa(ssl->keys.dtls_state.curEpoch, additional);
                #endif

                additional[AEAD_TYPE_OFFSET] = ssl->curRL.type;
                additional[AEAD_VMAJ_OFFSET] = ssl->curRL.pvMajor;
                additional[AEAD_VMIN_OFFSET] = ssl->curRL.pvMinor;

                c16toa(sz - AEAD_EXP_IV_SZ - ssl->specs.aead_mac_size,
                                        additional + AEAD_LEN_OFFSET);
                XMEMCPY(nonce, ssl->keys.aead_dec_imp_IV, AEAD_IMP_IV_SZ);
                XMEMCPY(nonce + AEAD_IMP_IV_SZ, input, AEAD_EXP_IV_SZ);
                if (wc_AesCcmDecrypt(ssl->decrypt.aes,
                            plain + AEAD_EXP_IV_SZ,
                            input + AEAD_EXP_IV_SZ,
                                sz - AEAD_EXP_IV_SZ - ssl->specs.aead_mac_size,
                            nonce, AEAD_NONCE_SZ,
                            input + sz - ssl->specs.aead_mac_size,
                            ssl->specs.aead_mac_size,
                            additional, AEAD_AUTH_DATA_SZ) < 0) {
                    SendAlert(ssl, alert_fatal, bad_record_mac);
                    ret = VERIFY_MAC_ERROR;
                }
                ForceZero(nonce, AEAD_NONCE_SZ);
            }
            break;
        #endif

        #ifdef HAVE_CAMELLIA
            case wolfssl_camellia:
                wc_CamelliaCbcDecrypt(ssl->decrypt.cam, plain, input, sz);
                break;
        #endif

        #ifdef HAVE_HC128
            case wolfssl_hc128:
                ret = wc_Hc128_Process(ssl->decrypt.hc128, plain, input, sz);
                break;
        #endif

        #ifdef BUILD_RABBIT
            case wolfssl_rabbit:
                ret = wc_RabbitProcess(ssl->decrypt.rabbit, plain, input, sz);
                break;
        #endif

        #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            case wolfssl_chacha:
                ret = ChachaAEADDecrypt(ssl, plain, input, sz);
                break;
        #endif

        #ifdef HAVE_NULL_CIPHER
            case wolfssl_cipher_null:
                if (input != plain) {
                    XMEMMOVE(plain, input, sz);
                }
                break;
        #endif

            default:
                WOLFSSL_MSG("wolfSSL Decrypt programming error");
                ret = DECRYPT_ERROR;
    }

    return ret;
}


/* Switch dynamic output buffer back to static, buffer is assumed clear */
void ShrinkOutputBuffer(WOLFSSL* ssl)
{
	WOLFSSL_MSG("Shrinking output buffer\n");
	XFREE(ssl->buffers.outputBuffer.buffer - ssl->buffers.outputBuffer.offset, ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
	ssl->buffers.outputBuffer.buffer = ssl->buffers.outputBuffer.staticBuffer;
	ssl->buffers.outputBuffer.bufferSize  = STATIC_BUFFER_LEN;
	ssl->buffers.outputBuffer.dynamicFlag = 0;
	ssl->buffers.outputBuffer.offset      = 0;
}


/* Switch dynamic input buffer back to static, keep any remaining input */
/* forced free means cleaning up */
void ShrinkInputBuffer(WOLFSSL* ssl, int forcedFree)
{
	int usedLength = ssl->buffers.inputBuffer.length - ssl->buffers.inputBuffer.idx;
	if (!forcedFree && usedLength > STATIC_BUFFER_LEN)
		return;

	WOLFSSL_MSG("Shrinking input buffer\n");

	if (!forcedFree && usedLength)
		XMEMCPY(ssl->buffers.inputBuffer.staticBuffer, ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
			usedLength);

	XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
	ssl->buffers.inputBuffer.buffer = ssl->buffers.inputBuffer.staticBuffer;
	ssl->buffers.inputBuffer.bufferSize  = STATIC_BUFFER_LEN;
	ssl->buffers.inputBuffer.dynamicFlag = 0;
	ssl->buffers.inputBuffer.offset      = 0;
	ssl->buffers.inputBuffer.idx = 0;
	ssl->buffers.inputBuffer.length = usedLength;
}


/* Grow the input buffer, should only be to read cert or big app data */
int GrowInputBuffer(WOLFSSL* ssl, int size, int usedLength)
{
    byte* tmp;
    byte  hdrSz = DTLS_RECORD_HEADER_SZ;
    byte  align = ssl->options.dtls ? WOLFSSL_GENERAL_ALIGNMENT : 0;
    /* the encrypted data will be offset from the front of the buffer by
       the dtls record header, if the user wants encrypted alignment they need
       to define their alignment requirement. in tls we read record header
       to get size of record and put actual data back at front, so don't need */

    if (align) {
       while (align < hdrSz)
           align *= 2;
    }
    tmp = (byte*) XMALLOC(size + usedLength + align, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
    WOLFSSL_MSG("growing input buffer\n");

    if (!tmp) return MEMORY_E;
    if (align)
        tmp += align - hdrSz;

    if (usedLength)
        XMEMCPY(tmp, ssl->buffers.inputBuffer.buffer +
                    ssl->buffers.inputBuffer.idx, usedLength);

    if (ssl->buffers.inputBuffer.dynamicFlag)
        XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset,
              ssl->heap,DYNAMIC_TYPE_IN_BUFFER);

    ssl->buffers.inputBuffer.dynamicFlag = 1;
    if (align)
        ssl->buffers.inputBuffer.offset = align - hdrSz;
    else
        ssl->buffers.inputBuffer.offset = 0;
    ssl->buffers.inputBuffer.buffer = tmp;
    ssl->buffers.inputBuffer.bufferSize = size + usedLength;
    ssl->buffers.inputBuffer.idx    = 0;
    ssl->buffers.inputBuffer.length = usedLength;

    return 0;
}



/* Grow the output buffer */
static INLINE int _growOutputBuffer(WOLFSSL* ssl, int size)
{
	byte* tmp;
	byte  hdrSz = ssl->options.dtls ? DTLS_RECORD_HEADER_SZ : RECORD_HEADER_SZ;
	byte  align = WOLFSSL_GENERAL_ALIGNMENT;
	/* the encrypted data will be offset from the front of the buffer by
	the header, if the user wants encrypted alignment they need
	to define their alignment requirement */

	if (align) {
		while (align < hdrSz)
			align *= 2;
	}

	tmp = (byte*) XMALLOC(size + ssl->buffers.outputBuffer.length + align, ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
	WOLFSSL_MSG("growing output buffer\n");

	if (!tmp)
		return MEMORY_E;
	if (align)
		tmp += align - hdrSz;

	if (ssl->buffers.outputBuffer.length)
		XMEMCPY(tmp, ssl->buffers.outputBuffer.buffer, ssl->buffers.outputBuffer.length);

	if (ssl->buffers.outputBuffer.dynamicFlag)
		XFREE(ssl->buffers.outputBuffer.buffer -ssl->buffers.outputBuffer.offset, ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
	ssl->buffers.outputBuffer.dynamicFlag = 1;
	if (align)
		ssl->buffers.outputBuffer.offset = align - hdrSz;
	else
		ssl->buffers.outputBuffer.offset = 0;
	
	ssl->buffers.outputBuffer.buffer = tmp;
	ssl->buffers.outputBuffer.bufferSize = size + ssl->buffers.outputBuffer.length;
	return 0;
}

/* check available size into output buffer, make room if needed */
int CheckAvailableSize(WOLFSSL *ssl, int size)
{
	if (size < 0) {
		WOLFSSL_MSG("CheckAvailableSize() called with negative number");
		return BAD_FUNC_ARG;
	}

	if (ssl->buffers.outputBuffer.bufferSize - ssl->buffers.outputBuffer.length  < (word32)size) {
		if (_growOutputBuffer(ssl, size) < 0)
			return MEMORY_E;
	}

	return 0;
}



/* Does this cipher suite (first, second) have the requirement
an ephemeral key exchange will still require the key for signing
the key exchange so ECHDE_RSA requires an rsa key thus rsa_kea */
/* 3 cipher system can be used : Chacha, ECC or others(RSA) */
int CipherRequires(byte first, byte second, int requirement)
{
	if (first == CHACHA_BYTE)
	{
		switch (second)
		{
			case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 :
			if (requirement == REQUIRES_ECC_DSA)
			return 1;
			break;

			case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
			if (requirement == REQUIRES_RSA)
			return 1;
			if (requirement == REQUIRES_DHE)
			return 1;
			break;
			}
	}

	/* ECC extensions */
	if (first == ECC_BYTE)
	{
		switch (second)
		{
#ifndef NO_RSA
			case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			if (requirement == REQUIRES_RSA_SIG)
			return 1;
			break;

#ifndef NO_DES3
			case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			if (requirement == REQUIRES_RSA_SIG)
			return 1;
			break;
#endif

#ifndef NO_RC4
			case TLS_ECDHE_RSA_WITH_RC4_128_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_ECDH_RSA_WITH_RC4_128_SHA :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			if (requirement == REQUIRES_RSA_SIG)
			return 1;
			break;
#endif
#endif /* NO_RSA */

#ifndef NO_DES3
			case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA :
			if (requirement == REQUIRES_ECC_DSA)
			return 1;
			break;

			case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			break;
#endif
#ifndef NO_RC4
			case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA :
			if (requirement == REQUIRES_ECC_DSA)
			return 1;
			break;

			case TLS_ECDH_ECDSA_WITH_RC4_128_SHA :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			break;
#endif
#ifndef NO_RSA
			case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			if (requirement == REQUIRES_RSA_SIG)
			return 1;
			break;
#endif

			case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA :
			if (requirement == REQUIRES_ECC_DSA)
			return 1;
			break;

			case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			break;

			case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA :
			if (requirement == REQUIRES_ECC_DSA)
			return 1;
			break;

			case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			break;

			case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 :
			if (requirement == REQUIRES_ECC_DSA)
			return 1;
			break;

			case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 :
			if (requirement == REQUIRES_ECC_DSA)
			return 1;
			break;

			case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			break;

			case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			break;

#ifndef NO_RSA
			case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			if (requirement == REQUIRES_RSA_SIG)
			return 1;
			break;

			case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 :
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			if (requirement == REQUIRES_RSA_SIG)
			return 1;
			break;

			case TLS_RSA_WITH_AES_128_CCM_8 :
			case TLS_RSA_WITH_AES_256_CCM_8 :
			if (requirement == REQUIRES_RSA)
			return 1;
			if (requirement == REQUIRES_RSA_SIG)
			return 1;
			break;

			case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 :
			case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 :
			if (requirement == REQUIRES_RSA)
			return 1;
			if (requirement == REQUIRES_RSA_SIG)
			return 1;
			break;

			case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 :
			case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 :
			if (requirement == REQUIRES_RSA_SIG)
			return 1;
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			break;
#endif

			case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 :
			case TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 :
			if (requirement == REQUIRES_ECC_DSA)
			return 1;
			break;

			case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 :
			case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 :
			if (requirement == REQUIRES_ECC_DSA)
			return 1;
			break;

			case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 :
			case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 :
			if (requirement == REQUIRES_ECC_DSA)
			return 1;
			if (requirement == REQUIRES_ECC_STATIC)
			return 1;
			break;

			case TLS_PSK_WITH_AES_128_CCM:
			case TLS_PSK_WITH_AES_256_CCM:
			case TLS_PSK_WITH_AES_128_CCM_8:
			case TLS_PSK_WITH_AES_256_CCM_8:
			if (requirement == REQUIRES_PSK)
			return 1;
			break;

			case TLS_DHE_PSK_WITH_AES_128_CCM:
			case TLS_DHE_PSK_WITH_AES_256_CCM:
			if (requirement == REQUIRES_PSK)
			return 1;
			if (requirement == REQUIRES_DHE)
			return 1;
			break;

			default:
			WOLFSSL_MSG("Unsupported cipher suite, CipherRequires ECC");
			return 0;
			}   /* switch */
	}   /* if     */
	
	if (first != ECC_BYTE)
	{   /* normal suites */
		switch (second)
		{

#ifndef NO_RSA
			case SSL_RSA_WITH_RC4_128_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_NTRU_RSA_WITH_RC4_128_SHA :
			if (requirement == REQUIRES_NTRU)
			return 1;
			break;

			case SSL_RSA_WITH_RC4_128_MD5 :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case SSL_RSA_WITH_3DES_EDE_CBC_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA :
			if (requirement == REQUIRES_NTRU)
			return 1;
			break;

			case TLS_RSA_WITH_AES_128_CBC_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_RSA_WITH_AES_128_CBC_SHA256 :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_NTRU_RSA_WITH_AES_128_CBC_SHA :
			if (requirement == REQUIRES_NTRU)
			return 1;
			break;

			case TLS_RSA_WITH_AES_256_CBC_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_RSA_WITH_AES_256_CBC_SHA256 :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_RSA_WITH_NULL_SHA :
			case TLS_RSA_WITH_NULL_SHA256 :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_NTRU_RSA_WITH_AES_256_CBC_SHA :
			if (requirement == REQUIRES_NTRU)
			return 1;
			break;
#endif

			case TLS_PSK_WITH_AES_128_GCM_SHA256 :
			case TLS_PSK_WITH_AES_256_GCM_SHA384 :
			case TLS_PSK_WITH_AES_128_CBC_SHA256 :
			case TLS_PSK_WITH_AES_256_CBC_SHA384 :
			case TLS_PSK_WITH_AES_128_CBC_SHA :
			case TLS_PSK_WITH_AES_256_CBC_SHA :
			case TLS_PSK_WITH_NULL_SHA384 :
			case TLS_PSK_WITH_NULL_SHA256 :
			case TLS_PSK_WITH_NULL_SHA :
			if (requirement == REQUIRES_PSK)
			return 1;
			break;

			case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 :
			case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 :
			case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 :
			case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 :
			case TLS_DHE_PSK_WITH_NULL_SHA384 :
			case TLS_DHE_PSK_WITH_NULL_SHA256 :
			if (requirement == REQUIRES_DHE)
			return 1;
			if (requirement == REQUIRES_PSK)
			return 1;
			break;

#ifndef NO_RSA
			case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 :
			if (requirement == REQUIRES_RSA)
			return 1;
			if (requirement == REQUIRES_DHE)
			return 1;
			break;

			case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 :
			if (requirement == REQUIRES_RSA)
			return 1;
			if (requirement == REQUIRES_DHE)
			return 1;
			break;

			case TLS_DHE_RSA_WITH_AES_128_CBC_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			if (requirement == REQUIRES_DHE)
			return 1;
			break;

			case TLS_DHE_RSA_WITH_AES_256_CBC_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			if (requirement == REQUIRES_DHE)
			return 1;
			break;

			case TLS_RSA_WITH_HC_128_MD5 :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_RSA_WITH_HC_128_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_RSA_WITH_HC_128_B2B256:
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_RSA_WITH_AES_128_CBC_B2B256:
			case TLS_RSA_WITH_AES_256_CBC_B2B256:
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_RSA_WITH_RABBIT_SHA :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_RSA_WITH_AES_128_GCM_SHA256 :
			case TLS_RSA_WITH_AES_256_GCM_SHA384 :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 :
			case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 :
			if (requirement == REQUIRES_RSA)
			return 1;
			if (requirement == REQUIRES_DHE)
			return 1;
			break;

			case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA :
			case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA :
			case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 :
			case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 :
			if (requirement == REQUIRES_RSA)
			return 1;
			break;

			case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA :
			case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA :
			case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 :
			case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 :
			if (requirement == REQUIRES_RSA)
			return 1;
			if (requirement == REQUIRES_RSA_SIG)
			return 1;
			if (requirement == REQUIRES_DHE)
			return 1;
			break;
#endif
#ifdef HAVE_ANON
			case TLS_DH_anon_WITH_AES_128_CBC_SHA :
			if (requirement == REQUIRES_DHE)
			return 1;
			break;
#endif

			default:
			WOLFSSL_MSG("Unsupported cipher suite, CipherRequires");
			return 0;
			}  /* switch */
	}  /* if ECC / Normal suites else */

	return 0;
}

