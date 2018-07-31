
#include "cmnSsl.h"

#ifndef NO_OLD_TLS
/* fill with MD5 pad size since biggest required */
static const byte PAD1[PAD_MD5] =
                              { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
                              };
static const byte PAD2[PAD_MD5] =
                              { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
                              };

/* calculate MD5 hash for finished */
#ifdef WOLFSSL_TI_HASH
#include <wolfssl/wolfcrypt/hash.h>
#endif

static void _buildMD5(WOLFSSL* ssl, Hashes* hashes, const byte* sender)
{
	byte md5_result[MD5_DIGEST_SIZE];

#ifdef WOLFSSL_SMALL_STACK
	Md5* md5   = (Md5*)XMALLOC(sizeof(Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	Md5* md5_2 = (Md5*)XMALLOC(sizeof(Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
	Md5 md5[1];
	Md5 md5_2[1];
#endif

	/* make md5 inner */
	md5[0] = ssl->hsHashes->hashMd5 ; /* Save current position */

	wc_Md5Update(&ssl->hsHashes->hashMd5, sender, SIZEOF_SENDER);
	wc_Md5Update(&ssl->hsHashes->hashMd5, ssl->arrays->masterSecret,SECRET_LEN);
	wc_Md5Update(&ssl->hsHashes->hashMd5, PAD1, PAD_MD5);
	wc_Md5GetHash(&ssl->hsHashes->hashMd5, md5_result);
	wc_Md5RestorePos(&ssl->hsHashes->hashMd5, md5) ; /* Restore current position */

	/* make md5 outer */
	wc_InitMd5(md5_2) ;
	wc_Md5Update(md5_2, ssl->arrays->masterSecret,SECRET_LEN);
	wc_Md5Update(md5_2, PAD2, PAD_MD5);
	wc_Md5Update(md5_2, md5_result, MD5_DIGEST_SIZE);
	wc_Md5Final(md5_2, hashes->md5);

#ifdef WOLFSSL_SMALL_STACK
	XFREE(md5, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(md5_2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

}


/* calculate SHA hash for finished */
static void _buildSHA(WOLFSSL* ssl, Hashes* hashes, const byte* sender)
{
	byte sha_result[SHA_DIGEST_SIZE];

#ifdef WOLFSSL_SMALL_STACK
	Sha* sha = (Sha*)XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	Sha* sha2 = (Sha*)XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
	Sha sha[1];
	Sha sha2[1] ;
#endif
	/* make sha inner */
	sha[0] = ssl->hsHashes->hashSha ; /* Save current position */

	wc_ShaUpdate(&ssl->hsHashes->hashSha, sender, SIZEOF_SENDER);
	wc_ShaUpdate(&ssl->hsHashes->hashSha, ssl->arrays->masterSecret,SECRET_LEN);
	wc_ShaUpdate(&ssl->hsHashes->hashSha, PAD1, PAD_SHA);
	wc_ShaGetHash(&ssl->hsHashes->hashSha, sha_result);
	wc_ShaRestorePos(&ssl->hsHashes->hashSha, sha) ; /* Restore current position */

	/* make sha outer */
	wc_InitSha(sha2) ;
	wc_ShaUpdate(sha2, ssl->arrays->masterSecret,SECRET_LEN);
	wc_ShaUpdate(sha2, PAD2, PAD_SHA);
	wc_ShaUpdate(sha2, sha_result, SHA_DIGEST_SIZE);
	wc_ShaFinal(sha2, hashes->sha);

#ifdef WOLFSSL_SMALL_STACK
	XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(sha2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

}
#endif

/* Finished doesn't support SHA512, not SHA512 cipher suites yet */
int BuildFinished(WOLFSSL* ssl, Hashes* hashes, const byte* sender)
{
	int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
#ifdef WOLFSSL_SHA384
	Sha384* sha384 = (Sha384*)XMALLOC(sizeof(Sha384), NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#else
#ifdef WOLFSSL_SHA384
	Sha384 sha384[1];
#endif
#endif

#ifdef WOLFSSL_SMALL_STACK
	if (ssl == NULL
#ifdef WOLFSSL_SHA384
		|| sha384 == NULL
#endif
	) {
#ifdef WOLFSSL_SHA384
		XFREE(sha384, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
		return MEMORY_E;
	}
#endif

	/* store current states, building requires get_digest which resets state */
#ifdef WOLFSSL_SHA384
	sha384[0] = ssl->hsHashes->hashSha384;
#endif

#ifndef NO_TLS
	if (ssl->options.tls) {
		ret = BuildTlsFinished(ssl, hashes, sender);
	}
#endif
#ifndef NO_OLD_TLS
	if (!ssl->options.tls) {
		_buildMD5(ssl, hashes, sender);
		_buildSHA(ssl, hashes, sender);
	}
#endif

	/* restore */
	if (IsAtLeastTLSv1_2(ssl)) {
#ifdef WOLFSSL_SHA384
		ssl->hsHashes->hashSha384 = sha384[0];
#endif
	}

#ifdef WOLFSSL_SMALL_STACK
#ifdef WOLFSSL_SHA384
	XFREE(sha384, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#endif

	return ret;
}


#ifndef NO_OLD_TLS
int SSL_hmac(WOLFSSL* ssl, byte* digest, const byte* in, word32 sz,
                 int content, int verify)
{
    byte   result[MAX_DIGEST_SIZE];
    word32 digestSz = ssl->specs.hash_size;            /* actual sizes */
    word32 padSz    = ssl->specs.pad_size;
    int    ret      = 0;

    Md5 md5;
    Sha sha;

    /* data */
    byte seq[SEQ_SZ];
    byte conLen[ENUM_LEN + LENGTH_SZ];     /* content & length */
    const byte* macSecret = wolfSSL_GetMacSecret(ssl, verify);

#ifdef HAVE_FUZZER
    if (ssl->fuzzerCb)
        ssl->fuzzerCb(ssl, in, sz, FUZZ_HMAC, ssl->fuzzerCtx);
#endif

    XMEMSET(seq, 0, SEQ_SZ);
    conLen[0] = (byte)content;
    c16toa((word16)sz, &conLen[ENUM_LEN]);
    c32toa(GetSEQIncrement(ssl, verify), &seq[sizeof(word32)]);

    if (ssl->specs.mac_algorithm == md5_mac) {
        wc_InitMd5(&md5);
        /* inner */
        wc_Md5Update(&md5, macSecret, digestSz);
        wc_Md5Update(&md5, PAD1, padSz);
        wc_Md5Update(&md5, seq, SEQ_SZ);
        wc_Md5Update(&md5, conLen, sizeof(conLen));
        /* in buffer */
        wc_Md5Update(&md5, in, sz);
        wc_Md5Final(&md5, result);
        /* outer */
        wc_Md5Update(&md5, macSecret, digestSz);
        wc_Md5Update(&md5, PAD2, padSz);
        wc_Md5Update(&md5, result, digestSz);
        wc_Md5Final(&md5, digest);
    }
    else {
        ret = wc_InitSha(&sha);
        if (ret != 0)
            return ret;
        /* inner */
        wc_ShaUpdate(&sha, macSecret, digestSz);
        wc_ShaUpdate(&sha, PAD1, padSz);
        wc_ShaUpdate(&sha, seq, SEQ_SZ);
        wc_ShaUpdate(&sha, conLen, sizeof(conLen));
        /* in buffer */
        wc_ShaUpdate(&sha, in, sz);
        wc_ShaFinal(&sha, result);
        /* outer */
        wc_ShaUpdate(&sha, macSecret, digestSz);
        wc_ShaUpdate(&sha, PAD2, padSz);
        wc_ShaUpdate(&sha, result, digestSz);
        wc_ShaFinal(&sha, digest);
    }
    return 0;
}

#ifndef NO_CERTS
static void _buildMD5_CertVerify(WOLFSSL* ssl, byte* digest)
{
	byte md5_result[MD5_DIGEST_SIZE];

#ifdef WOLFSSL_SMALL_STACK
	Md5* md5   = (Md5*)XMALLOC(sizeof(Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	Md5* md5_2 = (Md5*)XMALLOC(sizeof(Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
	Md5 md5[1];
	Md5 md5_2[1];
#endif

	/* make md5 inner */
	md5[0] = ssl->hsHashes->hashMd5 ; /* Save current position */
	wc_Md5Update(&ssl->hsHashes->hashMd5, ssl->arrays->masterSecret,SECRET_LEN);
	wc_Md5Update(&ssl->hsHashes->hashMd5, PAD1, PAD_MD5);
	wc_Md5GetHash(&ssl->hsHashes->hashMd5, md5_result);
	wc_Md5RestorePos(&ssl->hsHashes->hashMd5, md5) ; /* Restore current position */

	/* make md5 outer */
	wc_InitMd5(md5_2) ;
	wc_Md5Update(md5_2, ssl->arrays->masterSecret, SECRET_LEN);
	wc_Md5Update(md5_2, PAD2, PAD_MD5);
	wc_Md5Update(md5_2, md5_result, MD5_DIGEST_SIZE);

	wc_Md5Final(md5_2, digest);

#ifdef WOLFSSL_SMALL_STACK
	XFREE(md5, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(md5_2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
}


static void _buildSHA_CertVerify(WOLFSSL* ssl, byte* digest)
{
	byte sha_result[SHA_DIGEST_SIZE];

#ifdef WOLFSSL_SMALL_STACK
	Sha* sha   = (Sha*)XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	Sha* sha2 = (Sha*)XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
	Sha sha[1];
	Sha sha2[1];
#endif

	/* make sha inner */
	sha[0] = ssl->hsHashes->hashSha ; /* Save current position */
	wc_ShaUpdate(&ssl->hsHashes->hashSha, ssl->arrays->masterSecret,SECRET_LEN);
	wc_ShaUpdate(&ssl->hsHashes->hashSha, PAD1, PAD_SHA);
	wc_ShaGetHash(&ssl->hsHashes->hashSha, sha_result);
	wc_ShaRestorePos(&ssl->hsHashes->hashSha, sha) ; /* Restore current position */

	/* make sha outer */
	wc_InitSha(sha2) ;
	wc_ShaUpdate(sha2, ssl->arrays->masterSecret,SECRET_LEN);
	wc_ShaUpdate(sha2, PAD2, PAD_SHA);
	wc_ShaUpdate(sha2, sha_result, SHA_DIGEST_SIZE);

	wc_ShaFinal(sha2, digest);

#ifdef WOLFSSL_SMALL_STACK
	XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(sha2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

}
#endif /* NO_CERTS */
#endif /* NO_OLD_TLS */

#ifndef NO_CERTS

int BuildCertHashes(WOLFSSL* ssl, Hashes* hashes)
{
    /* store current states, building requires get_digest which resets state */
    #ifdef WOLFSSL_SHA384
        Sha384 sha384 = ssl->hsHashes->hashSha384;
    #endif
    #ifdef WOLFSSL_SHA512
        Sha512 sha512 = ssl->hsHashes->hashSha512;
    #endif

    if (ssl->options.tls) {
#if ! defined( NO_OLD_TLS )
        wc_Md5GetHash(&ssl->hsHashes->hashMd5, hashes->md5);
        wc_ShaGetHash(&ssl->hsHashes->hashSha, hashes->sha);
#endif
        if (IsAtLeastTLSv1_2(ssl)) {
            int ret;

            #ifndef NO_SHA256
                ret = wc_Sha256GetHash(&ssl->hsHashes->hashSha256,hashes->sha256);
                if (ret != 0)
                    return ret;
            #endif
            #ifdef WOLFSSL_SHA384
                ret = wc_Sha384Final(&ssl->hsHashes->hashSha384,hashes->sha384);
                if (ret != 0)
                    return ret;
            #endif
            #ifdef WOLFSSL_SHA512
                ret = wc_Sha512Final(&ssl->hsHashes->hashSha512,hashes->sha512);
                if (ret != 0)
                    return ret;
            #endif
        }
    }
#if ! defined( NO_OLD_TLS )
    else {
        _buildMD5_CertVerify(ssl, hashes->md5);
        _buildSHA_CertVerify(ssl, hashes->sha);
    }

    /* restore */
#endif
    if (IsAtLeastTLSv1_2(ssl)) {
        #ifdef WOLFSSL_SHA384
            ssl->hsHashes->hashSha384 = sha384;
        #endif
        #ifdef WOLFSSL_SHA512
            ssl->hsHashes->hashSha512 = sha512;
        #endif
    }

    return 0;
}
#endif /* WOLFSSL_LEANPSK */

/* Build SSL Message, encrypted; used in sendXXX functions */
int BuildMessage(WOLFSSL* ssl, byte* output, int outSz, const byte* input, int inSz, int type)
{
#ifdef HAVE_TRUNCATED_HMAC
	word32 digestSz = min(ssl->specs.hash_size, ssl->truncated_hmac ? TRUNCATED_HMAC_SZ : ssl->specs.hash_size);
#else
	word32 digestSz = ssl->specs.hash_size;
#endif
	word32 sz = RECORD_HEADER_SZ + inSz + digestSz;
	word32 pad  = 0, i;
	word32 idx  = RECORD_HEADER_SZ;
	word32 ivSz = 0;      /* TLSv1.1  IV */
	word32 headerSz = RECORD_HEADER_SZ;
	word16 size;
	byte               iv[AES_BLOCK_SIZE];                  /* max size */
	int ret        = 0;
	int atomicUser = 0;

#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls) {
		sz       += DTLS_RECORD_EXTRA;
		idx      += DTLS_RECORD_EXTRA;
		headerSz += DTLS_RECORD_EXTRA;
	}
#endif

#ifdef ATOMIC_USER
	if (ssl->ctx->MacEncryptCb)
		atomicUser = 1;
#endif

	if (ssl->specs.cipher_type == block) {
		word32 blockSz = ssl->specs.block_size;
		if (ssl->options.tls1_1) {
			ivSz = blockSz;
			sz  += ivSz;

			if (ivSz > (word32)sizeof(iv))
				return BUFFER_E;

			ret = wc_RNG_GenerateBlock(ssl->rng, iv, ivSz);
			if (ret != 0)
				return ret;

		}
		sz += 1;       /* pad byte */
		pad = (sz - headerSz) % blockSz;
		pad = blockSz - pad;
		sz += pad;
	}

#ifdef HAVE_AEAD
	if (ssl->specs.cipher_type == aead) {
		if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
			ivSz = AEAD_EXP_IV_SZ;

		sz += (ivSz + ssl->specs.aead_mac_size - digestSz);
		XMEMCPY(iv, ssl->keys.aead_exp_IV, AEAD_EXP_IV_SZ);
	}
#endif
	if (sz > (word32)outSz) {
		WOLFSSL_MSG("Oops, want to write past output buffer size");
		return BUFFER_E;
	}
	size = (word16)(sz - headerSz);    /* include mac and digest */
	AddRecordHeader(output, size, (byte)type, ssl);

	/* write to output */
	if (ivSz) {
		XMEMCPY(output + idx, iv, min(ivSz, sizeof(iv)));
		idx += ivSz;
	}
	XMEMCPY(output + idx, input, inSz);
	idx += inSz;

	if (type == handshake) {
		ret = HashOutput(ssl, output, headerSz + inSz, ivSz);
		if (ret != 0)
			return ret;
	}

	if (ssl->specs.cipher_type == block) {
		word32 tmpIdx = idx + digestSz;

	for (i = 0; i <= pad; i++)
		output[tmpIdx++] = (byte)pad; /* pad byte gets pad value too */
	}

	if (atomicUser) {   /* User Record Layer Callback handling */
#ifdef ATOMIC_USER
		if ( (ret = ssl->ctx->MacEncryptCb(ssl, output + idx,  output + headerSz + ivSz, inSz, type, 0,
			output + headerSz, output + headerSz, size, ssl->MacEncryptCtx)) != 0)
				return ret;
#endif
	}
	else 
	{
		if (ssl->specs.cipher_type != aead)
		{
#ifdef HAVE_TRUNCATED_HMAC
			if (ssl->truncated_hmac && ssl->specs.hash_size > digestSz)
			{
#ifdef WOLFSSL_SMALL_STACK
				byte* hmac = NULL;
#else
				byte  hmac[MAX_DIGEST_SIZE];
#endif

#ifdef WOLFSSL_SMALL_STACK
				hmac = (byte*)XMALLOC(MAX_DIGEST_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
				if (hmac == NULL)
					return MEMORY_E;
#endif

				ret = ssl->hmac(ssl, hmac, output + headerSz + ivSz, inSz,	type, 0);
				XMEMCPY(output + idx, hmac, digestSz);

#ifdef WOLFSSL_SMALL_STACK
				XFREE(hmac, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
			} else
#endif
			ret = ssl->hmac(ssl, output+idx, output + headerSz + ivSz, inSz, type, 0);
		}
		
		if (ret != 0)
			return ret;

		if ( (ret = Encrypt(ssl, output + headerSz, output+headerSz,size)) != 0)
			return ret;
	}

	return sz;
}


