
#include "cmnSsl.h"

#ifndef NO_CERTS
/* process the buffer buff, legnth sz, into ctx of format and 
   type used tracks bytes consumed, 
   userChain specifies a user cert chain to pass during the handshake
1: PEM to DER
2: Decrypted DER into plaintext when needed
3: Assign CA/Cert/Private Key to CertificateManager/SSL/CTX respectively
4: Parse and check cert and key
*/
int ProcessBuffer(WOLFSSL_CTX* ctx, const unsigned char* buff,
                         long sz, SSL_FILETYPE_T format, CERT_TYPE_T type, WOLFSSL* ssl,
                         long* used, int userChain)
{
	buffer        der;        /* holds DER or RAW (for NTRU) */
	int           ret;
	int           dynamicType = 0;
	int           eccKey = 0;
	int           rsaKey = 0;
	void*         heap = ctx ? ctx->heap : NULL;
#ifdef WOLFSSL_SMALL_STACK
	EncryptedInfo* info = NULL;
#else
	EncryptedInfo  info[1];
#endif

	(void)dynamicType;
	(void)rsaKey;

	if (used)
		*used = sz;     /* used bytes default to sz, PEM chain may shorten*/

	if (format != SSL_FILETYPE_ASN1 && format != SSL_FILETYPE_PEM && format != SSL_FILETYPE_RAW)
		return SSL_BAD_FILETYPE;

	if (ctx == NULL && ssl == NULL)
		return BAD_FUNC_ARG;

	if (type == CA_TYPE)
		dynamicType = DYNAMIC_TYPE_CA;
	else if (type == CERT_TYPE)
		dynamicType = DYNAMIC_TYPE_CERT;
	else
		dynamicType = DYNAMIC_TYPE_KEY;

#ifdef WOLFSSL_SMALL_STACK
	info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (info == NULL)
		return MEMORY_E;
#endif

	info->set      = 0;
	info->ctx      = ctx;
	info->consumed = 0;
	der.buffer     = 0;

	/* 1: PEM format into DER format 
	*/
	if (format == SSL_FILETYPE_PEM)
	{
		ret = PemToDer(buff, sz, type, &der, heap, info, &eccKey);
		if (ret < 0) {
#ifdef WOLFSSL_SMALL_STACK
			XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
			XFREE(der.buffer, heap, dynamicType);
			return ret;
		}

		if (used)
			*used = info->consumed;

		/* we may have a user cert chain, try to consume */
		if (userChain && type == CERT_TYPE && info->consumed < sz)
		{
#ifdef WOLFSSL_SMALL_STACK
			byte   staticBuffer[1];                 /* force heap usage */
#else
			byte   staticBuffer[FILE_BUFFER_SIZE];  /* tmp chain buffer */
#endif
			byte*  chainBuffer = staticBuffer;
			byte*  shrinked    = NULL;   /* shrinked to size chainBuffer
			* or staticBuffer */
			int    dynamicBuffer = 0;
			word32 bufferSz = sizeof(staticBuffer);
			long   consumed = info->consumed;
			word32 idx = 0;
			int    gotOne = 0;

			if ( (sz - consumed) > (int)bufferSz)
			{
				WOLFSSL_MSG("Growing Tmp Chain Buffer");
				bufferSz = (word32)(sz - consumed);
				/* will shrink to actual size */
				chainBuffer = (byte*)XMALLOC(bufferSz, heap, DYNAMIC_TYPE_FILE);
				if (chainBuffer == NULL) {
#ifdef WOLFSSL_SMALL_STACK
					XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
					XFREE(der.buffer, heap, dynamicType);
					return MEMORY_E;
				}
				dynamicBuffer = 1;
			}

			WOLFSSL_MSG("Processing Cert Chain");
			while (consumed < sz)
			{
				buffer part;
				info->consumed = 0;
				part.buffer = 0;

				ret = PemToDer(buff + consumed, sz - consumed, type, &part, heap, info, &eccKey);
				if (ret == 0) {
					gotOne = 1;
					if ( (idx + part.length) > bufferSz) {
						WOLFSSL_MSG("   Cert Chain bigger than buffer");
						ret = BUFFER_E;
					}
					else {
						c32to24(part.length, &chainBuffer[idx]);
						idx += CERT_HEADER_SZ;
						XMEMCPY(&chainBuffer[idx], part.buffer,part.length);
						idx += part.length;
						consumed  += info->consumed;
						if (used)
							*used += info->consumed;
					}
				}

				XFREE(part.buffer, heap, dynamicType);

				if (ret == SSL_NO_PEM_HEADER && gotOne) {
					WOLFSSL_MSG("We got one good PEM so stuff at end ok");
					break;
				}

				if (ret < 0) {
					WOLFSSL_MSG("   Error in Cert in Chain");
					if (dynamicBuffer)
						XFREE(chainBuffer, heap, DYNAMIC_TYPE_FILE);
#ifdef WOLFSSL_SMALL_STACK
					XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
					XFREE(der.buffer, heap, dynamicType);
					return ret;
				}
				WOLFSSL_MSG("   Consumed another Cert in Chain");
			}
			WOLFSSL_MSG("Finished Processing Cert Chain");

			/* only retain actual size used */
			shrinked = (byte*)XMALLOC(idx, heap, dynamicType);
			if (shrinked)
			{
				if (ssl) {
					if (ssl->buffers.certChain.buffer && ssl->buffers.weOwnCertChain) {
						XFREE(ssl->buffers.certChain.buffer, heap, dynamicType);
					}
					ssl->buffers.certChain.buffer = shrinked;
					ssl->buffers.certChain.length = idx;
					XMEMCPY(ssl->buffers.certChain.buffer, chainBuffer,idx);
					ssl->buffers.weOwnCertChain = 1;
				}
				else if (ctx) {
					if (ctx->certChain.buffer)
						XFREE(ctx->certChain.buffer, heap, dynamicType);
					ctx->certChain.buffer = shrinked;
					ctx->certChain.length = idx;
					XMEMCPY(ctx->certChain.buffer, chainBuffer, idx);
				}
			}

			if (dynamicBuffer)
				XFREE(chainBuffer, heap, DYNAMIC_TYPE_FILE);

			if (shrinked == NULL) {
#ifdef WOLFSSL_SMALL_STACK
				XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
				XFREE(der.buffer, heap, dynamicType);
				return MEMORY_E;
			}
		}
	}
	else {  /* ASN1 (DER) or RAW (NTRU) */
		der.buffer = (byte*) XMALLOC(sz, heap, dynamicType);
		if (!der.buffer) {
#ifdef WOLFSSL_SMALL_STACK
			XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
			return MEMORY_ERROR;
		}

		XMEMCPY(der.buffer, buff, sz);
		der.length = (word32)sz;
	}

	/* 2: DER is decrypted into plaintext */
#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
	if (info->set)
	{
		/* decrypt */
		int   passwordSz;
#ifdef WOLFSSL_SMALL_STACK
		char* password = NULL;
		byte* key      = NULL;
		byte* iv       = NULL;
#else
		char  password[80];
		byte  key[AES_256_KEY_SIZE];
#ifndef NO_MD5
		byte  iv[AES_IV_SIZE];
#endif
#endif

#ifdef WOLFSSL_SMALL_STACK
		password = (char*)XMALLOC(80, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		key      = (byte*)XMALLOC(AES_256_KEY_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		iv       = (byte*)XMALLOC(AES_IV_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);

		if (password == NULL || key == NULL || iv == NULL)
		{
			XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
			XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
			XFREE(iv,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
			ret = MEMORY_E;
		}
		else
#endif
		{
			if (!ctx || !ctx->passwd_cb)
			{
				ret = NO_PASSWORD;
			}
			else
			{
				passwordSz = ctx->passwd_cb(password, sizeof(password), 0, ctx->userdata);

				/* use file's salt for key derivation, hex decode first */
				if (Base16_Decode(info->iv, info->ivSz, info->iv, &info->ivSz) != 0) {
					ret = ASN_INPUT_E;
				}
#ifndef NO_MD5
				else if ((ret = EVP_BytesToKey(info->name, "MD5", info->iv, (byte*)password, passwordSz, 1, key, iv)) <= 0) {
				/* empty */
				}
#endif
#ifndef NO_DES3
				else if (XSTRNCMP(info->name, "DES-CBC", 7) == 0) {
					ret = wc_Des_CbcDecryptWithKey(der.buffer, der.buffer, der.length, key, info->iv);
				}
				else if (XSTRNCMP(info->name, "DES-EDE3-CBC", 13) == 0) {
					ret = wc_Des3_CbcDecryptWithKey(der.buffer, der.buffer, der.length, key, info->iv);
				}
#endif
#ifndef NO_AES
				else if (XSTRNCMP(info->name, "AES-128-CBC", 13) == 0) {
					ret = wc_AesCbcDecryptWithKey(der.buffer, der.buffer, der.length, key, AES_128_KEY_SIZE, info->iv);
				}
				else if (XSTRNCMP(info->name, "AES-192-CBC", 13) == 0) {
					ret = wc_AesCbcDecryptWithKey(der.buffer, der.buffer, der.length,  key, AES_192_KEY_SIZE, info->iv);
				}
				else if (XSTRNCMP(info->name, "AES-256-CBC", 13) == 0) {
					ret = wc_AesCbcDecryptWithKey(der.buffer, der.buffer, der.length, key, AES_256_KEY_SIZE, info->iv);
				}
#endif
				else {
					ret = SSL_BAD_FILE;
				}
			}

		}
	
#ifdef WOLFSSL_SMALL_STACK
		XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		XFREE(key,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
		XFREE(iv,       NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

		if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
			XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
			XFREE(der.buffer, heap, dynamicType);
			return ret;
		}
	}
#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */

#ifdef WOLFSSL_SMALL_STACK
	XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif


	/* 3: assigned into CTX or SSL as the different types of DER */
	if (type == CA_TYPE)
	{/* translate the der buffer into CA of CertificateManager */
		if (ctx == NULL) {
			WOLFSSL_MSG("Need context for CA load");
			XFREE(der.buffer, heap, dynamicType);
			return BAD_FUNC_ARG;
		}
		
		return AddCA(ctx->cm, der, WOLFSSL_USER_CA, ctx->verifyPeer);
		      /* takes der over */
	}
	else if (type == CERT_TYPE)
	{
		if (ssl) {
			if (ssl->buffers.weOwnCert && ssl->buffers.certificate.buffer)
				XFREE(ssl->buffers.certificate.buffer, heap, dynamicType);
			ssl->buffers.certificate = der;
			ssl->buffers.weOwnCert = 1;
		}
		else if (ctx) {
			if (ctx->certificate.buffer)
				XFREE(ctx->certificate.buffer, heap, dynamicType);
			ctx->certificate = der;     /* takes der over */
		}
	}
	else if (type == PRIVATEKEY_TYPE)
	{
		if (ssl) {
			if (ssl->buffers.weOwnKey && ssl->buffers.key.buffer)
				XFREE(ssl->buffers.key.buffer, heap, dynamicType);
			ssl->buffers.key = der;
			ssl->buffers.weOwnKey = 1;
		}
		else if (ctx) {
			if (ctx->privateKey.buffer)
				XFREE(ctx->privateKey.buffer, heap, dynamicType);
			ctx->privateKey = der;      /* takes der over */
		}
	}
	else {
		XFREE(der.buffer, heap, dynamicType);
		return SSL_BAD_CERTTYPE;
	}


	/* 4: decode and check the private key or certificate respectively */
	if (type == PRIVATEKEY_TYPE && format != SSL_FILETYPE_RAW)
	{
#ifndef NO_RSA
		if (!eccKey)
		{
			/* make sure RSA key can be used */
			word32 idx = 0;
#ifdef WOLFSSL_SMALL_STACK
			RsaKey* key = NULL;
#else
			RsaKey  key[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
			key = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
			if (key == NULL)
				return MEMORY_E;
#endif

			ret = wc_InitRsaKey(key, 0);
			if (ret == 0)
			{
				if (wc_RsaPrivateKeyDecode(der.buffer, &idx, key, der.length) != 0)
				{
#ifdef HAVE_ECC
				/* could have DER ECC (or pkcs8 ecc), no easy way to tell */
					eccKey = 1;  /* so try it out */
#endif
					if (!eccKey)
						ret = SSL_BAD_FILE;
				}
				else {
					rsaKey = 1;
					(void)rsaKey;  /* for no ecc builds */
				}
			}

			wc_FreeRsaKey(key);

#ifdef WOLFSSL_SMALL_STACK
			XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

			if (ret != 0)
			return ret;
		}
#endif

#ifdef HAVE_ECC
		if (!rsaKey)
		{
			/* make sure ECC key can be used */
			word32  idx = 0;
			ecc_key key;

			wc_ecc_init(&key);
			if (wc_EccPrivateKeyDecode(der.buffer,&idx,&key,der.length) != 0)
			{
				wc_ecc_free(&key);
				return SSL_BAD_FILE;
			}
			wc_ecc_free(&key);
			eccKey = 1;
			if (ctx)
				ctx->haveStaticECC = 1;
			if (ssl)
				ssl->options.haveStaticECC = 1;
		}
#endif /* HAVE_ECC */
	}
	else if (type == CERT_TYPE)
	{
#ifdef WOLFSSL_SMALL_STACK
		DecodedCert* cert = NULL;
#else
		DecodedCert  cert[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
		cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (cert == NULL)
			return MEMORY_E;
#endif

		WOLFSSL_MSG("Checking cert signature type");
		InitDecodedCert(cert, der.buffer, der.length, heap);

		if (DecodeToKey(cert, 0) < 0)
		{
			WOLFSSL_MSG("Decode to key failed");
#ifdef WOLFSSL_SMALL_STACK
			XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
			return SSL_BAD_FILE;
		}
		
		switch (cert->signatureOID)
		{
			case CTC_SHAwECDSA:
			case CTC_SHA256wECDSA:
			case CTC_SHA384wECDSA:
			case CTC_SHA512wECDSA:
				WOLFSSL_MSG("ECDSA cert signature");
				if (ctx)
					ctx->haveECDSAsig = 1;
				if (ssl)
					ssl->options.haveECDSAsig = 1;
				break;
			
			default:
				WOLFSSL_MSG("Not ECDSA cert signature");
				break;
		}

#ifdef HAVE_ECC
		if (ctx)
			ctx->pkCurveOID = cert->pkCurveOID;
		if (ssl)
			ssl->pkCurveOID = cert->pkCurveOID;
#endif

		FreeDecodedCert(cert);
#ifdef WOLFSSL_SMALL_STACK
		XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
	}

	return SSL_SUCCESS;
}


/* CA PEM file for verification, may have multiple/chain certs to process */
int ProcessChainBuffer(WOLFSSL_CTX* ctx, const unsigned char* buff,
                            long sz, SSL_FILETYPE_T format, CERT_TYPE_T type, WOLFSSL* ssl)
{
	long used   = 0;
	int  ret    = 0;
	int  gotOne = 0;

	WOLFSSL_ENTER();
	while (used < sz) {
		long consumed = 0;

		ret = ProcessBuffer(ctx, buff + used, sz - used, format, type, ssl, &consumed, 0);
		if (ret == SSL_NO_PEM_HEADER && gotOne) {
			WOLFSSL_MSG("We got one good PEM file so stuff at end ok");
			ret = SSL_SUCCESS;
			break;
		}

		if (ret < 0)
		break;

		WOLFSSL_MSG("   Processed a CA");
		gotOne = 1;
		used += consumed;
	}

	return ret;
}


/* process a file with name fname into ctx of format and type
   userChain specifies a user certificate chain to pass during handshake */
int ProcessFile(WOLFSSL_CTX* ctx, const char* fname, SSL_FILETYPE_T format, CERT_TYPE_T type, 
	WOLFSSL* ssl, int userChain, WOLFSSL_CRL* crl)
{
#ifdef WOLFSSL_SMALL_STACK
	byte   staticBuffer[1]; /* force heap usage */
#else
	byte   staticBuffer[FILE_BUFFER_SIZE];
#endif
	byte*  myBuffer = staticBuffer;
	int    dynamic = 0;
	int    ret;
	long   sz = 0;
	XFILE  file;
	void*  heapHint = ctx ? ctx->heap : NULL;

	(void)crl;
	(void)heapHint;

	if (fname == NULL)
		return SSL_BAD_FILE;

	DEBUG_MSG( "processing file: %s\n", fname);
	wolfSslDebug( "%s processing file: %s\n", __FUNCTION__ , fname);
	printf( "%s processing file: %s\n", __FUNCTION__ , fname);

	file = XFOPEN(fname, "rb");
	if (file == XBADFILE)
		return SSL_BAD_FILE;
	XFSEEK(file, 0, XSEEK_END);
	sz = XFTELL(file);
	XREWIND(file);

	if (sz > (long)sizeof(staticBuffer)) {
		WOLFSSL_MSG("Getting dynamic buffer");
		myBuffer = (byte*)XMALLOC(sz, heapHint, DYNAMIC_TYPE_FILE);
		if (myBuffer == NULL) {
			XFCLOSE(file);
			return SSL_BAD_FILE;
		}
		dynamic = 1;
	}
	else if (sz < 0) {
		XFCLOSE(file);
		return SSL_BAD_FILE;
	}

	if ( (ret = (int)XFREAD(myBuffer, sz, 1, file)) < 0)
		ret = SSL_BAD_FILE;
	else
	{
		if (type == CA_TYPE && format == SSL_FILETYPE_PEM)
			ret = ProcessChainBuffer(ctx, myBuffer, sz, format, type, ssl);
#ifdef HAVE_CRL
		else if (type == CRL_TYPE)
			ret = BufferLoadCRL(crl, myBuffer, sz, format);
#endif
		else
			ret = ProcessBuffer(ctx, myBuffer, sz, format, type, ssl, NULL, userChain);
	}

	XFCLOSE(file);
	if (dynamic)
		XFREE(myBuffer, heapHint, DYNAMIC_TYPE_FILE);

	return ret;
}


/* loads file then loads each file in path, no c_rehash 
one verify_location is a CA in CTX->CertificateManager->caTable, eg. CA is used to verify
*/
int wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX* ctx, const char* file, const char* path)
{
	int ret = SSL_SUCCESS;

	WOLFSSL_ENTER();
	(void)path;

	if (ctx == NULL || (file == NULL && path == NULL) )
		return SSL_FAILURE;

	if (file)
		ret = ProcessFile(ctx, file, SSL_FILETYPE_PEM, CA_TYPE, NULL, 0, NULL);

	if (ret == SSL_SUCCESS && path)
	{/* try to load each regular file in path */
#ifdef USE_WINDOWS_API
		WIN32_FIND_DATAA FindFileData;
		HANDLE hFind;
#ifdef WOLFSSL_SMALL_STACK
		char*  name = NULL;
#else
		char   name[MAX_FILENAME_SZ];
#endif

#ifdef WOLFSSL_SMALL_STACK
		name = (char*)XMALLOC(MAX_FILENAME_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (name == NULL)
			return MEMORY_E;
#endif

		XMEMSET(name, 0, MAX_FILENAME_SZ);
		XSTRNCPY(name, path, MAX_FILENAME_SZ - 4);
		XSTRNCAT(name, "\\*", 3);

		hFind = FindFirstFileA(name, &FindFileData);
		if (hFind == INVALID_HANDLE_VALUE) {
			WOLFSSL_MSG("FindFirstFile for path verify locations failed");
#ifdef WOLFSSL_SMALL_STACK
			XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
			return BAD_PATH_ERROR;
		}

		do {
			if (FindFileData.dwFileAttributes != FILE_ATTRIBUTE_DIRECTORY) {
				XSTRNCPY(name, path, MAX_FILENAME_SZ/2 - 3);
				XSTRNCAT(name, "\\", 2);
				XSTRNCAT(name, FindFileData.cFileName, MAX_FILENAME_SZ/2);

				ret = ProcessFile(ctx, name, SSL_FILETYPE_PEM, CA_TYPE, NULL,0, NULL);
			}
		} while (ret == SSL_SUCCESS && FindNextFileA(hFind, &FindFileData));

#ifdef WOLFSSL_SMALL_STACK
		XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

		FindClose(hFind);
#elif !defined(NO_WOLFSSL_DIR)
		struct dirent* entry;
		DIR*   dir = opendir(path);
#ifdef WOLFSSL_SMALL_STACK
		char*  name = NULL;
#else
		char   name[MAX_FILENAME_SZ];
#endif

		if (dir == NULL) {
			WOLFSSL_MSG("opendir path verify locations failed");
			return BAD_PATH_ERROR;
		}

#ifdef WOLFSSL_SMALL_STACK
		name = (char*)XMALLOC(MAX_FILENAME_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (name == NULL)
			return MEMORY_E;
#endif

		while ( ret == SSL_SUCCESS && (entry = readdir(dir)) != NULL)
		{
			struct stat s;

			XMEMSET(name, 0, MAX_FILENAME_SZ);
			XSTRNCPY(name, path, MAX_FILENAME_SZ/2 - 2);
			XSTRNCAT(name, "/", 1);
			XSTRNCAT(name, entry->d_name, MAX_FILENAME_SZ/2);

			if (stat(name, &s) != 0) {
				WOLFSSL_MSG("stat on name failed");
				ret = BAD_PATH_ERROR;
			}
			else if (s.st_mode & S_IFREG)
				ret = ProcessFile(ctx, name, SSL_FILETYPE_PEM, CA_TYPE, NULL,0, NULL);
		}

#ifdef WOLFSSL_SMALL_STACK
		XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
		closedir(dir);
#endif
	}

	/* lzj */
	if(ret !=SSL_SUCCESS)
		ret = SSL_FAILURE;
	
	return ret;
}


int wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX* ctx, const char* file, SSL_FILETYPE_T format)
{
	WOLFSSL_ENTER();
	if (ProcessFile(ctx, file, format, CERT_TYPE, NULL, 0, NULL) == SSL_SUCCESS)
		return SSL_SUCCESS;

	return SSL_FAILURE;
}


int wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX* ctx, const char* file,SSL_FILETYPE_T format)
{
	WOLFSSL_ENTER();
	if (ProcessFile(ctx, file, format, PRIVATEKEY_TYPE, NULL, 0, NULL)== SSL_SUCCESS)
		return SSL_SUCCESS;

	return SSL_FAILURE;
}

int wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX* ctx, const char* file)
{
	/* procces up to MAX_CHAIN_DEPTH plus subject cert */
	WOLFSSL_ENTER();
	if (ProcessFile(ctx, file, SSL_FILETYPE_PEM,CERT_TYPE,NULL,1, NULL)== SSL_SUCCESS)
		return SSL_SUCCESS;

	return SSL_FAILURE;
}



int wolfSSL_use_certificate_chain_file(WOLFSSL* ssl, const char* file)
{
	/* procces up to MAX_CHAIN_DEPTH plus subject cert */
	WOLFSSL_ENTER();
	if (ProcessFile(ssl->ctx, file, SSL_FILETYPE_PEM, CERT_TYPE, ssl, 1, NULL)== SSL_SUCCESS)
		return SSL_SUCCESS;

	return SSL_FAILURE;
}


int wolfSSL_use_certificate_file(WOLFSSL* ssl, const char* file, SSL_FILETYPE_T format)
{
	WOLFSSL_ENTER();
	if (ProcessFile(ssl->ctx, file, format, CERT_TYPE, ssl, 0, NULL)== SSL_SUCCESS)
		return SSL_SUCCESS;

	return SSL_FAILURE;
}


int wolfSSL_use_PrivateKey_file(WOLFSSL* ssl, const char* file, SSL_FILETYPE_T format)
{
	WOLFSSL_ENTER();
	if (ProcessFile(ssl->ctx, file, format, PRIVATEKEY_TYPE, ssl, 0, NULL) == SSL_SUCCESS)
		return SSL_SUCCESS;

	return SSL_FAILURE;
}


#ifdef WOLFSSL_DER_LOAD

/* Add format parameter to allow DER load of CA files */
int wolfSSL_CTX_der_load_verify_locations(WOLFSSL_CTX* ctx, const char* file, SSL_FILETYPE_T format)
{
    WOLFSSL_ENTER();
    if (ctx == NULL || file == NULL)
        return SSL_FAILURE;

    if (ProcessFile(ctx, file, format, CA_TYPE, NULL, 0, NULL) == SSL_SUCCESS)
        return SSL_SUCCESS;

    return SSL_FAILURE;
}

#endif /* WOLFSSL_DER_LOAD */

#ifdef HAVE_NTRU

int wolfSSL_CTX_use_NTRUPrivateKey_file(WOLFSSL_CTX* ctx, const char* file)
{
    WOLFSSL_ENTER();
    if (ctx == NULL)
        return SSL_FAILURE;

    if (ProcessFile(ctx, file, SSL_FILETYPE_RAW, PRIVATEKEY_TYPE, NULL, 0, NULL)
                         == SSL_SUCCESS) {
        ctx->haveNTRU = 1;
        return SSL_SUCCESS;
    }

    return SSL_FAILURE;
}

#endif /* HAVE_NTRU */


#endif /* !NO_CERTS */

