

#include "cmnSsl.h"

/* 1: certificate */
static const char* BEGIN_CERT         = "-----BEGIN CERTIFICATE-----";
static const char* END_CERT           = "-----END CERTIFICATE-----";

/* 2: certificate request */
static const char* BEGIN_CERT_REQ     = "-----BEGIN CERTIFICATE REQUEST-----";
static const char* END_CERT_REQ       = "-----END CERTIFICATE REQUEST-----";

/* 3: DH params, DH key */
static const char* BEGIN_DH_PARAM     = "-----BEGIN DH PARAMETERS-----";
static const char* END_DH_PARAM       = "-----END DH PARAMETERS-----";

/* 4: CRL */
static const char* BEGIN_X509_CRL     = "-----BEGIN X509 CRL-----";
static const char* END_X509_CRL       = "-----END X509 CRL-----";

/* 5: certificate */
static const char* BEGIN_RSA_PRIV     = "-----BEGIN RSA PRIVATE KEY-----";
static const char* END_RSA_PRIV       = "-----END RSA PRIVATE KEY-----";

/* 6: certificate */
static const char* BEGIN_PRIV_KEY     = "-----BEGIN PRIVATE KEY-----";
static const char* END_PRIV_KEY       = "-----END PRIVATE KEY-----";

/* 7: certificate */
static const char* BEGIN_ENC_PRIV_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
static const char* END_ENC_PRIV_KEY   = "-----END ENCRYPTED PRIVATE KEY-----";

/* 8: certificate */
static const char* BEGIN_EC_PRIV      = "-----BEGIN EC PRIVATE KEY-----";
static const char* END_EC_PRIV        = "-----END EC PRIVATE KEY-----";

/* 9: certificate */
static const char* BEGIN_DSA_PRIV     = "-----BEGIN DSA PRIVATE KEY-----";
static const char* END_DSA_PRIV       = "-----END DSA PRIVATE KEY-----";

/* Remove PEM header/footer, convert to ASN1, store any encrypted data
   info->consumed tracks of PEM bytes consumed in case multiple parts */
int PemToDer(const unsigned char* buff, long longSz, int type,
                  buffer* der, void* heap, EncryptedInfo* info, int* eccKey)
{
	const char* header      = NULL;
	const char* footer      = NULL;
	char*       headerEnd;
	char*       footerEnd;
	char*       consumedEnd;
	char*       bufferEnd   = (char*)(buff + longSz);
	long        neededSz;
	int         ret         = 0;
	int         dynamicType = 0;
	int         sz          = (int)longSz;

	switch (type)
	{
		case CA_TYPE:       /* same as below */
		case CERT_TYPE:
			header= BEGIN_CERT;
			footer= END_CERT;
			break;
			
		case CRL_TYPE:
			header= BEGIN_X509_CRL;
			footer= END_X509_CRL;
			break;
			
		case DH_PARAM_TYPE:
			header= BEGIN_DH_PARAM;
			footer= END_DH_PARAM;
			break;
			
		case CERTREQ_TYPE:
			header= BEGIN_CERT_REQ;
			footer= END_CERT_REQ;
			break;
			
		default:
			header= BEGIN_RSA_PRIV;
			footer= END_RSA_PRIV;
			break;
	}

	switch (type) {
		case CA_TYPE:
			dynamicType = DYNAMIC_TYPE_CA;   break;
		case CERT_TYPE:
			dynamicType = DYNAMIC_TYPE_CERT; break;
		case CRL_TYPE:
			dynamicType = DYNAMIC_TYPE_CRL;  break;
		default:
			dynamicType = DYNAMIC_TYPE_KEY;  break;
	}

	/* find header */
	for (;;)
	{
		headerEnd = XSTRNSTR((char*)buff, header, sz);
		if (headerEnd || type != PRIVATEKEY_TYPE)
		{
			break;
		}
		else if (header == BEGIN_RSA_PRIV) ///???
		{
			header =  BEGIN_PRIV_KEY;
			footer = END_PRIV_KEY;
		}
		else if (header == BEGIN_PRIV_KEY)
		{
			header =  BEGIN_ENC_PRIV_KEY;
			footer = END_ENC_PRIV_KEY;
		}
		else if (header == BEGIN_ENC_PRIV_KEY) {
			header =  BEGIN_EC_PRIV;
			footer = END_EC_PRIV;
		}
		else if (header == BEGIN_EC_PRIV) {
			header =  BEGIN_DSA_PRIV;
			footer = END_DSA_PRIV;
		}
		else
			break;
	}

	if (!headerEnd) {
		WOLFSSL_MSG("Couldn't find PEM header");
		return SSL_NO_PEM_HEADER;
	}

	headerEnd += XSTRLEN(header);

	/* eat end of line */
	if (headerEnd[0] == '\n')
		headerEnd++;
	else if (headerEnd[1] == '\n')
		headerEnd += 2;
	else
		return SSL_BAD_FILE;

	if (type == PRIVATEKEY_TYPE)
	{
		if (eccKey)
			*eccKey = header == BEGIN_EC_PRIV;      
	}

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
	{
		/* remove encrypted header if there */
		char encHeader[] = "Proc-Type";
		char* line = XSTRNSTR(headerEnd, encHeader, PEM_LINE_LEN);
		if (line)
		{
			char* newline;
			char* finish;
			char* start  = XSTRNSTR(line, "DES", PEM_LINE_LEN);

			if (!start)
				start = XSTRNSTR(line, "AES", PEM_LINE_LEN);

			if (!start) return SSL_BAD_FILE;
			if (!info)  return SSL_BAD_FILE;

			finish = XSTRNSTR(start, ",", PEM_LINE_LEN);

			if (start && finish && (start < finish))
			{
				newline = XSTRNSTR(finish, "\r", PEM_LINE_LEN);

				XMEMCPY(info->name, start, finish - start);
				info->name[finish - start] = 0;
				XMEMCPY(info->iv, finish + 1, sizeof(info->iv));

				if (!newline)
					newline = XSTRNSTR(finish, "\n", PEM_LINE_LEN);
				if (newline && (newline > finish))
				{
					info->ivSz = (word32)(newline - (finish + 1));
					info->set = 1;
				}
				else
					return SSL_BAD_FILE;
			}
			else
				return SSL_BAD_FILE;

			/* eat blank line */
			while (*newline == '\r' || *newline == '\n')
				newline++;
			headerEnd = newline;
		}
	}
#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */


	/* find footer */
	footerEnd = XSTRNSTR((char*)buff, footer, sz);
	if (!footerEnd)
		return SSL_BAD_FILE;

	consumedEnd = footerEnd + XSTRLEN(footer);

	if (consumedEnd < bufferEnd) {  /* handle no end of line on last line */
		/* eat end of line */
		if (consumedEnd[0] == '\n')
			consumedEnd++;
		else if (consumedEnd[1] == '\n')
			consumedEnd += 2;
		else
			return SSL_BAD_FILE;
	}

	if (info)
		info->consumed = (long)(consumedEnd - (char*)buff);

	/* set up der buffer */
	neededSz = (long)(footerEnd - headerEnd);
	if (neededSz > sz || neededSz < 0)
		return SSL_BAD_FILE;

	der->buffer = (byte*)XMALLOC(neededSz, heap, dynamicType);
	if (!der->buffer)
		return MEMORY_ERROR;

	der->length = (word32)neededSz;

	if (Base64_Decode((byte*)headerEnd, (word32)neededSz, der->buffer, &der->length) < 0)
		return SSL_BAD_FILE;

	if (header == BEGIN_PRIV_KEY)
	{
		/* pkcs8 key, convert and adjust length */
		if ((ret = ToTraditional(der->buffer, der->length)) < 0)
			return ret;

		der->length = ret;
		return 0;
	}

#if (defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)) && !defined(NO_PWDBASED)
	if (header == BEGIN_ENC_PRIV_KEY)
	{
		int   passwordSz;
#ifdef WOLFSSL_SMALL_STACK
		char* password = NULL;
#else
		char  password[80];
#endif

		if (!info || !info->ctx || !info->ctx->passwd_cb)
			return SSL_BAD_FILE;  /* no callback error */

#ifdef WOLFSSL_SMALL_STACK
		password = (char*)XMALLOC(80, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (password == NULL)
			return MEMORY_E;
#endif
		passwordSz = info->ctx->passwd_cb(password, sizeof(password), 0, info->ctx->userdata);
		/* convert and adjust length */
		ret = ToTraditionalEnc(der->buffer, der->length, password, passwordSz);

#ifdef WOLFSSL_SMALL_STACK
		XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

		if (ret < 0)
			return ret;

		der->length = ret;
		return 0;
	}
#endif

	return 0;
}

#ifdef WOLFSSL_CERT_GEN

/* load pem cert from file into der buffer, return der size or error */
int wolfSSL_PemCertToDer(const char* fileName, unsigned char* derBuf, int derSz)
{
#ifdef WOLFSSL_SMALL_STACK
	EncryptedInfo* info = NULL;
	byte   staticBuffer[1]; /* force XMALLOC */
#else
	EncryptedInfo info[1];
	byte   staticBuffer[FILE_BUFFER_SIZE];
#endif
	int    dynamic = 0;
	int    ret     = 0;
	int    ecc     = 0;
	long   sz      = 0;
	buffer converted;
	byte*  fileBuf = staticBuffer;

	XFILE  file    = XFOPEN(fileName, "rb");

	WOLFSSL_ENTER();

	if (file == XBADFILE)
		return SSL_BAD_FILE;

	XFSEEK(file, 0, XSEEK_END);
	sz = XFTELL(file);
	XREWIND(file);
	if (sz < 0)
	{
		XFCLOSE(file);
		return SSL_BAD_FILE;
	}
	
	if (sz > (long)sizeof(staticBuffer))
	{
		fileBuf = (byte*)XMALLOC(sz, 0, DYNAMIC_TYPE_FILE);
		if (fileBuf == NULL)
		{
			XFCLOSE(file);
			return MEMORY_E;
		}

		dynamic = 1;
	}

	converted.buffer = 0;
	
	if ( (ret = (int)XFREAD(fileBuf, sz, 1, file)) < 0)
		ret = SSL_BAD_FILE;
	else
	{
#ifdef WOLFSSL_SMALL_STACK
		info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (info == NULL)
			ret = MEMORY_E;
		else
#endif
		{
			ret = PemToDer(fileBuf, sz, CA_TYPE, &converted, 0, info, &ecc);
#ifdef WOLFSSL_SMALL_STACK
			XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
		}
	}

	if (ret == 0) {
		if (converted.length < (word32)derSz) {
			XMEMCPY(derBuf, converted.buffer, converted.length);
			ret = converted.length;
		}
		else
			ret = BUFFER_E;
	}

	XFREE(converted.buffer, 0, DYNAMIC_TYPE_CA);

	XFCLOSE(file);
	if (dynamic)
		XFREE(fileBuf, 0, DYNAMIC_TYPE_FILE);

	return ret;
}
#endif /* WOLFSSL_CERT_GEN */




/* Return bytes written to buff or < 0 for error */
int wolfSSL_CertPemToDer(const unsigned char* pem, int pemSz, unsigned char* buff, int buffSz, CERT_TYPE_T type)
{
    int            eccKey = 0;
    int            ret;
    buffer         der;
#ifdef WOLFSSL_SMALL_STACK
    EncryptedInfo* info = NULL;
#else
    EncryptedInfo  info[1];
#endif

	WOLFSSL_ENTER();

    if (pem == NULL || buff == NULL || buffSz <= 0) {
        WOLFSSL_MSG("Bad pem der args");
        return BAD_FUNC_ARG;
    }

    if (type != CERT_TYPE && type != CA_TYPE && type != CERTREQ_TYPE) {
        WOLFSSL_MSG("Bad cert type");
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (info == NULL)
        return MEMORY_E;
#endif

    info->set      = 0;
    info->ctx      = NULL;
    info->consumed = 0;
    der.buffer     = NULL;

    ret = PemToDer(pem, pemSz, type, &der, NULL, info, &eccKey);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret < 0) {
        WOLFSSL_MSG("Bad Pem To Der");
    }
    else {
        if (der.length <= (word32)buffSz) {
            XMEMCPY(buff, der.buffer, der.length);
            ret = der.length;
        }
        else {
            WOLFSSL_MSG("Bad der length");
            ret = BAD_FUNC_ARG;
        }
    }

    XFREE(der.buffer, NULL, DYNAMIC_TYPE_KEY);

    return ret;
}


#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)

/* our KeyPemToDer password callback, password in userData */
static INLINE int __ourPasswordCb(char* passwd, int sz, int rw, void* userdata)
{
    (void)rw;

    if (userdata == NULL)
        return 0;

    XSTRNCPY(passwd, (char*)userdata, sz);
    return min((word32)sz, (word32)XSTRLEN((char*)userdata));
}

#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */

/* Return bytes written to buff or < 0 for error */
int wolfSSL_KeyPemToDer(const unsigned char* pem, int pemSz, unsigned char* buff,
                       int buffSz, const char* pass)
{
    int            eccKey = 0;
    int            ret;
    buffer         der;
#ifdef WOLFSSL_SMALL_STACK
    EncryptedInfo* info = NULL;
#else
    EncryptedInfo  info[1];
#endif

    (void)pass;


    if (pem == NULL || buff == NULL || buffSz <= 0) {
        WOLFSSL_MSG("Bad pem der args");
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (info == NULL)
        return MEMORY_E;
#endif

    info->set      = 0;
    info->ctx      = NULL;
    info->consumed = 0;
    der.buffer     = NULL;

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    if (pass) {
        info->ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
        if (info->ctx == NULL) {
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return MEMORY_E;
        }

        wolfSSL_CTX_set_default_passwd_cb(info->ctx, __ourPasswordCb);
        wolfSSL_CTX_set_default_passwd_cb_userdata(info->ctx, (void*)pass);
    }
#endif

    ret = PemToDer(pem, pemSz, PRIVATEKEY_TYPE, &der, NULL, info, &eccKey);

    if (info->ctx)
        wolfSSL_CTX_free(info->ctx);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret < 0) {
        WOLFSSL_MSG("Bad Pem To Der");
    }
    else {
        if (der.length <= (word32)buffSz) {
            XMEMCPY(buff, der.buffer, der.length);
            ret = der.length;
        }
        else {
            WOLFSSL_MSG("Bad der length");
            ret = BAD_FUNC_ARG;
        }
    }

    XFREE(der.buffer, NULL, DYNAMIC_TYPE_KEY);

    return ret;
}


