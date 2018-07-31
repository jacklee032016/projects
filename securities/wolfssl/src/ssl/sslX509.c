
#include <cmnSsl.h>


#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)

void wolfSSL_FreeX509(WOLFSSL_X509* x509)
{
	WOLFSSL_ENTER();
	FreeX509(x509);
}


/* return the next, if any, altname from the peer cert */
char* wolfSSL_X509_get_next_altname(WOLFSSL_X509* cert)
{
	char* ret = NULL;
	WOLFSSL_ENTER();

	/* don't have any to work with */
	if (cert == NULL || cert->altNames == NULL)
		return NULL;

	/* already went through them */
	if (cert->altNamesNext == NULL)
		return NULL;

	ret = cert->altNamesNext->name;
	cert->altNamesNext = cert->altNamesNext->next;

	return ret;
}


WOLFSSL_X509_NAME* wolfSSL_X509_get_issuer_name(WOLFSSL_X509* cert)
{
	WOLFSSL_ENTER();
	return &cert->issuer;
}


WOLFSSL_X509_NAME* wolfSSL_X509_get_subject_name(WOLFSSL_X509* cert)
{
	WOLFSSL_ENTER();
	return &cert->subject;
}


int wolfSSL_X509_get_isCA(WOLFSSL_X509* x509)
{
	int isCA = 0;

	WOLFSSL_ENTER();

	if (x509 != NULL)
		isCA = x509->isCa;

	WOLFSSL_LEAVE( isCA);

	return isCA;
}


#ifdef OPENSSL_EXTRA
int wolfSSL_X509_ext_isSet_by_NID(WOLFSSL_X509* x509, int nid)
{
	int isSet = 0;

	WOLFSSL_ENTER();

	if (x509 != NULL) {
		switch (nid) {
			case BASIC_CA_OID: isSet = x509->basicConstSet; break;
			case ALT_NAMES_OID: isSet = x509->subjAltNameSet; break;
			case AUTH_KEY_OID: isSet = x509->authKeyIdSet; break;
			case SUBJ_KEY_OID: isSet = x509->subjKeyIdSet; break;
			case KEY_USAGE_OID: isSet = x509->keyUsageSet; break;
#ifdef WOLFSSL_SEP
			case CERT_POLICY_OID: isSet = x509->certPolicySet; break;
#endif /* WOLFSSL_SEP */
		}
	}

	WOLFSSL_LEAVE(isSet);

	return isSet;
}


int wolfSSL_X509_ext_get_critical_by_NID(WOLFSSL_X509* x509, int nid)
{
	int crit = 0;

	WOLFSSL_ENTER();

	if (x509 != NULL) {
		switch (nid) {
			case BASIC_CA_OID: crit = x509->basicConstCrit; break;
			case ALT_NAMES_OID: crit = x509->subjAltNameCrit; break;
			case AUTH_KEY_OID: crit = x509->authKeyIdCrit; break;
			case SUBJ_KEY_OID: crit = x509->subjKeyIdCrit; break;
			case KEY_USAGE_OID: crit = x509->keyUsageCrit; break;
#ifdef WOLFSSL_SEP
			case CERT_POLICY_OID: crit = x509->certPolicyCrit; break;
#endif /* WOLFSSL_SEP */
		}
	}

	WOLFSSL_LEAVE( crit);

	return crit;
}


int wolfSSL_X509_get_isSet_pathLength(WOLFSSL_X509* x509)
{
	int isSet = 0;

	WOLFSSL_ENTER();

	if (x509 != NULL)
	isSet = x509->basicConstPlSet;

	WOLFSSL_LEAVE( isSet);

	return isSet;
}


word32 wolfSSL_X509_get_pathLength(WOLFSSL_X509* x509)
{
	word32 pathLength = 0;

	WOLFSSL_ENTER();

	if (x509 != NULL)
	pathLength = x509->pathLength;

	WOLFSSL_LEAVE( pathLength);

	return pathLength;
}


unsigned int wolfSSL_X509_get_keyUsage(WOLFSSL_X509* x509)
{
word16 usage = 0;

	WOLFSSL_ENTER();

	if (x509 != NULL)
	usage = x509->keyUsage;

	WOLFSSL_LEAVE( usage);

	return usage;
}


byte* wolfSSL_X509_get_authorityKeyID(WOLFSSL_X509* x509, byte* dst, int* dstLen)
{
	byte *id = NULL;
	int copySz = 0;

	WOLFSSL_ENTER();

	if (x509 != NULL) {
		if (x509->authKeyIdSet) {
			copySz = min(dstLen != NULL ? *dstLen : 0, (int)x509->authKeyIdSz);
			id = x509->authKeyId;
		}

		if (dst != NULL && dstLen != NULL && id != NULL && copySz > 0) {
			XMEMCPY(dst, id, copySz);
			id = dst;
			*dstLen = copySz;
		}
	}

	WOLFSSL_LEAVE( copySz);

	return id;
}


byte* wolfSSL_X509_get_subjectKeyID( WOLFSSL_X509* x509, byte* dst, int* dstLen)
{
	byte *id = NULL;
	int copySz = 0;

	WOLFSSL_ENTER();

	if (x509 != NULL) {
		if (x509->subjKeyIdSet) {
			copySz = min(dstLen != NULL ? *dstLen : 0, (int)x509->subjKeyIdSz);
			id = x509->subjKeyId;
		}

		if (dst != NULL && dstLen != NULL && id != NULL && copySz > 0) {
			XMEMCPY(dst, id, copySz);
			id = dst;
			*dstLen = copySz;
		}
	}

	WOLFSSL_LEAVE(copySz);

	return id;
}


int wolfSSL_X509_NAME_entry_count(WOLFSSL_X509_NAME* name)
{
	int count = 0;

	WOLFSSL_ENTER();

	if (name != NULL)
		count = name->fullName.entryCount;

	WOLFSSL_LEAVE( count);
	return count;
}


int wolfSSL_X509_NAME_get_text_by_NID(WOLFSSL_X509_NAME* name, int nid, char* buf, int len)
{
	char *text = NULL;
	int textSz = 0;

	WOLFSSL_ENTER();

	switch (nid)
	{
		case ASN_COMMON_NAME:
		text = name->fullName.fullName + name->fullName.cnIdx;
		textSz = name->fullName.cnLen;
		break;
		
		case ASN_SUR_NAME:
		text = name->fullName.fullName + name->fullName.snIdx;
		textSz = name->fullName.snLen;
		break;
		
		case ASN_SERIAL_NUMBER:
		text = name->fullName.fullName + name->fullName.serialIdx;
		textSz = name->fullName.serialLen;
		break;
		
		case ASN_COUNTRY_NAME:
		text = name->fullName.fullName + name->fullName.cIdx;
		textSz = name->fullName.cLen;
		break;
		
		case ASN_LOCALITY_NAME:
		text = name->fullName.fullName + name->fullName.lIdx;
		textSz = name->fullName.lLen;
		break;
		
		case ASN_STATE_NAME:
		text = name->fullName.fullName + name->fullName.stIdx;
		textSz = name->fullName.stLen;
		break;
		
		case ASN_ORG_NAME:
		text = name->fullName.fullName + name->fullName.oIdx;
		textSz = name->fullName.oLen;
		break;
		
		case ASN_ORGUNIT_NAME:
		text = name->fullName.fullName + name->fullName.ouIdx;
		textSz = name->fullName.ouLen;
		break;
		default:
		break;
	}

	if (buf != NULL && text != NULL) {
		textSz = min(textSz, len);
		XMEMCPY(buf, text, textSz);
		buf[textSz] = '\0';
	}

	WOLFSSL_LEAVE( textSz);
	return textSz;
}
#endif


/* copy name into in buffer, at most sz bytes, if buffer is null will
malloc buffer, call responsible for freeing                     */
char* wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME* name, char* in, int sz)
{
	int copySz = min(sz, name->sz);

	WOLFSSL_ENTER();
	if (!name->sz) return in;

	if (!in) {
		in = (char*)XMALLOC(name->sz, 0, DYNAMIC_TYPE_OPENSSL);
		if (!in ) return in;
		copySz = name->sz;
	}

	if (copySz == 0)
	return in;

	XMEMCPY(in, name->name, copySz - 1);
	in[copySz - 1] = 0;

	return in;
}


int wolfSSL_X509_get_signature_type(WOLFSSL_X509* x509)
{
	int type = 0;

	WOLFSSL_ENTER();

	if (x509 != NULL)
	type = x509->sigOID;

	return type;
}


int wolfSSL_X509_get_signature(WOLFSSL_X509* x509, unsigned char* buf, int* bufSz)
{
	WOLFSSL_ENTER();
	if (x509 == NULL || bufSz == NULL || *bufSz < (int)x509->sig.length)
	return SSL_FATAL_ERROR;

	if (buf != NULL)
		XMEMCPY(buf, x509->sig.buffer, x509->sig.length);
	*bufSz = x509->sig.length;

	return SSL_SUCCESS;
}


/* write X509 serial number in unsigned binary to buffer
buffer needs to be at least EXTERNAL_SERIAL_SIZE (32) for all cases
return SSL_SUCCESS on success */
int wolfSSL_X509_get_serial_number(WOLFSSL_X509* x509, byte* in, int* inOutSz)
{
	WOLFSSL_ENTER();
	if (x509 == NULL || in == NULL ||inOutSz == NULL || *inOutSz < x509->serialSz)
	return BAD_FUNC_ARG;

	XMEMCPY(in, x509->serial, x509->serialSz);
	*inOutSz = x509->serialSz;

	return SSL_SUCCESS;
}


const byte* wolfSSL_X509_get_der(WOLFSSL_X509* x509, int* outSz)
{
	WOLFSSL_ENTER();

	if (x509 == NULL || outSz == NULL)
	return NULL;

	*outSz = (int)x509->derCert.length;
	return x509->derCert.buffer;
}


int wolfSSL_X509_version(WOLFSSL_X509* x509)
{
	WOLFSSL_ENTER();

	if (x509 == NULL)
	return 0;

	return x509->version;
}


const byte* wolfSSL_X509_notBefore(WOLFSSL_X509* x509)
{
WOLFSSL_ENTER();

if (x509 == NULL)
return NULL;

return x509->notBefore;
}


const byte* wolfSSL_X509_notAfter(WOLFSSL_X509* x509)
{
WOLFSSL_ENTER();

if (x509 == NULL)
return NULL;

return x509->notAfter;
}


#ifdef WOLFSSL_SEP

/* copy oid into in buffer, at most *inOutSz bytes, if buffer is null will
malloc buffer, call responsible for freeing. Actual size returned in
*inOutSz. Requires inOutSz be non-null */
byte* wolfSSL_X509_get_device_type(WOLFSSL_X509* x509, byte* in, int *inOutSz)
{
	int copySz;

	WOLFSSL_ENTER();
	if (inOutSz == NULL) return NULL;
	if (!x509->deviceTypeSz) return in;

	copySz = min(*inOutSz, x509->deviceTypeSz);

	if (!in) {
	in = (byte*)XMALLOC(x509->deviceTypeSz, 0, DYNAMIC_TYPE_OPENSSL);
	if (!in) return in;
	copySz = x509->deviceTypeSz;
	}

	XMEMCPY(in, x509->deviceType, copySz);
	*inOutSz = copySz;

	return in;
}


byte* wolfSSL_X509_get_hw_type(WOLFSSL_X509* x509, byte* in, int* inOutSz)
{
	int copySz;

	WOLFSSL_ENTER();
	if (inOutSz == NULL) return NULL;
	if (!x509->hwTypeSz) return in;

	copySz = min(*inOutSz, x509->hwTypeSz);

	if (!in) {
	in = (byte*)XMALLOC(x509->hwTypeSz, 0, DYNAMIC_TYPE_OPENSSL);
	if (!in) return in;
	copySz = x509->hwTypeSz;
	}

	XMEMCPY(in, x509->hwType, copySz);
	*inOutSz = copySz;

	return in;
}


byte* wolfSSL_X509_get_hw_serial_number(WOLFSSL_X509* x509,byte* in,int* inOutSz)
{
	int copySz;

	WOLFSSL_ENTER();
	if (inOutSz == NULL) return NULL;
	if (!x509->hwTypeSz) return in;

	copySz = min(*inOutSz, x509->hwSerialNumSz);

	if (!in) {
	in = (byte*)XMALLOC(x509->hwSerialNumSz, 0, DYNAMIC_TYPE_OPENSSL);
	if (!in) return in;
	copySz = x509->hwSerialNumSz;
	}

	XMEMCPY(in, x509->hwSerialNum, copySz);
	*inOutSz = copySz;

	return in;
}

#endif /* WOLFSSL_SEP */


WOLFSSL_X509* wolfSSL_X509_d2i(WOLFSSL_X509** x509, const byte* in, int len)
{
	WOLFSSL_X509 *newX509 = NULL;

	WOLFSSL_ENTER();

	if (in != NULL && len != 0) {
#ifdef WOLFSSL_SMALL_STACK
		DecodedCert* cert = NULL;
#else
		DecodedCert  cert[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
		cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (cert == NULL)
		return NULL;
#endif

		InitDecodedCert(cert, (byte*)in, len, NULL);
		if (ParseCertRelative(cert, CERT_TYPE, 0, NULL) == 0) {
		newX509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL, DYNAMIC_TYPE_X509);
		if (newX509 != NULL) {
		InitX509(newX509, 1);
		if (CopyDecodedToX509(newX509, cert) != 0) {
		XFREE(newX509, NULL, DYNAMIC_TYPE_X509);
		newX509 = NULL;
		}
		}
		}
		FreeDecodedCert(cert);
#ifdef WOLFSSL_SMALL_STACK
		XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
	}

	if (x509 != NULL)
	*x509 = newX509;

	return newX509;
}


#ifndef NO_FILESYSTEM

#ifndef NO_STDIO_FILESYSTEM

WOLFSSL_X509* wolfSSL_X509_d2i_fp(WOLFSSL_X509** x509, XFILE file)
{
	WOLFSSL_X509* newX509 = NULL;

	WOLFSSL_ENTER();

	if (file != XBADFILE)
	{
	byte* fileBuffer = NULL;
	long sz = 0;

	XFSEEK(file, 0, XSEEK_END);
	sz = XFTELL(file);
	XREWIND(file);

	if (sz < 0) {
	WOLFSSL_MSG("Bad tell on FILE");
	return NULL;
	}

	fileBuffer = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE);
	if (fileBuffer != NULL) {
	int ret = (int)XFREAD(fileBuffer, sz, 1, file);
	if (ret > 0) {
	newX509 = wolfSSL_X509_d2i(NULL, fileBuffer, (int)sz);
	}
	XFREE(fileBuffer, NULL, DYNAMIC_TYPE_FILE);
	}
	}

	if (x509 != NULL)
	*x509 = newX509;

	return newX509;
	}

#endif /* NO_STDIO_FILESYSTEM */

WOLFSSL_X509* wolfSSL_X509_load_certificate_file(const char* fname, int format)
{
#ifdef WOLFSSL_SMALL_STACK
	byte  staticBuffer[1]; /* force heap usage */
#else
	byte  staticBuffer[FILE_BUFFER_SIZE];
#endif
	byte* fileBuffer = staticBuffer;
	int   dynamic = 0;
	int   ret;
	long  sz = 0;
	XFILE file;

	WOLFSSL_X509* x509 = NULL;
	buffer der;

	WOLFSSL_ENTER();

	/* Check the inputs */
	if ((fname == NULL) ||(format != SSL_FILETYPE_ASN1 && format != SSL_FILETYPE_PEM))
		return NULL;

	file = XFOPEN(fname, "rb");
	if (file == XBADFILE)
		return NULL;

	XFSEEK(file, 0, XSEEK_END);
	sz = XFTELL(file);
	XREWIND(file);

	if (sz > (long)sizeof(staticBuffer))
	{
		fileBuffer = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE);
		if (fileBuffer == NULL) {
			XFCLOSE(file);
			return NULL;
		}
		dynamic = 1;
	}
	else if (sz < 0) {
		XFCLOSE(file);
		return NULL;
	}

	ret = (int)XFREAD(fileBuffer, sz, 1, file);
	if (ret < 0) {
		XFCLOSE(file);
		if (dynamic)
		XFREE(fileBuffer, NULL, DYNAMIC_TYPE_FILE);
		return NULL;
	}

	XFCLOSE(file);

	der.buffer = NULL;
	der.length = 0;

	if (format == SSL_FILETYPE_PEM) {
	int ecc = 0;
#ifdef WOLFSSL_SMALL_STACK
	EncryptedInfo* info = NULL;
#else
	EncryptedInfo  info[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
	info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
	                               DYNAMIC_TYPE_TMP_BUFFER);
	if (info == NULL) {
	if (dynamic)
	XFREE(fileBuffer, NULL, DYNAMIC_TYPE_FILE);

	return NULL;
	}
#endif

	info->set = 0;
	info->ctx = NULL;
	info->consumed = 0;

	if (PemToDer(fileBuffer, sz, CERT_TYPE, &der, NULL, info, &ecc) != 0)
	{
	/* Only time this should fail, and leave `der` with a buffer
	is when the Base64 Decode fails. Release `der.buffer` in
	that case. */
	if (der.buffer != NULL) {
	XFREE(der.buffer, NULL, DYNAMIC_TYPE_CERT);
	der.buffer = NULL;
	}
	}

#ifdef WOLFSSL_SMALL_STACK
	XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
	}
	else {
	der.buffer = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_CERT);
	if (der.buffer != NULL) {
	XMEMCPY(der.buffer, fileBuffer, sz);
	der.length = (word32)sz;
	}
	}

	if (dynamic)
	XFREE(fileBuffer, NULL, DYNAMIC_TYPE_FILE);

	/* At this point we want `der` to have the certificate in DER format */
	/* ready to be decoded. */
	if (der.buffer != NULL) {
#ifdef WOLFSSL_SMALL_STACK
	DecodedCert* cert = NULL;
#else
	DecodedCert  cert[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
	cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
	                               DYNAMIC_TYPE_TMP_BUFFER);
	if (cert != NULL)
#endif
	{
	InitDecodedCert(cert, der.buffer, der.length, NULL);
	if (ParseCertRelative(cert, CERT_TYPE, 0, NULL) == 0) {
	x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
	                                     DYNAMIC_TYPE_X509);
	if (x509 != NULL) {
	InitX509(x509, 1);
	if (CopyDecodedToX509(x509, cert) != 0) {
	XFREE(x509, NULL, DYNAMIC_TYPE_X509);
	x509 = NULL;
	}
	}
	}

	FreeDecodedCert(cert);
#ifdef WOLFSSL_SMALL_STACK
	XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
	}

	XFREE(der.buffer, NULL, DYNAMIC_TYPE_CERT);
	}

	return x509;
}

#endif /* NO_FILESYSTEM */

#endif /* KEEP_PEER_CERT || SESSION_CERTS */


