
#include "cmnSsl.h"

#ifndef NO_CERTS

/* hash is the SHA digest of name, just use first 32 bits as hash */
static INLINE word32 _hashSigner(const byte* hash)
{
	return MakeWordFromHash(hash) % CA_TABLE_SIZE;
}


/* does CA already exist on signer list */
int AlreadySigner(WOLFSSL_CERT_MANAGER* cm, byte* hash)
{
	Signer* signers;
	int     ret = 0;
	word32  row = _hashSigner(hash);

	if (LockMutex(&cm->caLock) != 0)
		return  ret;
	
	signers = cm->caTable[row];
	while (signers) {
		byte* subjectHash;
#ifndef NO_SKID
		subjectHash = signers->subjectKeyIdHash;
#else
		subjectHash = signers->subjectNameHash;
#endif
		if (XMEMCMP(hash, subjectHash, SIGNER_DIGEST_SIZE) == 0) {
			ret = 1;
			break;
		}
		signers = signers->next;
	}
	UnLockMutex(&cm->caLock);

	return ret;
}


/* return CA if found, otherwise NULL 
* it is called in certificate library, and it is locked with SSL mutex????
*/
Signer* GetCA(void* vp, byte* hash)
{
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    word32  row = _hashSigner(hash);

    if (cm == NULL)
        return NULL;

    if (LockMutex(&cm->caLock) != 0)
        return ret;

    signers = cm->caTable[row];
    while (signers) {
        byte* subjectHash;
        #ifndef NO_SKID
            subjectHash = signers->subjectKeyIdHash;
        #else
            subjectHash = signers->subjectNameHash;
        #endif
        if (XMEMCMP(hash, subjectHash, SIGNER_DIGEST_SIZE) == 0) {
            ret = signers;
            break;
        }
        signers = signers->next;
    }
    UnLockMutex(&cm->caLock);

    return ret;
}


#ifndef NO_SKID
/* return CA if found, otherwise NULL. Walk through hash table. */
Signer* GetCAByName(void* vp, byte* hash)
{
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    word32  row;

    if (cm == NULL)
        return NULL;

    if (LockMutex(&cm->caLock) != 0)
        return ret;

    for (row = 0; row < CA_TABLE_SIZE && ret == NULL; row++) {
        signers = cm->caTable[row];
        while (signers && ret == NULL) {
            if (XMEMCMP(hash, signers->subjectNameHash, SIGNER_DIGEST_SIZE) == 0) {
                ret = signers;
            }
            signers = signers->next;
        }
    }
    UnLockMutex(&cm->caLock);

    return ret;
}
#endif


/* owns der, internal now uses too */
/* type flag ids from user or from chain received during verify
   don't allow chain ones to be added w/o isCA extension */
/* DER is buffer of CA certificate, which is needed to added into CertificateManager->caTable[] */   
int AddCA(WOLFSSL_CERT_MANAGER* cm, buffer der, int type, int verify)
{
	int         ret;
	Signer*     signer = 0;
	word32      row;
	byte*       subjectHash;
#ifdef WOLFSSL_SMALL_STACK
	DecodedCert* cert = NULL;
#else
	DecodedCert  cert[1];
#endif

	WOLFSSL_ENTER();

#ifdef WOLFSSL_SMALL_STACK
	cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (cert == NULL)
		return MEMORY_E;
#endif

	InitDecodedCert(cert, der.buffer, der.length, cm->heap);
	ret = ParseCert(cert, CA_TYPE, verify, cm);
	WOLFSSL_MSG("    Parsed new CA");

#ifndef NO_SKID
	subjectHash = cert->extSubjKeyId;
#else
	subjectHash = cert->subjectHash;
#endif

	if (ret == 0 && cert->isCA == 0 && type != WOLFSSL_USER_CA) {
	WOLFSSL_MSG("    Can't add as CA if not actually one");
	ret = NOT_CA_ERROR;
	}
#ifndef ALLOW_INVALID_CERTSIGN
	else if (ret == 0 && cert->isCA == 1 && type != WOLFSSL_USER_CA &&
	      (cert->extKeyUsage & KEYUSE_KEY_CERT_SIGN) == 0) {
	/* Intermediate CA certs are required to have the keyCertSign
	* extension set. User loaded root certs are not. */
	WOLFSSL_MSG("    Doesn't have key usage certificate signing");
	ret = NOT_CA_ERROR;
	}
#endif
	else if (ret == 0 && AlreadySigner(cm, subjectHash)) {
	WOLFSSL_MSG("    Already have this CA, not adding again");
	(void)ret;
	}
	else if (ret == 0) {
	/* take over signer parts */
	signer = MakeSigner(cm->heap);
	if (!signer)
	ret = MEMORY_ERROR;
	else {
	signer->keyOID         = cert->keyOID;
	signer->publicKey      = cert->publicKey;
	signer->pubKeySize     = cert->pubKeySize;
	signer->nameLen        = cert->subjectCNLen;
	signer->name           = cert->subjectCN;
#ifndef IGNORE_NAME_CONSTRAINTS
	signer->permittedNames = cert->permittedNames;
	signer->excludedNames  = cert->excludedNames;
#endif
#ifndef NO_SKID
	XMEMCPY(signer->subjectKeyIdHash, cert->extSubjKeyId,
	                                    SIGNER_DIGEST_SIZE);
#endif
	XMEMCPY(signer->subjectNameHash, cert->subjectHash,
	                                    SIGNER_DIGEST_SIZE);
	signer->keyUsage = cert->extKeyUsageSet ? cert->extKeyUsage
	                            : 0xFFFF;
	signer->next    = NULL; /* If Key Usage not set, all uses valid. */
	cert->publicKey = 0;    /* in case lock fails don't free here.   */
	cert->subjectCN = 0;
#ifndef IGNORE_NAME_CONSTRAINTS
	cert->permittedNames = NULL;
	cert->excludedNames = NULL;
#endif

#ifndef NO_SKID
	row = _hashSigner(signer->subjectKeyIdHash);
#else
	row = _hashSigner(signer->subjectNameHash);
#endif

	if (LockMutex(&cm->caLock) == 0) {
	signer->next = cm->caTable[row];
	cm->caTable[row] = signer;   /* takes ownership */
	UnLockMutex(&cm->caLock);
	if (cm->caCacheCallback)
	cm->caCacheCallback(der.buffer, (int)der.length, type);
	}
	else {
	WOLFSSL_MSG("    CA Mutex Lock failed");
	ret = BAD_MUTEX_E;
	FreeSigner(signer, cm->heap);
	}
	}
	}

	WOLFSSL_MSG("    Freeing Parsed CA");
	FreeDecodedCert(cert);
#ifdef WOLFSSL_SMALL_STACK
	XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
	WOLFSSL_MSG("    Freeing der CA");
	XFREE(der.buffer, cm->heap, DYNAMIC_TYPE_CA);
	WOLFSSL_MSG("        OK Freeing der CA");

	WOLFSSL_LEAVE( ret);

	return ret == 0 ? SSL_SUCCESS : ret;
	}

#endif /* !NO_CERTS */

