
#include "cmnCrypto.h"

#include "_asnCertEncoding.h"

#ifdef WOLFSSL_CERT_GEN

int makeAnyCert(Cert* cert, byte* derBuffer, word32 derSz,
                       RsaKey* rsaKey, ecc_key* eccKey, RNG* rng,
                       const byte* ntruKey, word16 ntruSz);

#ifdef HAVE_NTRU
int wc_MakeNtruCert(Cert* cert, byte* derBuffer, word32 derSz, const byte* ntruKey, word16 keySz, RNG* rng)
{
	return makeAnyCert(cert, derBuffer, derSz, NULL, NULL, rng, ntruKey, keySz);
}
#endif /* HAVE_NTRU */



/* Make an x509 Certificate v3 RSA or ECC from cert input, write to buffer */
int wc_MakeCert(Cert* cert, byte* derBuffer, word32 derSz, RsaKey* rsaKey, ecc_key* eccKey, RNG* rng)
{
	return makeAnyCert(cert, derBuffer, derSz, rsaKey, eccKey, rng, NULL, 0);
}


/* Make RSA signature from buffer (sz), write to sig (sigSz) */
static int _MakeSignature(const byte* buffer, int sz, byte* sig, int sigSz, RsaKey* rsaKey, ecc_key* eccKey, RNG* rng, int sigAlgoType)
{
	int encSigSz, digestSz, typeH = 0, ret = 0;
	byte digest[SHA256_DIGEST_SIZE]; /* max size */
#ifdef WOLFSSL_SMALL_STACK
	byte* encSig;
#else
	byte encSig[MAX_ENCODED_DIG_SZ + MAX_ALGO_SZ + MAX_SEQ_SZ];
#endif

	(void)digest;
	(void)digestSz;
	(void)encSig;
	(void)encSigSz;
	(void)typeH;

	(void)buffer;
	(void)sz;
	(void)sig;
	(void)sigSz;
	(void)rsaKey;
	(void)eccKey;
	(void)rng;

	switch (sigAlgoType) {
#ifndef NO_MD5
		case CTC_MD5wRSA:
			if ((ret = wc_Md5Hash(buffer, sz, digest)) == 0) {
				typeH    = MD5h;
				digestSz = MD5_DIGEST_SIZE;
			}
			break;
#endif
#ifndef NO_SHA
		case CTC_SHAwRSA:
		case CTC_SHAwECDSA:
			if ((ret = wc_ShaHash(buffer, sz, digest)) == 0) {
				typeH    = SHAh;
				digestSz = SHA_DIGEST_SIZE;          
			}
			break;
#endif
#ifndef NO_SHA256
		case CTC_SHA256wRSA:
		case CTC_SHA256wECDSA:
			if ((ret = wc_Sha256Hash(buffer, sz, digest)) == 0) {
				typeH    = SHA256h;
				digestSz = SHA256_DIGEST_SIZE;
			}
			break;
#endif
		default:
			WOLFSSL_MSG("MakeSignautre called with unsupported type");
			ret = ALGO_ID_E;
	}

	if (ret != 0)
		return ret;

#ifdef WOLFSSL_SMALL_STACK
	encSig = (byte*)XMALLOC(MAX_ENCODED_DIG_SZ + MAX_ALGO_SZ + MAX_SEQ_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (encSig == NULL)
		return MEMORY_E;
#endif

	ret = ALGO_ID_E;

#ifndef NO_RSA
	if (rsaKey) {
		/* signature */
		encSigSz = wc_EncodeSignature(encSig, digest, digestSz, typeH);
		ret = wc_RsaSSL_Sign(encSig, encSigSz, sig, sigSz, rsaKey, rng);
	}
#endif

#ifdef HAVE_ECC
	if (!rsaKey && eccKey) {
		word32 outSz = sigSz;
		ret = wc_ecc_sign_hash(digest, digestSz, sig, &outSz, rng, eccKey);
		if (ret == 0)
			ret = outSz;
	}
#endif

#ifdef WOLFSSL_SMALL_STACK
	XFREE(encSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

	return ret;
}


/* add signature to end of buffer, size of buffer assumed checked, return new length */
static int _AddSignature(byte* buffer, int bodySz, const byte* sig, int sigSz, int sigAlgoType)
{
	byte seq[MAX_SEQ_SZ];
	int  idx = bodySz, seqSz;

	/* algo */
	idx += SetAlgoID(sigAlgoType, buffer + idx, sigType, 0);
	/* bit string */
	buffer[idx++] = ASN_BIT_STRING;
	/* length */
	idx += SetLength(sigSz + 1, buffer + idx);
	buffer[idx++] = 0;   /* trailing 0 */
	/* signature */
	XMEMCPY(buffer + idx, sig, sigSz);
	idx += sigSz;

	/* make room for overall header */
	seqSz = SetSequence(idx, seq);
	XMEMMOVE(buffer + seqSz, buffer, idx);
	XMEMCPY(buffer, seq, seqSz);

	return idx + seqSz;
}


int wc_SignCert(int requestSz, int sType, byte* buffer, word32 buffSz, RsaKey* rsaKey, ecc_key* eccKey, RNG* rng)
{
	int sigSz;
#ifdef WOLFSSL_SMALL_STACK
	byte* sig;
#else
	byte sig[MAX_ENCODED_SIG_SZ];
#endif

	if (requestSz < 0)
		return requestSz;

#ifdef WOLFSSL_SMALL_STACK
	sig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (sig == NULL)
		return MEMORY_E;
#endif

	sigSz = _MakeSignature(buffer, requestSz, sig, MAX_ENCODED_SIG_SZ, rsaKey, eccKey, rng, sType);
	if (sigSz >= 0) {
		if (requestSz + MAX_SEQ_SZ * 2 + sigSz > (int)buffSz)
			sigSz = BUFFER_E;
		else
			sigSz = _AddSignature(buffer, requestSz, sig, sigSz, sType);
	}

#ifdef WOLFSSL_SMALL_STACK
	XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

	return sigSz;
}


int wc_MakeSelfCert(Cert* cert, byte* buffer, word32 buffSz, RsaKey* key, RNG* rng)
{
	int ret = wc_MakeCert(cert, buffer, buffSz, key, NULL, rng);
	if (ret < 0)
		return ret;

	return wc_SignCert(cert->bodySz, cert->sigType, buffer, buffSz, key, NULL,rng);
}



/* Initialize and Set Certficate defaults:
   version    = 3 (0x2)
   serial     = 0
   sigType    = SHA_WITH_RSA
   issuer     = blank
   daysValid  = 500
   selfSigned = 1 (true) use subject as issuer
   subject    = blank
*/
void wc_InitCert(Cert* cert)
{
    cert->version    = 2;   /* version 3 is hex 2 */
    cert->sigType    = CTC_SHAwRSA;
    cert->daysValid  = 500;
    cert->selfSigned = 1;
    cert->isCA       = 0;
    cert->bodySz     = 0;
#ifdef WOLFSSL_ALT_NAMES
    cert->altNamesSz   = 0;
    cert->beforeDateSz = 0;
    cert->afterDateSz  = 0;
#endif
    cert->keyType    = RSA_KEY;
    XMEMSET(cert->serial, 0, CTC_SERIAL_SIZE);

    cert->issuer.country[0] = '\0';
    cert->issuer.countryEnc = CTC_PRINTABLE;
    cert->issuer.state[0] = '\0';
    cert->issuer.stateEnc = CTC_UTF8;
    cert->issuer.locality[0] = '\0';
    cert->issuer.localityEnc = CTC_UTF8;
    cert->issuer.sur[0] = '\0';
    cert->issuer.surEnc = CTC_UTF8;
    cert->issuer.org[0] = '\0';
    cert->issuer.orgEnc = CTC_UTF8;
    cert->issuer.unit[0] = '\0';
    cert->issuer.unitEnc = CTC_UTF8;
    cert->issuer.commonName[0] = '\0';
    cert->issuer.commonNameEnc = CTC_UTF8;
    cert->issuer.email[0] = '\0';

    cert->subject.country[0] = '\0';
    cert->subject.countryEnc = CTC_PRINTABLE;
    cert->subject.state[0] = '\0';
    cert->subject.stateEnc = CTC_UTF8;
    cert->subject.locality[0] = '\0';
    cert->subject.localityEnc = CTC_UTF8;
    cert->subject.sur[0] = '\0';
    cert->subject.surEnc = CTC_UTF8;
    cert->subject.org[0] = '\0';
    cert->subject.orgEnc = CTC_UTF8;
    cert->subject.unit[0] = '\0';
    cert->subject.unitEnc = CTC_UTF8;
    cert->subject.commonName[0] = '\0';
    cert->subject.commonNameEnc = CTC_UTF8;
    cert->subject.email[0] = '\0';

#ifdef WOLFSSL_CERT_REQ
    cert->challengePw[0] ='\0';
#endif
}

#endif

