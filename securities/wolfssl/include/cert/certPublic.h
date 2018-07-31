/* definations and declarations about certificate
 */


#ifndef __CERT_PUBLIC_H__
#define __CERT_PUBLIC_H__

#include <wccTypes.h>

#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#if defined(WOLFSSL_CERT_GEN) && !defined(NO_RSA)
    #include <wckRsa.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

enum {
    ISSUER  = 0,
    SUBJECT = 1,

    EXTERNAL_SERIAL_SIZE = 32,

    BEFORE  = 0,
    AFTER   = 1
};

/* Certificate file Type */
typedef	enum CertType {
	CERT_TYPE       = 0,
	PRIVATEKEY_TYPE,
	DH_PARAM_TYPE,
	CRL_TYPE,
	CA_TYPE,
	ECC_PRIVATEKEY_TYPE,
	CERTREQ_TYPE
}CERT_TYPE_T;


/* Signature type, by OID sum */
enum Ctc_SigType {
    CTC_SHAwDSA      = 517,
    CTC_MD2wRSA      = 646,
    CTC_MD5wRSA      = 648,
    CTC_SHAwRSA      = 649,
    CTC_SHAwECDSA    = 520,
    CTC_SHA256wRSA   = 655,
    CTC_SHA256wECDSA = 524,
    CTC_SHA384wRSA   = 656,
    CTC_SHA384wECDSA = 525,
    CTC_SHA512wRSA   = 657,
    CTC_SHA512wECDSA = 526
};

enum Ctc_Encoding {
    CTC_UTF8       = 0x0c, /* utf8      */
    CTC_PRINTABLE  = 0x13  /* printable */
};


#ifdef WOLFSSL_CERT_GEN

#ifndef HAVE_ECC
    typedef struct ecc_key ecc_key;
#endif

enum Ctc_Misc {
    CTC_NAME_SIZE    =    64,
    CTC_DATE_SIZE    =    32,
    CTC_MAX_ALT_SIZE = 16384,   /* may be huge */
    CTC_SERIAL_SIZE  =     8
};

typedef struct CertName {
    char country[CTC_NAME_SIZE];
    char countryEnc;
    char state[CTC_NAME_SIZE];
    char stateEnc;
    char locality[CTC_NAME_SIZE];
    char localityEnc;
    char sur[CTC_NAME_SIZE];
    char surEnc;
    char org[CTC_NAME_SIZE];
    char orgEnc;
    char unit[CTC_NAME_SIZE];
    char unitEnc;
    char commonName[CTC_NAME_SIZE];
    char commonNameEnc;
    char email[CTC_NAME_SIZE];  /* !!!! email has to be last !!!! */
} CertName;


/* for user to fill for certificate generation */
typedef struct Cert {
    int      version;                   /* x509 version  */
    byte     serial[CTC_SERIAL_SIZE];   /* serial number */
    int      sigType;                   /* signature algo type */
    CertName issuer;                    /* issuer info */
    int      daysValid;                 /* validity days */
    int      selfSigned;                /* self signed flag */
    CertName subject;                   /* subject info */
    int      isCA;                      /* is this going to be a CA */
    /* internal use only */
    int      bodySz;                    /* pre sign total size */
    int      keyType;                   /* public key type of subject */
#ifdef WOLFSSL_ALT_NAMES
    byte     altNames[CTC_MAX_ALT_SIZE]; /* altNames copy */
    int      altNamesSz;                 /* altNames size in bytes */
    byte     beforeDate[CTC_DATE_SIZE];  /* before date copy */
    int      beforeDateSz;               /* size of copy */
    byte     afterDate[CTC_DATE_SIZE];   /* after date copy */
    int      afterDateSz;                /* size of copy */
#endif
#ifdef WOLFSSL_CERT_REQ
    char     challengePw[CTC_NAME_SIZE];
#endif
} Cert;
#endif /* WOLFSSL_CERT_GEN */


#ifdef WOLFSSL_CERT_GEN



/* Initialize and Set Certficate defaults:
   version    = 3 (0x2)
   serial     = 0 (Will be randomly generated)
   sigType    = SHA_WITH_RSA
   issuer     = blank
   daysValid  = 500
   selfSigned = 1 (true) use subject as issuer
   subject    = blank
   isCA       = 0 (false)
   keyType    = RSA_KEY (default)
*/
WOLFSSL_API void wc_InitCert(Cert*);
WOLFSSL_API int  wc_MakeCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*,  ecc_key*, RNG*);

#ifdef WOLFSSL_CERT_REQ
    WOLFSSL_API int  certMakeCertReq(byte* derBuffer, word32 derSz, Cert*, RsaKey*, ecc_key*);
#endif
WOLFSSL_API int  wc_SignCert(int requestSz, int sigType, byte* derBuffer, word32 derSz, RsaKey*, ecc_key*, RNG*);
WOLFSSL_API int  wc_MakeSelfCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*, RNG*);
WOLFSSL_API int  wc_SetIssuer(Cert*, const char*);
WOLFSSL_API int  wc_SetSubject(Cert*, const char*);
#ifdef WOLFSSL_ALT_NAMES
    WOLFSSL_API int  wc_SetAltNames(Cert*, const char*);
#endif
WOLFSSL_API int  wc_SetIssuerBuffer(Cert*, const byte*, int);
WOLFSSL_API int  wc_SetSubjectBuffer(Cert*, const byte*, int);
WOLFSSL_API int  wc_SetAltNamesBuffer(Cert*, const byte*, int);
WOLFSSL_API int  wc_SetDatesBuffer(Cert*, const byte*, int);

    #ifdef HAVE_NTRU
        WOLFSSL_API int  wc_MakeNtruCert(Cert*, byte* derBuffer, word32 derSz, const byte* ntruKey, word16 keySz, RNG*);
    #endif

#endif /* WOLFSSL_CERT_GEN */


#if defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_CERT_GEN)
    WOLFSSL_API int wc_DerToPem(const byte* der, word32 derSz, byte* output, word32 outputSz, int type);
#endif

#ifdef HAVE_ECC
    /* private key helpers */
    WOLFSSL_API int wc_EccPrivateKeyDecode(const byte* input,word32* inOutIdx, ecc_key*,word32);
    WOLFSSL_API int wc_EccKeyToDer(ecc_key*, byte* output, word32 inLen);
#endif

/* DER encode signature */
WOLFSSL_API word32 wc_EncodeSignature(byte* out, const byte* digest, word32 digSz, int hashOID);
WOLFSSL_API int wc_GetCTC_HashOID(int type);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_ASN_PUBLIC_H */

