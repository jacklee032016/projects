/* asn.h
 *
 */

#ifndef __CERT_ASN_H__
#define __CERT_ASN_H__

#include <wccTypes.h>

#ifndef NO_ASN

#include <wccInteger.h>
#ifndef NO_RSA
    #include <wckRsa.h>
#endif

/* fips declare of RsaPrivateKeyDecode @wc_fips */
#if defined(HAVE_FIPS) && !defined(NO_RSA)
    #include <cyassl/ctaocrypt/rsa.h>
#endif

#ifndef NO_DH
    #include <wckDh.h>
#endif
#ifndef NO_DSA
    #include <wckDsa.h>
#endif
#ifndef NO_SHA
    #include <wchSha.h>
#endif
#ifndef NO_MD5
    #include <wchMd5.h>
#endif
#include <wchSha256.h>

#ifdef HAVE_ECC
#include <wckEcc.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif


/* ASN Tags   */
enum ASN_Tags {
    ASN_BOOLEAN           = 0x01,
    ASN_INTEGER           = 0x02,
    ASN_BIT_STRING        = 0x03,
    ASN_OCTET_STRING      = 0x04,
    ASN_TAG_NULL          = 0x05,
    ASN_OBJECT_ID         = 0x06,
    ASN_ENUMERATED        = 0x0a,
    ASN_UTF8STRING        = 0x0c,
    ASN_SEQUENCE          = 0x10,
    ASN_SET               = 0x11,
    ASN_UTC_TIME          = 0x17,
    ASN_OTHER_TYPE        = 0x00,
    ASN_RFC822_TYPE       = 0x01,
    ASN_DNS_TYPE          = 0x02,
    ASN_DIR_TYPE          = 0x04,
    ASN_GENERALIZED_TIME  = 0x18,
    CRL_EXTENSIONS        = 0xa0,
    ASN_EXTENSIONS        = 0xa3,
    ASN_LONG_LENGTH       = 0x80
};

enum  ASN_Flags{
    ASN_CONSTRUCTED       = 0x20,
    ASN_CONTEXT_SPECIFIC  = 0x80
};

enum DN_Tags {
    ASN_COMMON_NAME   = 0x03,   /* CN */
    ASN_SUR_NAME      = 0x04,   /* SN */
    ASN_SERIAL_NUMBER = 0x05,   /* serialNumber */
    ASN_COUNTRY_NAME  = 0x06,   /* C  */
    ASN_LOCALITY_NAME = 0x07,   /* L  */
    ASN_STATE_NAME    = 0x08,   /* ST */
    ASN_ORG_NAME      = 0x0a,   /* O  */
    ASN_ORGUNIT_NAME  = 0x0b    /* OU */
};

enum PBES {
    PBE_MD5_DES      = 0,
    PBE_SHA1_DES     = 1,
    PBE_SHA1_DES3    = 2,
    PBE_SHA1_RC4_128 = 3,
    PBES2            = 13       /* algo ID */
};

enum ENCRYPTION_TYPES {
    DES_TYPE  = 0,
    DES3_TYPE = 1,
    RC4_TYPE  = 2
};

enum ECC_TYPES {
    ECC_PREFIX_0 = 160,
    ECC_PREFIX_1 = 161
};

enum Misc_ASN {
    ASN_NAME_MAX        = 256,
    MAX_SALT_SIZE       =  64,     /* MAX PKCS Salt length */
    MAX_IV_SIZE         =  64,     /* MAX PKCS Iv length */
    MAX_KEY_SIZE        =  64,     /* MAX PKCS Key  length */
    PKCS5               =   5,     /* PKCS oid tag */
    PKCS5v2             =   6,     /* PKCS #5 v2.0 */
    PKCS12              =  12,     /* PKCS #12 */
    MAX_UNICODE_SZ      = 256,
    ASN_BOOL_SIZE       =   2,     /* including type */
    ASN_ECC_HEADER_SZ   =   2,     /* String type + 1 byte len */
    ASN_ECC_CONTEXT_SZ  =   2,     /* Content specific type + 1 byte len */
#ifdef NO_SHA
    KEYID_SIZE          = SHA256_DIGEST_SIZE,
#else
    KEYID_SIZE          = SHA_DIGEST_SIZE,
#endif
    RSA_INTS            =   8,     /* RSA ints in private key */
    MIN_DATE_SIZE       =  13,
    MAX_DATE_SIZE       =  32,
    ASN_GEN_TIME_SZ     =  15,     /* 7 numbers * 2 + Zulu tag */
    MAX_ENCODED_SIG_SZ  = 512,
    MAX_SIG_SZ          = 256,
    MAX_ALGO_SZ         =  20,
    MAX_SEQ_SZ          =   5,     /* enum(seq | con) + length(4) */
    MAX_SET_SZ          =   5,     /* enum(set | con) + length(4) */
    MAX_OCTET_STR_SZ    =   5,     /* enum(set | con) + length(4) */
    MAX_EXP_SZ          =   5,     /* enum(contextspec|con|exp) + length(4) */
    MAX_PRSTR_SZ        =   5,     /* enum(prstr) + length(4) */
    MAX_VERSION_SZ      =   5,     /* enum + id + version(byte) + (header(2))*/
    MAX_ENCODED_DIG_SZ  =  73,     /* sha512 + enum(bit or octet) + legnth(4) */
    MAX_RSA_INT_SZ      = 517,     /* RSA raw sz 4096 for bits + tag + len(4) */
    MAX_NTRU_KEY_SZ     = 610,     /* NTRU 112 bit public key */
    MAX_NTRU_ENC_SZ     = 628,     /* NTRU 112 bit DER public encoding */
    MAX_LENGTH_SZ       =   4,     /* Max length size for DER encoding */
    MAX_RSA_E_SZ        =  16,     /* Max RSA public e size */
    MAX_CA_SZ           =  32,     /* Max encoded CA basic constraint length */
    MAX_SN_SZ           =  35,     /* Max encoded serial number (INT) length */
#ifdef WOLFSSL_CERT_GEN
    #ifdef WOLFSSL_CERT_REQ
                          /* Max encoded cert req attributes length */
        MAX_ATTRIB_SZ   = MAX_SEQ_SZ * 3 + (11 + MAX_SEQ_SZ) * 2 +
                          MAX_PRSTR_SZ + CTC_NAME_SIZE, /* 11 is the OID size */
    #endif
    #ifdef WOLFSSL_ALT_NAMES
        MAX_EXTENSIONS_SZ   = 1 + MAX_LENGTH_SZ + CTC_MAX_ALT_SIZE,
    #else
        MAX_EXTENSIONS_SZ   = 1 + MAX_LENGTH_SZ + MAX_CA_SZ,
    #endif
                                   /* Max total extensions, id + len + others */
#endif
    MAX_OCSP_EXT_SZ     = 58,      /* Max OCSP Extension length */
    MAX_OCSP_NONCE_SZ   = 18,      /* OCSP Nonce size           */
    EIGHTK_BUF          = 8192,    /* Tmp buffer size           */
    MAX_PUBLIC_KEY_SZ   = MAX_NTRU_ENC_SZ + MAX_ALGO_SZ + MAX_SEQ_SZ * 2
                                   /* use bigger NTRU size */
};


enum Oid_Types {
    hashType  = 0,
    sigType   = 1,
    keyType   = 2,
    curveType = 3,
    blkType   = 4
};


enum Hash_Sum  {
    MD2h    = 646,
    MD5h    = 649,
    SHAh    =  88,
    SHA256h = 414,
    SHA384h = 415,
    SHA512h = 416
};


enum Block_Sum {
    DESb  = 69,
    DES3b = 652
};


enum Key_Sum {
    DSAk   = 515,
    RSAk   = 645,
    NTRUk  = 274,
    ECDSAk = 518
};


enum Ecc_Sum {
    ECC_256R1 = 526,
    ECC_384R1 = 210,
    ECC_521R1 = 211,
    ECC_160R1 = 184,
    ECC_192R1 = 520,
    ECC_224R1 = 209
};


enum KDF_Sum {
    PBKDF2_OID = 660
};


enum Extensions_Sum {
    BASIC_CA_OID    = 133,
    ALT_NAMES_OID   = 131,
    CRL_DIST_OID    = 145,
    AUTH_INFO_OID   = 69,
    CA_ISSUER_OID   = 117,
    AUTH_KEY_OID    = 149,
    SUBJ_KEY_OID    = 128,
    CERT_POLICY_OID = 146,
    KEY_USAGE_OID   = 129,  /* 2.5.29.15 */
    INHIBIT_ANY_OID = 168,  /* 2.5.29.54 */
    EXT_KEY_USAGE_OID = 151, /* 2.5.29.37 */
    NAME_CONS_OID   = 144   /* 2.5.29.30 */
};

enum CertificatePolicy_Sum {
    CP_ANY_OID      = 146  /* id-ce 32 0 */
};

enum SepHardwareName_Sum {
    HW_NAME_OID     = 79   /* 1.3.6.1.5.5.7.8.4 from RFC 4108*/
};

enum AuthInfo_Sum {
    AIA_OCSP_OID      = 116, /* 1.3.6.1.5.5.7.48.1 */
    AIA_CA_ISSUER_OID = 117  /* 1.3.6.1.5.5.7.48.2 */
};

enum ExtKeyUsage_Sum { /* From RFC 5280 */
    EKU_ANY_OID         = 151, /* 2.5.29.37.0, anyExtendedKeyUsage         */
    EKU_SERVER_AUTH_OID = 71,  /* 1.3.6.1.5.5.7.3.1, id-kp-serverAuth      */
    EKU_CLIENT_AUTH_OID = 72,  /* 1.3.6.1.5.5.7.3.2, id-kp-clientAuth      */
    EKU_OCSP_SIGN_OID   = 79   /* 1.3.6.1.5.5.7.3.9, OCSPSigning           */
};


enum VerifyType {
    NO_VERIFY = 0,
    VERIFY    = 1
};


/* Key usage extension bits */
#define KEYUSE_DIGITAL_SIG    0x0100
#define KEYUSE_CONTENT_COMMIT 0x0080
#define KEYUSE_KEY_ENCIPHER   0x0040
#define KEYUSE_DATA_ENCIPHER  0x0020
#define KEYUSE_KEY_AGREE      0x0010
#define KEYUSE_KEY_CERT_SIGN  0x0008
#define KEYUSE_CRL_SIGN       0x0004
#define KEYUSE_ENCIPHER_ONLY  0x0002
#define KEYUSE_DECIPHER_ONLY  0x0001

#define EXTKEYUSE_ANY         0x08
#define EXTKEYUSE_OCSP_SIGN   0x04
#define EXTKEYUSE_CLIENT_AUTH 0x02
#define EXTKEYUSE_SERVER_AUTH 0x01


typedef struct DNS_entry {
	struct DNS_entry* next;   /* next on DNS list */
	char*      name;   /* actual DNS name */
}DNS_entry;



typedef struct Base_entry {
	struct Base_entry	*next;   /* next on name base list */
	char			*name;   /* actual name base */
	int			nameSz; /* name length */
	byte			type;   /* Name base type (DNS or RFC822) */
}Base_entry;


typedef	struct DecodedName
{
	char*   fullName;
	int     fullNameLen;
	int     entryCount;
	int     cnIdx;
	int     cnLen;
	int     snIdx;
	int     snLen;
	int     cIdx;
	int     cLen;
	int     lIdx;
	int     lLen;
	int     stIdx;
	int     stLen;
	int     oIdx;
	int     oLen;
	int     ouIdx;
	int     ouLen;
	int     emailIdx;
	int     emailLen;
	int     uidIdx;
	int     uidLen;
	int     serialIdx;
	int     serialLen;
}DecodedName;


typedef	struct DecodedCert
{
	byte		*publicKey;	/* point to the buffer of source */
	word32	pubKeySize;
	int		pubKeyStored;
	
	word32  certBegin;               /* offset to start of cert          */
	word32  sigIndex;                /* offset to start of signature     */
	word32  sigLength;               /* length of signature              */
	word32  signatureOID;            /* sum of algorithm object id       */
	word32  keyOID;                  /* sum of key algo  object id       */
	int     version;                 /* cert version, 1 or 3             */
	
	DNS_entry* altNames;             /* alt names list of dns entries    */
#ifndef IGNORE_NAME_CONSTRAINTS
	DNS_entry* altEmailNames;        /* alt names list of RFC822 entries */
	Base_entry* permittedNames;      /* Permitted name bases             */
	Base_entry* excludedNames;       /* Excluded name bases              */
#endif /* IGNORE_NAME_CONSTRAINTS */
	byte    subjectHash[KEYID_SIZE]; /* hash of all Names                */
	byte    issuerHash[KEYID_SIZE];  /* hash of all Names                */
#ifdef HAVE_OCSP
	byte    issuerKeyHash[KEYID_SIZE]; /* hash of the public Key         */
#endif /* HAVE_OCSP */

	byte*   signature;               /* not owned, points into raw cert  */

	char*   subjectCN;               /* CommonName                       */
	int     subjectCNLen;            /* CommonName Length                */
	char    subjectCNEnc;            /* CommonName Encoding              */
	int     subjectCNStored;         /* have we saved a copy we own      */
	
	char    issuer[ASN_NAME_MAX];    /* full name including common name  */
	char    subject[ASN_NAME_MAX];   /* full name including common name  */
	int     verify;                  /* Default to yes, but could be off */
	
	byte*   source;                  /* byte buffer holder cert, NOT owner */
	word32  srcIdx;                  /* current offset into buffer       */
	word32  maxIdx;                  /* max offset based on init size    */
	void*   heap;                    /* for user memory overrides        */
	byte    serial[EXTERNAL_SERIAL_SIZE];  /* raw serial number          */
	int     serialSz;                /* raw serial bytes stored */
	byte*   extensions;              /* not owned, points into raw cert  */
	int     extensionsSz;            /* length of cert extensions */
	word32  extensionsIdx;           /* if want to go back and parse later */
	byte*   extAuthInfo;             /* Authority Information Access URI */
	int     extAuthInfoSz;           /* length of the URI                */
	byte*   extCrlInfo;              /* CRL Distribution Points          */
	int     extCrlInfoSz;            /* length of the URI                */
	byte    extSubjKeyId[KEYID_SIZE]; /* Subject Key ID                  */
	byte    extSubjKeyIdSet;         /* Set when the SKID was read from cert */
	byte    extAuthKeyId[KEYID_SIZE]; /* Authority Key ID                */
	byte    extAuthKeyIdSet;         /* Set when the AKID was read from cert */
#ifndef IGNORE_NAME_CONSTRAINTS
	byte    extNameConstraintSet;
#endif /* IGNORE_NAME_CONSTRAINTS */
	byte    isCA;                    /* CA basic constraint true         */
	byte    weOwnAltNames;           /* altNames haven't been given to copy */
	byte    extKeyUsageSet;
	word16  extKeyUsage;             /* Key usage bitfield               */
	byte    extExtKeyUsageSet;       /* Extended Key Usage               */
	byte    extExtKeyUsage;          /* Extended Key usage bitfield      */
#ifdef OPENSSL_EXTRA
	byte    extBasicConstSet;
	byte    extBasicConstCrit;
	byte    extBasicConstPlSet;
	word32  pathLength;              /* CA basic constraint path length, opt */
	byte    extSubjAltNameSet;
	byte    extSubjAltNameCrit;
	byte    extAuthKeyIdCrit;
#ifndef IGNORE_NAME_CONSTRAINTS
	byte    extNameConstraintCrit;
#endif /* IGNORE_NAME_CONSTRAINTS */
	byte    extSubjKeyIdCrit;
	byte    extKeyUsageCrit;
	byte    extExtKeyUsageCrit;
	byte*   extExtKeyUsageSrc;
	word32  extExtKeyUsageSz;
	word32  extExtKeyUsageCount;
	byte*   extAuthKeyIdSrc;
	word32  extAuthKeyIdSz;
	byte*   extSubjKeyIdSrc;
	word32  extSubjKeyIdSz;
#endif
#ifdef HAVE_ECC
	word32  pkCurveOID;           /* Public Key's curve OID */
#endif /* HAVE_ECC */
	byte*   beforeDate;
	int     beforeDateLen;
	byte*   afterDate;
	int     afterDateLen;
#ifdef HAVE_PKCS7
	byte*   issuerRaw;               /* pointer to issuer inside source */
	int     issuerRawLen;
#endif
#ifndef IGNORE_NAME_CONSTRAINT
	byte*   subjectRaw;               /* pointer to subject inside source */
	int     subjectRawLen;
#endif
#if defined(WOLFSSL_CERT_GEN)
	/* easy access to subject info for other sign */
	char*   subjectSN;
	int     subjectSNLen;
	char    subjectSNEnc;
	char*   subjectC;
	int     subjectCLen;
	char    subjectCEnc;
	char*   subjectL;
	int     subjectLLen;
	char    subjectLEnc;
	char*   subjectST;
	int     subjectSTLen;
	char    subjectSTEnc;
	char*   subjectO;
	int     subjectOLen;
	char    subjectOEnc;
	char*   subjectOU;
	int     subjectOULen;
	char    subjectOUEnc;
	char*   subjectEmail;
	int     subjectEmailLen;
#endif /* WOLFSSL_CERT_GEN */
#ifdef OPENSSL_EXTRA
	DecodedName issuerName;
	DecodedName subjectName;
#endif /* OPENSSL_EXTRA */
#ifdef WOLFSSL_SEP
	int     deviceTypeSz;
	byte*   deviceType;
	int     hwTypeSz;
	byte*   hwType;
	int     hwSerialNumSz;
	byte*   hwSerialNum;
#ifdef OPENSSL_EXTRA
	byte    extCertPolicySet;
	byte    extCertPolicyCrit;
#endif /* OPENSSL_EXTRA */
#endif /* WOLFSSL_SEP */
	}DecodedCert;


#ifdef NO_SHA
    #define SIGNER_DIGEST_SIZE SHA256_DIGEST_SIZE
#else
    #define SIGNER_DIGEST_SIZE SHA_DIGEST_SIZE
#endif

/* CA Signers */
/* if change layout change PERSIST_CERT_CACHE functions too */
typedef	struct Signer {
	word32  pubKeySize;
	word32  keyOID;                  /* key type */
	word16  keyUsage;
	byte*   publicKey;
	int     nameLen;
	char*   name;                    /* common name */
#ifndef IGNORE_NAME_CONSTRAINTS
	Base_entry* permittedNames;
	Base_entry* excludedNames;
#endif /* IGNORE_NAME_CONSTRAINTS */
	byte    subjectNameHash[SIGNER_DIGEST_SIZE]; /* sha hash of names in certificate */
#ifndef NO_SKID
	byte    subjectKeyIdHash[SIGNER_DIGEST_SIZE];/* sha hash of names in certificate */
#endif
	struct Signer* next;
}Signer;


/* not for public consumption but may use for testing sometimes */
#ifdef WOLFSSL_TEST_CERT
    #define WOLFSSL_TEST_API WOLFSSL_API
#else
    #define WOLFSSL_TEST_API WOLFSSL_LOCAL
#endif

WOLFSSL_TEST_API void FreeAltNames(DNS_entry*, void*);
#ifndef IGNORE_NAME_CONSTRAINTS
    WOLFSSL_TEST_API void FreeNameSubtrees(Base_entry*, void*);
#endif /* IGNORE_NAME_CONSTRAINTS */
WOLFSSL_TEST_API void InitDecodedCert(DecodedCert*, byte*, word32, void*);
WOLFSSL_TEST_API void FreeDecodedCert(DecodedCert*);
WOLFSSL_TEST_API int  ParseCert(DecodedCert*, int type, int verify, void* cm);

WOLFSSL_LOCAL int ParseCertRelative(DecodedCert*, int type, int verify,void* cm);
WOLFSSL_LOCAL int DecodeToKey(DecodedCert*, int verify);

WOLFSSL_LOCAL Signer* MakeSigner(void*);
WOLFSSL_LOCAL void    FreeSigner(Signer*, void*);
WOLFSSL_LOCAL void    FreeSignerTable(Signer**, int, void*);


WOLFSSL_LOCAL int ToTraditional(byte* buffer, word32 length);
WOLFSSL_LOCAL int ToTraditionalEnc(byte* buffer, word32 length,const char*, int);

WOLFSSL_LOCAL int ValidateDate(const byte* date, byte format, int dateType);

/* ASN.1 helper functions */
WOLFSSL_LOCAL int GetLength(const byte* input, word32* inOutIdx, int* len, word32 maxIdx);
WOLFSSL_LOCAL int GetSequence(const byte* input, word32* inOutIdx, int* len, word32 maxIdx);
WOLFSSL_LOCAL int GetSet(const byte* input, word32* inOutIdx, int* len,  word32 maxIdx);
WOLFSSL_LOCAL int GetMyVersion(const byte* input, word32* inOutIdx, int* version);
WOLFSSL_LOCAL int GetInt(mp_int* mpi, const byte* input, word32* inOutIdx, word32 maxIdx);
WOLFSSL_LOCAL int GetAlgoId(const byte* input, word32* inOutIdx, word32* oid, word32 maxIdx);
WOLFSSL_LOCAL word32 SetLength(word32 length, byte* output);
WOLFSSL_LOCAL word32 SetSequence(word32 len, byte* output);
WOLFSSL_LOCAL word32 SetOctetString(word32 len, byte* output);
WOLFSSL_LOCAL word32 SetImplicit(byte tag, byte number, word32 len,byte* output);
WOLFSSL_LOCAL word32 SetExplicit(byte number, word32 len, byte* output);
WOLFSSL_LOCAL word32 SetSet(word32 len, byte* output);
WOLFSSL_LOCAL word32 SetAlgoID(int algoOID, byte* output, int type, int curveSz);
WOLFSSL_LOCAL int SetMyVersion(word32 version, byte* output, int header);
WOLFSSL_LOCAL int SetSerialNumber(const byte* sn, word32 snSz, byte* output);
WOLFSSL_LOCAL int GetNameHash(const byte* source, word32* idx, byte* hash, 	int maxIdx);

#ifdef HAVE_ECC
    /* ASN sig helpers */
    WOLFSSL_LOCAL int StoreECC_DSA_Sig(byte* out, word32* outLen, mp_int* r, mp_int* s);
    WOLFSSL_LOCAL int DecodeECC_DSA_Sig(const byte* sig, word32 sigLen, mp_int* r, mp_int* s);
#endif

#ifdef WOLFSSL_CERT_GEN

enum cert_enums {
    NAME_ENTRIES    =  8,
    JOINT_LEN       =  2,
    EMAIL_JOINT_LEN =  9,
    RSA_KEY         = 10,
    NTRU_KEY        = 11,
    ECC_KEY         = 12
};

#ifndef WOLFSSL_PEMCERT_TODER_DEFINED
#ifndef NO_FILESYSTEM
/* forward from wolfSSL */
WOLFSSL_API
int wolfSSL_PemCertToDer(const char* fileName, unsigned char* derBuf, int derSz);
#define WOLFSSL_PEMCERT_TODER_DEFINED
#endif
#endif

#endif /* WOLFSSL_CERT_GEN */



/* for pointer use */

#ifdef HAVE_OCSP

enum Ocsp_Response_Status {
    OCSP_SUCCESSFUL        = 0, /* Response has valid confirmations */
    OCSP_MALFORMED_REQUEST = 1, /* Illegal confirmation request */
    OCSP_INTERNAL_ERROR    = 2, /* Internal error in issuer */
    OCSP_TRY_LATER         = 3, /* Try again later */
    OCSP_SIG_REQUIRED      = 5, /* Must sign the request (4 is skipped) */
    OCSP_UNAUTHROIZED      = 6  /* Request unauthorized */
};


enum Ocsp_Cert_Status {
    CERT_GOOD    = 0,
    CERT_REVOKED = 1,
    CERT_UNKNOWN = 2
};


enum Ocsp_Sums {
    OCSP_BASIC_OID = 117,
    OCSP_NONCE_OID = 118
};


typedef	struct CertStatus
{
	struct	CertStatus* next;

	byte serial[EXTERNAL_SERIAL_SIZE];
	int serialSz;

	int status;

	byte thisDate[MAX_DATE_SIZE];
	byte nextDate[MAX_DATE_SIZE];
	byte thisDateFormat;
	byte nextDateFormat;
}CertStatus;


typedef struct OcspResponse {
    int     responseStatus;  /* return code from Responder */

    byte*   response;        /* Pointer to beginning of OCSP Response */
    word32  responseSz;      /* length of the OCSP Response */

    byte    producedDate[MAX_DATE_SIZE];
							 /* Date at which this response was signed */
    byte    producedDateFormat; /* format of the producedDate */
    byte*   issuerHash;
    byte*   issuerKeyHash;

    byte*   cert;
    word32  certSz;

    byte*   sig;             /* Pointer to sig in source */
    word32  sigSz;           /* Length in octets for the sig */
    word32  sigOID;          /* OID for hash used for sig */

    CertStatus* status;      /* certificate status to fill out */

    byte*   nonce;           /* pointer to nonce inside ASN.1 response */
    int     nonceSz;         /* length of the nonce string */

    byte*   source;          /* pointer to source buffer, not owned */
    word32  maxIdx;          /* max offset based on init size */
}OcspResponse;


typedef	struct OcspRequest {
    DecodedCert* cert;

    byte    useNonce;
    byte    nonce[MAX_OCSP_NONCE_SZ];
    int     nonceSz;

    byte*   issuerHash;      /* pointer to issuerHash in source cert */
    byte*   issuerKeyHash;   /* pointer to issuerKeyHash in source cert */
    byte*   serial;          /* pointer to serial number in source cert */
    int     serialSz;        /* length of the serial number */

    byte*   dest;            /* pointer to the destination ASN.1 buffer */
    word32  destSz;          /* length of the destination buffer */
}OcspRequest;


WOLFSSL_LOCAL void InitOcspResponse(OcspResponse*, CertStatus*, byte*, word32);
WOLFSSL_LOCAL int  OcspResponseDecode(OcspResponse*);

WOLFSSL_LOCAL void InitOcspRequest(OcspRequest*, DecodedCert*, byte, byte*, word32);
WOLFSSL_LOCAL int  EncodeOcspRequest(OcspRequest*);

WOLFSSL_LOCAL int  CompareOcspReqResp(OcspRequest*, OcspResponse*);


#endif /* HAVE_OCSP */


#ifdef HAVE_CRL

typedef struct RevokedCert {
	byte					serialNumber[EXTERNAL_SERIAL_SIZE];
	int					serialSz;
	struct RevokedCert	*next;
}RevokedCert;


typedef struct DecodedCRL {
	word32  certBegin;               /* offset to start of cert          */
	word32  sigIndex;                /* offset to start of signature     */
	word32  sigLength;               /* length of signature              */
	word32  signatureOID;            /* sum of algorithm object id       */
	byte*   signature;               /* pointer into raw source, not owned */
	byte    issuerHash[SIGNER_DIGEST_SIZE]; /* issuer hash               */
	byte    crlHash[SIGNER_DIGEST_SIZE]; /* raw crl data hash            */
	byte    lastDate[MAX_DATE_SIZE]; /* last date updated  */
	byte    nextDate[MAX_DATE_SIZE]; /* next update date   */
	byte    lastDateFormat;          /* format of last date */
	byte    nextDateFormat;          /* format of next date */
	RevokedCert* certs;              /* revoked cert list  */
	int          totalCerts;         /* number on list     */
}DecodedCRL;

WOLFSSL_LOCAL void InitDecodedCRL(DecodedCRL*);
WOLFSSL_LOCAL int  ParseCRL(DecodedCRL*, const byte* buff, word32 sz, void* cm);
WOLFSSL_LOCAL void FreeDecodedCRL(DecodedCRL*);


#endif /* HAVE_CRL */

/* from asn.c. lzj */
#ifdef HAVE_RTP_SYS
    #include "os.h"           /* dc_rtc_api needs    */
    #include "dc_rtc_api.h"   /* to get current time */
#endif

#include "cmnCrypto.h"


#ifdef HAVE_NTRU
    #include "ntru_crypto.h"
#endif

#ifdef HAVE_ECC
#include <wckEcc.h>
#endif

#ifdef WOLFSSL_DEBUG_ENCODING
    #ifdef FREESCALE_MQX
        #include <fio.h>
    #else
        #include <stdio.h>
    #endif
#endif

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of XSTRNCPY */
    #pragma warning(disable: 4996)
#endif


#ifndef TRUE
    #define TRUE  1
#endif
#ifndef FALSE
    #define FALSE 0
#endif

/******************************************************************
* Define 3 macros of XTIME/XGMTIME/XVALIDATE_DATE in different platform
******************************************************************/

#ifdef HAVE_RTP_SYS
    /* uses parital <time.h> structures */
    #define XTIME(tl)  (0)
    #define XGMTIME(c, t) my_gmtime((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
#elif defined(MICRIUM)
    #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
        #define XVALIDATE_DATE(d,f,t) NetSecure_ValidateDateHandler((d),(f),(t))
    #else
        #define XVALIDATE_DATE(d, f, t) (0)
    #endif
    #define NO_TIME_H
    /* since Micrium not defining XTIME or XGMTIME, CERT_GEN not available */
#elif defined(MICROCHIP_TCPIP_V5) || defined(MICROCHIP_TCPIP)
    #include <time.h>
    #define XTIME(t1) pic32_time((t1))
    #define XGMTIME(c, t) gmtime((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
#elif defined(FREESCALE_MQX)
    #define XTIME(t1)  mqx_time((t1))
    #define XGMTIME(c, t) mqx_gmtime((c), (t))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
#elif defined(WOLFSSL_MDK_ARM)
    #if defined(WOLFSSL_MDK5)
        #include "cmsis_os.h"
    #else
        #include <rtl.h>
    #endif
    #undef RNG
    #include "wolfssl_MDK_ARM.h"
    #undef RNG
    #define RNG wolfSSL_RNG /*for avoiding name conflict in "stm32f2xx.h" */
    #define XTIME(tl)  (0)
    #define XGMTIME(c, t) wolfssl_MDK_gmtime((c))
    #define XVALIDATE_DATE(d, f, t)  ValidateDate((d), (f), (t))
#elif defined(USER_TIME)
    /* user time, and gmtime compatible functions, there is a gmtime 
       implementation here that WINCE uses, so really just need some ticks
       since the EPOCH 
    */

struct tm {
	int tm_sec;     /* seconds after the minute [0-60] */
	int tm_min;     /* minutes after the hour [0-59] */
	int tm_hour;    /* hours since midnight [0-23] */
	int tm_mday;    /* day of the month [1-31] */
	int tm_mon;     /* months since January [0-11] */
	int tm_year;    /* years since 1900 */
	int tm_wday;    /* days since Sunday [0-6] */
	int tm_yday;    /* days since January 1 [0-365] */
	int tm_isdst;   /* Daylight Savings Time flag */
	long    tm_gmtoff;  /* offset from CUT in seconds */
	char    *tm_zone;   /* timezone abbreviation */
};

typedef long time_t;

    /* forward declaration */
    struct tm* gmtime(const time_t* timer);
    extern time_t XTIME(time_t * timer);

    #define XGMTIME(c, t) gmtime((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))

    #ifdef STACK_TRAP
        /* for stack trap tracking, don't call os gmtime on OS X/linux,
           uses a lot of stack spce */
        extern time_t time(time_t * timer);
        #define XTIME(tl)  time((tl))
    #endif /* STACK_TRAP */

#elif defined(TIME_OVERRIDES)
    /* user would like to override time() and gmtime() functionality */

    #ifndef HAVE_TIME_T_TYPE
        typedef long time_t;
    #endif
    extern time_t XTIME(time_t * timer);

    #ifndef HAVE_TM_TYPE
struct tm {
	int  tm_sec;     /* seconds after the minute [0-60] */
	int  tm_min;     /* minutes after the hour [0-59] */
	int  tm_hour;    /* hours since midnight [0-23] */
	int  tm_mday;    /* day of the month [1-31] */
	int  tm_mon;     /* months since January [0-11] */
	int  tm_year;    /* years since 1900 */
	int  tm_wday;    /* days since Sunday [0-6] */
	int  tm_yday;    /* days since January 1 [0-365] */
	int  tm_isdst;   /* Daylight Savings Time flag */
	long tm_gmtoff;  /* offset from CUT in seconds */
	char *tm_zone;   /* timezone abbreviation */
};
    #endif
    extern struct tm* XGMTIME(const time_t* timer, struct tm* tmp);

    #ifndef HAVE_VALIDATE_DATE
        #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
    #endif
#else
    /* default */
    /* uses complete <time.h> facility */
    #include <time.h>
    #define XTIME(tl)     time((tl))
    #define XGMTIME(c, t) gmtime((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
#endif


word32 SetDigest(const byte* digest, word32 digSz, byte* output);
void GetTime(int* value, const byte* date, int* idx);

#if 0
INLINE word32 btoi(byte b)
{
    return b - 0x30;
}
#else
#define btoi(b)  ((b)-0x30)


#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* !NO_ASN */
#endif /* WOLF_CRYPT_ASN_H */

