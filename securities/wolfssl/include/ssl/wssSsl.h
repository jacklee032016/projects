/* ssl.h
 */

/* wolfSSL API */

#ifndef __WSS_SSL_H__
#define __WSS_SSL_H__


#define LIBWOLFSSL_VERSION_STRING		"3.6.0"
#define LIBWOLFSSL_VERSION_HEX		0x03006000

#ifndef NO_FILESYSTEM
    #ifdef FREESCALE_MQX
        #include <fio.h>
    #else
        #include <stdio.h>   /* ERR_printf */
    #endif
#endif

#ifdef WOLFSSL_PREFIX
    #include "prefix_ssl.h"
#endif

#ifdef LIBWOLFSSL_VERSION_STRING
    #define WOLFSSL_VERSION LIBWOLFSSL_VERSION_STRING
#endif

#ifdef _WIN32
    /* wincrypt.h clashes */
    #undef OCSP_REQUEST
    #undef OCSP_RESPONSE
#endif



#ifdef __cplusplus
    extern "C" {
#endif

/* data types which are not defined */
typedef struct WOLFSSL_X509_LOOKUP    WOLFSSL_X509_LOOKUP;
typedef struct WOLFSSL_X509_LOOKUP_METHOD WOLFSSL_X509_LOOKUP_METHOD;
typedef struct WOLFSSL_X509_CRL       WOLFSSL_X509_CRL;
typedef struct WOLFSSL_ASN1_INTEGER   WOLFSSL_ASN1_INTEGER;
typedef struct WOLFSSL_X509_EXTENSION WOLFSSL_X509_EXTENSION;
typedef struct WOLFSSL_ASN1_TIME      WOLFSSL_ASN1_TIME;
typedef struct WOLFSSL_ASN1_OBJECT    WOLFSSL_ASN1_OBJECT;
typedef struct WOLFSSL_ASN1_STRING    WOLFSSL_ASN1_STRING;
typedef struct WOLFSSL_dynlock_value  WOLFSSL_dynlock_value;


typedef struct WOLFSSL_EVP_PKEY {
    int type;         /* openssh dereference */
    int save_type;    /* openssh dereference */
    int pkey_sz;
    union {
        char* ptr;
    } pkey;
    #ifdef HAVE_ECC
        int pkey_curve;
    #endif
} WOLFSSL_EVP_PKEY;

typedef struct WOLFSSL_MD4_CTX {
    int buffer[32];      /* big enough to hold, check size in Init */
} WOLFSSL_MD4_CTX;


typedef struct WOLFSSL_COMP_METHOD {
    int type;            /* stunnel dereference */
} WOLFSSL_COMP_METHOD;


typedef struct WOLFSSL_X509_STORE {
    int                  cache;          /* stunnel dereference */
    struct WOLFSSL_CERT_MANAGER* cm;
} WOLFSSL_X509_STORE;

typedef struct WOLFSSL_ALERT {
    int code;
    int level;
} WOLFSSL_ALERT;

typedef struct WOLFSSL_ALERT_HISTORY {
    WOLFSSL_ALERT last_rx;
    WOLFSSL_ALERT last_tx;
} WOLFSSL_ALERT_HISTORY;

typedef struct WOLFSSL_X509_REVOKED {
    WOLFSSL_ASN1_INTEGER* serialNumber;          /* stunnel dereference */
} WOLFSSL_X509_REVOKED;


typedef struct WOLFSSL_X509_OBJECT {
    union {
        char* ptr;
        WOLFSSL_X509_CRL* crl;           /* stunnel dereference */
    } data;
} WOLFSSL_X509_OBJECT;


typedef struct WOLFSSL_X509_STORE_CTX {
    WOLFSSL_X509_STORE* store;    /* Store full of a CA cert chain */
    struct WOLFSSL_X509* current_cert;   /* stunnel dereference */
    char* domain;                /* subject CN domain name */
    void* ex_data;               /* external data, for fortress build */
    void* userCtx;               /* user ctx */
    int   error;                 /* current error */
    int   error_depth;           /* cert depth for this error */
    int   discardSessionCerts;   /* so verify callback can flag for discard */
} WOLFSSL_X509_STORE_CTX;


/* Valid Alert types from page 16/17 */
enum AlertDescription {
    close_notify            = 0,
    unexpected_message      = 10,
    bad_record_mac          = 20,
    record_overflow         = 22,
    decompression_failure   = 30,
    handshake_failure       = 40,
    no_certificate          = 41,
    bad_certificate         = 42,
    unsupported_certificate = 43,
    certificate_revoked     = 44,
    certificate_expired     = 45,
    certificate_unknown     = 46,
    illegal_parameter       = 47,
    decrypt_error           = 51,
    #ifdef WOLFSSL_MYSQL_COMPATIBLE
    /* catch name conflict for enum protocol with MYSQL build */
    wc_protocol_version     = 70,
    #else
    protocol_version        = 70,
    #endif
    no_renegotiation        = 100,
    unrecognized_name       = 112
};


enum AlertLevel {
    alert_warning = 1,
    alert_fatal = 2
};



/* extras */

#define STACK_OF(x) x


#define WOLFSSL_DEFAULT_CIPHER_LIST ""   /* default all */
#define WOLFSSL_RSA_F4 0x10001L

enum {
    OCSP_NOCERTS     = 1,
    OCSP_NOINTERN    = 2,
    OCSP_NOSIGS      = 4,
    OCSP_NOCHAIN     = 8,
    OCSP_NOVERIFY    = 16,
    OCSP_NOEXPLICIT  = 32,
    OCSP_NOCASIGN    = 64,
    OCSP_NODELEGATED = 128,
    OCSP_NOCHECKS    = 256,
    OCSP_TRUSTOTHER  = 512,
    OCSP_RESPID_KEY  = 1024,
    OCSP_NOTIME      = 2048,

    OCSP_CERTID   = 2,
    OCSP_REQUEST  = 4,
    OCSP_RESPONSE = 8,
    OCSP_BASICRESP = 16,

    WOLFSSL_OCSP_URL_OVERRIDE = 1,
    WOLFSSL_OCSP_NO_NONCE     = 2,
    WOLFSSL_OCSP_CHECKALL     = 4,

    WOLFSSL_CRL_CHECKALL = 1,

    ASN1_GENERALIZEDTIME = 4,

    SSL_OP_MICROSOFT_SESS_ID_BUG = 1,
    SSL_OP_NETSCAPE_CHALLENGE_BUG = 2,
    SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 3,
    SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = 4,
    SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = 5,
    SSL_OP_MSIE_SSLV2_RSA_PADDING = 6,
    SSL_OP_SSLEAY_080_CLIENT_DH_BUG = 7,
    SSL_OP_TLS_D5_BUG = 8,
    SSL_OP_TLS_BLOCK_PADDING_BUG = 9,
    SSL_OP_TLS_ROLLBACK_BUG = 10,
    SSL_OP_ALL = 11,
    SSL_OP_EPHEMERAL_RSA = 12,
    SSL_OP_NO_SSLv3 = 13,
    SSL_OP_NO_TLSv1 = 14,
    SSL_OP_PKCS1_CHECK_1 = 15,
    SSL_OP_PKCS1_CHECK_2 = 16,
    SSL_OP_NETSCAPE_CA_DN_BUG = 17,
    SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 18,
    SSL_OP_SINGLE_DH_USE = 19,
    SSL_OP_NO_TICKET = 20,
    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 21,
    SSL_OP_NO_QUERY_MTU = 22,
    SSL_OP_COOKIE_EXCHANGE = 23,
    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 24,
    SSL_OP_SINGLE_ECDH_USE = 25,
    SSL_OP_CIPHER_SERVER_PREFERENCE = 26,

    SSL_MAX_SSL_SESSION_ID_LENGTH = 32,

    EVP_R_BAD_DECRYPT = 2,

    SSL_CB_LOOP = 4,
    SSL_ST_CONNECT = 5,
    SSL_ST_ACCEPT  = 6,
    SSL_CB_ALERT   = 7,
    SSL_CB_READ    = 8,
    SSL_CB_HANDSHAKE_DONE = 9,

    SSL_MODE_ENABLE_PARTIAL_WRITE = 2,

    BIO_FLAGS_BASE64_NO_NL = 1,
    BIO_CLOSE   = 1,
    BIO_NOCLOSE = 0,

    NID_undef = 0,

    X509_FILETYPE_PEM = 8,
    X509_LU_X509      = 9,
    X509_LU_CRL       = 12,

    X509_V_ERR_CRL_SIGNATURE_FAILURE = 13,
    X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 14,
    X509_V_ERR_CRL_HAS_EXPIRED                = 15,
    X509_V_ERR_CERT_REVOKED                   = 16,
    X509_V_ERR_CERT_CHAIN_TOO_LONG            = 17,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT      = 18,
    X509_V_ERR_CERT_NOT_YET_VALID             = 19,
    X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 20,
    X509_V_ERR_CERT_HAS_EXPIRED               = 21,
    X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD  = 22,

    X509_V_OK = 0,

    CRYPTO_LOCK = 1,
    CRYPTO_NUM_LOCKS = 10
};

/* extras end */


typedef	enum{
	SSL_FILETYPE_PEM		= 1,
	SSL_FILETYPE_ASN1		= 2,
	SSL_FILETYPE_RAW		= 3, /* NTRU raw key blob */
	SSL_FILETYPE_DEFAULT	= 2, /* ASN1 */
}SSL_FILETYPE_T;

enum { /* ssl Constants */
    SSL_ERROR_NONE      =  0,   /* for most functions */
    SSL_FAILURE         =  0,   /* for some functions */
    SSL_SUCCESS         =  1,
    SSL_SHUTDOWN_NOT_DONE =  2,  /* call wolfSSL_shutdown again to complete */

    SSL_BAD_CERTTYPE    = -8,
    SSL_BAD_STAT        = -7,
    SSL_BAD_PATH        = -6,
    SSL_BAD_FILETYPE    = -5,
    SSL_BAD_FILE        = -4,
    SSL_NOT_IMPLEMENTED = -3,
    SSL_UNKNOWN         = -2,
    SSL_FATAL_ERROR     = -1,

    SSL_VERIFY_NONE                 = 0,
    SSL_VERIFY_PEER                 = 1,
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
    SSL_VERIFY_CLIENT_ONCE          = 4,

    SSL_SESS_CACHE_OFF                = 30,
    SSL_SESS_CACHE_CLIENT             = 31,
    SSL_SESS_CACHE_SERVER             = 32,
    SSL_SESS_CACHE_BOTH               = 33,
    SSL_SESS_CACHE_NO_AUTO_CLEAR      = 34,
    SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 35,

    SSL_ERROR_WANT_READ        =  2,
    SSL_ERROR_WANT_WRITE       =  3,
    SSL_ERROR_WANT_CONNECT     =  7,
    SSL_ERROR_WANT_ACCEPT      =  8,
    SSL_ERROR_SYSCALL          =  5,
    SSL_ERROR_WANT_X509_LOOKUP = 83,
    SSL_ERROR_ZERO_RETURN      =  6,
    SSL_ERROR_SSL              = 85,

    SSL_SENT_SHUTDOWN     = 1,
    SSL_RECEIVED_SHUTDOWN = 2,
    SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 4,
    SSL_OP_NO_SSLv2       = 8,

    SSL_R_SSL_HANDSHAKE_FAILURE           = 101,
    SSL_R_TLSV1_ALERT_UNKNOWN_CA          = 102,
    SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 103,
    SSL_R_SSLV3_ALERT_BAD_CERTIFICATE     = 104,

    PEM_BUFSIZE = 1024
};


/* extra begins */

enum {  /* ERR Constants */
    ERR_TXT_STRING = 1
};



/* I/O Callback default errors */
enum IOerrors {
    WOLFSSL_CBIO_ERR_GENERAL    = -1,     /* general unexpected err */
    WOLFSSL_CBIO_ERR_WANT_READ  = -2,     /* need to call read  again */
    WOLFSSL_CBIO_ERR_WANT_WRITE = -2,     /* need to call write again */
    WOLFSSL_CBIO_ERR_CONN_RST   = -3,     /* connection reset */
    WOLFSSL_CBIO_ERR_ISR        = -4,     /* interrupt */
    WOLFSSL_CBIO_ERR_CONN_CLOSE = -5,     /* connection closed or epipe */
    WOLFSSL_CBIO_ERR_TIMEOUT    = -6      /* socket timeout */
};


/* CA cache callbacks */
enum {
    WOLFSSL_SSLV3    = 0,
    WOLFSSL_TLSV1    = 1,
    WOLFSSL_TLSV1_1  = 2,
    WOLFSSL_TLSV1_2  = 3,
    WOLFSSL_USER_CA  = 1,          /* user added as trusted */
    WOLFSSL_CHAIN_CA = 2           /* added to cache from trusted chain */
};


/* Atomic User Needs */
enum {
    WOLFSSL_SERVER_END = 0,
    WOLFSSL_CLIENT_END = 1,
    WOLFSSL_BLOCK_TYPE = 2,
    WOLFSSL_STREAM_TYPE = 3,
    WOLFSSL_AEAD_TYPE = 4,
    WOLFSSL_TLS_HMAC_INNER_SZ = 13      /* SEQ_SZ + ENUM + VERSION_SZ + LEN_SZ */
};

/* for GetBulkCipher and internal use */
enum BulkCipherAlgorithm {
    wolfssl_cipher_null,
    wolfssl_rc4,
    wolfssl_rc2,
    wolfssl_des,
    wolfssl_triple_des,             /* leading 3 (3des) not valid identifier */
    wolfssl_des40,
    wolfssl_idea,
    wolfssl_aes,
    wolfssl_aes_gcm,
    wolfssl_aes_ccm,
    wolfssl_chacha,
    wolfssl_camellia,
    wolfssl_hc128,                  /* wolfSSL extensions */
    wolfssl_rabbit
};


/* for KDF TLS 1.2 mac types */
enum KDF_MacAlgorithm {
    wolfssl_sha256 = 4,     /* needs to match internal MACAlgorithm */
    wolfssl_sha384,
    wolfssl_sha512
};


/* TLS Extensions */

/* Server Name Indication */
#ifdef HAVE_SNI

/* SNI types */
enum {
    WOLFSSL_SNI_HOST_NAME = 0
};


#ifndef NO_WOLFSSL_SERVER

/* SNI options */
enum {
    WOLFSSL_SNI_CONTINUE_ON_MISMATCH = 0x01, /* do not abort on mismatch flag */
    WOLFSSL_SNI_ANSWER_ON_MISMATCH   = 0x02  /* fake match on mismatch flag */
};


/* SNI status */
enum {
    WOLFSSL_SNI_NO_MATCH   = 0,
    WOLFSSL_SNI_FAKE_MATCH = 1, /* if WOLFSSL_SNI_ANSWER_ON_MISMATCH is enabled */
    WOLFSSL_SNI_REAL_MATCH = 2
};


#endif
#endif

/* Maximum Fragment Length */
#ifdef HAVE_MAX_FRAGMENT

/* Fragment lengths */
enum {
    WOLFSSL_MFL_2_9  = 1, /*  512 bytes */
    WOLFSSL_MFL_2_10 = 2, /* 1024 bytes */
    WOLFSSL_MFL_2_11 = 3, /* 2048 bytes */
    WOLFSSL_MFL_2_12 = 4, /* 4096 bytes */
    WOLFSSL_MFL_2_13 = 5  /* 8192 bytes *//* wolfSSL ONLY!!! */
};

#ifndef NO_WOLFSSL_CLIENT


#endif
#endif

/* Truncated HMAC */
#ifdef HAVE_TRUNCATED_HMAC
#ifndef NO_WOLFSSL_CLIENT


#endif
#endif

/* Elliptic Curves */
enum {
    WOLFSSL_ECC_SECP160R1 = 0x10,
    WOLFSSL_ECC_SECP192R1 = 0x13,
    WOLFSSL_ECC_SECP224R1 = 0x15,
    WOLFSSL_ECC_SECP256R1 = 0x17,
    WOLFSSL_ECC_SECP384R1 = 0x18,
    WOLFSSL_ECC_SECP521R1 = 0x19
};

#ifdef HAVE_SUPPORTED_CURVES
#ifndef NO_WOLFSSL_CLIENT


#endif
#endif

/* Secure Renegotiation */
#ifdef HAVE_SECURE_RENEGOTIATION


#endif

/* Session Ticket */
#ifdef HAVE_SESSION_TICKET

#ifndef NO_WOLFSSL_CLIENT
typedef int (*CallbackSessionTicket)(WOLFSSL*, const unsigned char*, int, void*);

#endif /* NO_WOLFSSL_CLIENT */

#ifndef NO_WOLFSSL_SERVER

enum TicketEncRet {
    WOLFSSL_TICKET_RET_FATAL  = -1,  /* fatal error, don't use ticket */
    WOLFSSL_TICKET_RET_OK     =  0,  /* ok, use ticket */
    WOLFSSL_TICKET_RET_REJECT,       /* don't use ticket, but not fatal */
    WOLFSSL_TICKET_RET_CREATE        /* existing ticket ok and create new one */
};


#endif /* NO_WOLFSSL_SERVER */

#endif /* HAVE_SESSION_TICKET */

#define WOLFSSL_CRL_MONITOR   0x01   /* monitor this dir flag */
#define WOLFSSL_CRL_START_MON 0x02   /* start monitoring flag */

/* SSL Version */
typedef struct ProtocolVersion {
	byte		major;
	byte		minor;
} WOLFSSL_PACK ProtocolVersion;


/* wolfSSL method type */
typedef	struct WOLFSSL_METHOD{
	ProtocolVersion	version;
	byte				side;         /* connection side, server or client */
	byte				downgrade;    /* whether to downgrade version, default no */
}WOLFSSL_METHOD;

/* wolfSSL buffer type */
typedef struct buffer {
	byte		*buffer;
	word32	length;
} buffer;

#define    MAX_PSK_ID_LEN	128  /* max psk identity/hint supported */


/* wolfSSL context type */
typedef struct WOLFSSL_CTX
{
	WOLFSSL_METHOD* method;
	wolfSSL_Mutex   countMutex;    /* reference count mutex */
	int         refCount;         /* reference count */
#ifndef NO_DH
	buffer      serverDH_P;
	buffer      serverDH_G;
#endif
#ifndef NO_CERTS
	buffer      certificate;
	buffer      certChain;
	/* chain after self, in DER, with leading size for each cert */
	buffer      privateKey;
	WOLFSSL_CERT_MANAGER* cm;      /* our cert manager, ctx owns SSL will use */
#endif
	struct Suites		*suites;           /* make dynamic, user may not need/set */
	void*       heap;             /* for user memory overrides */
	/* verify fields in CTX */
	byte        verifyPeer;
	byte        verifyNone;
	byte        failNoCert;
	
	byte        sessionCacheOff;
	byte        sessionCacheFlushOff;
	byte        sendVerify;       /* for client side */
	byte        haveRSA;          /* RSA available */
	byte        haveDH;           /* server DH parms set by user */
	byte        haveNTRU;         /* server private NTRU  key loaded */
	byte        haveECDSAsig;     /* server cert signed w/ ECDSA */
	byte        haveStaticECC;    /* static server ECC private key */
	byte        partialWrite;     /* only one msg per write call */
	byte        quietShutdown;    /* don't send close notify */
	byte        groupMessages;    /* group handshake messages before sending */
	byte        minDowngrade;     /* minimum downgrade version */
#ifndef NO_DH
	word16      minDhKeySz;       /* minimum DH key size */
#endif

	CallbackIORecv		CBIORecv;
	CallbackIOSend		CBIOSend;
#ifdef WOLFSSL_DTLS
	CallbackGenCookie	CBIOCookie;       /* gen cookie callback */
#endif
	VerifyCallback			verifyCallback;     /* cert verification callback */
	word32				timeout;            /* session timeout */

#ifdef HAVE_ECC
	word16          eccTempKeySz;       /* in octets 20 - 66 */
	word32          pkCurveOID;         /* curve Ecc_Sum */
#endif

#ifndef NO_PSK
	byte        havePSK;                /* psk key set by user */
	psk_client_callback client_psk_cb;  /* client callback */
	psk_server_callback server_psk_cb;  /* server callback */
	char        server_hint[MAX_PSK_ID_LEN];
#endif /* NO_PSK */
#ifdef HAVE_ANON
	byte        haveAnon;               /* User wants to allow Anon suites */
#endif /* HAVE_ANON */
#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
	pem_password_cb passwd_cb;
	void*            userdata;
#endif /* OPENSSL_EXTRA */
#ifdef HAVE_OCSP
	WOLFSSL_OCSP      ocsp;
#endif
#ifdef HAVE_CAVIUM
	int              devId;            /* cavium device id to use */
#endif
#ifdef HAVE_TLS_EXTENSIONS
	TLSX* extensions;                  /* RFC 6066 TLS Extensions data */
#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SEVER)
	SessionTicketEncCb ticketEncCb;   /* enc/dec session ticket Cb */
	void*              ticketEncCtx;  /* session encrypt context */
	int                ticketHint;    /* ticket hint in seconds */
#endif
#endif
#ifdef ATOMIC_USER
	CallbackMacEncrypt    MacEncryptCb;    /* Atomic User Mac/Encrypt Cb */
	CallbackDecryptVerify DecryptVerifyCb; /* Atomic User Decrypt/Verify Cb */
#endif
#ifdef HAVE_PK_CALLBACKS
#ifdef HAVE_ECC
	CallbackEccSign   EccSignCb;    /* User EccSign   Callback handler */
	CallbackEccVerify EccVerifyCb;  /* User EccVerify Callback handler */
#endif /* HAVE_ECC */
#ifndef NO_RSA 
	CallbackRsaSign   RsaSignCb;    /* User RsaSign   Callback handler */
	CallbackRsaVerify RsaVerifyCb;  /* User RsaVerify Callback handler */
	CallbackRsaEnc    RsaEncCb;     /* User Rsa Public Encrypt  handler */
	CallbackRsaDec    RsaDecCb;     /* User Rsa Private Decrypt handler */
#endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */
	}WOLFSSL_CTX;


#ifdef __cplusplus
    }
#endif


#endif

