/* crl.h
 *
 */


#ifndef __WSC_CRL_H__
#define __WSC_CRL_H__

#ifdef HAVE_CRL

#ifdef NO_SHA
    #define CRL_DIGEST_SIZE SHA256_DIGEST_SIZE
#else
    #define CRL_DIGEST_SIZE SHA_DIGEST_SIZE
#endif

/* Complete CRL */
typedef struct CRL_Entry
{
	struct CRL_Entry	*next;                      /* next entry */
	byte				issuerHash[CRL_DIGEST_SIZE];  /* issuer hash                 */ 
	/* byte    crlHash[CRL_DIGEST_SIZE];      raw crl data hash           */ 
	/* restore the hash here if needed for optimized comparisons */
	byte				lastDate[MAX_DATE_SIZE]; /* last date updated  */
	byte				nextDate[MAX_DATE_SIZE]; /* next update date   */
	byte				lastDateFormat;          /* last date format */
	byte				nextDateFormat;          /* next date format */
	RevokedCert		*certs;              /* revoked cert list  */
	int				totalCerts;         /* number on list     */
}CRL_Entry;


/* CRL directory monitor */
typedef struct CRL_Monitor {
	char		*path;      /* full dir path, if valid pointer we're using */
	int		type;      /* PEM or ASN1 type */
}CRL_Monitor;

/* wolfSSL CRL controller */
typedef struct WOLFSSL_CRL {
	struct WOLFSSL_CERT_MANAGER	*cm;            /* pointer back to cert manager */
	CRL_Entry						*crlList;       /* our CRL list */
	wolfSSL_Mutex					crlLock;       /* CRL list lock */
	CRL_Monitor						monitors[2];   /* PEM and DER possible */
#ifdef HAVE_CRL_MONITOR
	pthread_t		tid;           /* monitoring thread */
	int			mfd;           /* monitor fd, -1 if no init yet */
#endif
}WOLFSSL_CRL;
#else
//#ifndef HAVE_CRL
    typedef struct WOLFSSL_CRL WOLFSSL_CRL;
#endif


#ifdef HAVE_OCSP
/*  Online Certificate Status Protocol */
#ifdef NO_SHA
    #define OCSP_DIGEST_SIZE SHA256_DIGEST_SIZE
#else
    #define OCSP_DIGEST_SIZE SHA_DIGEST_SIZE
#endif

typedef struct OCSP_Entry{
	struct		OCSP_Entry* next;                        /* next entry             */
	byte			issuerHash[OCSP_DIGEST_SIZE];    /* issuer hash            */ 
	byte			issuerKeyHash[OCSP_DIGEST_SIZE]; /* issuer public key hash */
	CertStatus	*status;                      /* OCSP response list     */
	int			 totalStatus;                 /* number on list         */
}OCSP_Entry;


/* wolfSSL OCSP controller */
typedef	struct WOLFSSL_OCSP
{
	struct WOLFSSL_CERT_MANAGER	*cm;            /* pointer back to cert manager */
	OCSP_Entry						*ocspList;      /* OCSP response list */
	wolfSSL_Mutex					ocspLock;      /* OCSP list lock */
}WOLFSSL_OCSP;

#else
//#ifndef HAVE_OCSP
	typedef struct WOLFSSL_OCSP WOLFSSL_OCSP;
#endif

#ifndef CA_TABLE_SIZE
    #define CA_TABLE_SIZE 11
#endif

/* callbacks internal used */
typedef void (*CallbackCACache)(unsigned char* der, int sz, int type);
typedef void (*CbMissingCRL)(const char* url);
typedef int  (*CbOCSPIO)(void*, const char*, int, unsigned char*, int, unsigned char**);
typedef void (*CbOCSPRespFree)(void*,unsigned char*);

/* wolfSSL Certificate Manager */
typedef	struct WOLFSSL_CERT_MANAGER
{
	Signer			*caTable[CA_TABLE_SIZE]; /* the CA signer table */
	void				*heap;               /* heap helper */
	WOLFSSL_CRL	*crl;                /* CRL checker */
	WOLFSSL_OCSP*   ocsp;               /* OCSP checker */
	char*           ocspOverrideURL;    /* use this responder */
	void*           ocspIOCtx;          /* I/O callback CTX */
	CallbackCACache caCacheCallback;    /* CA cache addition callback */
	CbMissingCRL    cbMissingCRL;       /* notify through cb of missing crl */
	CbOCSPIO        ocspIOCb;           /* I/O callback for OCSP lookup */
	CbOCSPRespFree  ocspRespFreeCb;     /* Frees OCSP Response from IO Cb */
	wolfSSL_Mutex   caLock;             /* CA list lock */
	byte            crlEnabled;         /* is CRL on ? */
	byte            crlCheckAll;        /* always leaf, but all ? */
	byte            ocspEnabled;        /* is OCSP on ? */
	byte            ocspCheckAll;       /* always leaf, but all ? */
	byte            ocspSendNonce;      /* send the OCSP nonce ? */
	byte            ocspUseOverrideURL; /* ignore cert's responder, override */
}WOLFSSL_CERT_MANAGER;



#ifdef __cplusplus
    extern "C" {
#endif

//typedef struct WOLFSSL_CRL WOLFSSL_CRL;

WOLFSSL_LOCAL int  InitCRL(WOLFSSL_CRL*, WOLFSSL_CERT_MANAGER*);
WOLFSSL_LOCAL void FreeCRL(WOLFSSL_CRL*, int dynamic);

WOLFSSL_LOCAL int  LoadCRL(WOLFSSL_CRL* crl, const char* path, int type, int mon);
WOLFSSL_LOCAL int  BufferLoadCRL(WOLFSSL_CRL*, const byte*, long, int);
WOLFSSL_LOCAL int  CheckCertCRL(WOLFSSL_CRL*, DecodedCert*);


#ifdef __cplusplus
    }
#endif


#endif

