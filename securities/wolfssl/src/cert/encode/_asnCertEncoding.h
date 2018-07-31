
#ifndef	___ASN_CERT_H__
#define	___ASN_CERT_H__


#ifdef WOLFSSL_CERT_GEN

/* DER encoded x509 Certificate : only used in encoding */
typedef struct DerCert {
	byte size[MAX_LENGTH_SZ];          /* length encoded */
	byte version[MAX_VERSION_SZ];      /* version encoded */
	byte serial[CTC_SERIAL_SIZE + MAX_LENGTH_SZ]; /* serial number encoded */
	byte sigAlgo[MAX_ALGO_SZ];         /* signature algo encoded */
	byte issuer[ASN_NAME_MAX];         /* issuer  encoded */
	byte subject[ASN_NAME_MAX];        /* subject encoded */
	byte validity[MAX_DATE_SIZE*2 + MAX_SEQ_SZ*2];  /* before and after dates */
	byte publicKey[MAX_PUBLIC_KEY_SZ]; /* rsa / ntru public key encoded */
	byte ca[MAX_CA_SZ];                /* basic constraint CA true size */
	byte extensions[MAX_EXTENSIONS_SZ];  /* all extensions */
#ifdef WOLFSSL_CERT_REQ
	byte attrib[MAX_ATTRIB_SZ];        /* Cert req attributes encoded */
#endif
	int  sizeSz;                       /* encoded size length */
	int  versionSz;                    /* encoded version length */
	int  serialSz;                     /* encoded serial length */
	int  sigAlgoSz;                    /* enocded sig alog length */
	int  issuerSz;                     /* encoded issuer length */
	int  subjectSz;                    /* encoded subject length */
	int  validitySz;                   /* encoded validity length */
	int  publicKeySz;                  /* encoded public key length */
	int  caSz;                         /* encoded CA extension length */
	int  extensionsSz;                 /* encoded extensions total length */
	int  total;                        /* total encoded lengths */
#ifdef WOLFSSL_CERT_REQ
	int  attribSz;
#endif
} DerCert;

#endif

int SetExtensions(byte* output, const byte* ext, int extSz, int header);


#endif

