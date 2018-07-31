
#ifndef HEADER_CRYPTO_MISC_H
#define HEADER_CRYPTO_MISC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "crypto.h"

/**************************************************************************
 * X509 declarations 
 **************************************************************************/
#define X509_OK                             0
#define X509_NOT_OK                         -1
#define X509_VFY_ERROR_NO_TRUSTED_CERT      -2
#define X509_VFY_ERROR_BAD_SIGNATURE        -3      
#define X509_VFY_ERROR_NOT_YET_VALID        -4
#define X509_VFY_ERROR_EXPIRED              -5
#define X509_VFY_ERROR_SELF_SIGNED          -6
#define X509_VFY_ERROR_INVALID_CHAIN        -7
#define X509_VFY_ERROR_UNSUPPORTED_DIGEST   -8
#define X509_INVALID_PRIV_KEY               -9
#define X509_MAX_CERTS                      -10

/*
 * The Distinguished Name
 */
#define X509_COMMON_NAME				0
#define X509_ORGANIZATION				1
#define X509_ORGANIZATIONAL_UNIT		2
#define X509_NUM_DN_TYPES				3

/* AttributeTypeAndValue :id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 } :0x55(2*40+5), 0x04
* rfc5280#A.1
*/
typedef	enum _x520_name_type
{
	X520_COMMON_NAME = 3,
	X520_ORGANIZATION_NAME = 0x0A,
	X520_ORGAN_UNIT_NAME = 0x0B,
}X520_NAME_TYPE;


#define	X509_SERIAL_LENGTH			20

struct _x509_ctx
{
#ifdef  _DEBUG
	char				version; /* 0:V1; 1:V2; 2:V3 */
	char				serialNumber[X509_SERIAL_LENGTH];
	uint8_t			serialLength;
	
#endif
/*
Common Name	:	CN
Organizational Unit name	:	OU
Organization name	:	O
Locality	:	L
State or province name	:	S
Country	:	C
*/
	char				*caDn[X509_NUM_DN_TYPES];	/* issuer in cert */
	char				*dn[X509_NUM_DN_TYPES];		/* subject in cert */
	char				**subject_alt_dnsnames;

	time_t			not_before;
	time_t			not_after;
	
	uint8_t			*signature;
	uint16_t			sig_len;
	uint8_t			sig_type;

	RSA_CTX			*rsa_ctx;
	bigint			*digest;
	struct _x509_ctx	*next;
};

typedef struct _x509_ctx X509;

#ifdef CONFIG_SSL_CERT_VERIFICATION
typedef struct 
{
	X509 *cert[CONFIG_X509_MAX_CA_CERTS];
} CA_CERT;
#endif

EXP_FUNC int STDCALL x509_new(const uint8_t *cert, int *len, X509 **ctx);
EXP_FUNC void STDCALL x509_free(X509 *x509_ctx);
#ifdef CONFIG_SSL_CERT_VERIFICATION
EXP_FUNC int STDCALL x509_verify(const CA_CERT *ca_cert_ctx, const X509 *cert);
#endif
#ifdef CONFIG_SSL_FULL_MODE
EXP_FUNC void STDCALL x509_print(const X509 *cert, CA_CERT *ca_cert_ctx);
EXP_FUNC const char* STDCALL x509_display_error(int error);
#endif

/**************************************************************************
 * ASN1 declarations 
 **************************************************************************/
#define ASN1_INTEGER				0x02
#define ASN1_BIT_STRING			0x03
#define ASN1_OCTET_STRING			0x04
#define ASN1_NULL					0x05
#define ASN1_OID					0x06
#define ASN1_PRINTABLE_STR2		0x0C

#define ASN1_PRINTABLE_STR			0x13
#define ASN1_TELETEX_STR			0x14
#define ASN1_IA5_STR				0x16
#define ASN1_UTC_TIME				0x17
#define ASN1_GENERALIZED_TIME		0x18
#define ASN1_UNICODE_STR			0x1e

#define ASN1_SEQUENCE				0x30
#define ASN1_SET					0x31

#define ASN1_IMPLICIT_TAG			0x80
#define ASN1_CONTEXT_DNSNAME		0x82

#define ASN1_EXPLICIT_TAG			0xa0
#define ASN1_V3_DATA				0xa3


#define SIG_TYPE_MD2            0x02
#define SIG_TYPE_MD5            0x04
#define SIG_TYPE_SHA1           0x05
#define SIG_TYPE_SHA256         0x0b
#define SIG_TYPE_SHA384         0x0c
#define SIG_TYPE_SHA512         0x0d

uint32_t get_asn1_length(const uint8_t *buf, int *offset);
EXP_FUNC int STDCALL asn1_get_private_key(const uint8_t *buf, int len, RSA_CTX **rsa_ctx);
int asn1_next_obj(const uint8_t *buf, int *offset, int obj_type);
int asn1_skip_obj(const uint8_t *buf, int *offset, int obj_type);
int asn1_get_int(const uint8_t *buf, int *offset, uint8_t **object);
int asn1_version(const uint8_t *cert, int *offset, X509 *x509_ctx);
int asn1_validity(const uint8_t *cert, int *offset, X509 *x509_ctx);
int asn1_name(const uint8_t *cert, int *offset, char *dn[]);
int asn1_public_key(const uint8_t *cert, int *offset, X509 *x509_ctx);
#ifdef CONFIG_SSL_CERT_VERIFICATION
int asn1_signature(const uint8_t *cert, int *offset, X509 *x509_ctx);
int asn1_find_subjectaltname(const uint8_t* cert, int offset);
int asn1_compare_dn(char * const dn1[], char * const dn2[]);
#endif /* CONFIG_SSL_CERT_VERIFICATION */
int asn1_signature_type(const uint8_t *cert, 
                                int *offset, X509 *x509_ctx);

int asn1_serial_number(const uint8_t *buf, int *offset, X509 *_x509);


/**************************************************************************
 * MISC declarations 
 **************************************************************************/
#define SALT_SIZE               8

typedef void (STDCALL *crypt_func)(void *, const uint8_t *, uint8_t *, int);
typedef void (STDCALL *hmac_func)(const uint8_t *msg, int length, const uint8_t *key, int key_len, uint8_t *digest);

EXP_FUNC int STDCALL get_file(const char *filename, uint8_t **buf);

#if defined(CONFIG_SSL_FULL_MODE) || defined(WIN32) || defined(CONFIG_DEBUG)
EXP_FUNC void STDCALL print_blob(const uint8_t *data, int size, const char *format, ...);
#else
    #define print_blob(...)
#endif

EXP_FUNC int STDCALL base64_decode(const char *in,  int len, uint8_t *out, int *outlen);

#ifdef __cplusplus
}
#endif

#endif

