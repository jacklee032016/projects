/*
* ECPTLS: Embedded Cross-Platform TLS and Crypto Definations
* Zhijie, Li, Nov.17,2015
*/
#ifndef	__ECP_TLS_H__
#define	__ECP_TLS_H__


/****** definations for TLS protocol *******/

#define	SSL_MASTER_SECRET_SIZE		48
#define	TLS_FINISHED_VERIFY_SIZE		12

#define	TLS_GMT_UNIX_TIME_SIZE		4
#define	TLS_RANDOM_BITS_SIZE			28
#define	TLS_RANDOM_SIZE             		(TLS_GMT_UNIX_TIME_SIZE+TLS_RANDOM_BITS_SIZE)


#define	SSL_MASTER_SECRET_NAME		"master secret"
#define	SSL_KEY_EXPAND_NAME			"key expansion"

#define	TLS_FINISH_LABEL_CLIENT		"client finished"
#define	TLS_FINISH_LABEL_SERVER		"server finished"


/* protocol types */
typedef	enum
{
	TLS_CNT_CHANGE_CIPHER_SPEC	= 20,
	TLS_CNT_ALERT					= 21,
	TLS_CNT_HANDSHAKE			= 22,
	TLS_CNT_APP_DATA				= 23
}TLS_CNT_TYPE;


/* handshaking types */
typedef	enum
{
	HS_HELLO_REQUEST		= 0,
	HS_CLIENT_HELLO		= 1,
	HS_SERVER_HELLO		= 2,
	HS_CERTIFICATE			= 11,
	HS_SERVER_KEY_XCHG	= 12,
	HS_CERT_REQ			= 13,
	HS_SERVER_HELLO_DONE = 14,
	HS_CERT_VERIFY			= 15,
	HS_CLIENT_KEY_XCHG	= 16,
	HS_FINISHED			= 20
}HAND_SHAKE_T;


typedef	enum
{
	TLS_ALERT_LEVEL_WARNING	= 1,
	TLS_ALERT_LEVEL_FATAL		= 2
}TLS_ALERT_LEVEL_T;

typedef	enum
{
	TLS_ALERT_CLOSE_NOTIFY				= 0,
	TLS_ALERT_UNEXPECTED_MESSAGE		= 10,
	TLS_ALERT_BAD_RECORD_MAC 			= 20,
	TLS_ALERT_DECRYPTION_FAILED 			= 21,
	TLS_ALERT_RECORD_OVERFLOW			= 22,
	TLS_ALERT_DECOMPRESS_FAILED			= 30,
	TLS_ALERT_HANDSHAKE_FAILURE			= 40,
	TLS_ALERT_NO_CERT_RESERVED			= 41,
	TLS_ALERT_BAD_CERTIFICATE			= 42,
	TLS_ALERT_UNSPPORTED_CERT			= 43,
	TLS_ALERT_CERT_REVOKED				= 44,
	TLS_ALERT_CERT_EXPIRED				= 45,
	TLS_ALERT_CERT_UNKNOWN				= 46,
	TLS_ALERT_ILLEGAL_PARAMETER			= 47,
	TLS_ALERT_UNKNOWN_CA				= 48,
	TSL_ALERT_ACCESS_DENIED				= 49,
	TLS_ALERT_DECODE_ERROR				= 50,
	TLS_ALERT_DECRYPT_ERROR				= 51,
	TLS_ALERT_EXPORT_RESTRICT_RESERVED	= 60,
	TLS_ALERT_INVALID_VERSION			= 70,
	TLS_ALERT_INSUFFICIENT_SECURITY		= 71,
	TLS_ALERT_INTERNEL_ERROR				= 80,
	TLS_ALERT_USER_CANCELED				= 90,
	TLS_ALERT_NO_RENEGOTIATION			= 100
}TLS_ALERT_DESCRIPT_T;


/* in TLS 1.1, SHA1 and MD5 are default.*/
typedef	enum
{
	CST_RC4_128_MD5 =	0x04,/* stream cipher*/
	CST_RC4_128_SHA = 0x05,
	
	CST_AES128_CBC_SHA = 0x2f,/* block cipher, SHA1 is default */
	CST_AES256_CBC_SHA = 0x35,
}CIPHER_SPEC_T;

#ifdef	WIN32
#pragma pack(push, 1) //packing is now 1
#endif

/* header of record protocol, 5 bytes */
struct _TLS_RECORD_HEADER
{
	unsigned	char		cntType;
	unsigned char		major;
	unsigned char		minor;
	unsigned short	length;
}__attribute__ ((packed));

struct _TLS_ALERT_HEADER
{
	unsigned char		level;
	unsigned char		description;
}__attribute__ ((packed));


/* header of handshake protocol, 4 bytes */
struct _TLS_HS_HEADER
{
	unsigned	char		hsType;
	unsigned char		lengthHigh;
	unsigned short	length;
}__attribute__ ((packed));


struct _TLS_HS_HELLO_MSG_HEADER
{
	unsigned char		major;
	unsigned char		minor;
	uint32_t			gmtUnixTime;
	unsigned char		random[TLS_RANDOM_BITS_SIZE];
}__attribute__ ((packed));

struct	_TLS_CIPHER_SUITE
{
	unsigned char		keyExchange;
	unsigned char		cipherSpec;
}__attribute__ ((packed));



typedef	struct _TLS_RECORD_HEADER			TLS_RECORD_HEADER;

typedef	struct _TLS_ALERT_HEADER				TLS_ALERT_HEADER;

typedef	struct _TLS_HS_HEADER 				TLS_HS_HEADER;

typedef	struct _TLS_HS_HELLO_MSG_HEADER		TLS_HS_HELLO_MSG_HEADER;


typedef	struct _TLS_CIPHER_SUITE				TLS_CIPHER_SUITE;


typedef	struct
{
	char					*name;
	TLS_CIPHER_SUITE	cipherSuites;
}STR_CIPHER_SUITE;

#define	SSL_PORT_HTTP				443

#ifdef	WIN32
#pragma pack(pop) //packing is 8
#endif

/* need to predefine before ssl_lib.h gets to it */
#define SSL_SESSION_ID_SIZE                     32

typedef	enum
{
	TLS_STATE_OFF		=0,
	TLS_STATE_CLIENT_HELLO,
	TLS_STATE_SERVER_HELLO,
	TLS_STATE_CLIENT_FINISH,
	TLS_STATE_SERVER_FINISH,
	TLS_STATE_APP,
	TLS_STATE_RENEGOTIATE,
	TLS_STATE_ERR		=0xFE,
	TLS_STATE_CONTINUE		=0xFF
}TLS_STATE_T;

typedef	enum
{
	TLS_EVENT_HELLO,
	TLS_EVENT_CERT,
	TLS_EVENT_KEYEXCHANGE,
	TLS_EVENT_CERT_REQ,
	TLS_EVNET_HELLO_DONE,
	TLS_EVENT_CERT_VERIFY,
	TLS_EVENT_CIPHER_CHANGED,
	TLS_EVENT_FINISH,
	TLS_EVENT_HELLO_REQ,
	TLS_EVENT_APP,	/* data from app */
}TLS_EVENT_T;



#define SSL_PROTOCOL_MIN_VERSION    0x31   /* TLS v1.0 */
#define SSL_PROTOCOL_MINOR_VERSION  0x02   /* TLS v1.1 */
#define SSL_PROTOCOL_VERSION_MAX    0x32   /* TLS v1.1 */
#define SSL_PROTOCOL_VERSION1_1     0x32   /* TLS v1.1 */

#define SSL_SERVER_READ             0
#define SSL_SERVER_WRITE            1
#define SSL_CLIENT_READ             2
#define SSL_CLIENT_WRITE            3


/* some macros to muck around with flag bits */
#define SET_SSL_FLAG(A)             (ssl->flag |= A)
#define CLR_SSL_FLAG(A)             (ssl->flag &= ~A)
#define IS_SET_SSL_FLAG(A)          (ssl->flag & A)

#define MAX_KEY_BYTE_SIZE			512     /* for a 4096 bit key */
#define RT_MAX_PLAIN_LENGTH		16384
#define RT_EXTRA					1024
#define BM_RECORD_OFFSET			5
#define SSL_RECORD_SIZE             5
#define SSL_HS_HDR_SIZE             4


#ifdef CONFIG_SSL_SKELETON_MODE
#define NUM_PROTOCOLS               1
#else
#define NUM_PROTOCOLS               4
#endif

#define PARANOIA_CHECK(A, B)        if (A < B) { \
    ret = SSL_ERROR_INVALID_HANDSHAKE; goto error; }


typedef struct 
{
	uint8_t		cipher;
	
	uint8_t		key_size;
	uint8_t		iv_size;
	uint8_t		key_block_size;	/* refer to sec 6.3 of specs */
	uint8_t		padding_size;
	uint8_t		digest_size;
	
	hmac_func	hmac;
	crypt_func	encrypt;
	crypt_func	decrypt;
} cipher_info_t;

struct _SSLObjLoader 
{
	uint8_t	*buf;
	int		len;
};

typedef struct _SSLObjLoader SSLObjLoader;

typedef struct 
{
	time_t	conn_time;
	uint8_t	session_id[SSL_SESSION_ID_SIZE];
	uint8_t	master_secret[SSL_MASTER_SECRET_SIZE];
} SSL_SESSION;

typedef struct
{
	uint8_t	*buf;
	int		size;
} SSL_CERT;

typedef struct
{
	MD5_CTX	md5_ctx;
	SHA1_CTX	sha1_ctx;
	
	uint8_t		final_finish_mac[TLS_FINISHED_VERIFY_SIZE];/* store the rxed finish verify data */
	uint8_t		*key_block;
	
	uint8_t		master_secret[SSL_MASTER_SECRET_SIZE];
	uint8_t		client_random[TLS_RANDOM_SIZE]; /* client's random sequence */
	uint8_t		server_random[TLS_RANDOM_SIZE]; /* server's random sequence */
	uint16_t		bm_proc_index;
} DISPOSABLE_CTX;

struct _SSL
{
	uint32_t				flag;
	uint16_t				need_bytes;
	uint16_t				got_bytes;
	uint8_t				record_type;
	uint8_t				cipher;
	uint8_t				sess_id_size;
	uint8_t				version;
	uint8_t				client_version;
	int16_t				next_state;
	int16_t				hs_status;

	TLS_STATE_T			status;
	DISPOSABLE_CTX		*dc;         /* temporary data which we'll get rid of soon */
	int					client_fd;
	
	const cipher_info_t		*cipher_info;
	void					*encrypt_ctx;
	void					*decrypt_ctx;
	
	uint8_t				bm_all_data[RT_MAX_PLAIN_LENGTH+RT_EXTRA];
	uint8_t				*bm_data;
	uint16_t				bm_index;
	uint16_t				bm_read_index;
	
	struct _SSL			*next;
	struct _SSL			*prev;
	struct _SSL_CTX		*ctx;
#ifndef CONFIG_SSL_SKELETON_MODE
	uint16_t				session_index;
	SSL_SESSION			*session;
#endif

#ifdef CONFIG_SSL_CERT_VERIFICATION
	X509			*x509_ctx;
#endif

	uint8_t		session_id[SSL_SESSION_ID_SIZE];

	uint8_t		client_mac[HASH_MD_LENGTH_SHA1];  /* write MAC secrect */
	uint8_t		server_mac[HASH_MD_LENGTH_SHA1];  /* write MAC secrect */

	uint8_t		read_sequence[8];		/* 64 bit sequence number */
	uint8_t		write_sequence[8];		/* 64 bit sequence number */
	
	uint8_t		hmac_header[SSL_RECORD_SIZE];    /* rx hmac */
};

typedef struct _SSL SSL;



typedef	struct	_fsm_event_t
{
	TLS_EVENT_T			event;
	
	TLS_STATE_T			( *handler)(SSL *ssl);
}fsm_event_t;


typedef	struct	_fsm_req_status_t
{
	TLS_STATE_T			state;

	int					size;
	fsm_event_t			*events;
}fsm_req_status_t;


typedef	struct	_TLS_FSM
{
	int					size;
	fsm_req_status_t		*states;
}TLS_FSM;


struct _SSL_CTX
{
	uint32_t			options;
	RSA_CTX			*rsa_ctx;	/* private key of RSA */
	
#ifdef CONFIG_SSL_CERT_VERIFICATION
	CA_CERT			*ca_cert_ctx;		/* CA(x509) certs array */
#endif

	uint8_t			chain_length;
	/* cert chain, hold raw data, so can be used for different cert type */
	SSL_CERT		certs[CONFIG_SSL_MAX_CERTS];/* cert(buf of x509) chain */

	SSL				*head;
	SSL				*tail;
	
#ifndef CONFIG_SSL_SKELETON_MODE
	uint16_t			num_sessions;
	SSL_SESSION		**ssl_sessions;
#endif

#ifdef CONFIG_SSL_CTX_MUTEXING
	SSL_CTX_MUTEX_TYPE mutex;
#endif

#ifdef CONFIG_OPENSSL_COMPATIBLE
	void				*bonus_attr;
#endif

	TLS_FSM			*fsm;
};

typedef struct _SSL_CTX SSL_CTX;

/* backwards compatibility */
typedef struct _SSL_CTX SSLCTX;

extern const uint8_t ssl_prot_prefs[NUM_PROTOCOLS];

SSL *ssl_new(SSL_CTX *ssl_ctx, int client_fd);
void disposable_new(SSL *ssl);
void disposable_free(SSL *ssl);
int send_packet(SSL *ssl, uint8_t protocol, 
        const uint8_t *in, int length);
int do_svr_handshake(SSL *ssl, HAND_SHAKE_T handshake_type, uint8_t *buf, int hs_len);
int do_clnt_handshake(SSL *ssl, HAND_SHAKE_T handshake_type, uint8_t *buf, int hs_len);
int process_finished(SSL *ssl, uint8_t *buf, int hs_len);
int process_sslv23_client_hello(SSL *ssl);
int send_alert(SSL *ssl, int error_code);
int send_finished(SSL *ssl);
int send_certificate(SSL *ssl);
int send_change_cipher_spec(SSL *ssl);
void finished_digest(SSL *ssl, const char *label, uint8_t *digest);
void generate_master_secret(SSL *ssl, const uint8_t *premaster_secret);
void add_packet(SSL *ssl, const uint8_t *pkt, int len);
EXP_FUNC int STDCALL add_cert(SSL_CTX *ssl_ctx, const uint8_t *buf, int len);
int add_private_key(SSL_CTX *ssl_ctx, SSLObjLoader *ssl_obj);
void ssl_obj_free(SSLObjLoader *ssl_obj);
int pkcs8_decode(SSL_CTX *ssl_ctx, SSLObjLoader *ssl_obj, const char *password);
int pkcs12_decode(SSL_CTX *ssl_ctx, SSLObjLoader *ssl_obj, const char *password);
int load_key_certs(SSL_CTX *ssl_ctx);
#ifdef CONFIG_SSL_CERT_VERIFICATION
EXP_FUNC int STDCALL add_cert_auth(SSL_CTX *ssl_ctx, const uint8_t *buf, int len);
void remove_ca_certs(CA_CERT *ca_cert_ctx);
#endif
#ifdef CONFIG_SSL_ENABLE_CLIENT
int do_client_connect(SSL *ssl);
#endif

#ifdef CONFIG_SSL_FULL_MODE
void DISPLAY_STATE(SSL *ssl, int is_send, uint8_t state, int not_ok);
void DISPLAY_CERT(SSL *ssl, const X509 *x509_ctx);
void DISPLAY_RSA(SSL *ssl,  const RSA_CTX *rsa_ctx);
void ecpDebugDumpAlert(SSL *ssl, TLS_ALERT_HEADER *header, int isRx);
#else
#define DISPLAY_STATE(A,B,C,D)
#define DISPLAY_CERT(A,B)
#define DISPLAY_RSA(A,B)
#define ecpDebugDumpAlert(A, B, C)
#endif

#ifdef CONFIG_SSL_CERT_VERIFICATION
int process_certificate(SSL *ssl, X509 **x509_ctx);
#endif

SSL_SESSION *ssl_session_update(int max_sessions, 
        SSL_SESSION *ssl_sessions[], SSL *ssl,
        const uint8_t *session_id);
void kill_ssl_session(SSL_SESSION **ssl_sessions, SSL *ssl);


int set_key_block(SSL *ssl, int is_write);
int do_handshake(SSL *ssl, uint8_t *buf, int read_len);


EXP_FUNC int STDCALL client_socket_init(unsigned char *dnsName, uint16_t port);
EXP_FUNC int STDCALL server_socket_init(int port);


char *getSystemErrorMsg(void );



const char *ecpTlsHandshakeName(HAND_SHAKE_T hst);
const char *ecpTlsProtocolName(TLS_CNT_TYPE protocol);

int	ecpFillData(uint8_t *buf, uint8_t *data, uint32_t len);

#endif

