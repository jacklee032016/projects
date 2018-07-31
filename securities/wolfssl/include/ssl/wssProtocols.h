/*
* All definations and declarations about SSL/TLS/DTLS protocol
*/

#ifndef __WSS_PROTOCOLS_H__
#define __WSS_PROTOCOLS_H__

typedef	enum HandShakeType {
	no_shake            = -1,
	hello_request       = 0, 
	HST_CLIENT_HELLO        = 1, 
	server_hello        = 2,
	hello_verify_request = 3,       /* DTLS addition */
	session_ticket      =  4,
	certificate         = 11, 
	server_key_exchange = 12,
	certificate_request = 13, 
	server_hello_done   = 14,
	certificate_verify  = 15, 
	client_key_exchange = 16,
	finished            = 20,
	certificate_status  = 22,
	/* simulate unique handshake type for sanity checks.  record layer change_cipher conflicts with handshake finished */
	change_cipher_hs    = 55 
}HAND_SHAKE_TYPE_T;


enum SSL_VERSION
{
	DTLS_MAJOR      = 0xfe,     /* DTLS major version number */
	DTLS_MINOR      = 0xff,     /* DTLS minor version number */
	DTLSv1_2_MINOR  = 0xfd,     /* DTLS minor version number */

	SSLv3_MAJOR     = 3,        /* SSLv3 and TLSv1+  major version number */
	SSLv3_MINOR     = 0,        /* TLSv1   minor version number */

	TLSv1_MINOR     = 1,        /* TLSv1   minor version number */
	TLSv1_1_MINOR   = 2,        /* TLSv1_1 minor version number */
	TLSv1_2_MINOR   = 3,        /* TLSv1_2 minor version number */
};

enum SSL_CONSTANTS
{
	HANDSHAKE_HEADER_SZ   = 4,  /* type + length(3)        */
	RECORD_HEADER_SZ      = 5,  /* type + version + len(2) */

};

/* client connect state for nonblocking restart */
enum ConnectState {
	CONNECT_BEGIN = 0,
	CLIENT_HELLO_SENT,
	HELLO_AGAIN,               /* HELLO_AGAIN s for DTLS case */
	HELLO_AGAIN_REPLY,
	FIRST_REPLY_DONE,
	FIRST_REPLY_FIRST,
	FIRST_REPLY_SECOND,
	FIRST_REPLY_THIRD,
	FIRST_REPLY_FOURTH,
	FINISHED_DONE,
	SECOND_REPLY_DONE
};


/* server accept state for nonblocking restart */
enum AcceptState {
	ACCEPT_BEGIN = 0,
	ACCEPT_CLIENT_HELLO_DONE,
	HELLO_VERIFY_SENT,
	ACCEPT_FIRST_REPLY_DONE,
	SERVER_HELLO_SENT,
	CERT_SENT,
	KEY_EXCHANGE_SENT,
	CERT_REQ_SENT,
	SERVER_HELLO_DONE,
	ACCEPT_SECOND_REPLY_DONE,
	TICKET_SENT,
	CHANGE_CIPHER_SENT,
	ACCEPT_FINISHED_DONE,
	ACCEPT_THIRD_REPLY_DONE
};


/* Record Layer Header identifier from page 12 */
typedef	enum ContentType {
	no_type				= 0,
	change_cipher_spec	= 20, 
	alert				= 21, 
	handshake			= 22, 
	application_data		= 23 
}CONTENT_TYPE_T;



/* record layer header for PlainText, Compressed, and CipherText */
typedef struct RecordLayerHeader
{
	byte		type;
	byte		pvMajor;
	byte		pvMinor;
	byte		length[2];
} RecordLayerHeader;


/* record layer header for DTLS PlainText, Compressed, and CipherText */
typedef struct DtlsRecordLayerHeader
{
	byte		type;
	byte		pvMajor;
	byte		pvMinor;
	byte		epoch[2];             /* increment on cipher state change */
	byte		sequence_number[6];   /* per record */
	byte		length[2];
} DtlsRecordLayerHeader;


/* handshake header, same for each message type, pgs 20/21 */
typedef struct HandShakeHeader
{
	byte			type;
	word24		length;
} HandShakeHeader;


/* DTLS handshake header, same for each message type */
typedef struct DtlsHandShakeHeader
{
	byte			type;
	word24		length;
	byte			message_seq[2];    /* start at 0, restransmit gets same # */
	word24		fragment_offset;   /* bytes in previous fragments */
	word24		fragment_length;   /* length of this fragment */
} DtlsHandShakeHeader;



#endif

