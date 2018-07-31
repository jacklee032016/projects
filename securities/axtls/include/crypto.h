
#ifndef HEADER_CRYPTO_H
#define HEADER_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include "compacts.h"

#include "bigint_impl.h"
#include "bigint.h"


/****** definations for cryptography ******/
typedef	enum	
{
	HASH_MD_LENGTH_MD5			= 16,
	HASH_MD_LENGTH_RIPEMD		= 20,
	HASH_MD_LENGTH_SHA1			= 20,
	HASH_MD_LENGTH_SHA256		= 32,
	HASH_MD_LENGTH_SHA384		= 48,
	HASH_MD_LENGTH_SHA512		= 64
}HASH_MD_LENGTH;

typedef	enum
{
	HASH_DATA_LENGTH_MD5		= 64,
	HASH_DATA_LENGTH_RIPEMD		= 64,
	HASH_DATA_LENGTH_SHA1		= 64,
	HASH_DATA_LENGTH_SHA256		= 64,
	HASH_DATA_LENGTH_SHA512		= 128
}HASH_DATA_LENGTH;



#ifndef STDCALL
#define STDCALL
#endif
#ifndef EXP_FUNC
#define EXP_FUNC
#endif


/* enable features based on a 'super-set' capbaility. */
#if defined(CONFIG_SSL_FULL_MODE) 
#define CONFIG_SSL_ENABLE_CLIENT
#define CONFIG_SSL_CERT_VERIFICATION
#elif defined(CONFIG_SSL_ENABLE_CLIENT)
#define CONFIG_SSL_CERT_VERIFICATION
#endif

/*
 * AES declarations 
*/
#define AES_MAXROUNDS			14
#define AES_BLOCKSIZE			16
#define AES_IV_SIZE				16

typedef struct aes_key_st 
{
	uint16_t		rounds;
	uint16_t		key_size;
	uint32_t		ks[(AES_MAXROUNDS+1)*8];
	uint8_t		iv[AES_IV_SIZE];
} AES_CTX;

typedef enum
{
	AES_MODE_128,
	AES_MODE_256
} AES_MODE;

EXP_FUNC void STDCALL AES_set_key(AES_CTX *ctx, const uint8_t *key, const uint8_t *iv, AES_MODE mode);
EXP_FUNC void STDCALL AES_cbc_encrypt(AES_CTX *ctx, const uint8_t *msg, uint8_t *out, int length);
EXP_FUNC void STDCALL AES_cbc_decrypt(AES_CTX *ks, const uint8_t *in, uint8_t *out, int length);
EXP_FUNC void STDCALL AES_convert_key(AES_CTX *ctx);

typedef struct 
{
	uint8_t x, y, m[256];
} RC4_CTX;

EXP_FUNC void STDCALL RC4_setup(RC4_CTX *s, const uint8_t *key, int length);
EXP_FUNC void STDCALL RC4_crypt(RC4_CTX *s, const uint8_t *msg, uint8_t *data, int length);


typedef struct 
{
	uint32_t Intermediate_Hash[HASH_MD_LENGTH_SHA1/4]; /* Message Digest */
	uint32_t Length_Low;            /* Message length in bits */
	uint32_t Length_High;           /* Message length in bits */
	uint16_t Message_Block_Index;   /* Index into message block array   */
	uint8_t Message_Block[64];      /* 512-bit message blocks */
} SHA1_CTX;

EXP_FUNC void STDCALL SHA1_Init(SHA1_CTX *);
EXP_FUNC void STDCALL SHA1_Update(SHA1_CTX *, const uint8_t * msg, int len);
EXP_FUNC void STDCALL SHA1_Final(uint8_t *digest, SHA1_CTX *);


typedef struct
{
	uint32_t total[2];
	uint32_t state[8];
	uint8_t buffer[64];
} SHA256_CTX;

EXP_FUNC void STDCALL SHA256_Init(SHA256_CTX *c);
EXP_FUNC void STDCALL SHA256_Update(SHA256_CTX *, const uint8_t *input, int len);
EXP_FUNC void STDCALL SHA256_Final(uint8_t *digest, SHA256_CTX *);

typedef struct
{
	union
	{
		uint64_t h[8];
		uint8_t digest[64];
	}h_dig;
	
	union
	{
		uint64_t w[80];
		uint8_t buffer[128];
	}w_buf;
	
	size_t		size;
	uint64_t		totalSize;
} SHA512_CTX;

EXP_FUNC void STDCALL SHA512_Init(SHA512_CTX *c);
EXP_FUNC void STDCALL SHA512_Update(SHA512_CTX *, const uint8_t *input, int len);
EXP_FUNC void STDCALL SHA512_Final(uint8_t *digest, SHA512_CTX *);


#define HASH_MD_LENGTH_SHA384   48

typedef SHA512_CTX SHA384_CTX;
EXP_FUNC void STDCALL SHA384_Init(SHA384_CTX *c);
EXP_FUNC void STDCALL SHA384_Update(SHA384_CTX *, const uint8_t *input, int len);
EXP_FUNC void STDCALL SHA384_Final(uint8_t *digest, SHA384_CTX *);



typedef struct 
{
	uint32_t	state[4];		/* state (ABCD) */
	uint32_t	count[2];	/* number of bits, modulo 2^64 (lsb first) */
	
	uint8_t	buffer[HASH_DATA_LENGTH_MD5];	/* input buffer */
} MD5_CTX;

EXP_FUNC void STDCALL MD5_Init(MD5_CTX *);
EXP_FUNC void STDCALL MD5_Update(MD5_CTX *, const uint8_t *msg, int len);
EXP_FUNC void STDCALL MD5_Final(uint8_t *digest, MD5_CTX *);


EXP_FUNC void STDCALL hmac_md5(const uint8_t *msg, int length, const uint8_t *key, int key_len, uint8_t *digest);
EXP_FUNC void STDCALL hmac_sha1(const uint8_t *msg, int length, const uint8_t *key, int key_len, uint8_t *digest);



typedef struct 
{
	bigint	*m;		/* modulus */
	bigint	*e;		/* public exponent */
	bigint	*d;		/* private exponent */
#ifdef CONFIG_BIGINT_CRT
	bigint	*p;		/* p as in m = pq */
	bigint	*q;		/* q as in m = pq */
	bigint	*dP;	/* d mod (p-1) */
	bigint	*dQ;	/* d mod (q-1) */
	bigint	*qInv;	/* q^-1 mod p */
#endif
	int		num_octets;		/* length of modulus(Phi) */
	BI_CTX	*bi_ctx;
} RSA_CTX;


#include "crypto_misc.h"


EXP_FUNC void STDCALL RSA_priv_key_new(RSA_CTX **rsa_ctx, 
        const uint8_t *modulus, int mod_len,
        const uint8_t *pub_exp, int pub_len,
        const uint8_t *priv_exp, int priv_len
#ifdef CONFIG_BIGINT_CRT
      , const uint8_t *p, int p_len,
        const uint8_t *q, int q_len,
        const uint8_t *dP, int dP_len,
        const uint8_t *dQ, int dQ_len,
        const uint8_t *qInv, int qInv_len
#endif
        );
EXP_FUNC void STDCALL RSA_pub_key_new(RSA_CTX **rsa_ctx, const uint8_t *modulus, int mod_len, const uint8_t *pub_exp, int pub_len);
EXP_FUNC void STDCALL RSA_free(RSA_CTX *ctx);
EXP_FUNC int STDCALL RSA_decryptOrVerify(const RSA_CTX *ctx, const uint8_t *in_data, uint8_t *out_data, int out_len, int is_decryption);

EXP_FUNC bigint * STDCALL RSA_private(const RSA_CTX *c, bigint *bi_msg);
#if defined(CONFIG_SSL_CERT_VERIFICATION) || defined(CONFIG_SSL_GENERATE_X509_CERT)
//EXP_FUNC bigint * STDCALL RSA_sign_verify(BI_CTX *ctx, const uint8_t *sig, int sig_len,
//        bigint *modulus, bigint *pub_exp);
EXP_FUNC bigint * STDCALL RSA_public(const RSA_CTX * c, bigint *bi_msg);
EXP_FUNC int STDCALL RSA_encryptOrSign(const RSA_CTX *ctx, const uint8_t *in_data, uint16_t in_len, uint8_t *out_data, int is_signing);
EXP_FUNC void STDCALL RSA_print(const RSA_CTX *ctx);
#endif

/*
 * RNG declarations 
*/
EXP_FUNC void STDCALL RNG_initialize(void);
EXP_FUNC void STDCALL RNG_custom_init(const uint8_t *seed_buf, int size);
EXP_FUNC void STDCALL RNG_terminate(void);
EXP_FUNC int STDCALL get_random(int num_rand_bytes, uint8_t *rand_data);
int get_random_NZ(int num_rand_bytes, uint8_t *rand_data);



EXP_FUNC void	STDCALL axDebugDump(void *buf, int size);
EXP_FUNC uint64_t STDCALL axBe64ToHost(uint64_t be);
EXP_FUNC void STDCALL axPrintf(const char *format,...);



#ifdef __cplusplus
}
#endif

#endif 

