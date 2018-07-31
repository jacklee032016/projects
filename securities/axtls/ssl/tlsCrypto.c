
#include "tls.h"


/**
 * The cipher map containing all the essentials for each cipher.
 */
#ifdef CONFIG_SSL_SKELETON_MODE
static const cipher_info_t cipher_info[NUM_PROTOCOLS] = 
{
	{   /* RC4-SHA */
		CST_RC4_128_SHA,	/* RC4-SHA */
		16,					/* key size */
		0,					/* iv size */ 
		2*(HASH_MD_LENGTH_SHA1+16),	/* key block size */
		0,						/* no padding */
		HASH_MD_LENGTH_SHA1,	/* digest size */
		hmac_sha1,				/* hmac algorithm */
		(crypt_func)RC4_crypt,          /* encrypt */
		(crypt_func)RC4_crypt           /* decrypt */
	},
};
#else
static const cipher_info_t cipher_info[NUM_PROTOCOLS] = 
{
	{   /* AES128-SHA */
		CST_AES128_CBC_SHA,                 /* AES128-SHA */
		16,                             /* key size */
		16,                             /* iv size */ 
		2*(HASH_MD_LENGTH_SHA1+16+16),            /* key block size */
		16,                             /* block padding size */
		HASH_MD_LENGTH_SHA1,                      /* digest size */
		hmac_sha1,
		(crypt_func)AES_cbc_encrypt,
		(crypt_func)AES_cbc_decrypt
	},
	
	{   /* AES256-SHA */
		CST_AES256_CBC_SHA,                 /* AES256-SHA */
		32,                             /* key size */
		16,                             /* iv size */ 
		2*(HASH_MD_LENGTH_SHA1+32+16),            /* key block size */
		16,                             /* block padding size */
		HASH_MD_LENGTH_SHA1,                      /* digest size */
		hmac_sha1,                      /* hmac algorithm */
		(crypt_func)AES_cbc_encrypt,
		(crypt_func)AES_cbc_decrypt
	},
	
	{   /* RC4-SHA */
		CST_RC4_128_SHA,                /* RC4-SHA */
		16,                             /* key size */
		0,                              /* iv size */ 
		2*(HASH_MD_LENGTH_SHA1+16),               /* key block size */
		0,                              /* no padding */
		HASH_MD_LENGTH_SHA1,                      /* digest size */
		hmac_sha1,
		(crypt_func)RC4_crypt,
		(crypt_func)RC4_crypt
	},
	
	/*
	* This protocol is from SSLv2 days and is unlikely to be used - but was
	* useful for testing different possible digest algorithms.
	*/
	{   /* RC4-MD5 */
		CST_RC4_128_MD5,                /* RC4-MD5 */
		16,                             /* key size */
		0,                              /* iv size */ 
		2*(HASH_MD_LENGTH_MD5+16),                /* key block size */
		0,                              /* no padding */
		HASH_MD_LENGTH_MD5,                       /* digest size */
		hmac_md5,
		(crypt_func)RC4_crypt,
		(crypt_func)RC4_crypt
	},
};
#endif


/**
 * @brief Get what we need for key info.
 * @param cipher    [in]    The cipher information we are after
 * @param key_size  [out]   The key size for the cipher
 * @param iv_size   [out]   The iv size for the cipher
 * @return  The amount of key information we need.
 */
static const cipher_info_t *get_cipher_info(uint8_t cipher)
{
    int i;

    for (i = 0; i < NUM_PROTOCOLS; i++)
    {
        if (cipher_info[i].cipher == cipher)
        {
            return &cipher_info[i];
        }
    }

    return NULL;  /* error */
}

/**
 * Add a packet to the end of our sent and received packets, so that we may use
 * it to calculate the hash at the end.
 */
void add_packet(SSL *ssl, const uint8_t *pkt, int len)
{
	MD5_Update(&ssl->dc->md5_ctx, pkt, len);
	SHA1_Update(&ssl->dc->sha1_ctx, pkt, len);
}

/* data expansion function of MD5 in section 5 of specs */
static void __p_hash_md5(const uint8_t *sec, int sec_len, uint8_t *seed, int seed_len, uint8_t *out, int olen)
{
	uint8_t a1[128];

	/* A(1) */
	hmac_md5(seed, seed_len, sec, sec_len, a1);
	memcpy(&a1[HASH_MD_LENGTH_MD5], seed, seed_len);
	hmac_md5(a1, HASH_MD_LENGTH_MD5+seed_len, sec, sec_len, out);

	while (olen > HASH_MD_LENGTH_MD5)
	{
		uint8_t a2[HASH_MD_LENGTH_MD5];
		out += HASH_MD_LENGTH_MD5;
		olen -= HASH_MD_LENGTH_MD5;

		/* A(N) */
		hmac_md5(a1, HASH_MD_LENGTH_MD5, sec, sec_len, a2);
		memcpy(a1, a2, HASH_MD_LENGTH_MD5);

		/* work out the actual hash */
		hmac_md5(a1, HASH_MD_LENGTH_MD5+seed_len, sec, sec_len, out);
	}
}

/* data expansion function of SHA1 in section 5 of specs */
static void __p_hash_sha1(const uint8_t *sec, int sec_len, uint8_t *seed, int seed_len, uint8_t *out, int olen)
{
    uint8_t a1[128];

    /* A(1) */
    hmac_sha1(seed, seed_len, sec, sec_len, a1);
    memcpy(&a1[HASH_MD_LENGTH_SHA1], seed, seed_len);
    hmac_sha1(a1, HASH_MD_LENGTH_SHA1+seed_len, sec, sec_len, out);

    while (olen > HASH_MD_LENGTH_SHA1)
    {
        uint8_t a2[HASH_MD_LENGTH_SHA1];
        out += HASH_MD_LENGTH_SHA1;
        olen -= HASH_MD_LENGTH_SHA1;

        /* A(N) */
        hmac_sha1(a1, HASH_MD_LENGTH_SHA1, sec, sec_len, a2);
        memcpy(a1, a2, HASH_MD_LENGTH_SHA1);

        /* work out the actual hash */
        hmac_sha1(a1, HASH_MD_LENGTH_SHA1+seed_len, sec, sec_len, out);
    }
}


/* PRF in section 5 of specs. Used in creation of master secret (section 8), key block(sec 6.3).
* Here, seed is also called salt 
*/
static void prf(const uint8_t *sec, int sec_len, uint8_t *seed, int seed_len, uint8_t *out, int olen)
{
	int len, i;
	const uint8_t *S1, *S2;
	uint8_t xbuf[256]; /* needs to be > the amount of key data */
	uint8_t ybuf[256]; /* needs to be > the amount of key data */

	len = sec_len/2;
	S1 = sec;
	S2 = &sec[len];
	len += (sec_len & 1); /* add for odd, make longer */

	__p_hash_md5(S1, len, seed, seed_len, xbuf, olen);
	__p_hash_sha1(S2, len, seed, seed_len, ybuf, olen);

	for (i = 0; i < olen; i++)
		out[i] = xbuf[i] ^ ybuf[i];
}

/**
 * Generate a master secret based on the client/server random data and the premaster secret.
 */
void generate_master_secret(SSL *ssl, const uint8_t *premaster_secret)
{
	uint8_t buf[128];   /* needs to be > 13+32+32 in size */
	strcpy((char *)buf, SSL_MASTER_SECRET_NAME);
	memcpy(&buf[13], ssl->dc->client_random, TLS_RANDOM_SIZE);
	memcpy(&buf[45], ssl->dc->server_random, TLS_RANDOM_SIZE);
	prf(premaster_secret, SSL_MASTER_SECRET_SIZE, buf, (TLS_RANDOM_SIZE+TLS_RANDOM_SIZE)+13, ssl->dc->master_secret, SSL_MASTER_SECRET_SIZE);
}

/**
 * Generate a 'random' blob of data used for the generation of keys.
 * key block is splitted into client/server write key(contains IV)/secrect. 
 * The write key of client/server is used as salt of key creation of cipher algorithm.
 * refer to sec 6 of specs
 */
static void _generate_key_block(uint8_t *client_random, uint8_t *server_random,
        uint8_t *master_secret, uint8_t *key_block, int key_block_size)
{
	uint8_t buf[128];
	strcpy((char *)buf, SSL_KEY_EXPAND_NAME);
	memcpy(&buf[13], server_random, TLS_RANDOM_SIZE);
	memcpy(&buf[45], client_random, TLS_RANDOM_SIZE);
	prf(master_secret, SSL_MASTER_SECRET_SIZE, buf, 77, key_block, key_block_size);
}
    
/**
 * Retrieve (and initialise) the context of a cipher.
 */
static void *_crypt_new(SSL *ssl, uint8_t *key, uint8_t *iv, int is_decrypt)
{
	switch (ssl->cipher)
	{
#ifndef CONFIG_SSL_SKELETON_MODE
		case CST_AES128_CBC_SHA:
		{
			AES_CTX *aes_ctx = (AES_CTX *)malloc(sizeof(AES_CTX));
			AES_set_key(aes_ctx, key, iv, AES_MODE_128);

			if (is_decrypt)
			{
				AES_convert_key(aes_ctx);
			}

			return (void *)aes_ctx;
		}

		case CST_AES256_CBC_SHA:
		{
			AES_CTX *aes_ctx = (AES_CTX *)malloc(sizeof(AES_CTX));
			AES_set_key(aes_ctx, key, iv, AES_MODE_256);

			if (is_decrypt)
			{
				AES_convert_key(aes_ctx);
			}

			return (void *)aes_ctx;
		}

		case CST_RC4_128_MD5:
#endif
		case CST_RC4_128_SHA:
		{
			RC4_CTX *rc4_ctx = (RC4_CTX *)malloc(sizeof(RC4_CTX));
			RC4_setup(rc4_ctx, key, 16);
			return (void *)rc4_ctx;
		}
	}

	return NULL;    /* its all gone wrong */
}

/**
 * Work out the cipher keys we are going to use for this session based on the master secret.
 */
int set_key_block(SSL *ssl, int is_write)
{
	uint8_t *q;
	uint8_t client_key[32], server_key[32]; /* big enough for AES256 */
	uint8_t client_iv[16], server_iv[16];   /* big enough for AES128/256 */
	int is_client = IS_SET_SSL_FLAG(SSL_IS_CLIENT);
	const cipher_info_t *ciph_info = get_cipher_info(ssl->cipher);

	if (ciph_info == NULL)
		return -1;

	/* only do once in a handshake */
	if (ssl->dc->key_block == NULL)
	{
		ssl->dc->key_block = (uint8_t *)malloc(ciph_info->key_block_size);

#if 0
		print_blob(ssl->dc->client_random, 32, "client" );
		print_blob(ssl->dc->server_random, 32, "server");
		print_blob(ssl->dc->master_secret, SSL_MASTER_SECRET_SIZE, "master");
#endif
		_generate_key_block(ssl->dc->client_random, ssl->dc->server_random, ssl->dc->master_secret, 
			ssl->dc->key_block, ciph_info->key_block_size);
#if 0
		print_blob(ssl->dc->key_block, ciph_info->key_block_size, "keyblock");
#endif
	}

	q = ssl->dc->key_block;

	if ((is_client && is_write) || (!is_client && !is_write))
	{
		memcpy(ssl->client_mac, q, ciph_info->digest_size);
	}

	q += ciph_info->digest_size;

	if ((!is_client && is_write) || (is_client && !is_write))
	{
		memcpy(ssl->server_mac, q, ciph_info->digest_size);
	}

	q += ciph_info->digest_size;
	memcpy(client_key, q, ciph_info->key_size);
	q += ciph_info->key_size;
	memcpy(server_key, q, ciph_info->key_size);
	q += ciph_info->key_size;

#ifndef CONFIG_SSL_SKELETON_MODE 
	if (ciph_info->iv_size)    /* RC4 has no IV, AES does */
	{
		memcpy(client_iv, q, ciph_info->iv_size);
		q += ciph_info->iv_size;
		memcpy(server_iv, q, ciph_info->iv_size);
		q += ciph_info->iv_size;
	}
#endif

	free(is_write ? ssl->encrypt_ctx : ssl->decrypt_ctx);

	/* now initialise the ciphers */
	if (is_client)
	{
		finished_digest(ssl, TLS_FINISH_LABEL_SERVER, ssl->dc->final_finish_mac);

		if (is_write)
			ssl->encrypt_ctx = _crypt_new(ssl, client_key, client_iv, 0);
		else
			ssl->decrypt_ctx = _crypt_new(ssl, server_key, server_iv, 1);
	}
	else
	{
		finished_digest(ssl, TLS_FINISH_LABEL_CLIENT, ssl->dc->final_finish_mac);

		if (is_write)
			ssl->encrypt_ctx = _crypt_new(ssl, server_key, server_iv, 0);
		else
			ssl->decrypt_ctx = _crypt_new(ssl, client_key, client_iv, 1);
	}

	ssl->cipher_info = ciph_info;
	return 0;
}



/** 
 * Calculate the digest used in the finished message. This function also
 * doubles up as a certificate verify function.
 */
void finished_digest(SSL *ssl, const char *label, uint8_t *digest)
{
	uint8_t mac_buf[128]; 
	uint8_t *q = mac_buf;
	MD5_CTX md5_ctx = ssl->dc->md5_ctx;
	SHA1_CTX sha1_ctx = ssl->dc->sha1_ctx;

	if (label)
	{
		strcpy((char *)q, label);
		q += strlen(label);
	}

	MD5_Final(q, &md5_ctx);
	q += HASH_MD_LENGTH_MD5;

	SHA1_Final(q, &sha1_ctx);
	q += HASH_MD_LENGTH_SHA1;

	if (label)
	{
		prf(ssl->dc->master_secret, SSL_MASTER_SECRET_SIZE, mac_buf, (int)(q-mac_buf), digest, TLS_FINISHED_VERIFY_SIZE);
	}
	else    /* for use in a certificate verify */
	{
		memcpy(digest, mac_buf, HASH_MD_LENGTH_MD5 + HASH_MD_LENGTH_SHA1);
	}

#if 0
	printf("label: %s\n", label);
	print_blob(ssl->dc->master_secret, 48, "master secret");
	print_blob(mac_buf, q-mac_buf, "mac_buf");
	print_blob(digest, TLS_FINISHED_VERIFY_SIZE, "finished digest");
#endif
}   

