/**
 * HMAC implementation - This code was originally taken from RFC2104
 * See http://www.ietf.org/rfc/rfc2104.txt and
 * http://www.faqs.org/rfcs/rfc2202.html
 */

#include "crypto.h"

/**
 * Perform HMAC-MD5
 * NOTE: does not handle keys larger than the block size.
 */
EXP_FUNC void STDCALL hmac_md5(const uint8_t *msg, int length, const uint8_t *key, int key_len, uint8_t *digest)
{
	MD5_CTX context;
	uint8_t k_ipad[HASH_DATA_LENGTH_MD5];
	uint8_t k_opad[HASH_DATA_LENGTH_MD5];
	int i;

	memset(k_ipad, 0, sizeof k_ipad);
	memset(k_opad, 0, sizeof k_opad);
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	for (i = 0; i < HASH_DATA_LENGTH_MD5; i++) 
	{
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* Hash( ( key XOR iPad), text) */
	MD5_Init(&context);
	MD5_Update(&context, k_ipad, HASH_DATA_LENGTH_MD5);
	MD5_Update(&context, msg, length);
	MD5_Final(digest, &context);

	/* Hash((key XOR oPad), H1) */
	MD5_Init(&context);
	MD5_Update(&context, k_opad, HASH_DATA_LENGTH_MD5);
	MD5_Update(&context, digest, HASH_MD_LENGTH_MD5);
	MD5_Final(digest, &context);
}

/**
 * Perform HMAC-SHA1
 * NOTE: does not handle keys larger than the block size.
 */
EXP_FUNC void STDCALL hmac_sha1(const uint8_t *msg, int length, const uint8_t *key, int key_len, uint8_t *digest)
{
	SHA1_CTX context;
	uint8_t k_ipad[HASH_DATA_LENGTH_SHA1];
	uint8_t k_opad[HASH_DATA_LENGTH_SHA1];
	int i;

	memset(k_ipad, 0, sizeof k_ipad);
	memset(k_opad, 0, sizeof k_opad);
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	for (i = 0; i < HASH_DATA_LENGTH_SHA1; i++) 
	{
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	SHA1_Init(&context);
	SHA1_Update(&context, k_ipad, HASH_DATA_LENGTH_SHA1);
	SHA1_Update(&context, msg, length);
	SHA1_Final(digest, &context);
	SHA1_Init(&context);
	SHA1_Update(&context, k_opad, HASH_DATA_LENGTH_SHA1);
	SHA1_Update(&context, digest, HASH_MD_LENGTH_SHA1);
	SHA1_Final(digest, &context);
}

