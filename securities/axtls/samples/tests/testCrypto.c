
#include "ecp.h"

/* AES tests : Run through a couple of the RFC3602 tests to verify that AES is correct.
 */
#define TEST1_SIZE  16
#define TEST2_SIZE  32

static int AES_test(BI_CTX *bi_ctx)
{
    AES_CTX aes_key;
    int res = 1;
    uint8_t key[TEST1_SIZE];
    uint8_t iv[TEST1_SIZE];

    {
        /*
            Case #1: Encrypting 16 bytes (1 block) using AES-CBC
            Key       : 0x06a9214036b8a15b512e03d534120006
            IV        : 0x3dafba429d9eb430b422da802c9fac41
            Plaintext : "Single block msg"
            Ciphertext: 0xe353779c1079aeb82708942dbe77181a

        */
        char *in_str =  "Single block msg";
        uint8_t ct[TEST1_SIZE];
        uint8_t enc_data[TEST1_SIZE];
        uint8_t dec_data[TEST1_SIZE];

        bigint *key_bi = bi_str_import( bi_ctx, "06A9214036B8A15B512E03D534120006");
        bigint *iv_bi = bi_str_import( bi_ctx, "3DAFBA429D9EB430B422DA802C9FAC41");
        bigint *ct_bi = bi_str_import( bi_ctx, "E353779C1079AEB82708942DBE77181A");
        bi_export(bi_ctx, key_bi, key, TEST1_SIZE);
        bi_export(bi_ctx, iv_bi, iv, TEST1_SIZE);
        bi_export(bi_ctx, ct_bi, ct, TEST1_SIZE);

        AES_set_key(&aes_key, key, iv, AES_MODE_128);
        AES_cbc_encrypt(&aes_key, (const uint8_t *)in_str, 
                enc_data, sizeof(enc_data));
		
        BINARYC_COMPARE(enc_data, ct, sizeof(ct), "AES ENCRYPT #1" );

        AES_set_key(&aes_key, key, iv, AES_MODE_128);
        AES_convert_key(&aes_key);
        AES_cbc_decrypt(&aes_key, enc_data, dec_data, sizeof(enc_data));

        BINARYC_COMPARE(dec_data, in_str, sizeof(dec_data), "AES DECRYPT #1");
    }

    {
        /*
            Case #2: Encrypting 32 bytes (2 blocks) using AES-CBC 
            Key       : 0xc286696d887c9aa0611bbb3e2025a45a
            IV        : 0x562e17996d093d28ddb3ba695a2e6f58
            Plaintext : 0x000102030405060708090a0b0c0d0e0f
                          101112131415161718191a1b1c1d1e1f
            Ciphertext: 0xd296cd94c2cccf8a3a863028b5e1dc0a
                          7586602d253cfff91b8266bea6d61ab1
        */
        uint8_t in_data[TEST2_SIZE];
        uint8_t ct[TEST2_SIZE];
        uint8_t enc_data[TEST2_SIZE];
        uint8_t dec_data[TEST2_SIZE];

        bigint *in_bi = bi_str_import(bi_ctx,
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        bigint *key_bi = bi_str_import(
                bi_ctx, "C286696D887C9AA0611BBB3E2025A45A");
        bigint *iv_bi = bi_str_import(
                bi_ctx, "562E17996D093D28DDB3BA695A2E6F58");
        bigint *ct_bi = bi_str_import(bi_ctx,
            "D296CD94C2CCCF8A3A863028B5E1DC0A7586602D253CFFF91B8266BEA6D61AB1");
        bi_export(bi_ctx, in_bi, in_data, TEST2_SIZE);
        bi_export(bi_ctx, key_bi, key, TEST1_SIZE);
        bi_export(bi_ctx, iv_bi, iv, TEST1_SIZE);
        bi_export(bi_ctx, ct_bi, ct, TEST2_SIZE);

        AES_set_key(&aes_key, key, iv, AES_MODE_128);
        AES_cbc_encrypt(&aes_key, (const uint8_t *)in_data, 
                enc_data, sizeof(enc_data));

        BINARYC_COMPARE(enc_data, ct, sizeof(ct), "AES ENCRYPT #2");

        AES_set_key(&aes_key, key, iv, AES_MODE_128);
        AES_convert_key(&aes_key);
        AES_cbc_decrypt(&aes_key, enc_data, dec_data, sizeof(enc_data));
        BINARYC_COMPARE(dec_data, in_data, sizeof(dec_data), "AES DECRYPT #2");
    }

    res = 0;

end:
    return res;
}

/*
 * RC4 tests 
 * ARC4 tests vectors from OpenSSL (crypto/rc4/rc4test.c)
 */
static const uint8_t keys[7][30]=
{
    {8,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
    {8,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
    {8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {4,0xef,0x01,0x23,0x45},
    {8,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
    {4,0xef,0x01,0x23,0x45},
};

static const uint8_t data_len[7]={8,8,8,20,28,10};
static uint8_t data[7][30]=
{
    {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xff},
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff},
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff},
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xff},
     {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
            0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
            0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
            0x12,0x34,0x56,0x78,0xff},
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff},
            {0},
};

static const uint8_t output[7][30]=
{
    {0x75,0xb7,0x87,0x80,0x99,0xe0,0xc5,0x96,0x00},
    {0x74,0x94,0xc2,0xe7,0x10,0x4b,0x08,0x79,0x00},
    {0xde,0x18,0x89,0x41,0xa3,0x37,0x5d,0x3a,0x00},
    {0xd6,0xa1,0x41,0xa7,0xec,0x3c,0x38,0xdf,
        0xbd,0x61,0x5a,0x11,0x62,0xe1,0xc7,0xba,
        0x36,0xb6,0x78,0x58,0x00},
        {0x66,0xa0,0x94,0x9f,0x8a,0xf7,0xd6,0x89,
            0x1f,0x7f,0x83,0x2b,0xa8,0x33,0xc0,0x0c,
            0x89,0x2e,0xbe,0x30,0x14,0x3c,0xe2,0x87,
            0x40,0x01,0x1e,0xcf,0x00},
            {0xd6,0xa1,0x41,0xa7,0xec,0x3c,0x38,0xdf,0xbd,0x61,0x00},
            {0},
};

static int RC4_test(BI_CTX *bi_ctx)
{
	int i, res = 1;
	RC4_CTX s;
	char	info[256];

	for (i = 0; i < 6; i++)
	{
		RC4_setup(&s, &keys[i][1], keys[i][0]);
		RC4_crypt(&s, data[i], data[i], data_len[i]);
		
		SPRINTF(info, sizeof(info), "RC4 CRYPT #%d", i);

		BINARYC_COMPARE(data[i], output[i], data_len[i], info);
	}

	res = 0;

end:
	return res;
}

/*
 * SHA1 tests :* Run through a couple of the RFC3174 tests to verify that SHA1 is correct.
 */
static int SHA1_test(BI_CTX *bi_ctx)
{
    SHA1_CTX ctx;
    uint8_t ct[HASH_MD_LENGTH_SHA1];
    uint8_t digest[HASH_MD_LENGTH_SHA1];
    int res = 1;

    {
        const char *in_str = "abc";
        bigint *ct_bi = bi_str_import(bi_ctx,
                "A9993E364706816ABA3E25717850C26C9CD0D89D");
        bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_SHA1);

        SHA1_Init(&ctx);
        SHA1_Update(&ctx, (const uint8_t *)in_str, strlen(in_str));
        SHA1_Final(digest, &ctx);

       BINARYC_COMPARE(digest, ct, sizeof(ct), "SHA1 #1");
    }

    {
        const char *in_str =
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        bigint *ct_bi = bi_str_import(bi_ctx,
                "84983E441C3BD26EBAAE4AA1F95129E5E54670F1");
        bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_SHA1);

        SHA1_Init(&ctx);
        SHA1_Update(&ctx, (const uint8_t *)in_str, strlen(in_str));
        SHA1_Final(digest, &ctx);

        BINARYC_COMPARE(digest, ct, sizeof(ct), "SHA1 #2");
    }

    res = 0;

end:
    return res;
}

/* SHA256 tests : Run through a couple of the SHA-2 tests to verify that SHA256 is correct.
*/
static int SHA256_test(BI_CTX *bi_ctx)
{
    SHA256_CTX ctx;
    uint8_t ct[HASH_MD_LENGTH_SHA256];
    uint8_t digest[HASH_MD_LENGTH_SHA256];
    int res = 1;

    {
        const char *in_str = "abc";
        bigint *ct_bi = bi_str_import(bi_ctx,
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
        bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_SHA256);

        SHA256_Init(&ctx);
        SHA256_Update(&ctx, (const uint8_t *)in_str, strlen(in_str));
        SHA256_Final(digest, &ctx);

        BINARYC_COMPARE(digest, ct, sizeof(ct), "SHA256 #1");
    }

    {
        const char *in_str =
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        bigint *ct_bi = bi_str_import(bi_ctx,
            "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1");
        bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_SHA256);

        SHA256_Init(&ctx);
        SHA256_Update(&ctx, (const uint8_t *)in_str, strlen(in_str));
        SHA256_Final(digest, &ctx);

        BINARYC_COMPARE(digest, ct, sizeof(ct), "SHA256 #2");
    }

    res = 0;

end:
    return res;
}

/* Run through a couple of the SHA-2 tests to verify that SHA384 is correct */
static int SHA384_test(BI_CTX *bi_ctx)
{
    SHA384_CTX ctx;
    uint8_t ct[HASH_MD_LENGTH_SHA384];
    uint8_t digest[HASH_MD_LENGTH_SHA384];
    int res = 1;

	{
		const char *in_str = "abc";
		bigint *ct_bi = bi_str_import(bi_ctx,
		"CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7");
		bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_SHA384);

		SHA384_Init(&ctx);
		SHA384_Update(&ctx, (const uint8_t *)in_str, strlen(in_str));
		SHA384_Final(digest, &ctx);

		BINARYC_COMPARE(digest, ct, sizeof(ct), "SHA384 #1");
	}

	{
		const char *in_str =
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		bigint *ct_bi = bi_str_import(bi_ctx,
		"3391FDDDFC8DC7393707A65B1B4709397CF8B1D162AF05ABFE8F450DE5F36BC6B0455A8520BC4E6F5FE95B1FE3C8452B");
		bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_SHA384);

		SHA384_Init(&ctx);
		SHA384_Update(&ctx, (const uint8_t *)in_str, strlen(in_str));
		SHA384_Final(digest, &ctx);

		BINARYC_COMPARE(digest, ct, sizeof(ct), "SHA384 #2");
	}

	res = 0;

end:
	return res;
}

/* Run through a couple of the SHA-2 tests to verify that SHA512 is correct */
static int SHA512_test(BI_CTX *bi_ctx)
{
    SHA512_CTX ctx;
    uint8_t ct[HASH_MD_LENGTH_SHA512];
    uint8_t digest[HASH_MD_LENGTH_SHA512];
    int res = 1;

	{
		const char *in_str = "abc";
		bigint *ct_bi = bi_str_import(bi_ctx,
		"DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F");
		bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_SHA512);

		SHA512_Init(&ctx);
		SHA512_Update(&ctx, (const uint8_t *)in_str, strlen(in_str));
		SHA512_Final(digest, &ctx);

		BINARYC_COMPARE(digest, ct, sizeof(ct), "SHA512 #1");
	}

    {
        const char *in_str =
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        bigint *ct_bi = bi_str_import(bi_ctx,
            "204A8FC6DDA82F0A0CED7BEB8E08A41657C16EF468B228A8279BE331A703C33596FD15C13B1B07F9AA1D3BEA57789CA031AD85C7A71DD70354EC631238CA3445");
        bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_SHA512);

        SHA512_Init(&ctx);
        SHA512_Update(&ctx, (const uint8_t *)in_str, strlen(in_str));
        SHA512_Final(digest, &ctx);

        BINARYC_COMPARE(digest, ct, sizeof(ct), "SHA512 #2");
    }

    res = 0;

end:
    return res;
}

/* Run through a couple of the RFC1321 tests to verify that MD5 is correct */
static int MD5_test(BI_CTX *bi_ctx)
{
	MD5_CTX ctx;
	uint8_t ct[HASH_MD_LENGTH_MD5];
	uint8_t digest[HASH_MD_LENGTH_MD5];
	int res = 1;

	{
		const char *in_str =  "abc";
		/* change string into binary memory block */
		bigint *ct_bi = bi_str_import(bi_ctx, "900150983CD24FB0D6963F7D28E17F72");/*32 bits/16 bytes, MD5 result of 'abc' */
		bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_MD5);

		MD5_Init(&ctx);
		MD5_Update(&ctx, (const uint8_t *)in_str, strlen(in_str));
		MD5_Final(digest, &ctx);

		BINARYC_COMPARE(digest, ct, sizeof(ct), "MD5 #1");
	}

	{
		const char *in_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		bigint *ct_bi = bi_str_import(bi_ctx, "D174AB98D277D9F5A5611C2C9F419D9F");
		bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_MD5);

		MD5_Init(&ctx);
		MD5_Update(&ctx, (const uint8_t *)in_str, strlen(in_str));
		MD5_Final(digest, &ctx);

		BINARYC_COMPARE(digest, ct, sizeof(ct), "MD5 #2");
	}
	res = 0;

end:
	return res;
}


/* Run through a couple of the RFC2202 tests to verify that HMAC is correct */
static int HMAC_test(BI_CTX *bi_ctx)
{
	uint8_t key[HASH_MD_LENGTH_SHA1];
	uint8_t ct[HASH_MD_LENGTH_SHA1];
	uint8_t dgst[HASH_MD_LENGTH_SHA1];
	int res = 1;
	const char *key_str;

	/* openssl dgst  -hmac 0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B -md5 file.log : for HMAC-MD5 */
	const char *data_str = "Hi There";
	bigint *key_bi = bi_str_import(bi_ctx, "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
	bigint *ct_bi = bi_str_import(bi_ctx, "9294727A3638BB1C13F48EF8158BFC9D");/* Hash result */
	bi_export(bi_ctx, key_bi, key, HASH_MD_LENGTH_MD5);
	bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_MD5);
	hmac_md5((const uint8_t *)data_str, 8, key, HASH_MD_LENGTH_MD5, dgst);

	BINARYC_COMPARE(dgst, ct, HASH_MD_LENGTH_MD5, "HMAC MD5 #1");


	data_str = "what do ya want for nothing?";
	key_str = "Jefe";
	/* openssl dgst  -hmac Jefe|"Jefe" -md5 file.log : for HMAC-MD5 */
	ct_bi = bi_str_import(bi_ctx, "750C783E6AB0B503EAA86E310A5DB738");
	bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_MD5);
	hmac_md5((const uint8_t *)data_str, 28, (const uint8_t *)key_str, 4, dgst);
	BINARYC_COMPARE(dgst, ct, HASH_MD_LENGTH_MD5, "HMAC MD5 #2");


	/* openssl dgst  -hmac 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b file.log: for HMAC-SHA1
	?? The binary key can not be used as command line arguments */
	data_str = "Hi There";
	key_bi = bi_str_import(bi_ctx, "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
	bi_export(bi_ctx, key_bi, key, HASH_MD_LENGTH_SHA1);
	ct_bi = bi_str_import(bi_ctx, "B617318655057264E28BC0B6FB378C8EF146BE00");
	bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_SHA1);

	print_blob(key, HASH_MD_LENGTH_SHA1, "KEY:");
	
	hmac_sha1((const uint8_t *)data_str, 8, (const uint8_t *)key, HASH_MD_LENGTH_SHA1, dgst);
	BINARYC_COMPARE(dgst, ct, HASH_MD_LENGTH_SHA1, "HMAC SHA1 #1");

	data_str = "what do ya want for nothing?";
	key_str = "Jefe";
	ct_bi = bi_str_import(bi_ctx, "EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79");
	bi_export(bi_ctx, ct_bi, ct, HASH_MD_LENGTH_SHA1);
	print_blob(ct, HASH_MD_LENGTH_SHA1, "Raw:\"EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79\", bi_export is:");
	axDebugDump(ct, HASH_MD_LENGTH_SHA1);

	hmac_sha1((const uint8_t *)data_str, 28, (const uint8_t *)key_str, 5, dgst);
	BINARYC_COMPARE(dgst, ct, HASH_MD_LENGTH_SHA1, "HMAC SHA1 #2");

	res = 0;

end:
	return res;
}


static int testOpenSslHMac(BI_CTX *bi_ctx)
{
	uint8_t openSslResult[HASH_MD_LENGTH_SHA1];
	uint8_t dgst[HASH_MD_LENGTH_SHA1];
	int res = 1;
	const char *key_str= "Jefe";
	bigint	*ct_bi;

  	char	*data_str = "what do ya want for nothing?";
	
//	ct_bi = bi_str_import(bi_ctx, "EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79");
	/* one import create one bigint into ctx, and this bigint is freed by one export operation, so the import and export must be paired
	so when these 2 operations are called, the ct_bi refers to 2 different bigint.
	*/
	ct_bi = bi_str_import(bi_ctx, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"); /* openssl dgst -hmac Jefe file.txt */
	bi_export(bi_ctx, ct_bi, openSslResult, HASH_MD_LENGTH_SHA1);
	print_blob(openSslResult, HASH_MD_LENGTH_SHA1, "OpenSSL Raw:\"effcdf6ae5eb2fa2d27416d5f184df9c259a7c79\", bi_export is:");

	hmac_sha1((const uint8_t *)data_str, 28, (const uint8_t *)key_str, 4, dgst);
	print_blob(dgst, HASH_MD_LENGTH_SHA1, "Digest:");
	BINARYC_COMPARE(dgst, openSslResult, HASH_MD_LENGTH_SHA1, "HMAC SHA1 #1");

	res = 0;

end:
	return res;
}


static int BIGINT_test(BI_CTX *ctx)
{
	int res = 1;

#ifndef CONFIG_INTEGER_8BIT 
#ifndef CONFIG_INTEGER_16BIT 
	bigint *bi_data, *bi_exp, *bi_res;
	const char *expnt, *plaintext, *mod;
	uint8_t compare[MAX_KEY_BYTE_SIZE];

	/* 512 bit key: 64 byte number */
	plaintext = "01aaaaaaaaaabbbbbbbbbbbbbbbccccccccccccccdddddddddddddeeeeeeeeee";

	mod = "C30773C8ABE09FCC279EE0E5343370DE"
		"8B2FFDB6059271E3005A7CEEF0D35E0A"
		"1F9915D95E63560836CC2EB2C289270D"
		"BCAE8CAF6F5E907FC2759EE220071E1B";

	expnt = "A1E556CD1738E10DF539E35101334E97"
		"BE8D391C57A5C89A7AD9A2EA2ACA1B3D"
		"F3140F5091CC535CBAA47CEC4159EE1F"
		"B6A3661AFF1AB758426EAB158452A9B9";

	bi_data = bi_import(ctx, (uint8_t *)plaintext, strlen(plaintext));
	/* set exponentiation (e) of modula logarithm, e and phi are co-prime */
	bi_exp = int_to_bi(ctx, 0x10001);
	/* set modulus (Phi) of modula logarithm */
	bi_set_mod(ctx, bi_str_import(ctx, mod), 0);
	bi_res = bi_mod_power(ctx, bi_data, bi_exp);

	bi_data = bi_res;   /* resuse again - see if we get the original */

	/* the second power operation, but with different exp. same result???? lzj */
	bi_exp = bi_str_import(ctx, expnt);
	bi_res = bi_mod_power(ctx, bi_data, bi_exp);
	bi_free_mod(ctx, 0);

	bi_export(ctx, bi_res, compare, 64);

	BINARYC_COMPARE(plaintext, compare, 64, "BIGINT_test");
#endif
#endif


	/*
	* Multiply with psssible carry issue (8 bit)
	*/
	{
		bigint *bi_x = bi_str_import(ctx, "AFD5060E224B70DA99EFB385BA5C0D2BEA0AD1DAAA52686E1A02D677BC65C1DA7A496BBDCC02999E8814F10AFC4B8E0DD4E6687E0762CE717A5EA1E452B5C56065C8431F0FB9D23CFF3A4B4149798C0670AF7F9565A0EAE5CF1AB16A1F0C3DD5E485DC5ABB96EBE0B6778A15B7302CBCE358E4BF2E2E30932758AC6EFA9F5828");
		bigint *arg2 = bi_clone(ctx, bi_x);
		bigint *arg3 = bi_clone(ctx, bi_x);
		bigint *sqr_result = bi_square(ctx, bi_x);
		bigint *mlt_result = bi_multiply(ctx, arg2, arg3);

		if (bi_compare(sqr_result, mlt_result) != 0)
		{
			bi_print("SQR_RESULT", sqr_result);
			bi_print("MLT_RESULT", mlt_result);
			bi_free(ctx, sqr_result);
			bi_free(ctx, mlt_result);
			goto end;
		}
		else
		{
			printf("\t\tBIGINT_test: SQR equal to MLT in BigInt\n");
		}

		bi_free(ctx, sqr_result);
		bi_free(ctx, mlt_result);
	}

	res = 0;

end:
    return res;
}

/* Use the results from openssl to verify PKCS1 etc */
static int RSA_test(void)
{
    int res = 1;
    const char *plaintext = /* 128 byte hex number */
        "1aaaaaaaaaabbbbbbbbbbbbbbbccccccccccccccdddddddddddddeeeeeeeeee2"
        "1aaaaaaaaaabbbbbbbbbbbbbbbccccccccccccccdddddddddddddeeeeeeeee2\012";
    uint8_t enc_data[128], dec_data[128];
    RSA_CTX *rsa_ctx = NULL;
    BI_CTX *bi_ctx;
    bigint *plaintext_bi;
    bigint *enc_data_bi, *dec_data_bi;
    uint8_t enc_data2[128], dec_data2[128];
    int len; 
    uint8_t *buf;

    RNG_initialize();

    /* extract the private key elements */
    if(len = get_file(TEST_CERT_DIR"axTLS.key_1024", &buf)< 0)
		goto end;
	
    if (asn1_get_private_key(buf, len, &rsa_ctx) < 0)
    {
        goto end;
    }

    free(buf);
    bi_ctx = rsa_ctx->bi_ctx;
    plaintext_bi = bi_import(bi_ctx, 
            (const uint8_t *)plaintext, strlen(plaintext));

    /* basic rsa encrypt */
    enc_data_bi = RSA_public(rsa_ctx, plaintext_bi);
    bi_export(bi_ctx, bi_copy(enc_data_bi), enc_data, sizeof(enc_data));

    /* basic rsa decrypt */
    dec_data_bi = RSA_private(rsa_ctx, enc_data_bi);
    bi_export(bi_ctx, dec_data_bi, dec_data, sizeof(dec_data));

    BINARYC_COMPARE(dec_data, plaintext, strlen(plaintext), "RSA DECRYPT #1");

    if (RSA_encryptOrSign(rsa_ctx, (const uint8_t *)"abc", 3, enc_data2, 0) < 0)
    {
        printf("Error: ENCRYPT #2 failed\n");
        goto end;
    }

    RSA_decryptOrVerify(rsa_ctx, enc_data2, dec_data2, sizeof(dec_data2), 1);
    BINARYC_COMPARE("abc", dec_data2, 3, "RSA DECRYPT #2");


    RSA_free(rsa_ctx);
    res = 0;

end:
    RNG_terminate();
    return res;
}

int testCrypto(void)
{
	int ret = 1;
	BI_CTX *bi_ctx;

	bi_ctx = bi_initialize();
#if 0
	TEST_WITH_ARGUMENT(AES_test, bi_ctx, ret);
    
	TEST_WITH_ARGUMENT(RC4_test, bi_ctx, ret);

	TEST_WITH_ARGUMENT(MD5_test, bi_ctx, ret);

	TEST_WITH_ARGUMENT(SHA1_test, bi_ctx, ret);

	TEST_WITH_ARGUMENT(SHA256_test, bi_ctx, ret);

	TEST_WITH_ARGUMENT(SHA384_test, bi_ctx, ret);

	TEST_WITH_ARGUMENT(SHA512_test, bi_ctx, ret);


	TEST_NO_ARGUMENT(RSA_test, ret);
#endif
	TEST_WITH_ARGUMENT(BIGINT_test, bi_ctx, ret);
	TEST_WITH_ARGUMENT(HMAC_test, bi_ctx, ret);

	TEST_WITH_ARGUMENT(testOpenSslHMac, bi_ctx, ret);

cleanup:
	bi_terminate(bi_ctx);

	return ret;
}


int main(int argc, char *argv[])
{
	int ret = 0;

	TEST_NO_ARGUMENT(testCrypto, ret);

	printf("**** ALL TESTS PASSED ****\n"); TTY_FLUSH();
cleanup:
	return ret;
}


