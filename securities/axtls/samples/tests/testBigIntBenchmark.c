
/**
 * Some performance testing of bigint.
 */

#include "ecp.h"

struct	BI_TEST
{
	char		*plainText;
	int		len;

	char		*rsaKeyName;
};


int testOneBiPerf(struct BI_TEST *test)
{
	RSA_CTX		*rsaCtx = NULL;
	BI_CTX		*biCtx;
	
	bigint *bi_data, *bi_res;
	float diff;
	
	int res = 1;
	struct timeval tv_old, tv_new;

	uint8_t compare[MAX_KEY_BYTE_SIZE];
	int i, max_biggie = 10;    /* really crank performance */
	int len; 
	uint8_t *buf;

	if( len = get_file(test->rsaKeyName, &buf) < 0)
		return 1;
	
	asn1_get_private_key(buf, len, &rsaCtx);
	biCtx = rsaCtx->bi_ctx;
	
	bi_data = bi_import(biCtx, (uint8_t *)test->plainText, test->len);
	bi_res = RSA_public(rsaCtx, bi_data);
	bi_data = bi_res;   /* reuse again */

	gettimeofday(&tv_old, NULL);
	for (i = 0; i < max_biggie; i++)
	{
		bi_res = RSA_private(rsaCtx, bi_copy(bi_data));
		if (i < max_biggie-1)
		{
			bi_free(biCtx, bi_res);
		}
	}

	gettimeofday(&tv_new, NULL);
	bi_free(biCtx, bi_data);

	diff = (tv_new.tv_sec-tv_old.tv_sec)*1000 + (tv_new.tv_usec-tv_old.tv_usec)/1000;
	printf("%d bit decrypt time: %.2fms\n", test->len*8, diff/max_biggie);
	
	TTY_FLUSH();
	bi_export(biCtx, bi_res, compare, test->len);
	RSA_free(rsaCtx);
	free(buf);

	if (memcmp(test->plainText, compare, test->len) != 0)
		return 1;

	return 0;
}

int main(int argc, char *argv[])
{
#ifdef CONFIG_SSL_CERT_VERIFICATION
	int i, res = 0;    /* really crank performance */

	struct BI_TEST tests[] ={
		{/* 512 bit key: 64 byte number */
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^",
			64,
			TEST_CERT_DIR"axTLS.key_512"
		},
		{/* 1024 bit key : 128 byte number */
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^"
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^",
			128,
			TEST_CERT_DIR"axTLS.key_1024"
		},
		{/* 2048 bit key: 256 byte number */
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^"
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^"
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^"
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^",
			256,
			TEST_CERT_DIR"axTLS.key_2048"
		},
		{/* 4096 bit key: 512 byte number */
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^"
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^"
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^"
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^"
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^"
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^"
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^"
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*^",
			512,
			TEST_CERT_DIR"axTLS.key_4096"
		}
	};


	for(i=0;i < sizeof(tests)/sizeof(struct BI_TEST); i++)
	{
		TEST_WITH_ARGUMENT(testOneBiPerf, &tests[i], res);
	}

cleanup:
	return res;
#else
	return 0;
#endif
	}

