/*
* openssl x509 -text -in $1 > cert.txt or 
* openssl x509 -noout -in cert.pem -issuer -subject -dates
*/

#include "ecp.h"
enum
{
	TEST_CERT_CA		=1,	/* must be DER */
	TEST_CERT_CERT 	=2,	/* must be DER */
	TEST_CERT_CODED	=3,
};

static testOneCaCert(char *certFileNmae, int type)
{
	int res = -1, len;
	SSL_CTX *ssl_ctx;
	uint8_t *buf = NULL;

	printf("%s Cert '%s' is testing.....\n", (type==1)?"":"CA",  certFileNmae);
	if( (ssl_ctx = ssl_ctx_new(SSL_DISPLAY_ALL, 0)) == NULL)
		return res;

	TRACE();
	if(type == 3)
	{/* PEM or DER format */
		res = ssl_obj_load(ssl_ctx, SSL_OBJ_X509_CERT, certFileNmae, NULL);
	}
	else
	{/* buffer in DER format */
		len = get_file(certFileNmae, &buf);
		if(type == 2)
		{
			res = add_cert(ssl_ctx, buf, len);/* always 509 certs ?? */
		}
		else
		{
	TRACE();
			res = add_cert_auth(ssl_ctx, buf, len);
		}
	}
	
	printf("\t%s Cert '%s' \n", (type==1)?"":"CA",  certFileNmae, (res<0)?"Failed":"OK!");
	if(res<0)
		ssl_display_error(res);

	ssl_ctx_free(ssl_ctx);
	if(buf)
		free(buf);

	return res;
}

/* Cert Testing */
static int testCerts(void)
{
	int res = -1, len;
	X509 *x509_ctx;
	SSL_CTX *ssl_ctx;
	uint8_t *buf = NULL;

//	if(testOneCaCert(VALIDATE_CERT_DIR"microsoft.x509_ca.pem", 3))
//		return res;
#if 0
	if(testOneCaCert(VALIDATE_CERT_DIR"microsoft.x509_ca", TEST_CERT_CA))
		return res;
	if(testOneCaCert(VALIDATE_CERT_DIR"thawte.x509_ca", TEST_CERT_CERT))
		return res;

#endif
	if(testOneCaCert(VALIDATE_CERT_DIR"deutsche_telecom.x509_ca", TEST_CERT_CA))
		return res;

	if(testOneCaCert(VALIDATE_CERT_DIR"equifax.x509_ca", TEST_CERT_CA))
		return res;

	if(testOneCaCert(VALIDATE_CERT_DIR"gnutls.cer", TEST_CERT_CERT))
		return res;

	if(testOneCaCert(VALIDATE_CERT_DIR"socgen.cer", TEST_CERT_CERT))
		return res;

	if(testOneCaCert(VALIDATE_CERT_DIR"camster_duckdns_org.crt", TEST_CERT_CODED))
		return res;
	
	if(testOneCaCert(VALIDATE_CERT_DIR"comodo.sha384.cer", TEST_CERT_CODED))
		return res;
	
	if(testOneCaCert(VALIDATE_CERT_DIR"ms_iis.cer", TEST_CERT_CODED))
		return res;


#if 0
	printf("Test X509 Certificate '%s'.....\n", "qualityssl.com.der");
	if (get_file(VALIDATE_CERT_DIR"qualityssl.com.der", &buf) < 0 ||x509_new(buf, &len, &x509_ctx))
	{
		printf("Cert #10\n");
		res = -1;
		goto bad_cert;
	}

	TRACE();
	if (strcmp(x509_ctx->subject_alt_dnsnames[1], "qualityssl.com"))
	{
		printf("Cert #11\n");
		res = -1;
		goto bad_cert;
	}
	x509_print(x509_ctx, NULL);
	x509_free(x509_ctx);
	printf("\ttest X509 Certificate '%s' OK!\n", "qualityssl.com.der");


#if 1	
	// this bundle has two DSA (1.2.840.10040.4.3 invalid) certificates
	ssl_ctx = ssl_ctx_new(0xFFFFFFFF, 0);
	if (ssl_obj_load(ssl_ctx, SSL_OBJ_X509_CACERT, VALIDATE_CERT_DIR"ca-bundle.crt", NULL))
	{
		goto bad_cert;
	}

	ssl_ctx_free(ssl_ctx);
#else
	/* add_cert_auth only can be used after decoded from DER/PEM */
	if(testOneCaCert(CERT_HOME_DIR"ca-bundle.crt", TEST_CERT_CA))
		return res;
#endif

#endif
	TRACE();
	res = 0;        /* all ok */
	printf("All Certificate tests passed\n");
	if(buf)
		free(buf);

bad_cert:
    if (res)
        printf("Error: A certificate test failed\n");

    return res;
}


int main(int argc, char *argv[])
{
	int ret = 1;

	TEST_NO_ARGUMENT(testCerts, ret);

	ret = 0;        /* all ok */
	printf("**** ALL TESTS PASSED ****\n"); TTY_FLUSH();
cleanup:
	if (ret)
		printf("Error: Some tests failed!\n");

	return ret;
}

