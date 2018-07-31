

#include <libTest.h>

#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
	static const char* clientKey  = "./certs/client-key.der";
	static const char* clientCert = "./certs/client-cert.der";
#ifdef WOLFSSL_CERT_GEN
	static const char* caKeyFile  = "./certs/ca-key.der";
	static const char* caCertFile = "./certs/ca-cert.pem";
#ifdef HAVE_ECC
	static const char* eccCaKeyFile  = "./certs/ecc-key.der";
	static const char* eccCaCertFile = "./certs/server-ecc.pem";
#endif
#endif
#endif


int rsa_test(void)
{
	byte*   tmp;
	size_t bytes;
	RsaKey key;
	RNG    rng;
	word32 idx = 0;
	int    ret;
	byte   in[] = "Everyone gets Friday off.";
	word32 inLen = (word32)strlen((char*)in);
	byte   out[256];
	byte   plain[256];
#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
	FILE*  file = NULL, *file2 =NULL;
#endif
#ifdef WOLFSSL_TEST_CERT
	DecodedCert cert;
#endif

	tmp = (byte*)malloc(FOURK_BUF);
	if (tmp == NULL)
		return -40;

#ifdef USE_CERT_BUFFERS_1024
	XMEMCPY(tmp, client_key_der_1024, sizeof_client_key_der_1024);
	bytes = sizeof_client_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
	XMEMCPY(tmp, client_key_der_2048, sizeof_client_key_der_2048);
	bytes = sizeof_client_key_der_2048;
#else

	/*********************  based on DER key file  **************************/
	DEBUG_MSG("\n---------Test RSA case 1: client key with encryp/decrypt sign/verify\n");
	file = fopen(clientKey, "rb");
	if (!file) {
#if 1		
		err_sys("can't open '%s', Please run from home dir", clientKey);
#else
		wolfSslDebug("can't open '%s', Please run from home dir", clientKey);
		exit(-1);
#endif
		free(tmp);
	}

	wolfSslDebug("Open client key file of '%s' OK!\n", clientKey);
	bytes = fread(tmp, 1, FOURK_BUF, file);
	fclose(file);
#endif /* USE_CERT_BUFFERS */

	/* init key pair */
#ifdef HAVE_CAVIUM
	wc_RsaInitCavium(&key, CAVIUM_DEV_ID);
#endif
	ret = wc_InitRsaKey(&key, 0);
	if (ret != 0) {
		free(tmp);
		return -39;
	}
	ret = wc_RsaPrivateKeyDecode(tmp, &idx, &key, (word32)bytes);
	if (ret != 0) {
		free(tmp);
		return -41;
	}
	ret = wc_InitRng(&rng);
	if (ret != 0) {
		free(tmp);
		return -42;
	}

	/* case 1: encrypto /decrypto */
	ret = wc_RsaPublicEncrypt(in, inLen, out, sizeof(out), &key, &rng);
	if (ret < 0) {
		free(tmp);
		return -43;
	}
	ret = wc_RsaPrivateDecrypt(out, ret, plain, sizeof(plain), &key);
	if (ret < 0) {
		free(tmp);
		return -44;
	}
	if (memcmp(plain, in, inLen)) {
		free(tmp);
		return -45;
	}

	/* case 2: sign and verify */
	ret = wc_RsaSSL_Sign(in, inLen, out, sizeof(out), &key, &rng);
	if (ret < 0) {
		free(tmp);
		return -46;
	}
	memset(plain, 0, sizeof(plain));
	ret = wc_RsaSSL_Verify(out, ret, plain, sizeof(plain), &key);
	if (ret < 0) {
		free(tmp);
		return -47;
	}
	if (memcmp(plain, in, ret)) {
		free(tmp);
		return -48;
	}
	

	/*********************  based on DER certificate file  **************************/
	DEBUG_MSG("\n---------Test RSA case 2: Certificate parsing\n");
#ifdef USE_CERT_BUFFERS_1024
	XMEMCPY(tmp, client_cert_der_1024, sizeof_client_cert_der_1024);
	bytes = sizeof_client_cert_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
	XMEMCPY(tmp, client_cert_der_2048, sizeof_client_cert_der_2048);
	bytes = sizeof_client_cert_der_2048;
#else
	file2 = fopen(clientCert, "rb");
	if (!file2) {
		free(tmp);
		return -49;
	}

	wolfSslDebug("Open client cert file of '%s' OK!\n", clientCert);
	bytes = fread(tmp, 1, FOURK_BUF, file2);
	fclose(file2);
#endif


#ifdef WOLFSSL_TEST_CERT
	InitDecodedCert(&cert, tmp, (word32)bytes, 0);

	ret = ParseCert(&cert, CERT_TYPE, NO_VERIFY, 0);
	if (ret != 0) return -491;

	FreeDecodedCert(&cert);
#else
	(void)bytes;
#endif


#ifdef WOLFSSL_KEY_GEN
	{
		byte*  der;
		byte*  pem;
		int    derSz = 0;
		int    pemSz = 0;
		RsaKey derIn;
		RsaKey genKey;
		FILE*  keyFile;
		FILE*  pemFile;

		DEBUG_MSG("\n---------Test RSA case 3: create RSA key and stored in file\n");
		ret = wc_InitRsaKey(&genKey, 0);
		if (ret != 0)
			return -300;
		ret = wc_MakeRsaKey(&genKey, 1024, 65537, &rng);
		if (ret != 0)
			return -301;

		der = (byte*)malloc(FOURK_BUF);
		if (der == NULL) {
			wc_FreeRsaKey(&genKey);
			return -307;
		}
		pem = (byte*)malloc(FOURK_BUF);
		if (pem == NULL) {
			free(der);
			wc_FreeRsaKey(&genKey);
			return -308;
		}

		derSz = wc_RsaKeyToDer(&genKey, der, FOURK_BUF);
		if (derSz < 0) {
			free(der);
			free(pem);
			return -302;
		}

#ifdef FREESCALE_MQX
		keyFile = fopen("a:\\certs\\key.der", "wb");
#else
		keyFile = fopen("./key.der", "wb");
#endif
		if (!keyFile) {
			free(der);
			free(pem);
			wc_FreeRsaKey(&genKey);
			return -303;
		}
		ret = (int)fwrite(der, 1, derSz, keyFile);
		fclose(keyFile);
		if (ret != derSz) {
			free(der);
			free(pem);
			wc_FreeRsaKey(&genKey);
			return -313;
		}

		pemSz = wc_DerToPem(der, derSz, pem, FOURK_BUF, PRIVATEKEY_TYPE);
		if (pemSz < 0) {
			free(der);
			free(pem);
			wc_FreeRsaKey(&genKey);
			return -304;
		}

#ifdef FREESCALE_MQX
		pemFile = fopen("a:\\certs\\key.pem", "wb");
#else
		pemFile = fopen("./key.pem", "wb");
#endif
		if (!pemFile) {
			free(der);
			free(pem);
			wc_FreeRsaKey(&genKey);
			return -305;
		}
		ret = (int)fwrite(pem, 1, pemSz, pemFile);
		fclose(pemFile);
		if (ret != pemSz) {
			free(der);
			free(pem);
			wc_FreeRsaKey(&genKey);
			return -314;
		}

		ret = wc_InitRsaKey(&derIn, 0);
		if (ret != 0) {
			free(der);
			free(pem);
			wc_FreeRsaKey(&genKey);
			return -3060;
		}
		
		idx = 0;
		ret = wc_RsaPrivateKeyDecode(der, &idx, &derIn, derSz);
		if (ret != 0) {
			free(der);
			free(pem);
			wc_FreeRsaKey(&derIn);
			wc_FreeRsaKey(&genKey);
			return -306;
		}

		wc_FreeRsaKey(&derIn);
		wc_FreeRsaKey(&genKey);
		free(pem);
		free(der);
	}
#endif /* WOLFSSL_KEY_GEN */


#ifdef WOLFSSL_CERT_GEN
    /* self signed */
	{
		Cert        myCert;
		byte*       derCert;
		byte*       pem;
		FILE*       derFile;
		FILE*       pemFile;
		int         certSz;
		int         pemSz;
#ifdef WOLFSSL_TEST_CERT
		DecodedCert decode;
#endif

		DEBUG_MSG("\n---------Test RSA case 4: create self-signed Certificate and stored in file\n");
		derCert = (byte*)malloc(FOURK_BUF);
		if (derCert == NULL)
			return -309;
		pem = (byte*)malloc(FOURK_BUF);
		if (pem == NULL) {
			free(derCert);
			return -310;
		}

		wc_InitCert(&myCert);

		strncpy(myCert.subject.country, "US", CTC_NAME_SIZE);
		strncpy(myCert.subject.state, "OR", CTC_NAME_SIZE);
		strncpy(myCert.subject.locality, "Portland", CTC_NAME_SIZE);
		strncpy(myCert.subject.org, "yaSSL", CTC_NAME_SIZE);
		strncpy(myCert.subject.unit, "Development", CTC_NAME_SIZE);
		strncpy(myCert.subject.commonName, "www.yassl.com", CTC_NAME_SIZE);
		strncpy(myCert.subject.email, "info@yassl.com", CTC_NAME_SIZE);
		myCert.isCA    = 1;
		myCert.sigType = CTC_SHA256wRSA;

		certSz = wc_MakeSelfCert(&myCert, derCert, FOURK_BUF, &key, &rng);
		if (certSz < 0) {
			free(derCert);
			free(pem);
			return -401;
		}

#ifdef WOLFSSL_TEST_CERT
		InitDecodedCert(&decode, derCert, certSz, 0);
		ret = ParseCert(&decode, CERT_TYPE, NO_VERIFY, 0);
		if (ret != 0) {
			free(derCert);
			free(pem);
			return -402;
		}
		FreeDecodedCert(&decode);
#endif

#ifdef FREESCALE_MQX
		derFile = fopen("a:\\certs\\cert.der", "wb");
#else
		derFile = fopen("./cert.der", "wb");
#endif
		if (!derFile) {
			free(derCert);
			free(pem);
			return -403;
		}
		ret = (int)fwrite(derCert, 1, certSz, derFile);
		fclose(derFile);
		if (ret != certSz) {
			free(derCert);
			free(pem);
			return -414;
		}

		pemSz = wc_DerToPem(derCert, certSz, pem, FOURK_BUF, CERT_TYPE);
		if (pemSz < 0) {
			free(derCert);
			free(pem);
			return -404;
		}

#ifdef FREESCALE_MQX
		pemFile = fopen("a:\\certs\\cert.pem", "wb");
#else
		pemFile = fopen("./cert.pem", "wb");
#endif
		if (!pemFile) {
			free(derCert);
			free(pem);
			return -405;
		}
		ret = (int)fwrite(pem, 1, pemSz, pemFile);
		fclose(pemFile);
		if (ret != pemSz) {
			free(derCert);
			free(pem);
			return -406;
		}
		free(pem);
		free(derCert);
	}

    /* CA style */
	{
		RsaKey      caKey;
		Cert        myCert;
		byte*       derCert;
		byte*       pem;
		FILE*       derFile;
		FILE*       pemFile;
		int         certSz;
		int         pemSz;
		size_t      bytes3;
		word32      idx3 = 0;
		FILE*       file3 ;
#ifdef WOLFSSL_TEST_CERT
		DecodedCert decode;
#endif

		DEBUG_MSG("\n---------Test RSA case 4: create CA-signed Certificate and stored in file\n");
		derCert = (byte*)malloc(FOURK_BUF);
		if (derCert == NULL)
			return -311;
		pem = (byte*)malloc(FOURK_BUF);
		if (pem == NULL) {
			free(derCert);
			return -312;
		}

		file3 = fopen(caKeyFile, "rb");

		if (!file3) {
			free(derCert);
			free(pem);
			return -412;
		}

		bytes3 = fread(tmp, 1, FOURK_BUF, file3);
		fclose(file3);

		ret = wc_InitRsaKey(&caKey, 0);
		if (ret != 0) {
			free(derCert);
			free(pem);
			return -411;
		}
		ret = wc_RsaPrivateKeyDecode(tmp, &idx3, &caKey, (word32)bytes3);
		if (ret != 0) {
			free(derCert);
			free(pem);
			wc_FreeRsaKey(&caKey);
			return -413;
		}

		wc_InitCert(&myCert);

		strncpy(myCert.subject.country, "US", CTC_NAME_SIZE);
		strncpy(myCert.subject.state, "OR", CTC_NAME_SIZE);
		strncpy(myCert.subject.locality, "Portland", CTC_NAME_SIZE);
		strncpy(myCert.subject.org, "yaSSL", CTC_NAME_SIZE);
		strncpy(myCert.subject.unit, "Development", CTC_NAME_SIZE);
		strncpy(myCert.subject.commonName, "www.yassl.com", CTC_NAME_SIZE);
		strncpy(myCert.subject.email, "info@yassl.com", CTC_NAME_SIZE);

		/* lzj ?? */
		ret = wc_SetIssuer(&myCert, caCertFile);
		if (ret < 0) {
			free(derCert);
			free(pem);
			wc_FreeRsaKey(&caKey);
			return -405;
		}

		certSz = wc_MakeCert(&myCert, derCert, FOURK_BUF, &key, NULL, &rng);
		if (certSz < 0) {
			free(derCert);
			free(pem);
			wc_FreeRsaKey(&caKey);
			return -407;
		}

		certSz = wc_SignCert(myCert.bodySz, myCert.sigType, derCert, FOURK_BUF, &caKey, NULL, &rng);
		if (certSz < 0) {
			free(derCert);
			free(pem);
			wc_FreeRsaKey(&caKey);
			return -408;
		}


#ifdef WOLFSSL_TEST_CERT
		InitDecodedCert(&decode, derCert, certSz, 0);
		ret = ParseCert(&decode, CERT_TYPE, NO_VERIFY, 0);
		if (ret != 0) {
			free(derCert);
			free(pem);
			wc_FreeRsaKey(&caKey);
			return -409;
		}
		FreeDecodedCert(&decode);
#endif

#ifdef FREESCALE_MQX
		derFile = fopen("a:\\certs\\othercert.der", "wb");
#else
		derFile = fopen("./othercert.der", "wb");
#endif
		if (!derFile) {
			free(derCert);
			free(pem);
			wc_FreeRsaKey(&caKey);
			return -410;
		}
		ret = (int)fwrite(derCert, 1, certSz, derFile);
		fclose(derFile);
		if (ret != certSz) {
			free(derCert);
			free(pem);
			wc_FreeRsaKey(&caKey);
			return -416;
		}

		pemSz = wc_DerToPem(derCert, certSz, pem, FOURK_BUF, CERT_TYPE);
		if (pemSz < 0) {
			free(derCert);
			free(pem);
			wc_FreeRsaKey(&caKey);
			return -411;
		}

#ifdef FREESCALE_MQX
		pemFile = fopen("a:\\certs\\othercert.pem", "wb");
#else
		pemFile = fopen("./othercert.pem", "wb");
#endif
		if (!pemFile) {
			free(derCert);
			free(pem);
			wc_FreeRsaKey(&caKey);
			return -412;
		}
		ret = (int)fwrite(pem, 1, pemSz, pemFile);
		if (ret != pemSz) {
			free(derCert);
			free(pem);
			wc_FreeRsaKey(&caKey);
			return -415;
		}
		fclose(pemFile);
		free(pem);
		free(derCert);
		wc_FreeRsaKey(&caKey);
	}
	
#ifdef HAVE_ECC
    /* ECC CA style */
	{
		ecc_key     caKey;
		Cert        myCert;
		byte*       derCert;
		byte*       pem;
		FILE*       derFile;
		FILE*       pemFile;
		int         certSz;
		int         pemSz;
		size_t      bytes3;
		word32      idx3 = 0;
		FILE*       file3;
#ifdef WOLFSSL_TEST_CERT
		DecodedCert decode;
#endif

		DEBUG_MSG("\n---------Test RSA case 6: create CA(ECC format)-signed Certificate and stored in file\n");
		derCert = (byte*)malloc(FOURK_BUF);
		if (derCert == NULL)
			return -5311;
		pem = (byte*)malloc(FOURK_BUF);
		if (pem == NULL) {
			free(derCert);
			return -5312;
		}

		file3 = fopen(eccCaKeyFile, "rb");
		if (!file3) {
			free(derCert);
			free(pem);
			return -5412;
		}

		bytes3 = fread(tmp, 1, FOURK_BUF, file3);
		fclose(file3);

		wc_ecc_init(&caKey);
		ret = wc_EccPrivateKeyDecode(tmp, &idx3, &caKey, (word32)bytes3);
		if (ret != 0) {
			free(derCert);
			free(pem);
			return -5413;
		}

		wc_InitCert(&myCert);
		myCert.sigType = CTC_SHA256wECDSA;

		strncpy(myCert.subject.country, "US", CTC_NAME_SIZE);
		strncpy(myCert.subject.state, "OR", CTC_NAME_SIZE);
		strncpy(myCert.subject.locality, "Portland", CTC_NAME_SIZE);
		strncpy(myCert.subject.org, "wolfSSL", CTC_NAME_SIZE);
		strncpy(myCert.subject.unit, "Development", CTC_NAME_SIZE);
		strncpy(myCert.subject.commonName, "www.wolfssl.com", CTC_NAME_SIZE);
		strncpy(myCert.subject.email, "info@wolfssl.com", CTC_NAME_SIZE);

		ret = wc_SetIssuer(&myCert, eccCaCertFile);
		if (ret < 0) {
			free(pem);
			free(derCert);
			wc_ecc_free(&caKey);
			return -5405;
		}

		certSz = wc_MakeCert(&myCert, derCert, FOURK_BUF, NULL, &caKey, &rng);
		if (certSz < 0) {
			free(pem);
			free(derCert);
			wc_ecc_free(&caKey);
			return -5407;
		}

		certSz = wc_SignCert(myCert.bodySz, myCert.sigType, derCert, FOURK_BUF, NULL, &caKey, &rng);
		if (certSz < 0) {
			free(pem);
			free(derCert);
			wc_ecc_free(&caKey);
			return -5408;
		}

#ifdef WOLFSSL_TEST_CERT
		InitDecodedCert(&decode, derCert, certSz, 0);
		ret = ParseCert(&decode, CERT_TYPE, NO_VERIFY, 0);
		if (ret != 0) {
			free(pem);
			free(derCert);
			wc_ecc_free(&caKey);
			return -5409;
		}
		FreeDecodedCert(&decode);
#endif

#ifdef FREESCALE_MQX
		derFile = fopen("a:\\certs\\certecc.der", "wb");
#else
		derFile = fopen("./certecc.der", "wb");
#endif
		if (!derFile) {
			free(pem);
			free(derCert);
			wc_ecc_free(&caKey);
			return -5410;
		}
		ret = (int)fwrite(derCert, 1, certSz, derFile);
		fclose(derFile);
		if (ret != certSz) {
			free(pem);
			free(derCert);
			wc_ecc_free(&caKey);
			return -5414;
		}

		pemSz = wc_DerToPem(derCert, certSz, pem, FOURK_BUF, CERT_TYPE);
		if (pemSz < 0) {
			free(pem);
			free(derCert);
			wc_ecc_free(&caKey);
			return -5411;
		}

#ifdef FREESCALE_MQX
		pemFile = fopen("a:\\certs\\certecc.pem", "wb");
#else
		pemFile = fopen("./certecc.pem", "wb");
#endif
		if (!pemFile) {
			free(pem);
			free(derCert);
			wc_ecc_free(&caKey);
			return -5412;
		}
		ret = (int)fwrite(pem, 1, pemSz, pemFile);
		if (ret != pemSz) {
			free(pem);
			free(derCert);
			wc_ecc_free(&caKey);
			return -5415;
		}
		fclose(pemFile);
		free(pem);
		free(derCert);
		wc_ecc_free(&caKey);
	}
#endif /* HAVE_ECC */

#ifdef HAVE_NTRU
    {
        RsaKey      caKey;
        Cert        myCert;
        byte*       derCert;
        byte*       pem;
        FILE*       derFile;
        FILE*       pemFile;
        FILE*       caFile;
        FILE*       ntruPrivFile;
        int         certSz;
        int         pemSz;
        word32      idx3;
#ifdef WOLFSSL_TEST_CERT
        DecodedCert decode;
#endif
        derCert = (byte*)malloc(FOURK_BUF);
        if (derCert == NULL)
            return -311;
        pem = (byte*)malloc(FOURK_BUF);
        if (pem == NULL) {
            free(derCert);
            return -312;
        }

        byte   public_key[557];          /* sized for EES401EP2 */
        word16 public_key_len;           /* no. of octets in public key */
        byte   private_key[607];         /* sized for EES401EP2 */
        word16 private_key_len;          /* no. of octets in private key */
        DRBG_HANDLE drbg;
        static uint8_t const pers_str[] = {
                'C', 'y', 'a', 'S', 'S', 'L', ' ', 't', 'e', 's', 't'
        };
        word32 rc = ntru_crypto_drbg_instantiate(112, pers_str,
                          sizeof(pers_str), GetEntropy, &drbg);
        if (rc != DRBG_OK) {
            free(derCert);
            free(pem);
            return -448;
        }

	DEBUG_MSG("\n---------Test RSA case 7: create NTRU Certificate and stored in file\n");
        rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2,
                                             &public_key_len, NULL,
                                             &private_key_len, NULL);
        if (rc != NTRU_OK) {
            free(derCert);
            free(pem);
            return -449;
        }

        rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2,
                                             &public_key_len, public_key,
                                             &private_key_len, private_key);
        if (rc != NTRU_OK) {
            free(derCert);
            free(pem);
            return -450;
        }

        rc = ntru_crypto_drbg_uninstantiate(drbg);

        if (rc != NTRU_OK) {
            free(derCert);
            free(pem);
            return -451;
        }

        caFile = fopen(caKeyFile, "rb");

        if (!caFile) {
            free(derCert);
            free(pem);
            return -452;
        }

        bytes = fread(tmp, 1, FOURK_BUF, caFile);
        fclose(caFile);

        ret = wc_InitRsaKey(&caKey, 0);
        if (ret != 0) {
            free(derCert);
            free(pem);
            return -453;
        }
        ret = wc_RsaPrivateKeyDecode(tmp, &idx3, &caKey, (word32)bytes);
        if (ret != 0) {
            free(derCert);
            free(pem);
            return -454;
        }

        wc_InitCert(&myCert);

        strncpy(myCert.subject.country, "US", CTC_NAME_SIZE);
        strncpy(myCert.subject.state, "OR", CTC_NAME_SIZE);
        strncpy(myCert.subject.locality, "Portland", CTC_NAME_SIZE);
        strncpy(myCert.subject.org, "yaSSL", CTC_NAME_SIZE);
        strncpy(myCert.subject.unit, "Development", CTC_NAME_SIZE);
        strncpy(myCert.subject.commonName, "www.yassl.com", CTC_NAME_SIZE);
        strncpy(myCert.subject.email, "info@yassl.com", CTC_NAME_SIZE);

        ret = wc_SetIssuer(&myCert, caCertFile);
        if (ret < 0) {
            free(derCert);
            free(pem);
            wc_FreeRsaKey(&caKey);
            return -455;
        }

        certSz = wc_MakeNtruCert(&myCert, derCert, FOURK_BUF, public_key,
                              public_key_len, &rng);
        if (certSz < 0) {
            free(derCert);
            free(pem);
            wc_FreeRsaKey(&caKey);
            return -456;
        }

        certSz = wc_SignCert(myCert.bodySz, myCert.sigType, derCert, FOURK_BUF,
                          &caKey, NULL, &rng);
        wc_FreeRsaKey(&caKey);
        if (certSz < 0) {
            free(derCert);
            free(pem);
            return -457;
        }


#ifdef WOLFSSL_TEST_CERT
        InitDecodedCert(&decode, derCert, certSz, 0);
        ret = ParseCert(&decode, CERT_TYPE, NO_VERIFY, 0);
        if (ret != 0) {
            free(derCert);
            free(pem);
            return -458;
        }
        FreeDecodedCert(&decode);
#endif
        derFile = fopen("./ntru-cert.der", "wb");
        if (!derFile) {
            free(derCert);
            free(pem);
            return -459;
        }
        ret = (int)fwrite(derCert, 1, certSz, derFile);
        fclose(derFile);
        if (ret != certSz) {
            free(derCert);
            free(pem);
            return -473;
        }

        pemSz = wc_DerToPem(derCert, certSz, pem, FOURK_BUF, CERT_TYPE);
        if (pemSz < 0) {
            free(derCert);
            free(pem);
            return -460;
        }

        pemFile = fopen("./ntru-cert.pem", "wb");
        if (!pemFile) {
            free(derCert);
            free(pem);
            return -461;
        }
        ret = (int)fwrite(pem, 1, pemSz, pemFile);
        fclose(pemFile);
        if (ret != pemSz) {
            free(derCert);
            free(pem);
            return -474;
        }

        ntruPrivFile = fopen("./ntru-key.raw", "wb");
        if (!ntruPrivFile) {
            free(derCert);
            free(pem);
            return -462;
        }
        ret = (int)fwrite(private_key, 1, private_key_len, ntruPrivFile);
        fclose(ntruPrivFile);
        if (ret != private_key_len) {
            free(pem);
            free(derCert);
            return -475;
        }
        free(pem);
        free(derCert);
    }
#endif /* HAVE_NTRU */


#ifdef WOLFSSL_CERT_REQ
	{
		Cert        req;
		byte*       der;
		byte*       pem;
		int         derSz;
		int         pemSz;
		FILE*       reqFile;

		DEBUG_MSG("\n---------Test RSA case 8: create CERT-REQUEST and stored in file\n");
		der = (byte*)malloc(FOURK_BUF);
		if (der == NULL)
			return -463;
		pem = (byte*)malloc(FOURK_BUF);
		if (pem == NULL) {
			free(der);
			return -464;
		}

		wc_InitCert(&req);

		req.version = 0;
		req.isCA    = 1;
		strncpy(req.challengePw, "yassl123", CTC_NAME_SIZE);
		strncpy(req.subject.country, "US", CTC_NAME_SIZE);
		strncpy(req.subject.state, "OR", CTC_NAME_SIZE);
		strncpy(req.subject.locality, "Portland", CTC_NAME_SIZE);
		strncpy(req.subject.org, "yaSSL", CTC_NAME_SIZE);
		strncpy(req.subject.unit, "Development", CTC_NAME_SIZE);
		strncpy(req.subject.commonName, "www.yassl.com", CTC_NAME_SIZE);
		strncpy(req.subject.email, "info@yassl.com", CTC_NAME_SIZE);
		req.sigType = CTC_SHA256wRSA;

		derSz = certMakeCertReq(der, FOURK_BUF, &req, &key, NULL);
		if (derSz < 0) {
			free(pem);
			free(der);
			return -465;
		}

		derSz = wc_SignCert(req.bodySz, req.sigType, der, FOURK_BUF, &key, NULL, &rng);
		if (derSz < 0) {
			free(pem);
			free(der);
			return -466;
		}

		pemSz = wc_DerToPem(der, derSz, pem, FOURK_BUF, CERTREQ_TYPE);
		if (pemSz < 0) {
			free(pem);
			free(der);
			return -467;
		}

#ifdef FREESCALE_MQX
		reqFile = fopen("a:\\certs\\certreq.der", "wb");
#else
		reqFile = fopen("./certreq.der", "wb");
#endif
		if (!reqFile) {
			free(pem);
			free(der);
			return -468;
		}

		ret = (int)fwrite(der, 1, derSz, reqFile);
		fclose(reqFile);
		if (ret != derSz) {
			free(pem);
			free(der);
			return -471;
		}

#ifdef FREESCALE_MQX
		reqFile = fopen("a:\\certs\\certreq.pem", "wb");
#else
		reqFile = fopen("./certreq.pem", "wb");
#endif
		if (!reqFile) {
			free(pem);
			free(der);
			return -469;
		}
		ret = (int)fwrite(pem, 1, pemSz, reqFile);
		fclose(reqFile);
		if (ret != pemSz) {
			free(pem);
			free(der);
			return -470;
		}

		free(pem);
		free(der);
	}
#endif /* WOLFSSL_CERT_REQ */
#endif /* WOLFSSL_CERT_GEN */

	wc_FreeRsaKey(&key);
#ifdef HAVE_CAVIUM
	wc_RsaFreeCavium(&key);
#endif
	free(tmp);
	wc_FreeRng(&rng);

	return 0;
}



int dsa_test(void)
{
#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
        static const char* dsaKey = "./certs/dsa2048.der";
#endif

	int    ret, answer;
	word32 bytes;
	word32 idx = 0;
	byte   tmp[1024];
	DsaKey key;
	RNG    rng;
	Sha    sha;
	byte   hash[SHA_DIGEST_SIZE];
	byte   signature[40];


#ifdef USE_CERT_BUFFERS_1024
	XMEMCPY(tmp, dsa_key_der_1024, sizeof_dsa_key_der_1024);
	bytes = sizeof_dsa_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
	XMEMCPY(tmp, dsa_key_der_2048, sizeof_dsa_key_der_2048);
	bytes = sizeof_dsa_key_der_2048;
#else
	FILE*  file = fopen(dsaKey, "rb");

	if (!file)
		return -60;

	wolfSslDebug("Open DSA key file of '%s' OK!\n", dsaKey);
	bytes = (word32) fread(tmp, 1, sizeof(tmp), file);
	fclose(file);
#endif /* USE_CERT_BUFFERS */

	/* calculate hash of der certificate file */
	ret = wc_InitSha(&sha);
	if (ret != 0)
		return -4002;
	wc_ShaUpdate(&sha, tmp, bytes);
	wc_ShaFinal(&sha, hash);

	/* decode der certificate : both public and private key? */
	wc_InitDsaKey(&key);
	ret = DsaPrivateKeyDecode(tmp, &idx, &key, bytes);
	if (ret != 0) return -61;

	ret = wc_InitRng(&rng);
	if (ret != 0) return -62;

	/* signing hash with public key and random */
	ret = wc_DsaSign(hash, signature, &key, &rng);
	if (ret != 0) return -63;

	/* verifying the signed hash with private key */
	ret = wc_DsaVerify(hash, signature, &key, &answer);
	if (ret != 0)
		return -64;
	if (answer != 1)
		return -65;

	wc_FreeDsaKey(&key);
	wc_FreeRng(&rng);

	return 0;
}


int dh_test(void)
{
	int    ret;
	word32 bytes;
	word32 idx = 0, privSz, pubSz, privSz2, pubSz2, agreeSz, agreeSz2;
	byte   tmp[1024];
	byte   priv[256];
	byte   pub[256];
	byte   priv2[256];
	byte   pub2[256];
	byte   agree[256];
	byte   agree2[256];
	DhKey  key;
	DhKey  key2;
	RNG    rng;

#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
    #ifdef FREESCALE_MQX
        static const char* dhKey = "a:\\certs\\dh2048.der";
    #elif defined(NO_ASN)
        /* don't use file, no DER parsing */
    #else
        static const char* dhKey = "./certs/dh2048.der";
    #endif
#endif


#ifdef USE_CERT_BUFFERS_1024
	XMEMCPY(tmp, dh_key_der_1024, sizeof_dh_key_der_1024);
	bytes = sizeof_dh_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
	XMEMCPY(tmp, dh_key_der_2048, sizeof_dh_key_der_2048);
	bytes = sizeof_dh_key_der_2048;
#elif defined(NO_ASN)
	/* don't use file, no DER parsing */
#else
	FILE*  file = fopen(dhKey, "rb");

	if (!file)
		return -50;

	wolfSslDebug("Open DH Params file of '%s' OK!\n", dhKey);
	bytes = (word32) fread(tmp, 1, sizeof(tmp), file);
	fclose(file);
#endif /* USE_CERT_BUFFERS */

	(void)idx;
	(void)tmp;
	(void)bytes;

	wc_InitDhKey(&key);
	wc_InitDhKey(&key2);

	/* input data into key */
#ifdef NO_ASN
	ret = wc_DhSetKey(&key, dh_p, sizeof(dh_p), dh_g, sizeof(dh_g));
	if (ret != 0)
		return -51;

	ret = wc_DhSetKey(&key2, dh_p, sizeof(dh_p), dh_g, sizeof(dh_g));
	if (ret != 0)
		return -51;
#else
	ret = wc_DhKeyDecode(tmp, &idx, &key, bytes);
	if (ret != 0)
		return -51;

	idx = 0;
	ret = wc_DhKeyDecode(tmp, &idx, &key2, bytes);
	if (ret != 0)
		return -52;
#endif

	ret = wc_InitRng(&rng);
	if (ret != 0)
		return -53;

	ret =  wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz);
	ret += wc_DhGenerateKeyPair(&key2, &rng, priv2, &privSz2, pub2, &pubSz2);
	if (ret != 0)
		return -54;

	ret =  wc_DhAgree(&key, agree, &agreeSz, priv, privSz, pub2, pubSz2);
	ret += wc_DhAgree(&key2, agree2, &agreeSz2, priv2, privSz2, pub, pubSz);
	if (ret != 0)
		return -55;

	if (memcmp(agree, agree2, agreeSz))
		return -56;

	wc_FreeDhKey(&key);
	wc_FreeDhKey(&key2);
	wc_FreeRng(&rng);

	return 0;
}


int pkcs7enveloped_test(void)
{
	int ret = 0;

	int cipher = DES3b;
	int envelopedSz, decodedSz;
	PKCS7 pkcs7;
	byte* cert;
	byte* privKey;
	byte  enveloped[2048];
	byte  decoded[2048];

	size_t certSz;
	size_t privKeySz;
	FILE*  certFile;
	FILE*  keyFile;
	FILE*  pkcs7File;
	const char* pkcs7OutFile = "pkcs7envelopedData.der";

	const byte data[] = { /* Hello World */
		0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x6f,
		0x72,0x6c,0x64
	};

	/* read client cert and key in DER format */
	cert = (byte*)malloc(FOURK_BUF);
	if (cert == NULL)
		return -201;

	privKey = (byte*)malloc(FOURK_BUF);
	if (privKey == NULL) {
		free(cert);
		return -202;
	}

	certFile = fopen(clientCert, "rb");
	if (!certFile) {
		free(cert);
		free(privKey);
		err_sys("can't open ./certs/client-cert.der, Please run from wolfSSL home dir");
		return -42;
	}

	certSz = fread(cert, 1, FOURK_BUF, certFile);
	fclose(certFile);

	keyFile = fopen(clientKey, "rb");
	if (!keyFile) {
		free(cert);
		free(privKey);
		err_sys("can't open ./certs/client-key.der, ""Please run from wolfSSL home dir");
		return -43;
	}

	privKeySz = fread(privKey, 1, FOURK_BUF, keyFile);
	fclose(keyFile);

	wc_PKCS7_InitWithCert(&pkcs7, cert, (word32)certSz);
	pkcs7.content     = (byte*)data;
	pkcs7.contentSz   = (word32)sizeof(data);
	pkcs7.contentOID  = DATA;
	pkcs7.encryptOID  = cipher;
	pkcs7.privateKey  = privKey;
	pkcs7.privateKeySz = (word32)privKeySz;

	/* encode envelopedData */
	envelopedSz = wc_PKCS7_EncodeEnvelopedData(&pkcs7, enveloped, sizeof(enveloped));
	if (envelopedSz <= 0) {
		free(cert);
		free(privKey);
		return -203;
	}

	/* decode envelopedData */
	decodedSz = wc_PKCS7_DecodeEnvelopedData(&pkcs7, enveloped, envelopedSz, decoded, sizeof(decoded));
	if (decodedSz <= 0) {
		free(cert);
		free(privKey);
		return -204;
	}

	/* test decode result */
	if (memcmp(decoded, data, sizeof(data)) != 0) {
		free(cert);
		free(privKey);
		return -205;
	}

	/* output pkcs7 envelopedData for external testing */
	pkcs7File = fopen(pkcs7OutFile, "wb");
	if (!pkcs7File) {
		free(cert);
		free(privKey);
		return -206;
	}

	ret = (int)fwrite(enveloped, envelopedSz, 1, pkcs7File);
	fclose(pkcs7File);

	free(cert);
	free(privKey);
	wc_PKCS7_Free(&pkcs7);

	if (ret > 0)
		return 0;

	return ret;
}


int pkcs7signed_test(void)
{
	int ret = 0;

	FILE* file;
	byte* certDer;
	byte* keyDer;
	byte* out;
	char data[] = "Hello World";
	word32 dataSz, outSz, certDerSz, keyDerSz;
	PKCS7 msg;
	RNG rng;

	byte transIdOid[] = 	
		{ 0x06, 0x0a, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x07 };
	byte messageTypeOid[] = 	
		{ 0x06, 0x0a, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x02 };
	byte senderNonceOid[] = 	
		{ 0x06, 0x0a, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x05 };
	byte transId[(SHA_DIGEST_SIZE + 1) * 2 + 1];
	byte messageType[] = { 0x13, 2, '1', '9' };
	byte senderNonce[PKCS7_NONCE_SZ + 2];

	PKCS7Attrib attribs[] =
	{
		{ transIdOid, sizeof(transIdOid), transId, sizeof(transId) - 1 }, /* take off the null */
		{ messageTypeOid, sizeof(messageTypeOid),  messageType, sizeof(messageType) },
		{ senderNonceOid, sizeof(senderNonceOid), senderNonce, sizeof(senderNonce) }
	};

	dataSz = (word32) strlen(data);
	outSz = FOURK_BUF;

	certDer = (byte*)malloc(FOURK_BUF);
	if (certDer == NULL)
		return -207;
	keyDer = (byte*)malloc(FOURK_BUF);
	if (keyDer == NULL) {
		free(certDer);
		return -208;
	}
	out = (byte*)malloc(FOURK_BUF);
	if (out == NULL) {
		free(certDer);
		free(keyDer);
		return -209;
	}

	/* read in DER cert of recipient, into cert of size certSz */
	file = fopen(clientCert, "rb");
	if (!file) {
		free(certDer);
		free(keyDer);
		free(out);
		err_sys("can't open ./certs/client-cert.der, Please run from wolfSSL home dir");
		return -44;
	}
	certDerSz = (word32)fread(certDer, 1, FOURK_BUF, file);
	fclose(file);

	file = fopen(clientKey, "rb");
	if (!file) {
		free(certDer);
		free(keyDer);
		free(out);
		err_sys("can't open ./certs/client-key.der, Please run from wolfSSL home dir");
		return -45;
	}
	keyDerSz = (word32)fread(keyDer, 1, FOURK_BUF, file);
	fclose(file);

	ret = wc_InitRng(&rng);
	if (ret != 0) {
		free(certDer);
		free(keyDer);
		free(out);
		return -210;
	}

	senderNonce[0] = 0x04;
	senderNonce[1] = PKCS7_NONCE_SZ;

	ret = wc_RNG_GenerateBlock(&rng, &senderNonce[2], PKCS7_NONCE_SZ);
	if (ret != 0) {
		free(certDer);
		free(keyDer);
		free(out);
		return -211;
	}

	wc_PKCS7_InitWithCert(&msg, certDer, certDerSz);
	msg.privateKey = keyDer;
	msg.privateKeySz = keyDerSz;
	msg.content = (byte*)data;
	msg.contentSz = dataSz;
	msg.hashOID = SHAh;
	msg.encryptOID = RSAk;
	msg.signedAttribs = attribs;
	msg.signedAttribsSz = sizeof(attribs)/sizeof(PKCS7Attrib);
	msg.rng = &rng;
	
	{
		Sha sha;
		byte digest[SHA_DIGEST_SIZE];
		int i,j;

		transId[0] = 0x13;
		transId[1] = SHA_DIGEST_SIZE * 2;

		ret = wc_InitSha(&sha);
		if (ret != 0) {
			free(certDer);
			free(keyDer);
			free(out);
			return -4003;
		}
		wc_ShaUpdate(&sha, msg.publicKey, msg.publicKeySz);
		wc_ShaFinal(&sha, digest);

		for (i = 0, j = 2; i < SHA_DIGEST_SIZE; i++, j += 2) {
			/* lzj */
			//            snprintf((char*)&transId[j], 3, "%02x", digest[i]);
			_snprintf((char*)&transId[j], 3, "%02x", digest[i]);
		}
	}
	
	ret = wc_PKCS7_EncodeSignedData(&msg, out, outSz);
	if (ret < 0) {
		free(certDer);
		free(keyDer);
		free(out);
		wc_PKCS7_Free(&msg);
		return -212;
	}
	else
		outSz = ret;

	/* write PKCS#7 to output file for more testing */
	file = fopen("./pkcs7signedData.der", "wb");
	if (!file) {
		free(certDer);
		free(keyDer);
		free(out);
		wc_PKCS7_Free(&msg);
		return -213;
	}
	
	ret = (int)fwrite(out, 1, outSz, file);
	fclose(file);
	if (ret != (int)outSz) {
		free(certDer);
		free(keyDer);
		free(out);
		wc_PKCS7_Free(&msg);
		return -218;
	}

	wc_PKCS7_Free(&msg);
	wc_PKCS7_InitWithCert(&msg, NULL, 0);

	ret = wc_PKCS7_VerifySignedData(&msg, out, outSz);
	if (ret < 0) {
		free(certDer);
		free(keyDer);
		free(out);
		wc_PKCS7_Free(&msg);
		return -214;
	}

	if (msg.singleCert == NULL || msg.singleCertSz == 0) {
		free(certDer);
		free(keyDer);
		free(out);
		wc_PKCS7_Free(&msg);
		return -215;
	}

	file = fopen("./pkcs7cert.der", "wb");
	if (!file) {
		free(certDer);
		free(keyDer);
		free(out);
		wc_PKCS7_Free(&msg);
		return -216;
	}
	ret = (int)fwrite(msg.singleCert, 1, msg.singleCertSz, file);
	fclose(file);

	free(certDer);
	free(keyDer);
	free(out);
	wc_PKCS7_Free(&msg);

	wc_FreeRng(&rng);

	if (ret > 0)
		return 0;

	return ret;
}


int main(int argc, char** argv)
{
	int ret;

	func_args args;

	args.argc = argc;
	args.argv = argv;

	wolfSSL_Debugging_ON();
#if 0
  	TEST_FUNCTION(dh_test, DH, ret);

  	TEST_FUNCTION(dsa_test, DSA, ret);
	
  	TEST_FUNCTION(pkcs7enveloped_test, PKCS7enveloped, ret);

  	TEST_FUNCTION(pkcs7signed_test, PKCS7signed, ret);

#endif

  	TEST_FUNCTION(rsa_test, RSA, ret);

	args.return_code = ret;

	return args.return_code;
}


