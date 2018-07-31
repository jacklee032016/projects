
#include "cmnSsl.h"


const char* wolfSSL_get_version(WOLFSSL* ssl)
{
	WOLFSSL_ENTER();
    if (ssl->version.major == SSLv3_MAJOR) {
        switch (ssl->version.minor) {
            case SSLv3_MINOR :
                return "SSLv3";
            case TLSv1_MINOR :
                return "TLSv1";
            case TLSv1_1_MINOR :
                return "TLSv1.1";
            case TLSv1_2_MINOR :
                return "TLSv1.2";
            default:
                return "unknown";
        }
    }
    else if (ssl->version.major == DTLS_MAJOR) {
        switch (ssl->version.minor) {
            case DTLS_MINOR :
                return "DTLS";
            case DTLSv1_2_MINOR :
                return "DTLSv1.2";
            default:
                return "unknown";
        }
    }
    return "unknown";
}



int wolfSSL_get_current_cipher_suite(WOLFSSL* ssl)
{
	if (ssl)
		return (ssl->options.cipherSuite0 << 8) | ssl->options.cipherSuite;
	return 0;
}

WOLFSSL_CIPHER* wolfSSL_get_current_cipher(WOLFSSL* ssl)
{
	if (ssl)
		return &ssl->cipher;
	else
		return NULL;
}


const char* wolfSSL_CIPHER_get_name(const WOLFSSL_CIPHER* cipher)
{
	(void)cipher;

#ifndef NO_ERROR_STRINGS
	if (cipher)
	{
#if defined(HAVE_CHACHA)
		if (cipher->ssl->options.cipherSuite0 == CHACHA_BYTE)
		{
			/* ChaCha suites */
			switch (cipher->ssl->options.cipherSuite) {
#ifdef HAVE_CHACHA
#ifndef NO_RSA
				case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
				return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";

				case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
				return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
#endif
				case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 :
				return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
#endif
			}
		}
#endif

#if defined(HAVE_ECC) || defined(HAVE_AESCCM)
		/* Awkwardly, the ECC cipher suites use the ECC_BYTE as expected,
		* but the AES-CCM cipher suites also use it, even the ones that
		* aren't ECC. */
		if (cipher->ssl->options.cipherSuite0 == ECC_BYTE)
		{
			/* ECC suites */
			switch (cipher->ssl->options.cipherSuite) {
#ifdef HAVE_ECC
#ifndef NO_RSA
				case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 :
				return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
#endif
				case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 :
				return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
#ifndef NO_RSA
				case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 :
				return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
#endif
				case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 :
				return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
#ifndef NO_RSA
				case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 :
				return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
#endif
				case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 :
				return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
#ifndef NO_RSA
				case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 :
				return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
#endif
				case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 :
				return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
#ifndef NO_SHA
#ifndef NO_RSA
				case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA :
				return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
				case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA :
				return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
#endif
				case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA :
				return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
				case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA :
				return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
#ifndef NO_RC4
#ifndef NO_RSA
				case TLS_ECDHE_RSA_WITH_RC4_128_SHA :
				return "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
#endif
				case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA :
				return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
#endif
#ifndef NO_DES3
#ifndef NO_RSA
				case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA :
				return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
#endif
				case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA :
				return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
#endif

#ifndef NO_RSA
				case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA :
				return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA";
				case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA :
				return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA";
#endif
				case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA :
				return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
				case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA :
				return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
#ifndef NO_RC4
#ifndef NO_RSA
				case TLS_ECDH_RSA_WITH_RC4_128_SHA :
				return "TLS_ECDH_RSA_WITH_RC4_128_SHA";
#endif
				case TLS_ECDH_ECDSA_WITH_RC4_128_SHA :
				return "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
#endif
#ifndef NO_DES3
#ifndef NO_RSA
				case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA :
				return "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
#endif
				case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA :
				return "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
#endif
#endif /* NO_SHA */

#ifdef HAVE_AESGCM
#ifndef NO_RSA
				case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 :
				return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
				case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 :
				return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
#endif
				case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 :
				return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
				case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 :
				return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
#ifndef NO_RSA
				case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 :
				return "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
				case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 :
				return "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";
#endif
				case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 :
				return "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
				case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 :
				return "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_AESCCM
#ifndef NO_RSA
				case TLS_RSA_WITH_AES_128_CCM_8 :
				return "TLS_RSA_WITH_AES_128_CCM_8";
				case TLS_RSA_WITH_AES_256_CCM_8 :
				return "TLS_RSA_WITH_AES_256_CCM_8";
#endif
#ifndef NO_PSK
				case TLS_PSK_WITH_AES_128_CCM_8 :
				return "TLS_PSK_WITH_AES_128_CCM_8";
				case TLS_PSK_WITH_AES_256_CCM_8 :
				return "TLS_PSK_WITH_AES_256_CCM_8";
				case TLS_PSK_WITH_AES_128_CCM :
				return "TLS_PSK_WITH_AES_128_CCM";
				case TLS_PSK_WITH_AES_256_CCM :
				return "TLS_PSK_WITH_AES_256_CCM";
				case TLS_DHE_PSK_WITH_AES_128_CCM :
				return "TLS_DHE_PSK_WITH_AES_128_CCM";
				case TLS_DHE_PSK_WITH_AES_256_CCM :
				return "TLS_DHE_PSK_WITH_AES_256_CCM";
#endif
#ifdef HAVE_ECC
				case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
				return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8";
				case TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 :
				return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8";
#endif
#endif

				default:
				return "NONE";
			}
		}
#endif  /* ECC */

		if (cipher->ssl->options.cipherSuite0 != ECC_BYTE && cipher->ssl->options.cipherSuite0 != CHACHA_BYTE)
		{
			/* normal suites */
			switch (cipher->ssl->options.cipherSuite) {
#ifndef NO_RSA
#ifndef NO_RC4
#ifndef NO_SHA
				case SSL_RSA_WITH_RC4_128_SHA :
				return "SSL_RSA_WITH_RC4_128_SHA";
#endif
#ifndef NO_MD5
				case SSL_RSA_WITH_RC4_128_MD5 :
				return "SSL_RSA_WITH_RC4_128_MD5";
#endif
#endif
#ifndef NO_SHA
#ifndef NO_DES3
				case SSL_RSA_WITH_3DES_EDE_CBC_SHA :
				return "SSL_RSA_WITH_3DES_EDE_CBC_SHA";
#endif
				case TLS_RSA_WITH_AES_128_CBC_SHA :
				return "TLS_RSA_WITH_AES_128_CBC_SHA";
				case TLS_RSA_WITH_AES_256_CBC_SHA :
				return "TLS_RSA_WITH_AES_256_CBC_SHA";
#endif
				case TLS_RSA_WITH_AES_128_CBC_SHA256 :
				return "TLS_RSA_WITH_AES_128_CBC_SHA256";
				case TLS_RSA_WITH_AES_256_CBC_SHA256 :
				return "TLS_RSA_WITH_AES_256_CBC_SHA256";
#ifdef HAVE_BLAKE2
				case TLS_RSA_WITH_AES_128_CBC_B2B256:
				return "TLS_RSA_WITH_AES_128_CBC_B2B256";
				case TLS_RSA_WITH_AES_256_CBC_B2B256:
				return "TLS_RSA_WITH_AES_256_CBC_B2B256";
#endif
#ifndef NO_SHA
				case TLS_RSA_WITH_NULL_SHA :
				return "TLS_RSA_WITH_NULL_SHA";
#endif
				case TLS_RSA_WITH_NULL_SHA256 :
				return "TLS_RSA_WITH_NULL_SHA256";
#endif /* NO_RSA */
#ifndef NO_PSK
#ifndef NO_SHA
				case TLS_PSK_WITH_AES_128_CBC_SHA :
				return "TLS_PSK_WITH_AES_128_CBC_SHA";
				case TLS_PSK_WITH_AES_256_CBC_SHA :
				return "TLS_PSK_WITH_AES_256_CBC_SHA";
#endif
#ifndef NO_SHA256
				case TLS_PSK_WITH_AES_128_CBC_SHA256 :
				return "TLS_PSK_WITH_AES_128_CBC_SHA256";
				case TLS_PSK_WITH_NULL_SHA256 :
				return "TLS_PSK_WITH_NULL_SHA256";
				case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 :
				return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256";
				case TLS_DHE_PSK_WITH_NULL_SHA256 :
				return "TLS_DHE_PSK_WITH_NULL_SHA256";
#ifdef HAVE_AESGCM
				case TLS_PSK_WITH_AES_128_GCM_SHA256 :
				return "TLS_PSK_WITH_AES_128_GCM_SHA256";
				case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 :
				return "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256";
#endif
#endif
#ifdef WOLFSSL_SHA384
				case TLS_PSK_WITH_AES_256_CBC_SHA384 :
				return "TLS_PSK_WITH_AES_256_CBC_SHA384";
				case TLS_PSK_WITH_NULL_SHA384 :
				return "TLS_PSK_WITH_NULL_SHA384";
				case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 :
				return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384";
				case TLS_DHE_PSK_WITH_NULL_SHA384 :
				return "TLS_DHE_PSK_WITH_NULL_SHA384";
#ifdef HAVE_AESGCM
				case TLS_PSK_WITH_AES_256_GCM_SHA384 :
				return "TLS_PSK_WITH_AES_256_GCM_SHA384";
				case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 :
				return "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384";
#endif
#endif
#ifndef NO_SHA
				case TLS_PSK_WITH_NULL_SHA :
				return "TLS_PSK_WITH_NULL_SHA";
#endif
#endif /* NO_PSK */

#ifndef NO_RSA
				case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 :
				return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
				case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 :
				return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
#ifndef NO_SHA
				case TLS_DHE_RSA_WITH_AES_128_CBC_SHA :
				return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
				case TLS_DHE_RSA_WITH_AES_256_CBC_SHA :
				return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
#endif
#ifndef NO_HC128
#ifndef NO_MD5
				case TLS_RSA_WITH_HC_128_MD5 :
				return "TLS_RSA_WITH_HC_128_MD5";
#endif
#ifndef NO_SHA
				case TLS_RSA_WITH_HC_128_SHA :
				return "TLS_RSA_WITH_HC_128_SHA";
#endif
#ifdef HAVE_BLAKE2
				case TLS_RSA_WITH_HC_128_B2B256:
				return "TLS_RSA_WITH_HC_128_B2B256";
#endif
#endif /* NO_HC128 */
#ifndef NO_SHA
#ifndef NO_RABBIT
				case TLS_RSA_WITH_RABBIT_SHA :
				return "TLS_RSA_WITH_RABBIT_SHA";
#endif
#ifdef HAVE_NTRU
#ifndef NO_RC4
				case TLS_NTRU_RSA_WITH_RC4_128_SHA :
				return "TLS_NTRU_RSA_WITH_RC4_128_SHA";
#endif
#ifndef NO_DES3
				case TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA :
				return "TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA";
#endif
				case TLS_NTRU_RSA_WITH_AES_128_CBC_SHA :
				return "TLS_NTRU_RSA_WITH_AES_128_CBC_SHA";
				case TLS_NTRU_RSA_WITH_AES_256_CBC_SHA :
				return "TLS_NTRU_RSA_WITH_AES_256_CBC_SHA";
#endif /* HAVE_NTRU */
#endif /* NO_SHA */
				case TLS_RSA_WITH_AES_128_GCM_SHA256 :
				return "TLS_RSA_WITH_AES_128_GCM_SHA256";
				case TLS_RSA_WITH_AES_256_GCM_SHA384 :
				return "TLS_RSA_WITH_AES_256_GCM_SHA384";
				case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 :
				return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
				case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 :
				return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
#ifndef NO_SHA
				case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA :
				return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA";
				case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA :
				return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA";
#endif
				case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 :
				return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256";
				case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 :
				return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256";
#ifndef NO_SHA
				case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA :
				return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA";
				case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA :
				return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA";
#endif
				case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 :
				return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
				case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 :
				return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256";
#endif /* NO_RSA */
#ifdef BUILD_TLS_DH_anon_WITH_AES_128_CBC_SHA
				case TLS_DH_anon_WITH_AES_128_CBC_SHA :
				return "TLS_DH_anon_WITH_AES_128_CBC_SHA";
#endif
				default:
				return "NONE";
				}  /* switch */
			}  /* normal / ECC */
	}
#endif /* NO_ERROR_STRINGS */

	return "NONE";
}


const char* wolfSSL_get_cipher(WOLFSSL* ssl)
{
	return wolfSSL_CIPHER_get_name(wolfSSL_get_current_cipher(ssl));
}


