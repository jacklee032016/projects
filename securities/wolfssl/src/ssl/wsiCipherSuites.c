

#include "cmnSsl.h"

/* be sure to add to cipher_name_idx too !!!! */
static const char* const cipher_names[] =
{
#ifdef BUILD_SSL_RSA_WITH_RC4_128_SHA
    "RC4-SHA",
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    "RC4-MD5",
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    "DES-CBC3-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    "AES128-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
    "AES256-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA
    "NULL-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA256
    "NULL-SHA256",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    "DHE-RSA-AES128-SHA",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    "DHE-RSA-AES256-SHA",
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
    "DHE-PSK-AES256-GCM-SHA384",
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
    "DHE-PSK-AES128-GCM-SHA256",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_GCM_SHA384
    "PSK-AES256-GCM-SHA384",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_GCM_SHA256
    "PSK-AES128-GCM-SHA256",
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
    "DHE-PSK-AES256-CBC-SHA384",
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
    "DHE-PSK-AES128-CBC-SHA256",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA384
    "PSK-AES256-CBC-SHA384",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA256
    "PSK-AES128-CBC-SHA256",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
    "PSK-AES128-CBC-SHA",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
    "PSK-AES256-CBC-SHA",
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CCM
    "DHE-PSK-AES128-CCM",
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CCM
    "DHE-PSK-AES256-CCM",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM
    "PSK-AES128-CCM",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM
    "PSK-AES256-CCM",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM_8
    "PSK-AES128-CCM-8",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM_8
    "PSK-AES256-CCM-8",
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA384
    "DHE-PSK-NULL-SHA384",
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA256
    "DHE-PSK-NULL-SHA256",
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA384
    "PSK-NULL-SHA384",
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA256
    "PSK-NULL-SHA256",
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA
    "PSK-NULL-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_MD5
    "HC128-MD5",
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_SHA
    "HC128-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_B2B256
    "HC128-B2B256",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_B2B256
    "AES128-B2B256",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_B2B256
    "AES256-B2B256",
#endif

#ifdef BUILD_TLS_RSA_WITH_RABBIT_SHA
    "RABBIT-SHA",
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_RC4_128_SHA
    "NTRU-RC4-SHA",
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA
    "NTRU-DES-CBC3-SHA",
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_AES_128_CBC_SHA
    "NTRU-AES128-SHA",
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_AES_256_CBC_SHA
    "NTRU-AES256-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CCM_8
    "AES128-CCM-8",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CCM_8
    "AES256-CCM-8",
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
    "ECDHE-ECDSA-AES128-CCM-8",
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    "ECDHE-ECDSA-AES256-CCM-8",
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    "ECDHE-RSA-AES128-SHA",
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    "ECDHE-RSA-AES256-SHA",
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    "ECDHE-ECDSA-AES128-SHA",
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    "ECDHE-ECDSA-AES256-SHA",
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_RC4_128_SHA
    "ECDHE-RSA-RC4-SHA",
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    "ECDHE-RSA-DES-CBC3-SHA",
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    "ECDHE-ECDSA-RC4-SHA",
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    "ECDHE-ECDSA-DES-CBC3-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA256
    "AES128-SHA256",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA256
    "AES256-SHA256",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    "DHE-RSA-AES128-SHA256",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    "DHE-RSA-AES256-SHA256",
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    "ECDH-RSA-AES128-SHA",
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    "ECDH-RSA-AES256-SHA",
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    "ECDH-ECDSA-AES128-SHA",
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    "ECDH-ECDSA-AES256-SHA",
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_RC4_128_SHA
    "ECDH-RSA-RC4-SHA",
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    "ECDH-RSA-DES-CBC3-SHA",
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    "ECDH-ECDSA-RC4-SHA",
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    "ECDH-ECDSA-DES-CBC3-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256
    "AES128-GCM-SHA256",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_GCM_SHA384
    "AES256-GCM-SHA384",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    "DHE-RSA-AES128-GCM-SHA256",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    "DHE-RSA-AES256-GCM-SHA384",
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    "ECDHE-RSA-AES128-GCM-SHA256",
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    "ECDHE-RSA-AES256-GCM-SHA384",
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    "ECDHE-ECDSA-AES128-GCM-SHA256",
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    "ECDHE-ECDSA-AES256-GCM-SHA384",
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    "ECDH-RSA-AES128-GCM-SHA256",
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    "ECDH-RSA-AES256-GCM-SHA384",
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    "ECDH-ECDSA-AES128-GCM-SHA256",
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    "ECDH-ECDSA-AES256-GCM-SHA384",
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    "CAMELLIA128-SHA",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    "DHE-RSA-CAMELLIA128-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    "CAMELLIA256-SHA",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
    "DHE-RSA-CAMELLIA256-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
    "CAMELLIA128-SHA256",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
    "DHE-RSA-CAMELLIA128-SHA256",
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
    "CAMELLIA256-SHA256",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
    "DHE-RSA-CAMELLIA256-SHA256",
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    "ECDHE-RSA-AES128-SHA256",
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    "ECDHE-ECDSA-AES128-SHA256",
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    "ECDH-RSA-AES128-SHA256",
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    "ECDH-ECDSA-AES128-SHA256",
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    "ECDHE-RSA-AES256-SHA384",
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    "ECDHE-ECDSA-AES256-SHA384",
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    "ECDH-RSA-AES256-SHA384",
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    "ECDH-ECDSA-AES256-SHA384",
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    "ECDHE-RSA-CHACHA20-POLY1305",
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    "ECDHE-ECDSA-CHACHA20-POLY1305",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    "DHE-RSA-CHACHA20-POLY1305",
#endif

#ifdef BUILD_TLS_DH_anon_WITH_AES_128_CBC_SHA
    "ADH-AES128-SHA",
#endif

#ifdef HAVE_RENEGOTIATION_INDICATION
    "RENEGOTIATION-INFO",
#endif
};



/* cipher suite number that matches above name table */
static int cipher_name_idx[] =
{

#ifdef BUILD_SSL_RSA_WITH_RC4_128_SHA
    SSL_RSA_WITH_RC4_128_SHA,
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    SSL_RSA_WITH_RC4_128_MD5,
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_AES_128_CBC_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
    TLS_RSA_WITH_AES_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA
    TLS_RSA_WITH_NULL_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA256
    TLS_RSA_WITH_NULL_SHA256,
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_GCM_SHA384
    TLS_PSK_WITH_AES_256_GCM_SHA384,
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_GCM_SHA256
    TLS_PSK_WITH_AES_128_GCM_SHA256,
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA384
    TLS_PSK_WITH_AES_256_CBC_SHA384,
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA256
    TLS_PSK_WITH_AES_128_CBC_SHA256,
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
    TLS_PSK_WITH_AES_128_CBC_SHA,
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
    TLS_PSK_WITH_AES_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CCM
    TLS_DHE_PSK_WITH_AES_128_CCM,
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CCM
    TLS_DHE_PSK_WITH_AES_256_CCM,
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM
    TLS_PSK_WITH_AES_128_CCM,
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM
    TLS_PSK_WITH_AES_256_CCM,
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM_8
    TLS_PSK_WITH_AES_128_CCM_8,
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM_8
    TLS_PSK_WITH_AES_256_CCM_8,
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA384
    TLS_DHE_PSK_WITH_NULL_SHA384,
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA256
    TLS_DHE_PSK_WITH_NULL_SHA256,
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA384
    TLS_PSK_WITH_NULL_SHA384,
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA256
    TLS_PSK_WITH_NULL_SHA256,
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA
    TLS_PSK_WITH_NULL_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_MD5
    TLS_RSA_WITH_HC_128_MD5,
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_SHA
    TLS_RSA_WITH_HC_128_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_B2B256
    TLS_RSA_WITH_HC_128_B2B256,
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_B2B256
    TLS_RSA_WITH_AES_128_CBC_B2B256,
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_B2B256
    TLS_RSA_WITH_AES_256_CBC_B2B256,
#endif

#ifdef BUILD_TLS_RSA_WITH_RABBIT_SHA
    TLS_RSA_WITH_RABBIT_SHA,
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_RC4_128_SHA
    TLS_NTRU_RSA_WITH_RC4_128_SHA,
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA
    TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA,
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_AES_128_CBC_SHA
    TLS_NTRU_RSA_WITH_AES_128_CBC_SHA,
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_AES_256_CBC_SHA
    TLS_NTRU_RSA_WITH_AES_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CCM_8
    TLS_RSA_WITH_AES_128_CCM_8,
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CCM_8
    TLS_RSA_WITH_AES_256_CCM_8,
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_RC4_128_SHA
    TLS_ECDHE_RSA_WITH_RC4_128_SHA,
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA256
    TLS_RSA_WITH_AES_128_CBC_SHA256,
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA256
    TLS_RSA_WITH_AES_256_CBC_SHA256,
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_RC4_128_SHA
    TLS_ECDH_RSA_WITH_RC4_128_SHA,
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256
    TLS_RSA_WITH_AES_128_GCM_SHA256,
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_GCM_SHA384
    TLS_RSA_WITH_AES_256_GCM_SHA384,
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
#endif

#ifdef BUILD_TLS_DH_anon_WITH_AES_128_CBC_SHA
    TLS_DH_anon_WITH_AES_128_CBC_SHA,
#endif

#ifdef HAVE_RENEGOTIATION_INDICATION
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
#endif
};
/* returns the cipher_names array */
const char* const* GetCipherNames(void)
{
    return cipher_names;
}


/* returns the size of the cipher_names array */
int GetCipherNamesSize(void)
{
    return (int)(sizeof(cipher_names) / sizeof(char*));
}



static void __initSuitesHashSigAlgo(Suites* suites, int haveECDSAsig,int haveRSAsig, int haveAnon)
{
	int idx = 0;

	if (haveECDSAsig) {
#ifdef WOLFSSL_SHA512
		suites->hashSigAlgo[idx++] = sha512_mac;	/* H MAC algorithm */
		suites->hashSigAlgo[idx++] = ecc_dsa_sa_algo;	/* cipher, signature */
#endif
#ifdef WOLFSSL_SHA384
		suites->hashSigAlgo[idx++] = sha384_mac;
		suites->hashSigAlgo[idx++] = ecc_dsa_sa_algo;
#endif
#ifndef NO_SHA256
		suites->hashSigAlgo[idx++] = sha256_mac;
		suites->hashSigAlgo[idx++] = ecc_dsa_sa_algo;
#endif
#ifndef NO_SHA
		suites->hashSigAlgo[idx++] = sha_mac;
		suites->hashSigAlgo[idx++] = ecc_dsa_sa_algo;
#endif
	}

	if (haveRSAsig) {
#ifdef WOLFSSL_SHA512
		suites->hashSigAlgo[idx++] = sha512_mac;
		suites->hashSigAlgo[idx++] = rsa_sa_algo;
#endif
#ifdef WOLFSSL_SHA384
		suites->hashSigAlgo[idx++] = sha384_mac;
		suites->hashSigAlgo[idx++] = rsa_sa_algo;
#endif
#ifndef NO_SHA256
		suites->hashSigAlgo[idx++] = sha256_mac;
		suites->hashSigAlgo[idx++] = rsa_sa_algo;
#endif
#ifndef NO_SHA
		suites->hashSigAlgo[idx++] = sha_mac;
		suites->hashSigAlgo[idx++] = rsa_sa_algo;
#endif
	}

	if (haveAnon) {
#ifdef HAVE_ANON
		suites->hashSigAlgo[idx++] = sha_mac;
		suites->hashSigAlgo[idx++] = anonymous_sa_algo;
#endif
	}

	suites->hashSigAlgoSz = (word16)idx;
	}


/**
Set the enabled cipher suites.
@param [out] suites Suites structure.
@param [in]  list   List of cipher suites, only supports full name from cipher_name[] delimited by ':'.
@return true on success, else false.
*/
int _setCipherList(Suites* suites, const char* list)
{
	int       ret          = 0;
	int       idx          = 0;
	int       haveRSAsig   = 0;
	int       haveECDSAsig = 0;
	int       haveAnon     = 0;
	const int suiteSz      = GetCipherNamesSize();
	char*     next         = (char*)list;

	if (suites == NULL || list == NULL) {
		WOLFSSL_MSG("SetCipherList parameter error");
		return 0;
	}

	if (next[0] == 0 || XSTRNCMP(next, "ALL", 3) == 0)
		return 1; /* wolfSSL defualt */

	do
	{
		char*  current = next;
		char   name[MAX_SUITE_NAME + 1];
		int    i;
		word32 length;

		next   = XSTRSTR(next, ":");
		length = min(sizeof(name), !next ? (word32)XSTRLEN(current) /* last */
		             : (word32)(next - current));

		XSTRNCPY(name, current, length);
		name[(length == sizeof(name)) ? length - 1 : length] = 0;

		for (i = 0; i < suiteSz; i++)
		{
			if (XSTRNCMP(name, cipher_names[i], sizeof(name)) == 0)
			{
				suites->suites[idx++] = (XSTRSTR(name, "CHACHA")) ? CHACHA_BYTE
				          : (XSTRSTR(name, "EC"))     ? ECC_BYTE
				          : (XSTRSTR(name, "CCM"))    ? ECC_BYTE
				          : 0x00; /* normal */

				suites->suites[idx++] = (byte)cipher_name_idx[i];

				/* The suites are either ECDSA, RSA, PSK, or Anon. The RSA
				* suites don't necessarily have RSA in the name. */
				if ((haveECDSAsig == 0) && XSTRSTR(name, "ECDSA"))
					haveECDSAsig = 1;
				else if (XSTRSTR(name, "ADH"))
					haveAnon = 1;
				else if ((haveRSAsig == 0) && (XSTRSTR(name, "PSK") == NULL))
					haveRSAsig = 1;

				ret = 1; /* found at least one */
				break;
			}
		}
	}
	while (next++); /* ++ needed to skip ':' */

	if (ret) {
		suites->setSuites = 1;
		suites->suiteSz   = (word16)idx;
		__initSuitesHashSigAlgo(suites, haveECDSAsig, haveRSAsig, haveAnon);
	}

	return ret;
}

int wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list)
{
	/* alloc/init on demand only */
	if (ctx->suites == NULL)
	{
		ctx->suites = (Suites*)XMALLOC(sizeof(Suites), ctx->heap, DYNAMIC_TYPE_SUITES);
		if (ctx->suites == NULL) {
			WOLFSSL_MSG("Memory alloc for Suites failed");
			return SSL_FAILURE;
		}
		XMEMSET(ctx->suites, 0, sizeof(Suites));
	}

	return (_setCipherList(ctx->suites, list)) ? SSL_SUCCESS : SSL_FAILURE;
}


int wolfSSL_set_cipher_list(WOLFSSL* ssl, const char* list)
{
	return (_setCipherList(ssl->suites, list)) ? SSL_SUCCESS : SSL_FAILURE;
}



void InitSuites(Suites* suites, ProtocolVersion pv, word16 haveRSA,
                word16 havePSK, word16 haveDH, word16 haveNTRU,
                word16 haveECDSAsig, word16 haveStaticECC, int side)
{
    word16 idx = 0;
    int    tls    = pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_MINOR;
    int    tls1_2 = pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_2_MINOR;
    int    haveRSAsig = 1;

    (void)tls;  /* shut up compiler */
    (void)tls1_2;
    (void)haveDH;
    (void)havePSK;
    (void)haveNTRU;
    (void)haveStaticECC;

    if (suites == NULL) {
        WOLFSSL_MSG("InitSuites pointer error");
        return;
    }

    if (suites->setSuites)
        return;      /* trust user settings, don't override */

    if (side == WOLFSSL_SERVER_END && haveStaticECC) {
        haveRSA = 0;   /* can't do RSA with ECDSA key */
        (void)haveRSA; /* some builds won't read */
    }

    if (side == WOLFSSL_SERVER_END && haveECDSAsig) {
        haveRSAsig = 0;     /* can't have RSA sig if signed by ECDSA */
        (void)haveRSAsig;   /* non ecc builds won't read */
    }

#ifdef WOLFSSL_DTLS
    if (pv.major == DTLS_MAJOR) {
        tls    = 1;
        tls1_2 = pv.minor <= DTLSv1_2_MINOR;
    }
#endif

#ifdef HAVE_RENEGOTIATION_INDICATION
    if (side == WOLFSSL_CLIENT_END) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_EMPTY_RENEGOTIATION_INFO_SCSV;
    }
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveNTRU && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_NTRU_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveNTRU && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_NTRU_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_RC4_128_SHA
    if (tls && haveNTRU && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_NTRU_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveNTRU && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_GCM_SHA384
    if (tls1_2 && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_GCM_SHA256
    if (tls1_2 && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveRSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveRSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    if (tls && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    if (tls && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    if (tls && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    if (tls && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    if (tls && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    if (tls && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_RC4_128_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_RC4_128_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CCM_8
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CCM_8;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CCM_8
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CCM_8;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    if (tls1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_NULL_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_NULL_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA384
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA256
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CCM
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_128_CCM;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CCM
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_256_CCM;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CCM;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CCM;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM_8
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CCM_8;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM_8
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CCM_8;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA384
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_NULL_SHA384;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA384
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_NULL_SHA384;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA256
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_NULL_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA256
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_NULL_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_NULL_SHA;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_SHA
    if (haveRSA ) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = SSL_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    if (haveRSA ) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = SSL_RSA_WITH_RC4_128_MD5;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    if (haveRSA ) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = SSL_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_MD5
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_MD5;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_B2B256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_B2B256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_B2B256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CBC_B2B256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_B2B256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CBC_B2B256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_RABBIT_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_RABBIT_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_WITH_RSA_CAMELLIA_256_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256;
    }
#endif

    suites->suiteSz = idx;

    __initSuitesHashSigAlgo(suites, haveECDSAsig, haveRSAsig, 0);
}



#ifdef WOLFSSL_CALLBACKS

/* Initialisze HandShakeInfo */
void InitHandShakeInfo(HandShakeInfo* info)
{
	int i;

	info->cipherName[0] = 0;
	for (i = 0; i < MAX_PACKETS_HANDSHAKE; i++)
		info->packetNames[i][0] = 0;
	info->numberPackets = 0;
	info->negotiationError = 0;
}

/* Set Final HandShakeInfo parameters */
void FinishHandShakeInfo(HandShakeInfo* info, const WOLFSSL* ssl)
{
	int i;
	int sz = sizeof(cipher_name_idx)/sizeof(int);

	for (i = 0; i < sz; i++)
	{
		if (ssl->options.cipherSuite == (byte)cipher_name_idx[i])
		{
			if (ssl->options.cipherSuite0 == ECC_BYTE)
				continue;   /* ECC suites at end */
			XSTRNCPY(info->cipherName, cipher_names[i], MAX_CIPHERNAME_SZ);
			break;
		}
	}
	
	/* error max and min are negative numbers */
	if (ssl->error <= MIN_PARAM_ERR && ssl->error >= MAX_PARAM_ERR)
		info->negotiationError = ssl->error;
}


/* Add name to info packet names, increase packet name count */
void AddPacketName(const char* name, HandShakeInfo* info)
{
	if (info->numberPackets < MAX_PACKETS_HANDSHAKE)
	{
		XSTRNCPY(info->packetNames[info->numberPackets++], name, MAX_PACKETNAME_SZ);
	}
}


/* Initialisze TimeoutInfo */
void InitTimeoutInfo(TimeoutInfo* info)
{
	int i;

	info->timeoutName[0] = 0;
	info->flags          = 0;

	for (i = 0; i < MAX_PACKETS_HANDSHAKE; i++) {
		info->packets[i].packetName[0]     = 0;
		info->packets[i].timestamp.tv_sec  = 0;
		info->packets[i].timestamp.tv_usec = 0;
		info->packets[i].bufferValue       = 0;
		info->packets[i].valueSz           = 0;
	}
	info->numberPackets        = 0;
	info->timeoutValue.tv_sec  = 0;
	info->timeoutValue.tv_usec = 0;
}


/* Free TimeoutInfo */
void FreeTimeoutInfo(TimeoutInfo* info, void* heap)
{
	int i;
	(void)heap;
	for (i = 0; i < MAX_PACKETS_HANDSHAKE; i++)
	{
		if (info->packets[i].bufferValue) {
			XFREE(info->packets[i].bufferValue, heap, DYNAMIC_TYPE_INFO);
			info->packets[i].bufferValue = 0;
		}
	}
}


/* Add PacketInfo to TimeoutInfo */
void AddPacketInfo(const char* name, TimeoutInfo* info, const byte* data, int sz, void* heap)
{
	if (info->numberPackets < (MAX_PACKETS_HANDSHAKE - 1))
	{
		Timeval currTime;

		/* may add name after */
		if (name)
			XSTRNCPY(info->packets[info->numberPackets].packetName, name,	MAX_PACKETNAME_SZ);

		/* add data, put in buffer if bigger than static buffer */
		info->packets[info->numberPackets].valueSz = sz;
		if (sz < MAX_VALUE_SZ)
			XMEMCPY(info->packets[info->numberPackets].value, data, sz);
		else
		{
			info->packets[info->numberPackets].bufferValue = XMALLOC(sz, heap, DYNAMIC_TYPE_INFO);
			if (!info->packets[info->numberPackets].bufferValue)
				/* let next alloc catch, just don't fill, not fatal here  */
				info->packets[info->numberPackets].valueSz = 0;
			else
				XMEMCPY(info->packets[info->numberPackets].bufferValue, data, sz);
		}
		gettimeofday(&currTime, 0);
		info->packets[info->numberPackets].timestamp.tv_sec  = currTime.tv_sec;
		info->packets[info->numberPackets].timestamp.tv_usec = currTime.tv_usec;
		info->numberPackets++;
	}
}


/* Add packet name to previsouly added packet info */
void AddLateName(const char* name, TimeoutInfo* info)
{
	/* make sure we have a valid previous one */
	if (info->numberPackets > 0 && info->numberPackets < MAX_PACKETS_HANDSHAKE)
	{
		XSTRNCPY(info->packets[info->numberPackets - 1].packetName, name, MAX_PACKETNAME_SZ);
	}
}

/* Add record header to previsouly added packet info */
void AddLateRecordHeader(const RecordLayerHeader* rl, TimeoutInfo* info)
{
	/* make sure we have a valid previous one */
	if (info->numberPackets > 0 && info->numberPackets < MAX_PACKETS_HANDSHAKE)
	{
		if (info->packets[info->numberPackets - 1].bufferValue)
			XMEMCPY(info->packets[info->numberPackets - 1].bufferValue, rl, RECORD_HEADER_SZ);
		else
			XMEMCPY(info->packets[info->numberPackets - 1].value, rl, RECORD_HEADER_SZ);
	}
}

#endif /* WOLFSSL_CALLBACKS */



