
#include "mbedtls/entropy.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/dhm.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ccm.h"
#include "mbedtls/md2.h"
#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/arc4.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/camellia.h"
#include "mbedtls/base64.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"
#include "mbedtls/xtea.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/ecp.h"
#include "mbedtls/timing.h"

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif


int mbedtls_mpi_self_test( int verbose );
int mbedtls_base64_self_test( int verbose );
int mbedtls_timing_self_test( int verbose );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
int mbedtls_memory_buffer_alloc_self_test( int verbose );
#endif

int mbedtls_entropy_self_test( int verbose );
int mbedtls_ctr_drbg_self_test( int verbose );
int mbedtls_hmac_drbg_self_test( int verbose );


int mbedtls_md2_self_test( int verbose );
int mbedtls_md4_self_test( int verbose );
int mbedtls_md5_self_test( int verbose );
int mbedtls_ripemd160_self_test( int verbose );
int mbedtls_sha1_self_test( int verbose );
int mbedtls_sha256_self_test( int verbose );
int mbedtls_sha512_self_test( int verbose );

int mbedtls_arc4_self_test( int verbose );

int mbedtls_des_self_test( int verbose );
int mbedtls_aes_self_test( int verbose );
int mbedtls_camellia_self_test( int verbose );
int mbedtls_xtea_self_test( int verbose );

int mbedtls_gcm_self_test( int verbose );


int mbedtls_dhm_self_test( int verbose );
int mbedtls_rsa_self_test( int verbose );

int mbedtls_pkcs5_self_test( int verbose );
int mbedtls_x509_self_test( int verbose );


#ifdef __cplusplus
}
#endif


