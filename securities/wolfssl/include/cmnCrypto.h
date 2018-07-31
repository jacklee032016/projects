/*
* Commnd Header for crypto library
*/

#ifndef	__CMN_CRYPTO_H__
#define	__CMN_CRYPTO_H__

#include "cmnWcc.h"

#include <wchMd2.h>
#include <wchMd4.h>
#ifndef NO_MD5
#include <wchMd5.h>
#endif

#include <wchRipemd.h>
#include <wchHash.h>

#ifndef NO_SHA
#include <wchSha.h>
#endif
#ifndef NO_SHA256
#include <wchSha256.h>
#endif
#ifdef WOLFSSL_SHA512
#include <wchSha512.h>
#endif
#ifdef HAVE_BLAKE2
#include <wchBlake2.h>
#endif

#include <wcmHmac.h>
#include <wcmPoly1305.h>

#ifdef HAVE_FIPS
/* for fips */
    #include <cyassl/ctaocrypt/hmac.h>
#endif

#ifdef HAVE_CAVIUM
    #include "cavium_common.h"
#endif

#include <wcbAes.h>
#include <wcbDes3.h>
#include <wcbCamellia.h>

#include <wcsArc4.h>
#include <wcsChacha.h>
#include <wcsChacha20_poly1305.h>
#include <wcsHc128.h>
#include <wcsRabbit.h>

#include <wckDh.h>
#include <wckDsa.h>
#include <wckRsa.h>
#include <wckEcc.h>

#include <certPublic.h>
#include <certAsn.h>
#include <certPkcs7.h>

#ifdef CHACHA_AEAD_TEST
#include <stdio.h>
#endif


#ifndef WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MIN

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* WOLFSSL_HAVE_MIN */

#endif

