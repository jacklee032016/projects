/* hash.h
 *
 */

#ifndef __WCH_HASH_H__
#define __WCH_HASH_H__

#ifndef NO_MD5
#include <wchMd5.h>
WOLFSSL_API void wc_Md5GetHash(Md5*, byte*);
WOLFSSL_API void wc_Md5RestorePos(Md5*, Md5*) ;
#endif

#ifndef NO_SHA
#include <wchSha.h>
WOLFSSL_API int wc_ShaGetHash(Sha*, byte*);
WOLFSSL_API void wc_ShaRestorePos(Sha*, Sha*) ;
#endif

#ifndef NO_SHA256
#include <wchSha256.h>
WOLFSSL_API int wc_Sha256GetHash(Sha256*, byte*);
WOLFSSL_API void wc_Sha256RestorePos(Sha256*, Sha256*) ;
#endif

#endif

