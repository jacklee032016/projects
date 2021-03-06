/* poly1305.h
 * A MAC algoritm
 */

#ifndef __WCM_POLY1305_H__
#define __WCM_POLY1305_H__

#include <wccTypes.h>

#ifdef HAVE_POLY1305

#ifdef __cplusplus
    extern "C" {
#endif

/* auto detect between 32bit / 64bit */
#define HAS_SIZEOF_INT128_64BIT (defined(__SIZEOF_INT128__) && defined(__LP64__))
#define HAS_MSVC_64BIT (defined(_MSC_VER) && defined(_M_X64))
#define HAS_GCC_4_4_64BIT (defined(__GNUC__) && defined(__LP64__) && \
        ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4))))

#if (HAS_SIZEOF_INT128_64BIT || HAS_MSVC_64BIT || HAS_GCC_4_4_64BIT)
#define POLY130564
#else
#define POLY130532
#endif

enum {
    POLY1305 = 7,
    POLY1305_BLOCK_SIZE = 16,
    POLY1305_DIGEST_SIZE = 16,
    POLY1305_PAD_SIZE = 56
};

/* Poly1305 state */
typedef struct Poly1305 {
#if defined(POLY130564)
	word64 r[3];
	word64 h[3];
	word64 pad[2];
#else
	word32 r[5];
	word32 h[5];
	word32 pad[4];
#endif
	size_t leftover;
	unsigned char buffer[POLY1305_BLOCK_SIZE];
	unsigned char final;
} Poly1305;


/* does init */

WOLFSSL_API int wc_Poly1305SetKey(Poly1305* poly1305, const byte* key, word32 kySz);
WOLFSSL_API int wc_Poly1305Update(Poly1305* poly1305, const byte*, word32);
WOLFSSL_API int wc_Poly1305Final(Poly1305* poly1305, byte* tag);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_POLY1305 */
#endif /* WOLF_CRYPT_POLY1305_H */

