/**
 * An implementation of the RC4/ARC4 algorithm.
 */

#include "crypto.h"

/**
 * Get ready for an encrypt/decrypt operation
 */
EXP_FUNC void STDCALL RC4_setup(RC4_CTX *ctx, const uint8_t *key, int length)
{
    int i, j = 0, k = 0, a;
    uint8_t *m;

    ctx->x = 0;
    ctx->y = 0;
    m = ctx->m;

    for (i = 0; i < 256; i++)
        m[i] = i;

    for (i = 0; i < 256; i++)
    {
        a = m[i];
        j = (uint8_t)(j + a + key[k]);
        m[i] = m[j]; 
        m[j] = a;

        if (++k >= length) 
            k = 0;
    }
}

/**
 * Perform the encrypt/decrypt operation (can use it for either since this is a stream cipher).
 * NOTE: *msg and *out must be the same pointer (performance tweak)
 */
EXP_FUNC void STDCALL RC4_crypt(RC4_CTX *ctx, const uint8_t *msg, uint8_t *out, int length)
{ 
    int i;
    uint8_t *m, x, y, a, b;

    x = ctx->x;
    y = ctx->y;
    m = ctx->m;

    for (i = 0; i < length; i++)
    {
        a = m[++x];
        y += a;
        m[x] = b = m[y];
        m[y] = a;
        out[i] ^= m[(uint8_t)(a + b)];
    }

    ctx->x = x;
    ctx->y = y;
}

