
#ifndef BIGINT_HEADER
#define BIGINT_HEADER

#include "crypto.h"

EXP_FUNC BI_CTX* STDCALL bi_initialize(void);
EXP_FUNC void STDCALL bi_terminate(BI_CTX *ctx);
void bi_permanent(bigint *bi);
void bi_depermanent(bigint *bi);
EXP_FUNC void STDCALL bi_clear_cache(BI_CTX *ctx);
EXP_FUNC void STDCALL bi_free(BI_CTX *ctx, bigint *bi);
EXP_FUNC bigint* STDCALL bi_copy(bigint *bi);
EXP_FUNC bigint * STDCALL bi_clone(BI_CTX *ctx, const bigint *bi);
EXP_FUNC void STDCALL bi_export(BI_CTX *ctx, bigint *bi, uint8_t *data, int size);
EXP_FUNC bigint * STDCALL bi_import(BI_CTX *ctx, const uint8_t *data, int len);
EXP_FUNC bigint* STDCALL int_to_bi(BI_CTX *ctx, comp i);

/* the functions that actually do something interesting */
bigint *bi_add(BI_CTX *ctx, bigint *bia, bigint *bib);
bigint *bi_subtract(BI_CTX *ctx, bigint *bia, 
        bigint *bib, int *is_negative);
bigint *bi_divide(BI_CTX *ctx, bigint *bia, bigint *bim, int is_mod);
EXP_FUNC bigint* STDCALL bi_multiply(BI_CTX *ctx, bigint *bia, bigint *bib);
EXP_FUNC bigint* STDCALL bi_mod_power(BI_CTX *ctx, bigint *bi, bigint *biexp);
EXP_FUNC bigint * STDCALL bi_mod_power2(BI_CTX *ctx, bigint *bi, bigint *bim, bigint *biexp);
EXP_FUNC int STDCALL bi_compare(bigint *bia, bigint *bib);
EXP_FUNC void STDCALL bi_set_mod(BI_CTX *ctx, bigint *bim, int mod_offset);
EXP_FUNC void STDCALL bi_free_mod(BI_CTX *ctx, int mod_offset);

#ifdef CONFIG_SSL_FULL_MODE
EXP_FUNC void STDCALL bi_print(const char *label, bigint *bi);
EXP_FUNC bigint* STDCALL bi_str_import(BI_CTX *ctx, const char *data);
#endif

/**
 * @def bi_mod
 * Find the residue of B. bi_set_mod() must be called before hand.
 */
#define bi_mod(A, B)      bi_divide(A, B, ctx->bi_mod[ctx->mod_offset], 1)

/**
 * bi_residue() is technically the same as bi_mod(), but it uses the
 * appropriate reduction technique (which is bi_mod() when doing classical
 * reduction).
 */
#if defined(CONFIG_BIGINT_MONTGOMERY)
#define bi_residue(A, B)         bi_mont(A, B)
bigint *bi_mont(BI_CTX *ctx, bigint *bixy);
#elif defined(CONFIG_BIGINT_BARRETT)
#define bi_residue(A, B)         bi_barrett(A, B)
bigint *bi_barrett(BI_CTX *ctx, bigint *bi);
#else /* if defined(CONFIG_BIGINT_CLASSICAL) */
#define bi_residue(A, B)         bi_mod(A, B)
#endif

#ifdef CONFIG_BIGINT_SQUARE
EXP_FUNC bigint* STDCALL bi_square(BI_CTX *ctx, bigint *bi);
#else
#define bi_square(A, B)     bi_multiply(A, bi_copy(B), B)
#endif

#ifdef CONFIG_BIGINT_CRT
bigint *bi_crt(BI_CTX *ctx, bigint *bi,
        bigint *dP, bigint *dQ,
        bigint *p, bigint *q,
        bigint *qInv);
#endif

#endif
