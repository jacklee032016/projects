
#include "cmnSsl.h"


#ifdef OPENSSL_EXTRA

#ifdef FORTRESS
int wolfSSL_cmp_peer_cert_to_file(WOLFSSL* ssl, const char *fname)
{
    int ret = SSL_FATAL_ERROR;

	WOLFSSL_ENTER();
    if (ssl != NULL && fname != NULL)
    {
    #ifdef WOLFSSL_SMALL_STACK
        EncryptedInfo* info = NULL;
        byte           staticBuffer[1]; /* force heap usage */
    #else
        EncryptedInfo  info[1];
        byte           staticBuffer[FILE_BUFFER_SIZE];
    #endif
        byte*          myBuffer  = staticBuffer;
        int            dynamic   = 0;
        XFILE          file      = XBADFILE;
        long           sz        = 0;
        int            eccKey    = 0;
        WOLFSSL_CTX*    ctx       = ssl->ctx;
        WOLFSSL_X509*   peer_cert = &ssl->peerCert;
        buffer         fileDer;

        file = XFOPEN(fname, "rb");
        if (file == XBADFILE)
            return SSL_BAD_FILE;

        XFSEEK(file, 0, XSEEK_END);
        sz = XFTELL(file);
        XREWIND(file);

        if (sz > (long)sizeof(staticBuffer)) {
            WOLFSSL_MSG("Getting dynamic buffer");
            myBuffer = (byte*)XMALLOC(sz, ctx->heap, DYNAMIC_TYPE_FILE);
            dynamic = 1;
        }

    #ifdef WOLFSSL_SMALL_STACK
        info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
                                                   DYNAMIC_TYPE_TMP_BUFFER);
        if (info == NULL)
            ret = MEMORY_E;
        else
    #endif
        {
            info->set = 0;
            info->ctx = ctx;
            info->consumed = 0;
            fileDer.buffer = 0;

            if ((myBuffer != NULL) &&
                (sz > 0) &&
                (XFREAD(myBuffer, sz, 1, file) > 0) &&
                (PemToDer(myBuffer, sz, CERT_TYPE,
                          &fileDer, ctx->heap, info, &eccKey) == 0) &&
                (fileDer.length != 0) &&
                (fileDer.length == peer_cert->derCert.length) &&
                (XMEMCMP(peer_cert->derCert.buffer, fileDer.buffer,
                                                    fileDer.length) == 0))
            {
                ret = 0;
            }

        #ifdef WOLFSSL_SMALL_STACK
            XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }

        XFREE(fileDer.buffer, ctx->heap, DYNAMIC_TYPE_CERT);
        if (dynamic)
            XFREE(myBuffer, ctx->heap, DYNAMIC_TYPE_FILE);

        XFCLOSE(file);
    }

    return ret;
}
#endif


static RNG globalRNG;
static int initGlobalRNG = 0;

/* SSL_SUCCESS on ok */
int wolfSSL_RAND_seed(const void* seed, int len)
{

    WOLFSSL_MSG("wolfSSL_RAND_seed");

    (void)seed;
    (void)len;

    if (initGlobalRNG == 0) {
        if (wc_InitRng(&globalRNG) < 0) {
            WOLFSSL_MSG("wolfSSL Init Global RNG failed");
            return 0;
        }
        initGlobalRNG = 1;
    }

    return SSL_SUCCESS;
}


/* SSL_SUCCESS on ok */
int wolfSSL_RAND_bytes(unsigned char* buf, int num)
{
    int    ret = 0;
    int    initTmpRng = 0;
    RNG*   rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
    RNG*   tmpRNG = NULL;
#else
    RNG    tmpRNG[1];
#endif

	WOLFSSL_ENTER();

#ifdef WOLFSSL_SMALL_STACK
    tmpRNG = (RNG*)XMALLOC(sizeof(RNG), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmpRNG == NULL)
        return ret;
#endif

    if (wc_InitRng(tmpRNG) == 0) {
        rng = tmpRNG;
        initTmpRng = 1;
    }
    else if (initGlobalRNG)
        rng = &globalRNG;

    if (rng) {
        if (wc_RNG_GenerateBlock(rng, buf, num) != 0)
            WOLFSSL_MSG("Bad wc_RNG_GenerateBlock");
        else
            ret = SSL_SUCCESS;
    }

    if (initTmpRng)
        wc_FreeRng(tmpRNG);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpRNG, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

WOLFSSL_BN_CTX* wolfSSL_BN_CTX_new(void)
{
    static int ctx;  /* wolfcrypt doesn't now need ctx */

    WOLFSSL_MSG("wolfSSL_BN_CTX_new");

    return (WOLFSSL_BN_CTX*)&ctx;
}

void wolfSSL_BN_CTX_init(WOLFSSL_BN_CTX* ctx)
{
    (void)ctx;
    WOLFSSL_MSG("wolfSSL_BN_CTX_init");
}


void wolfSSL_BN_CTX_free(WOLFSSL_BN_CTX* ctx)
{
    (void)ctx;
    WOLFSSL_MSG("wolfSSL_BN_CTX_free");

    /* do free since static ctx that does nothing */
}


static void InitwolfSSL_BigNum(WOLFSSL_BIGNUM* bn)
{
    WOLFSSL_MSG("InitwolfSSL_BigNum");
    if (bn) {
        bn->neg      = 0;
        bn->internal = NULL;
    }
}


WOLFSSL_BIGNUM* wolfSSL_BN_new(void)
{
    WOLFSSL_BIGNUM* external;
    mp_int*        mpi;

    WOLFSSL_MSG("wolfSSL_BN_new");

    mpi = (mp_int*) XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (mpi == NULL) {
        WOLFSSL_MSG("wolfSSL_BN_new malloc mpi failure");
        return NULL;
    }

    external = (WOLFSSL_BIGNUM*) XMALLOC(sizeof(WOLFSSL_BIGNUM), NULL,
                                        DYNAMIC_TYPE_BIGINT);
    if (external == NULL) {
        WOLFSSL_MSG("wolfSSL_BN_new malloc WOLFSSL_BIGNUM failure");
        XFREE(mpi, NULL, DYNAMIC_TYPE_BIGINT);
        return NULL;
    }

    InitwolfSSL_BigNum(external);
    external->internal = mpi;
    if (mp_init(mpi) != MP_OKAY) {
        wolfSSL_BN_free(external);
        return NULL;
    }

    return external;
}


void wolfSSL_BN_free(WOLFSSL_BIGNUM* bn)
{
    WOLFSSL_MSG("wolfSSL_BN_free");
    if (bn) {
        if (bn->internal) {
            mp_clear((mp_int*)bn->internal);
            XFREE(bn->internal, NULL, DYNAMIC_TYPE_BIGINT);
            bn->internal = NULL;
        }
        XFREE(bn, NULL, DYNAMIC_TYPE_BIGINT);
    }
}


void wolfSSL_BN_clear_free(WOLFSSL_BIGNUM* bn)
{
    WOLFSSL_MSG("wolfSSL_BN_clear_free");

    wolfSSL_BN_free(bn);
}


/* SSL_SUCCESS on ok */
int wolfSSL_BN_sub(WOLFSSL_BIGNUM* r, const WOLFSSL_BIGNUM* a,
                  const WOLFSSL_BIGNUM* b)
{
    WOLFSSL_MSG("wolfSSL_BN_sub");

    if (r == NULL || a == NULL || b == NULL)
        return 0;

    if (mp_sub((mp_int*)a->internal,(mp_int*)b->internal,
               (mp_int*)r->internal) == MP_OKAY)
        return SSL_SUCCESS;

    WOLFSSL_MSG("wolfSSL_BN_sub mp_sub failed");
    return 0;
}


/* SSL_SUCCESS on ok */
int wolfSSL_BN_mod(WOLFSSL_BIGNUM* r, const WOLFSSL_BIGNUM* a,
                  const WOLFSSL_BIGNUM* b, const WOLFSSL_BN_CTX* c)
{
    (void)c;
    WOLFSSL_MSG("wolfSSL_BN_mod");

    if (r == NULL || a == NULL || b == NULL)
        return 0;

    if (mp_mod((mp_int*)a->internal,(mp_int*)b->internal,
               (mp_int*)r->internal) == MP_OKAY)
        return SSL_SUCCESS;

    WOLFSSL_MSG("wolfSSL_BN_mod mp_mod failed");
    return 0;
}


const WOLFSSL_BIGNUM* wolfSSL_BN_value_one(void)
{
    static WOLFSSL_BIGNUM* bn_one = NULL;

    WOLFSSL_MSG("wolfSSL_BN_value_one");

    if (bn_one == NULL) {
        bn_one = wolfSSL_BN_new();
        if (bn_one)
            mp_set_int((mp_int*)bn_one->internal, 1);
    }

    return bn_one;
}


int wolfSSL_BN_num_bytes(const WOLFSSL_BIGNUM* bn)
{
    WOLFSSL_MSG("wolfSSL_BN_num_bytes");

    if (bn == NULL || bn->internal == NULL)
        return 0;

    return mp_unsigned_bin_size((mp_int*)bn->internal);
}


int wolfSSL_BN_num_bits(const WOLFSSL_BIGNUM* bn)
{
    WOLFSSL_MSG("wolfSSL_BN_num_bits");

    if (bn == NULL || bn->internal == NULL)
        return 0;

    return mp_count_bits((mp_int*)bn->internal);
}


int wolfSSL_BN_is_zero(const WOLFSSL_BIGNUM* bn)
{
    WOLFSSL_MSG("wolfSSL_BN_is_zero");

    if (bn == NULL || bn->internal == NULL)
        return 0;

    return mp_iszero((mp_int*)bn->internal);
}


int wolfSSL_BN_is_one(const WOLFSSL_BIGNUM* bn)
{
    WOLFSSL_MSG("wolfSSL_BN_is_one");

    if (bn == NULL || bn->internal == NULL)
        return 0;

    if (mp_cmp_d((mp_int*)bn->internal, 1) == 0)
        return 1;

    return 0;
}


int wolfSSL_BN_is_odd(const WOLFSSL_BIGNUM* bn)
{
    WOLFSSL_MSG("wolfSSL_BN_is_odd");

    if (bn == NULL || bn->internal == NULL)
        return 0;

    return mp_isodd((mp_int*)bn->internal);
}


int wolfSSL_BN_cmp(const WOLFSSL_BIGNUM* a, const WOLFSSL_BIGNUM* b)
{
    WOLFSSL_MSG("wolfSSL_BN_cmp");

    if (a == NULL || a->internal == NULL || b == NULL || b->internal ==NULL)
        return 0;

    return mp_cmp((mp_int*)a->internal, (mp_int*)b->internal);
}


int wolfSSL_BN_bn2bin(const WOLFSSL_BIGNUM* bn, unsigned char* r)
{
    WOLFSSL_MSG("wolfSSL_BN_bn2bin");

    if (bn == NULL || bn->internal == NULL) {
        WOLFSSL_MSG("NULL bn error");
        return SSL_FATAL_ERROR;
    }

    if (r == NULL)
        return mp_unsigned_bin_size((mp_int*)bn->internal);

    if (mp_to_unsigned_bin((mp_int*)bn->internal, r) != MP_OKAY) {
        WOLFSSL_MSG("mp_to_unsigned_bin error");
        return SSL_FATAL_ERROR;
    }

    return mp_unsigned_bin_size((mp_int*)bn->internal);
}


WOLFSSL_BIGNUM* wolfSSL_BN_bin2bn(const unsigned char* str, int len,
                            WOLFSSL_BIGNUM* ret)
{
    WOLFSSL_MSG("wolfSSL_BN_bin2bn");

    if (ret && ret->internal) {
        if (mp_read_unsigned_bin((mp_int*)ret->internal, str, len) != 0) {
            WOLFSSL_MSG("mp_read_unsigned_bin failure");
            return NULL;
        }
    }
    else {
        WOLFSSL_MSG("wolfSSL_BN_bin2bn wants return bignum");
    }

    return ret;
}


int wolfSSL_mask_bits(WOLFSSL_BIGNUM* bn, int n)
{
    (void)bn;
    (void)n;
    WOLFSSL_MSG("wolfSSL_BN_mask_bits");

    return SSL_FATAL_ERROR;
}


/* SSL_SUCCESS on ok */
int wolfSSL_BN_rand(WOLFSSL_BIGNUM* bn, int bits, int top, int bottom)
{
    int           ret    = 0;
    int           len    = bits / 8;
    int           initTmpRng = 0;
    RNG*          rng    = NULL;
#ifdef WOLFSSL_SMALL_STACK
    RNG*          tmpRNG = NULL;
    byte*         buff   = NULL;
#else
    RNG           tmpRNG[1];
    byte          buff[1024];
#endif

    (void)top;
    (void)bottom;
    WOLFSSL_MSG("wolfSSL_BN_rand");

    if (bits % 8)
        len++;

#ifdef WOLFSSL_SMALL_STACK
    buff   = (byte*)XMALLOC(1024,        NULL, DYNAMIC_TYPE_TMP_BUFFER);
    tmpRNG = (RNG*) XMALLOC(sizeof(RNG), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buff == NULL || tmpRNG == NULL) {
        XFREE(buff,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
#endif

    if (bn == NULL || bn->internal == NULL)
        WOLFSSL_MSG("Bad function arguments");
    else if (wc_InitRng(tmpRNG) == 0) {
        rng = tmpRNG;
        initTmpRng = 1;
    }
    else if (initGlobalRNG)
        rng = &globalRNG;

    if (rng) {
        if (wc_RNG_GenerateBlock(rng, buff, len) != 0)
            WOLFSSL_MSG("Bad wc_RNG_GenerateBlock");
        else {
            buff[0]     |= 0x80 | 0x40;
            buff[len-1] |= 0x01;

            if (mp_read_unsigned_bin((mp_int*)bn->internal,buff,len) != MP_OKAY)
                WOLFSSL_MSG("mp read bin failed");
            else
                ret = SSL_SUCCESS;
        }
    }

    if (initTmpRng)
        wc_FreeRng(tmpRNG);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(buff,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(tmpRNG, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


int wolfSSL_BN_is_bit_set(const WOLFSSL_BIGNUM* bn, int n)
{
    (void)bn;
    (void)n;

    WOLFSSL_MSG("wolfSSL_BN_is_bit_set");

    return 0;
}


/* SSL_SUCCESS on ok */
int wolfSSL_BN_hex2bn(WOLFSSL_BIGNUM** bn, const char* str)
{
    int     ret     = 0;
    word32  decSz   = 1024;
#ifdef WOLFSSL_SMALL_STACK
    byte*   decoded = NULL;
#else
    byte    decoded[1024];
#endif

    WOLFSSL_MSG("wolfSSL_BN_hex2bn");

#ifdef WOLFSSL_SMALL_STACK
    decoded = (byte*)XMALLOC(decSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (decoded == NULL)
        return ret;
#endif

    if (str == NULL)
        WOLFSSL_MSG("Bad function argument");
    else if (Base16_Decode((byte*)str, (int)XSTRLEN(str), decoded, &decSz) < 0)
        WOLFSSL_MSG("Bad Base16_Decode error");
    else if (bn == NULL)
        ret = decSz;
    else {
        if (*bn == NULL)
            *bn = wolfSSL_BN_new();

        if (*bn == NULL)
            WOLFSSL_MSG("BN new failed");
        else if (wolfSSL_BN_bin2bn(decoded, decSz, *bn) == NULL)
            WOLFSSL_MSG("Bad bin2bn error");
        else
            ret = SSL_SUCCESS;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(decoded, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


WOLFSSL_BIGNUM* wolfSSL_BN_dup(const WOLFSSL_BIGNUM* bn)
{
    WOLFSSL_BIGNUM* ret;

    WOLFSSL_MSG("wolfSSL_BN_dup");

    if (bn == NULL || bn->internal == NULL) {
        WOLFSSL_MSG("bn NULL error");
        return NULL;
    }

    ret = wolfSSL_BN_new();
    if (ret == NULL) {
        WOLFSSL_MSG("bn new error");
        return NULL;
    }

    if (mp_copy((mp_int*)bn->internal, (mp_int*)ret->internal) != MP_OKAY) {
        WOLFSSL_MSG("mp_copy error");
        wolfSSL_BN_free(ret);
        return NULL;
    }

    return ret;
}


WOLFSSL_BIGNUM* wolfSSL_BN_copy(WOLFSSL_BIGNUM* r, const WOLFSSL_BIGNUM* bn)
{
    (void)r;
    (void)bn;

    WOLFSSL_MSG("wolfSSL_BN_copy");

    return NULL;
}


int wolfSSL_BN_set_word(WOLFSSL_BIGNUM* bn, unsigned long w)
{
    (void)bn;
    (void)w;

    WOLFSSL_MSG("wolfSSL_BN_set_word");

    return SSL_FATAL_ERROR;
}


int wolfSSL_BN_dec2bn(WOLFSSL_BIGNUM** bn, const char* str)
{
    (void)bn;
    (void)str;

    WOLFSSL_MSG("wolfSSL_BN_dec2bn");

    return SSL_FATAL_ERROR;
}


char* wolfSSL_BN_bn2dec(const WOLFSSL_BIGNUM* bn)
{
    (void)bn;

    WOLFSSL_MSG("wolfSSL_BN_bn2dec");

    return NULL;
}


#ifndef NO_DH

static void InitwolfSSL_DH(WOLFSSL_DH* dh)
{
    if (dh) {
        dh->p        = NULL;
        dh->g        = NULL;
        dh->pub_key  = NULL;
        dh->priv_key = NULL;
        dh->internal = NULL;
        dh->inSet    = 0;
        dh->exSet    = 0;
    }
}


WOLFSSL_DH* wolfSSL_DH_new(void)
{
    WOLFSSL_DH* external;
    DhKey*     key;

    WOLFSSL_MSG("wolfSSL_DH_new");

    key = (DhKey*) XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_DH);
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_DH_new malloc DhKey failure");
        return NULL;
    }

    external = (WOLFSSL_DH*) XMALLOC(sizeof(WOLFSSL_DH), NULL,
                                    DYNAMIC_TYPE_DH);
    if (external == NULL) {
        WOLFSSL_MSG("wolfSSL_DH_new malloc WOLFSSL_DH failure");
        XFREE(key, NULL, DYNAMIC_TYPE_DH);
        return NULL;
    }

    InitwolfSSL_DH(external);
    wc_InitDhKey(key);
    external->internal = key;

    return external;
}


void wolfSSL_DH_free(WOLFSSL_DH* dh)
{
    WOLFSSL_MSG("wolfSSL_DH_free");

    if (dh) {
        if (dh->internal) {
            wc_FreeDhKey((DhKey*)dh->internal);
            XFREE(dh->internal, NULL, DYNAMIC_TYPE_DH);
            dh->internal = NULL;
        }
        wolfSSL_BN_free(dh->priv_key);
        wolfSSL_BN_free(dh->pub_key);
        wolfSSL_BN_free(dh->g);
        wolfSSL_BN_free(dh->p);
        InitwolfSSL_DH(dh);  /* set back to NULLs for safety */

        XFREE(dh, NULL, DYNAMIC_TYPE_DH);
    }
}


static int SetDhInternal(WOLFSSL_DH* dh)
{
    int            ret = SSL_FATAL_ERROR;
    int            pSz = 1024;
    int            gSz = 1024;
#ifdef WOLFSSL_SMALL_STACK
    unsigned char* p   = NULL;
    unsigned char* g   = NULL;
#else
    unsigned char  p[1024];
    unsigned char  g[1024];
#endif

	WOLFSSL_ENTER();

    if (dh == NULL || dh->p == NULL || dh->g == NULL)
        WOLFSSL_MSG("Bad function arguments");
    else if (wolfSSL_BN_bn2bin(dh->p, NULL) > pSz)
        WOLFSSL_MSG("Bad p internal size");
    else if (wolfSSL_BN_bn2bin(dh->g, NULL) > gSz)
        WOLFSSL_MSG("Bad g internal size");
    else {
    #ifdef WOLFSSL_SMALL_STACK
        p = (unsigned char*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        g = (unsigned char*)XMALLOC(gSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        if (p == NULL || g == NULL) {
            XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
    #endif

        pSz = wolfSSL_BN_bn2bin(dh->p, p);
        gSz = wolfSSL_BN_bn2bin(dh->g, g);

        if (pSz <= 0 || gSz <= 0)
            WOLFSSL_MSG("Bad BN2bin set");
        else if (wc_DhSetKey((DhKey*)dh->internal, p, pSz, g, gSz) < 0)
            WOLFSSL_MSG("Bad DH SetKey");
        else {
            dh->inSet = 1;
            ret = 0;
        }

    #ifdef WOLFSSL_SMALL_STACK
        XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }


    return ret;
}


int wolfSSL_DH_size(WOLFSSL_DH* dh)
{
    WOLFSSL_MSG("wolfSSL_DH_size");

    if (dh == NULL)
        return 0;

    return wolfSSL_BN_num_bytes(dh->p);
}


/* return SSL_SUCCESS on ok, else 0 */
int wolfSSL_DH_generate_key(WOLFSSL_DH* dh)
{
    int            ret    = 0;
    word32         pubSz  = 768;
    word32         privSz = 768;
    int            initTmpRng = 0;
    RNG*           rng    = NULL;
#ifdef WOLFSSL_SMALL_STACK
    unsigned char* pub    = NULL;
    unsigned char* priv   = NULL;
    RNG*           tmpRNG = NULL;
#else
    unsigned char  pub [768];
    unsigned char  priv[768];
    RNG            tmpRNG[1];
#endif

    WOLFSSL_MSG("wolfSSL_DH_generate_key");

#ifdef WOLFSSL_SMALL_STACK
    tmpRNG = (RNG*)XMALLOC(sizeof(RNG),      NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pub    = (unsigned char*)XMALLOC(pubSz,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    priv   = (unsigned char*)XMALLOC(privSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (tmpRNG == NULL || pub == NULL || priv == NULL) {
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(pub,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(priv,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
#endif

    if (dh == NULL || dh->p == NULL || dh->g == NULL)
        WOLFSSL_MSG("Bad function arguments");
    else if (dh->inSet == 0 && SetDhInternal(dh) < 0)
            WOLFSSL_MSG("Bad DH set internal");
    else if (wc_InitRng(tmpRNG) == 0) {
        rng = tmpRNG;
        initTmpRng = 1;
    }
    else {
        WOLFSSL_MSG("Bad RNG Init, trying global");
        if (initGlobalRNG == 0)
            WOLFSSL_MSG("Global RNG no Init");
        else
            rng = &globalRNG;
    }

    if (rng) {
       if (wc_DhGenerateKeyPair((DhKey*)dh->internal, rng, priv, &privSz,
                                                               pub, &pubSz) < 0)
            WOLFSSL_MSG("Bad wc_DhGenerateKeyPair");
       else {
            if (dh->pub_key)
                wolfSSL_BN_free(dh->pub_key);
   
            dh->pub_key = wolfSSL_BN_new();
            if (dh->pub_key == NULL) {
                WOLFSSL_MSG("Bad DH new pub");
            }
            if (dh->priv_key)
                wolfSSL_BN_free(dh->priv_key);

            dh->priv_key = wolfSSL_BN_new();

            if (dh->priv_key == NULL) {
                WOLFSSL_MSG("Bad DH new priv");
            }

            if (dh->pub_key && dh->priv_key) {
               if (wolfSSL_BN_bin2bn(pub, pubSz, dh->pub_key) == NULL)
                   WOLFSSL_MSG("Bad DH bn2bin error pub");
               else if (wolfSSL_BN_bin2bn(priv, privSz, dh->priv_key) == NULL)
                   WOLFSSL_MSG("Bad DH bn2bin error priv");
               else
                   ret = SSL_SUCCESS;
            }
        }
    }

    if (initTmpRng)
        wc_FreeRng(tmpRNG);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpRNG, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pub,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(priv,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


/* return key size on ok, 0 otherwise */
int wolfSSL_DH_compute_key(unsigned char* key, WOLFSSL_BIGNUM* otherPub,
                          WOLFSSL_DH* dh)
{
    int            ret    = 0;
    word32         keySz  = 0;
    word32         pubSz  = 1024;
    word32         privSz = 1024;
#ifdef WOLFSSL_SMALL_STACK
    unsigned char* pub    = NULL;
    unsigned char* priv   = NULL;
#else
    unsigned char  pub [1024];
    unsigned char  priv[1024];
#endif

    WOLFSSL_MSG("wolfSSL_DH_compute_key");

#ifdef WOLFSSL_SMALL_STACK
    pub = (unsigned char*)XMALLOC(pubSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pub == NULL)
        return ret;

    priv = (unsigned char*)XMALLOC(privSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv == NULL) {
        XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return 0;
    }
#endif

    if (dh == NULL || dh->priv_key == NULL || otherPub == NULL)
        WOLFSSL_MSG("Bad function arguments");
    else if ((keySz = (word32)DH_size(dh)) == 0)
        WOLFSSL_MSG("Bad DH_size");
    else if (wolfSSL_BN_bn2bin(dh->priv_key, NULL) > (int)privSz)
        WOLFSSL_MSG("Bad priv internal size");
    else if (wolfSSL_BN_bn2bin(otherPub, NULL) > (int)pubSz)
        WOLFSSL_MSG("Bad otherPub size");
    else {
        privSz = wolfSSL_BN_bn2bin(dh->priv_key, priv);
        pubSz  = wolfSSL_BN_bn2bin(otherPub, pub);

        if (privSz <= 0 || pubSz <= 0)
            WOLFSSL_MSG("Bad BN2bin set");
        else if (wc_DhAgree((DhKey*)dh->internal, key, &keySz, priv, privSz, pub,
                                                                     pubSz) < 0)
            WOLFSSL_MSG("wc_DhAgree failed");
        else
            ret = (int)keySz;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(pub,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif /* NO_DH */


#ifndef NO_DSA
static void InitwolfSSL_DSA(WOLFSSL_DSA* dsa)
{
    if (dsa) {
        dsa->p        = NULL;
        dsa->q        = NULL;
        dsa->g        = NULL;
        dsa->pub_key  = NULL;
        dsa->priv_key = NULL;
        dsa->internal = NULL;
        dsa->inSet    = 0;
        dsa->exSet    = 0;
    }
}


WOLFSSL_DSA* wolfSSL_DSA_new(void)
{
    WOLFSSL_DSA* external;
    DsaKey*     key;

    WOLFSSL_MSG("wolfSSL_DSA_new");

    key = (DsaKey*) XMALLOC(sizeof(DsaKey), NULL, DYNAMIC_TYPE_DSA);
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_DSA_new malloc DsaKey failure");
        return NULL;
    }

    external = (WOLFSSL_DSA*) XMALLOC(sizeof(WOLFSSL_DSA), NULL,
                                    DYNAMIC_TYPE_DSA);
    if (external == NULL) {
        WOLFSSL_MSG("wolfSSL_DSA_new malloc WOLFSSL_DSA failure");
        XFREE(key, NULL, DYNAMIC_TYPE_DSA);
        return NULL;
    }

    InitwolfSSL_DSA(external);
    wc_InitDsaKey(key);
    external->internal = key;

    return external;
}


void wolfSSL_DSA_free(WOLFSSL_DSA* dsa)
{
    WOLFSSL_MSG("wolfSSL_DSA_free");

    if (dsa) {
        if (dsa->internal) {
            wc_FreeDsaKey((DsaKey*)dsa->internal);
            XFREE(dsa->internal, NULL, DYNAMIC_TYPE_DSA);
            dsa->internal = NULL;
        }
        wolfSSL_BN_free(dsa->priv_key);
        wolfSSL_BN_free(dsa->pub_key);
        wolfSSL_BN_free(dsa->g);
        wolfSSL_BN_free(dsa->q);
        wolfSSL_BN_free(dsa->p);
        InitwolfSSL_DSA(dsa);  /* set back to NULLs for safety */

        XFREE(dsa, NULL, DYNAMIC_TYPE_DSA);
    }
}


int wolfSSL_DSA_generate_key(WOLFSSL_DSA* dsa)
{
    (void)dsa;

    WOLFSSL_MSG("wolfSSL_DSA_generate_key");

    return 0;  /* key gen not needed by server */
}


int wolfSSL_DSA_generate_parameters_ex(WOLFSSL_DSA* dsa, int bits,
               unsigned char* seed, int seedLen, int* counterRet,
               unsigned long* hRet, void* cb)
{
    (void)dsa;
    (void)bits;
    (void)seed;
    (void)seedLen;
    (void)counterRet;
    (void)hRet;
    (void)cb;

    WOLFSSL_ENTER();

    return 0;  /* key gen not needed by server */
}
#endif /* NO_DSA */

#ifndef NO_RSA
static void InitwolfSSL_Rsa(WOLFSSL_RSA* rsa)
{
    if (rsa) {
        rsa->n        = NULL;
        rsa->e        = NULL;
        rsa->d        = NULL;
        rsa->p        = NULL;
        rsa->q        = NULL;
        rsa->dmp1     = NULL;
        rsa->dmq1     = NULL;
        rsa->iqmp     = NULL;
        rsa->internal = NULL;
        rsa->inSet    = 0;
        rsa->exSet    = 0;
    }
}


WOLFSSL_RSA* wolfSSL_RSA_new(void)
{
    WOLFSSL_RSA* external;
    RsaKey*     key;

    WOLFSSL_ENTER();

    key = (RsaKey*) XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_RSA);
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_RSA_new malloc RsaKey failure");
        return NULL;
    }

    external = (WOLFSSL_RSA*) XMALLOC(sizeof(WOLFSSL_RSA), NULL,
                                     DYNAMIC_TYPE_RSA);
    if (external == NULL) {
        WOLFSSL_MSG("wolfSSL_RSA_new malloc WOLFSSL_RSA failure");
        XFREE(key, NULL, DYNAMIC_TYPE_RSA);
        return NULL;
    }

    InitwolfSSL_Rsa(external);
    if (wc_InitRsaKey(key, NULL) != 0) {
        WOLFSSL_MSG("InitRsaKey WOLFSSL_RSA failure");
        XFREE(external, NULL, DYNAMIC_TYPE_RSA);
        XFREE(key, NULL, DYNAMIC_TYPE_RSA);
        return NULL;
    }
    external->internal = key;

    return external;
}


void wolfSSL_RSA_free(WOLFSSL_RSA* rsa)
{
    WOLFSSL_ENTER();

    if (rsa) {
        if (rsa->internal) {
            wc_FreeRsaKey((RsaKey*)rsa->internal);
            XFREE(rsa->internal, NULL, DYNAMIC_TYPE_RSA);
            rsa->internal = NULL;
        }
        wolfSSL_BN_free(rsa->iqmp);
        wolfSSL_BN_free(rsa->dmq1);
        wolfSSL_BN_free(rsa->dmp1);
        wolfSSL_BN_free(rsa->q);
        wolfSSL_BN_free(rsa->p);
        wolfSSL_BN_free(rsa->d);
        wolfSSL_BN_free(rsa->e);
        wolfSSL_BN_free(rsa->n);
        InitwolfSSL_Rsa(rsa);  /* set back to NULLs for safety */

        XFREE(rsa, NULL, DYNAMIC_TYPE_RSA);
    }
}
#endif /* NO_RSA */


#if !defined(NO_RSA) || !defined(NO_DSA)
static int SetIndividualExternal(WOLFSSL_BIGNUM** bn, mp_int* mpi)
{
    WOLFSSL_ENTER();

    if (mpi == NULL) {
        WOLFSSL_MSG("mpi NULL error");
        return SSL_FATAL_ERROR;
    }

    if (*bn == NULL) {
        *bn = wolfSSL_BN_new();
        if (*bn == NULL) {
            WOLFSSL_MSG("SetIndividualExternal alloc failed");
            return SSL_FATAL_ERROR;
        }
    }

    if (mp_copy(mpi, (mp_int*)((*bn)->internal)) != MP_OKAY) {
        WOLFSSL_MSG("mp_copy error");
        return SSL_FATAL_ERROR;
    }

    return 0;
}
#endif /* !NO_RSA && !NO_DSA */


#ifndef NO_DSA
static int SetDsaExternal(WOLFSSL_DSA* dsa)
{
    DsaKey* key;
    WOLFSSL_ENTER();

    if (dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("dsa key NULL error");
        return SSL_FATAL_ERROR;
    }

    key = (DsaKey*)dsa->internal;

    if (SetIndividualExternal(&dsa->p, &key->p) < 0) {
        WOLFSSL_MSG("dsa p key error");
        return SSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&dsa->q, &key->q) < 0) {
        WOLFSSL_MSG("dsa q key error");
        return SSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&dsa->g, &key->g) < 0) {
        WOLFSSL_MSG("dsa g key error");
        return SSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&dsa->pub_key, &key->y) < 0) {
        WOLFSSL_MSG("dsa y key error");
        return SSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&dsa->priv_key, &key->x) < 0) {
        WOLFSSL_MSG("dsa x key error");
        return SSL_FATAL_ERROR;
    }

    dsa->exSet = 1;

    return 0;
}
#endif /* NO_DSA */


#ifndef NO_RSA
static int SetRsaExternal(WOLFSSL_RSA* rsa)
{
    RsaKey* key;
    WOLFSSL_ENTER();

    if (rsa == NULL || rsa->internal == NULL) {
        WOLFSSL_MSG("rsa key NULL error");
        return SSL_FATAL_ERROR;
    }

    key = (RsaKey*)rsa->internal;

    if (SetIndividualExternal(&rsa->n, &key->n) < 0) {
        WOLFSSL_MSG("rsa n key error");
        return SSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&rsa->e, &key->e) < 0) {
        WOLFSSL_MSG("rsa e key error");
        return SSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&rsa->d, &key->d) < 0) {
        WOLFSSL_MSG("rsa d key error");
        return SSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&rsa->p, &key->p) < 0) {
        WOLFSSL_MSG("rsa p key error");
        return SSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&rsa->q, &key->q) < 0) {
        WOLFSSL_MSG("rsa q key error");
        return SSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&rsa->dmp1, &key->dP) < 0) {
        WOLFSSL_MSG("rsa dP key error");
        return SSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&rsa->dmq1, &key->dQ) < 0) {
        WOLFSSL_MSG("rsa dQ key error");
        return SSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&rsa->iqmp, &key->u) < 0) {
        WOLFSSL_MSG("rsa u key error");
        return SSL_FATAL_ERROR;
    }

    rsa->exSet = 1;

    return 0;
}


/* SSL_SUCCESS on ok */
int wolfSSL_RSA_generate_key_ex(WOLFSSL_RSA* rsa, int bits, WOLFSSL_BIGNUM* bn,
                               void* cb)
{
    int ret = SSL_FATAL_ERROR;

    WOLFSSL_ENTER();

    (void)rsa;
    (void)bits;
    (void)cb;
    (void)bn;

#ifdef WOLFSSL_KEY_GEN
    {
    #ifdef WOLFSSL_SMALL_STACK
        RNG* rng = NULL;
    #else
        RNG  rng[1];
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        rng = (RNG*)XMALLOC(sizeof(RNG), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (rng == NULL)
            return SSL_FATAL_ERROR;
    #endif

        if (wc_InitRng(rng) < 0)
            WOLFSSL_MSG("RNG init failed");
        else if (wc_MakeRsaKey((RsaKey*)rsa->internal, bits, 65537, rng) < 0)
            WOLFSSL_MSG("wc_MakeRsaKey failed");
        else if (SetRsaExternal(rsa) < 0)
            WOLFSSL_MSG("SetRsaExternal failed");
        else {
            rsa->inSet = 1;
            ret = SSL_SUCCESS;
        }

        wc_FreeRng(rng);
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(rng, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }
#else
    WOLFSSL_MSG("No Key Gen built in");
#endif
    return ret;
}


/* SSL_SUCCESS on ok */
int wolfSSL_RSA_blinding_on(WOLFSSL_RSA* rsa, WOLFSSL_BN_CTX* bn)
{
    (void)rsa;
    (void)bn;

    WOLFSSL_ENTER();

    return SSL_SUCCESS;  /* on by default */
}


int wolfSSL_RSA_public_encrypt(int len, unsigned char* fr,
                            unsigned char* to, WOLFSSL_RSA* rsa, int padding)
{
    (void)len;
    (void)fr;
    (void)to;
    (void)rsa;
    (void)padding;

    WOLFSSL_ENTER();

    return SSL_FATAL_ERROR;
}


int wolfSSL_RSA_private_decrypt(int len, unsigned char* fr,
                            unsigned char* to, WOLFSSL_RSA* rsa, int padding)
{
    (void)len;
    (void)fr;
    (void)to;
    (void)rsa;
    (void)padding;

    WOLFSSL_ENTER();

    return SSL_FATAL_ERROR;
}


int wolfSSL_RSA_size(const WOLFSSL_RSA* rsa)
{
    WOLFSSL_ENTER();

    if (rsa == NULL)
        return 0;

    return wolfSSL_BN_num_bytes(rsa->n);
}
#endif /* NO_RSA */


#ifndef NO_DSA
/* return SSL_SUCCESS on success, < 0 otherwise */
int wolfSSL_DSA_do_sign(const unsigned char* d, unsigned char* sigRet,
                       WOLFSSL_DSA* dsa)
{
    int    ret = SSL_FATAL_ERROR;
    int    initTmpRng = 0;
    RNG*   rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
    RNG*   tmpRNG = NULL;
#else
    RNG    tmpRNG[1];
#endif

    WOLFSSL_ENTER();

    if (d == NULL || sigRet == NULL || dsa == NULL)
        WOLFSSL_MSG("Bad function arguments");
    else if (dsa->inSet == 0)
        WOLFSSL_MSG("No DSA internal set");
    else {
    #ifdef WOLFSSL_SMALL_STACK
        tmpRNG = (RNG*)XMALLOC(sizeof(RNG), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (tmpRNG == NULL)
            return SSL_FATAL_ERROR;
    #endif

        if (wc_InitRng(tmpRNG) == 0) {
            rng = tmpRNG;
            initTmpRng = 1;
        }
        else {
            WOLFSSL_MSG("Bad RNG Init, trying global");
            if (initGlobalRNG == 0)
                WOLFSSL_MSG("Global RNG no Init");
            else
                rng = &globalRNG;
        }

        if (rng) {
            if (wc_DsaSign(d, sigRet, (DsaKey*)dsa->internal, rng) < 0)
                WOLFSSL_MSG("DsaSign failed");
            else
                ret = SSL_SUCCESS;
        }

        if (initTmpRng)
            wc_FreeRng(tmpRNG);
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }

    return ret;
}
#endif /* NO_DSA */


#ifndef NO_RSA
/* return SSL_SUCCES on ok, 0 otherwise */
int wolfSSL_RSA_sign(int type, const unsigned char* m,
                           unsigned int mLen, unsigned char* sigRet,
                           unsigned int* sigLen, WOLFSSL_RSA* rsa)
{
    word32 outLen;    
    word32 signSz;
    int    initTmpRng = 0;
    RNG*   rng        = NULL;
    int    ret        = 0;
#ifdef WOLFSSL_SMALL_STACK
    RNG*   tmpRNG     = NULL;
    byte*  encodedSig = NULL;
#else
    RNG    tmpRNG[1];
    byte   encodedSig[MAX_ENCODED_SIG_SZ];
#endif

    WOLFSSL_ENTER();

    if (m == NULL || sigRet == NULL || sigLen == NULL || rsa == NULL)
        WOLFSSL_MSG("Bad function arguments");
    else if (rsa->inSet == 0)
        WOLFSSL_MSG("No RSA internal set");
    else if (type != NID_md5 && type != NID_sha1)
        WOLFSSL_MSG("Bad md type");
    else {
        outLen = (word32)wolfSSL_BN_num_bytes(rsa->n);

    #ifdef WOLFSSL_SMALL_STACK
        tmpRNG = (RNG*)XMALLOC(sizeof(RNG), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (tmpRNG == NULL)
            return 0;

        encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (encodedSig == NULL) {
            XFREE(tmpRNG, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return 0;
        }
    #endif

        if (outLen == 0)
            WOLFSSL_MSG("Bad RSA size");
        else if (wc_InitRng(tmpRNG) == 0) {
            rng = tmpRNG;
            initTmpRng = 1;
        }
        else {
            WOLFSSL_MSG("Bad RNG Init, trying global");

            if (initGlobalRNG == 0)
                WOLFSSL_MSG("Global RNG no Init");
            else
                rng = &globalRNG;
        }
    }

    if (rng) {
        type = (type == NID_md5) ? MD5h : SHAh;

        signSz = wc_EncodeSignature(encodedSig, m, mLen, type);
        if (signSz == 0) {
            WOLFSSL_MSG("Bad Encode Signature");
        }
        else {
            *sigLen = wc_RsaSSL_Sign(encodedSig, signSz, sigRet, outLen,
                                  (RsaKey*)rsa->internal, rng);
            if (*sigLen <= 0)
                WOLFSSL_MSG("Bad Rsa Sign");
            else
                ret = SSL_SUCCESS;
        }

    }

    if (initTmpRng)
        wc_FreeRng(tmpRNG);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpRNG,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(encodedSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    WOLFSSL_MSG("wolfSSL_RSA_sign success");
    return ret;
}


int wolfSSL_RSA_public_decrypt(int flen, unsigned char* from,
                          unsigned char* to, WOLFSSL_RSA* rsa, int padding)
{
    (void)flen;
    (void)from;
    (void)to;
    (void)rsa;
    (void)padding;

    WOLFSSL_ENTER();

    return SSL_FATAL_ERROR;
}


/* generate p-1 and q-1, SSL_SUCCESS on ok */
int wolfSSL_RSA_GenAdd(WOLFSSL_RSA* rsa)
{
    int    err;
    mp_int tmp;

    WOLFSSL_ENTER();

    if (rsa == NULL || rsa->p == NULL || rsa->q == NULL || rsa->d == NULL ||
                       rsa->dmp1 == NULL || rsa->dmq1 == NULL) {
        WOLFSSL_MSG("rsa no init error");
        return SSL_FATAL_ERROR;
    }

    if (mp_init(&tmp) != MP_OKAY) {
        WOLFSSL_MSG("mp_init error");
        return SSL_FATAL_ERROR;
    }

    err = mp_sub_d((mp_int*)rsa->p->internal, 1, &tmp);
    if (err != MP_OKAY) {
        WOLFSSL_MSG("mp_sub_d error");
    }
    else
        err = mp_mod((mp_int*)rsa->d->internal, &tmp,
                     (mp_int*)rsa->dmp1->internal);

    if (err != MP_OKAY) {
        WOLFSSL_MSG("mp_mod error");
    }
    else
        err = mp_sub_d((mp_int*)rsa->q->internal, 1, &tmp);
    if (err != MP_OKAY) {
        WOLFSSL_MSG("mp_sub_d error");
    }
    else
        err = mp_mod((mp_int*)rsa->d->internal, &tmp,
                     (mp_int*)rsa->dmq1->internal);

    mp_clear(&tmp);

    if (err == MP_OKAY)
        return SSL_SUCCESS;
    else
        return SSL_FATAL_ERROR;
}
#endif /* NO_RSA */


void wolfSSL_HMAC_Init(WOLFSSL_HMAC_CTX* ctx, const void* key, int keylen,
                  const EVP_MD* type)
{
    WOLFSSL_ENTER();

    if (ctx == NULL) {
        WOLFSSL_MSG("no ctx on init");
        return;
    }

    if (type) {
        WOLFSSL_MSG("init has type");

        if (XSTRNCMP(type, "MD5", 3) == 0) {
            WOLFSSL_MSG("md5 hmac");
            ctx->type = MD5;
        }
        else if (XSTRNCMP(type, "SHA256", 6) == 0) {
            WOLFSSL_MSG("sha256 hmac");
            ctx->type = SHA256;
        }

        /* has to be last since would pick or 256, 384, or 512 too */
        else if (XSTRNCMP(type, "SHA", 3) == 0) {
            WOLFSSL_MSG("sha hmac");
            ctx->type = SHA;
        }
        else {
            WOLFSSL_MSG("bad init type");
        }
    }

    if (key && keylen) {
        WOLFSSL_MSG("keying hmac");
        wc_HmacSetKey(&ctx->hmac, ctx->type, (const byte*)key, (word32)keylen);
        /* OpenSSL compat, no error */
    }
}


void wolfSSL_HMAC_Update(WOLFSSL_HMAC_CTX* ctx, const unsigned char* data,
                    int len)
{
    WOLFSSL_ENTER();

    if (ctx && data) {
        WOLFSSL_MSG("updating hmac");
        wc_HmacUpdate(&ctx->hmac, data, (word32)len);
        /* OpenSSL compat, no error */
    }
}


void wolfSSL_HMAC_Final(WOLFSSL_HMAC_CTX* ctx, unsigned char* hash, unsigned int* len)
{
    WOLFSSL_ENTER();

    if (ctx && hash) {
        WOLFSSL_MSG("final hmac");
        wc_HmacFinal(&ctx->hmac, hash);
        /* OpenSSL compat, no error */

        if (len) {
            WOLFSSL_MSG("setting output len");
            switch (ctx->type) {
                case MD5:
                    *len = MD5_DIGEST_SIZE;
                    break;

                case SHA:
                    *len = SHA_DIGEST_SIZE;
                    break;

                case SHA256:
                    *len = SHA256_DIGEST_SIZE;
                    break;

                default:
                    WOLFSSL_MSG("bad hmac type");
            }
        }
    }
}


void wolfSSL_HMAC_cleanup(WOLFSSL_HMAC_CTX* ctx)
{
    (void)ctx;

    WOLFSSL_ENTER();
}


const WOLFSSL_EVP_MD* wolfSSL_EVP_get_digestbynid(int id)
{
    WOLFSSL_ENTER();

    switch(id) {
#ifndef NO_MD5
        case NID_md5:
            return wolfSSL_EVP_md5();
#endif
#ifndef NO_SHA
        case NID_sha1:
            return wolfSSL_EVP_sha1();
#endif
        default:
            WOLFSSL_MSG("Bad digest id value");
    }

    return NULL;
}


WOLFSSL_RSA* wolfSSL_EVP_PKEY_get1_RSA(WOLFSSL_EVP_PKEY* key)
{
    (void)key;
    WOLFSSL_ENTER();

    return NULL;
}


WOLFSSL_DSA* wolfSSL_EVP_PKEY_get1_DSA(WOLFSSL_EVP_PKEY* key)
{
    (void)key;
    WOLFSSL_MSG("wolfSSL_EVP_PKEY_get1_DSA");

    return NULL;
}


void* wolfSSL_EVP_X_STATE(const WOLFSSL_EVP_CIPHER_CTX* ctx)
{
    WOLFSSL_ENTER();

    if (ctx) {
        switch (ctx->cipherType) {
            case ARC4_TYPE:
                WOLFSSL_MSG("returning arc4 state");
                return (void*)&ctx->cipher.arc4.x;

            default:
                WOLFSSL_MSG("bad x state type");
                return 0;
        }
    }

    return NULL;
}


int wolfSSL_EVP_X_STATE_LEN(const WOLFSSL_EVP_CIPHER_CTX* ctx)
{
    WOLFSSL_ENTER();

    if (ctx) {
        switch (ctx->cipherType) {
            case ARC4_TYPE:
                WOLFSSL_MSG("returning arc4 state size");
                return sizeof(Arc4);

            default:
                WOLFSSL_MSG("bad x state type");
                return 0;
        }
    }

    return 0;
}


#ifndef NO_DES3

void wolfSSL_3des_iv(WOLFSSL_EVP_CIPHER_CTX* ctx, int doset,
                            unsigned char* iv, int len)
{
    (void)len;

    WOLFSSL_ENTER();

    if (ctx == NULL || iv == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return;
    }

    if (doset)
        wc_Des3_SetIV(&ctx->cipher.des3, iv);  /* OpenSSL compat, no ret */
    else
        memcpy(iv, &ctx->cipher.des3.reg, DES_BLOCK_SIZE);
}

#endif /* NO_DES3 */


#ifndef NO_AES

void wolfSSL_aes_ctr_iv(WOLFSSL_EVP_CIPHER_CTX* ctx, int doset,
                      unsigned char* iv, int len)
{
    (void)len;

    WOLFSSL_ENTER();

    if (ctx == NULL || iv == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return;
    }

    if (doset)
        wc_AesSetIV(&ctx->cipher.aes, iv);  /* OpenSSL compat, no ret */
    else
        memcpy(iv, &ctx->cipher.aes.reg, AES_BLOCK_SIZE);
}

#endif /* NO_AES */


const WOLFSSL_EVP_MD* wolfSSL_EVP_ripemd160(void)
{
    WOLFSSL_ENTER();

    return NULL;
}


int wolfSSL_EVP_MD_size(const WOLFSSL_EVP_MD* type)
{
    WOLFSSL_ENTER();

    if (type == NULL) {
        WOLFSSL_MSG("No md type arg");
        return BAD_FUNC_ARG;
    }

    if (XSTRNCMP(type, "SHA256", 6) == 0) {
        return SHA256_DIGEST_SIZE;
    }
#ifndef NO_MD5
    else if (XSTRNCMP(type, "MD5", 3) == 0) {
        return MD5_DIGEST_SIZE;
    }
#endif
#ifdef WOLFSSL_SHA384
    else if (XSTRNCMP(type, "SHA384", 6) == 0) {
        return SHA384_DIGEST_SIZE;
    }
#endif
#ifdef WOLFSSL_SHA512
    else if (XSTRNCMP(type, "SHA512", 6) == 0) {
        return SHA512_DIGEST_SIZE;
    }
#endif
#ifndef NO_SHA
    /* has to be last since would pick or 256, 384, or 512 too */
    else if (XSTRNCMP(type, "SHA", 3) == 0) {
        return SHA_DIGEST_SIZE;
    }
#endif

    return BAD_FUNC_ARG;
}


int wolfSSL_EVP_CIPHER_CTX_iv_length(const WOLFSSL_EVP_CIPHER_CTX* ctx)
{
    WOLFSSL_MSG("wolfSSL_EVP_CIPHER_CTX_iv_length");

    switch (ctx->cipherType) {

        case AES_128_CBC_TYPE :
        case AES_192_CBC_TYPE :
        case AES_256_CBC_TYPE :
            WOLFSSL_MSG("AES CBC");
            return AES_BLOCK_SIZE;

#ifdef WOLFSSL_AES_COUNTER
        case AES_128_CTR_TYPE :
        case AES_192_CTR_TYPE :
        case AES_256_CTR_TYPE :
            WOLFSSL_MSG("AES CTR");
            return AES_BLOCK_SIZE;
#endif

        case DES_CBC_TYPE :
            WOLFSSL_MSG("DES CBC");
            return DES_BLOCK_SIZE;

        case DES_EDE3_CBC_TYPE :
            WOLFSSL_MSG("DES EDE3 CBC");
            return DES_BLOCK_SIZE;

        case ARC4_TYPE :
            WOLFSSL_MSG("ARC4");
            return 0;

        case NULL_CIPHER_TYPE :
            WOLFSSL_MSG("NULL");
            return 0;

        default: {
            WOLFSSL_MSG("bad type");
        }
    }
    return 0;
}


void wolfSSL_OPENSSL_free(void* p)
{
    WOLFSSL_MSG("wolfSSL_OPENSSL_free");

    XFREE(p, NULL, 0);
}


int wolfSSL_PEM_write_bio_RSAPrivateKey(WOLFSSL_BIO* bio, RSA* rsa,
                                  const EVP_CIPHER* cipher,
                                  unsigned char* passwd, int len,
                                  pem_password_cb cb, void* arg)
{
    (void)bio;
    (void)rsa;
    (void)cipher;
    (void)passwd;
    (void)len;
    (void)cb;
    (void)arg;

    WOLFSSL_MSG("wolfSSL_PEM_write_bio_RSAPrivateKey");

    return SSL_FATAL_ERROR;
}



int wolfSSL_PEM_write_bio_DSAPrivateKey(WOLFSSL_BIO* bio, DSA* rsa,
                                  const EVP_CIPHER* cipher,
                                  unsigned char* passwd, int len,
                                  pem_password_cb cb, void* arg)
{
    (void)bio;
    (void)rsa;
    (void)cipher;
    (void)passwd;
    (void)len;
    (void)cb;
    (void)arg;

    WOLFSSL_MSG("wolfSSL_PEM_write_bio_DSAPrivateKey");

    return SSL_FATAL_ERROR;
}



WOLFSSL_EVP_PKEY* wolfSSL_PEM_read_bio_PrivateKey(WOLFSSL_BIO* bio,
                    WOLFSSL_EVP_PKEY** key, pem_password_cb cb, void* arg)
{
    (void)bio;
    (void)key;
    (void)cb;
    (void)arg;

    WOLFSSL_MSG("wolfSSL_PEM_read_bio_PrivateKey");

    return NULL;
}



#ifndef NO_RSA
/* Load RSA from Der, SSL_SUCCESS on success < 0 on error */
int wolfSSL_RSA_LoadDer(WOLFSSL_RSA* rsa, const unsigned char* der,  int derSz)
{
    word32 idx = 0;
    int    ret;

    WOLFSSL_ENTER();

    if (rsa == NULL || rsa->internal == NULL || der == NULL || derSz <= 0) {
        WOLFSSL_MSG("Bad function arguments");
        return BAD_FUNC_ARG;
    }

    ret = wc_RsaPrivateKeyDecode(der, &idx, (RsaKey*)rsa->internal, derSz);
    if (ret < 0) {
        WOLFSSL_MSG("RsaPrivateKeyDecode failed");
        return ret;
    }

    if (SetRsaExternal(rsa) < 0) {
        WOLFSSL_MSG("SetRsaExternal failed");
        return SSL_FATAL_ERROR;
    }

    rsa->inSet = 1;

    return SSL_SUCCESS;
}
#endif /* NO_RSA */


#ifndef NO_DSA
/* Load DSA from Der, SSL_SUCCESS on success < 0 on error */
int wolfSSL_DSA_LoadDer(WOLFSSL_DSA* dsa, const unsigned char* der,  int derSz)
{
    word32 idx = 0;
    int    ret;

    WOLFSSL_ENTER();

    if (dsa == NULL || dsa->internal == NULL || der == NULL || derSz <= 0) {
        WOLFSSL_MSG("Bad function arguments");
        return BAD_FUNC_ARG;
    }

    ret = DsaPrivateKeyDecode(der, &idx, (DsaKey*)dsa->internal, derSz);
    if (ret < 0) {
        WOLFSSL_MSG("DsaPrivateKeyDecode failed");
        return ret;
    }

    if (SetDsaExternal(dsa) < 0) {
        WOLFSSL_MSG("SetDsaExternal failed");
        return SSL_FATAL_ERROR;
    }

    dsa->inSet = 1;

    return SSL_SUCCESS;
}
#endif /* NO_DSA */




#endif /* OPENSSL_EXTRA */

