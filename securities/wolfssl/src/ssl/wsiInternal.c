/* internal.c
 */


#include "cmnSsl.h"

#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

#ifdef HAVE_NTRU
    #include "ntru_crypto.h"
#endif

#if defined(DEBUG_WOLFSSL) || defined(SHOW_SECRETS) || defined(CHACHA_AEAD_TEST)
    #ifdef FREESCALE_MQX
        #include <fio.h>
    #else
        #include <stdio.h>
    #endif
#endif

#ifdef __sun
    #include <sys/filio.h>
#endif


int IsTLS(const WOLFSSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_MINOR)
        return 1;

    return 0;
}


int IsAtLeastTLSv1_2(const WOLFSSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_2_MINOR)
        return 1;
    if (ssl->version.major == DTLS_MAJOR && ssl->version.minor <= DTLSv1_2_MINOR)
        return 1;

    return 0;
}


#ifdef HAVE_NTRU

static byte GetEntropy(ENTROPY_CMD cmd, byte* out)
{
    /* TODO: add locking? */
    static RNG rng;

    if (cmd == INIT)
        return (wc_InitRng(&rng) == 0) ? 1 : 0;

    if (out == NULL)
        return 0;

    if (cmd == GET_BYTE_OF_ENTROPY)
        return (wc_RNG_GenerateBlock(&rng, out, 1) == 0) ? 1 : 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
        *out = 1;
        return 1;
    }

    return 0;
}

#endif /* HAVE_NTRU */



#ifdef HAVE_LIBZ

    /* alloc user allocs to work with zlib */
    static void* myAlloc(void* opaque, unsigned int item, unsigned int size)
    {
        (void)opaque;
        return XMALLOC(item * size, opaque, DYNAMIC_TYPE_LIBZ);
    }


    static void myFree(void* opaque, void* memory)
    {
        (void)opaque;
        XFREE(memory, opaque, DYNAMIC_TYPE_LIBZ);
    }


    /* init zlib comp/decomp streams, 0 on success */
    static int InitStreams(WOLFSSL* ssl)
    {
        ssl->c_stream.zalloc = (alloc_func)myAlloc;
        ssl->c_stream.zfree  = (free_func)myFree;
        ssl->c_stream.opaque = (voidpf)ssl->heap;

        if (deflateInit(&ssl->c_stream, Z_DEFAULT_COMPRESSION) != Z_OK)
            return ZLIB_INIT_ERROR;

        ssl->didStreamInit = 1;

        ssl->d_stream.zalloc = (alloc_func)myAlloc;
        ssl->d_stream.zfree  = (free_func)myFree;
        ssl->d_stream.opaque = (voidpf)ssl->heap;

        if (inflateInit(&ssl->d_stream) != Z_OK) return ZLIB_INIT_ERROR;

        return 0;
    }


    static void FreeStreams(WOLFSSL* ssl)
    {
        if (ssl->didStreamInit) {
            deflateEnd(&ssl->c_stream);
            inflateEnd(&ssl->d_stream);
        }
    }


    /* compress in to out, return out size or error */
    static int myCompress(WOLFSSL* ssl, byte* in, int inSz, byte* out, int outSz)
    {
        int    err;
        int    currTotal = (int)ssl->c_stream.total_out;

        ssl->c_stream.next_in   = in;
        ssl->c_stream.avail_in  = inSz;
        ssl->c_stream.next_out  = out;
        ssl->c_stream.avail_out = outSz;

        err = deflate(&ssl->c_stream, Z_SYNC_FLUSH);
        if (err != Z_OK && err != Z_STREAM_END) return ZLIB_COMPRESS_ERROR;

        return (int)ssl->c_stream.total_out - currTotal;
    }


    /* decompress in to out, returnn out size or error */
    static int myDeCompress(WOLFSSL* ssl, byte* in,int inSz, byte* out,int outSz)
    {
        int    err;
        int    currTotal = (int)ssl->d_stream.total_out;

        ssl->d_stream.next_in   = in;
        ssl->d_stream.avail_in  = inSz;
        ssl->d_stream.next_out  = out;
        ssl->d_stream.avail_out = outSz;

        err = inflate(&ssl->d_stream, Z_SYNC_FLUSH);
        if (err != Z_OK && err != Z_STREAM_END) return ZLIB_DECOMPRESS_ERROR;

        return (int)ssl->d_stream.total_out - currTotal;
    }

#endif /* HAVE_LIBZ */



#ifdef WOLFSSL_DTLS

int DtlsPoolInit(WOLFSSL* ssl)
{
	if (ssl->dtls_pool == NULL)
	{
		int i;
		DtlsPool *pool = (DtlsPool*)XMALLOC(sizeof(DtlsPool), ssl->heap, DYNAMIC_TYPE_DTLS_POOL);
		if (pool == NULL) {
			WOLFSSL_MSG("DTLS Buffer Pool Memory error");
			return MEMORY_E;
		}

		for (i = 0; i < DTLS_POOL_SZ; i++)
		{
			pool->buf[i].length = 0;
			pool->buf[i].buffer = NULL;
		}
		
		pool->used = 0;
		ssl->dtls_pool = pool;
	}
	return 0;
}


int DtlsPoolSave(WOLFSSL* ssl, const byte *src, int sz)
{
    DtlsPool *pool = ssl->dtls_pool;
    if (pool != NULL && pool->used < DTLS_POOL_SZ) {
        buffer *pBuf = &pool->buf[pool->used];
        pBuf->buffer = (byte*)XMALLOC(sz, ssl->heap, DYNAMIC_TYPE_DTLS_POOL);
        if (pBuf->buffer == NULL) {
            WOLFSSL_MSG("DTLS Buffer Memory error");
            return MEMORY_ERROR;
        }
        XMEMCPY(pBuf->buffer, src, sz);
        pBuf->length = (word32)sz;
        pool->used++;
    }
    return 0;
}


void DtlsPoolReset(WOLFSSL* ssl)
{
    DtlsPool *pool = ssl->dtls_pool;
    if (pool != NULL) {
        buffer *pBuf;
        int i, used;

        used = pool->used;
        for (i = 0, pBuf = &pool->buf[0]; i < used; i++, pBuf++) {
            XFREE(pBuf->buffer, ssl->heap, DYNAMIC_TYPE_DTLS_POOL);
            pBuf->buffer = NULL;
            pBuf->length = 0;
        }
        pool->used = 0;
    }
    ssl->dtls_timeout = ssl->dtls_timeout_init;
}


int DtlsPoolTimeout(WOLFSSL* ssl)
{
    int result = -1;
    if (ssl->dtls_timeout <  ssl->dtls_timeout_max) {
        ssl->dtls_timeout *= DTLS_TIMEOUT_MULTIPLIER;
        result = 0;
    }
    return result;
}


int DtlsPoolSend(WOLFSSL* ssl)
{
    int ret;
    DtlsPool *pool = ssl->dtls_pool;

    if (pool != NULL && pool->used > 0) {
        int i;
        for (i = 0; i < pool->used; i++) {
            int sendResult;
            buffer* buf = &pool->buf[i];

            DtlsRecordLayerHeader* dtls = (DtlsRecordLayerHeader*)buf->buffer;

            word16 message_epoch;
            ato16(dtls->epoch, &message_epoch);
            if (message_epoch == ssl->keys.dtls_epoch) {
                /* Increment record sequence number on retransmitted handshake
                 * messages */
                c32to48(ssl->keys.dtls_sequence_number, dtls->sequence_number);
                ssl->keys.dtls_sequence_number++;
            }
            else {
                /* The Finished message is sent with the next epoch, keep its
                 * sequence number */
            }

            if ((ret = CheckAvailableSize(ssl, buf->length)) != 0)
                return ret;

            XMEMCPY(ssl->buffers.outputBuffer.buffer, buf->buffer, buf->length);
            ssl->buffers.outputBuffer.idx = 0;
            ssl->buffers.outputBuffer.length = buf->length;

            sendResult = SendBuffered(ssl);
            if (sendResult < 0) {
                return sendResult;
            }
        }
    }
    return 0;
}


/* functions for managing DTLS datagram reordering */

/* Need to allocate space for the handshake message header. The hashing
 * routines assume the message pointer is still within the buffer that
 * has the headers, and will include those headers in the hash. The store
 * routines need to take that into account as well. New will allocate
 * extra space for the headers. */
DtlsMsg* DtlsMsgNew(word32 sz, void* heap)
{
    DtlsMsg* msg = NULL;

    msg = (DtlsMsg*)XMALLOC(sizeof(DtlsMsg), heap, DYNAMIC_TYPE_DTLS_MSG);

    if (msg != NULL) {
        msg->buf = (byte*)XMALLOC(sz + DTLS_HANDSHAKE_HEADER_SZ,
                                                     heap, DYNAMIC_TYPE_NONE);
        if (msg->buf != NULL) {
            msg->next = NULL;
            msg->seq = 0;
            msg->sz = sz;
            msg->fragSz = 0;
            msg->msg = msg->buf + DTLS_HANDSHAKE_HEADER_SZ;
        }
        else {
            XFREE(msg, heap, DYNAMIC_TYPE_DTLS_MSG);
            msg = NULL;
        }
    }

    return msg;
}

void DtlsMsgDelete(DtlsMsg* item, void* heap)
{
    (void)heap;

    if (item != NULL) {
        if (item->buf != NULL)
            XFREE(item->buf, heap, DYNAMIC_TYPE_NONE);
        XFREE(item, heap, DYNAMIC_TYPE_DTLS_MSG);
    }
}


void DtlsMsgListDelete(DtlsMsg* head, void* heap)
{
    DtlsMsg* next;
    while (head) {
        next = head->next;
        DtlsMsgDelete(head, heap);
        head = next;
    }
}


void DtlsMsgSet(DtlsMsg* msg, word32 seq, const byte* data, byte type,
                                              word32 fragOffset, word32 fragSz)
{
    if (msg != NULL && data != NULL && msg->fragSz <= msg->sz &&
                    fragOffset <= msg->sz && (fragOffset + fragSz) <= msg->sz) {

        msg->seq = seq;
        msg->type = type;
        msg->fragSz += fragSz;
        /* If fragOffset is zero, this is either a full message that is out
         * of order, or the first fragment of a fragmented message. Copy the
         * handshake message header with the message data. Zero length messages
         * like Server Hello Done should be saved as well. */
        if (fragOffset == 0)
            XMEMCPY(msg->buf, data - DTLS_HANDSHAKE_HEADER_SZ,
                                            fragSz + DTLS_HANDSHAKE_HEADER_SZ);
        else {
            /* If fragOffet is non-zero, this is an additional fragment that
             * needs to be copied to its location in the message buffer. Also
             * copy the total size of the message over the fragment size. The
             * hash routines look at a defragmented message if it had actually
             * come across as a single handshake message. */
            XMEMCPY(msg->msg + fragOffset, data, fragSz);
        }
        c32to24(msg->sz, msg->msg - DTLS_HANDSHAKE_FRAG_SZ);
    }
}


DtlsMsg* DtlsMsgFind(DtlsMsg* head, word32 seq)
{
    while (head != NULL && head->seq != seq) {
        head = head->next;
    }
    return head;
}


DtlsMsg* DtlsMsgStore(DtlsMsg* head, word32 seq, const byte* data,
        word32 dataSz, byte type, word32 fragOffset, word32 fragSz, void* heap)
{

    /* See if seq exists in the list. If it isn't in the list, make
     * a new item of size dataSz, copy fragSz bytes from data to msg->msg
     * starting at offset fragOffset, and add fragSz to msg->fragSz. If
     * the seq is in the list and it isn't full, copy fragSz bytes from
     * data to msg->msg starting at offset fragOffset, and add fragSz to
     * msg->fragSz. The new item should be inserted into the list in its
     * proper position.
     *
     * 1. Find seq in list, or where seq should go in list. If seq not in
     *    list, create new item and insert into list. Either case, keep
     *    pointer to item.
     * 2. If msg->fragSz + fragSz < sz, copy data to msg->msg at offset
     *    fragOffset. Add fragSz to msg->fragSz.
     */

    if (head != NULL) {
        DtlsMsg* cur = DtlsMsgFind(head, seq);
        if (cur == NULL) {
            cur = DtlsMsgNew(dataSz, heap);
            if (cur != NULL) {
                DtlsMsgSet(cur, seq, data, type, fragOffset, fragSz);
                head = DtlsMsgInsert(head, cur);
            }
        }
        else {
            DtlsMsgSet(cur, seq, data, type, fragOffset, fragSz);
        }
    }
    else {
        head = DtlsMsgNew(dataSz, heap);
        DtlsMsgSet(head, seq, data, type, fragOffset, fragSz);
    }

    return head;
}


/* DtlsMsgInsert() is an in-order insert. */
DtlsMsg* DtlsMsgInsert(DtlsMsg* head, DtlsMsg* item)
{
    if (head == NULL || item->seq < head->seq) {
        item->next = head;
        head = item;
    }
    else if (head->next == NULL) {
        head->next = item;
    }
    else {
        DtlsMsg* cur = head->next;
        DtlsMsg* prev = head;
        while (cur) {
            if (item->seq < cur->seq) {
                item->next = cur;
                prev->next = item;
                break;
            }
            prev = cur;
            cur = cur->next;
        }
        if (cur == NULL) {
            prev->next = item;
        }
    }

    return head;
}

#endif /* WOLFSSL_DTLS */




/* add record layer header for message */
void AddRecordHeader(byte* output, word32 length, HAND_SHAKE_TYPE_T type, WOLFSSL* ssl)
{
	RecordLayerHeader	*rl;

	/* record layer header */
	rl = (RecordLayerHeader*)output;
	rl->type    = type;
	rl->pvMajor = ssl->version.major;       /* type and version same in each */
	rl->pvMinor = ssl->version.minor;

	if (!ssl->options.dtls)
		c16toa((word16)length, rl->length);
	else
	{
#ifdef WOLFSSL_DTLS
		DtlsRecordLayerHeader* dtls;

		/* dtls record layer header extensions */
		dtls = (DtlsRecordLayerHeader*)output;
		c16toa(ssl->keys.dtls_epoch, dtls->epoch);
		c32to48(ssl->keys.dtls_sequence_number++, dtls->sequence_number);
		c16toa((word16)length, dtls->length);
#endif
	}
}


/* add handshake header for message */
void AddHandShakeHeader(byte* output, word32 length, HAND_SHAKE_TYPE_T type, WOLFSSL* ssl)
{
	HandShakeHeader* hs;
	(void)ssl;

	/* handshake header */
	hs = (HandShakeHeader*)output;
	hs->type = type;
	c32to24(length, hs->length);         /* type and length same for each */
#ifdef WOLFSSL_DTLS
	if (ssl->options.dtls) {
	DtlsHandShakeHeader* dtls;

	/* dtls handshake header extensions */
	dtls = (DtlsHandShakeHeader*)output;
	c16toa(ssl->keys.dtls_handshake_number++, dtls->message_seq);
	c32to24(0, dtls->fragment_offset);
	c32to24(length, dtls->fragment_length);
	}
#endif
}


/* add both headers for handshake message */
void AddHeaders(byte* output, word32 length, HAND_SHAKE_TYPE_T type, WOLFSSL* ssl)
{
	if (!ssl->options.dtls) {
		AddRecordHeader(output, length + HANDSHAKE_HEADER_SZ, handshake, ssl);
		AddHandShakeHeader(output + RECORD_HEADER_SZ, length, type, ssl);
	}
#ifdef WOLFSSL_DTLS
	else  {
		AddRecordHeader(output, length+DTLS_HANDSHAKE_HEADER_SZ, handshake,ssl);
		AddHandShakeHeader(output + DTLS_RECORD_HEADER_SZ, length, type, ssl);
	}
#endif
}


#ifdef WOLFSSL_DTLS
static int GetDtlsHandShakeHeader(WOLFSSL* ssl, const byte* input,
                                  word32* inOutIdx, byte *type, word32 *size,
                                  word32 *fragOffset, word32 *fragSz,
                                  word32 totalSz)
{
    word32 idx = *inOutIdx;

    *inOutIdx += HANDSHAKE_HEADER_SZ + DTLS_HANDSHAKE_EXTRA;
    if (*inOutIdx > totalSz)
        return BUFFER_E;

    *type = input[idx++];
    c24to32(input + idx, size);
    idx += BYTE3_LEN;

    ato16(input + idx, &ssl->keys.dtls_peer_handshake_number);
    idx += DTLS_HANDSHAKE_SEQ_SZ;

    c24to32(input + idx, fragOffset);
    idx += DTLS_HANDSHAKE_FRAG_SZ;
    c24to32(input + idx, fragSz);

    return 0;
}
#endif




#ifndef NO_CERTS


#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)

/* Copy parts X509 needs from Decoded cert, 0 on success */
int CopyDecodedToX509(WOLFSSL_X509* x509, DecodedCert* dCert)
{
    int ret = 0;

    if (x509 == NULL || dCert == NULL)
        return BAD_FUNC_ARG;

    x509->version = dCert->version + 1;

    XSTRNCPY(x509->issuer.name, dCert->issuer, ASN_NAME_MAX);
    x509->issuer.name[ASN_NAME_MAX - 1] = '\0';
    x509->issuer.sz = (int)XSTRLEN(x509->issuer.name) + 1;
#ifdef OPENSSL_EXTRA
    if (dCert->issuerName.fullName != NULL) {
        XMEMCPY(&x509->issuer.fullName,
                                       &dCert->issuerName, sizeof(DecodedName));
        x509->issuer.fullName.fullName = (char*)XMALLOC(
                        dCert->issuerName.fullNameLen, NULL, DYNAMIC_TYPE_X509);
        if (x509->issuer.fullName.fullName != NULL)
            XMEMCPY(x509->issuer.fullName.fullName,
                     dCert->issuerName.fullName, dCert->issuerName.fullNameLen);
    }
#endif /* OPENSSL_EXTRA */

    XSTRNCPY(x509->subject.name, dCert->subject, ASN_NAME_MAX);
    x509->subject.name[ASN_NAME_MAX - 1] = '\0';
    x509->subject.sz = (int)XSTRLEN(x509->subject.name) + 1;
#ifdef OPENSSL_EXTRA
    if (dCert->subjectName.fullName != NULL) {
        XMEMCPY(&x509->subject.fullName,
                                      &dCert->subjectName, sizeof(DecodedName));
        x509->subject.fullName.fullName = (char*)XMALLOC(
                       dCert->subjectName.fullNameLen, NULL, DYNAMIC_TYPE_X509);
        if (x509->subject.fullName.fullName != NULL)
            XMEMCPY(x509->subject.fullName.fullName,
                   dCert->subjectName.fullName, dCert->subjectName.fullNameLen);
    }
#endif /* OPENSSL_EXTRA */

    XMEMCPY(x509->serial, dCert->serial, EXTERNAL_SERIAL_SIZE);
    x509->serialSz = dCert->serialSz;
    if (dCert->subjectCNLen < ASN_NAME_MAX) {
        XMEMCPY(x509->subjectCN, dCert->subjectCN, dCert->subjectCNLen);
        x509->subjectCN[dCert->subjectCNLen] = '\0';
    }
    else
        x509->subjectCN[0] = '\0';

#ifdef WOLFSSL_SEP
    {
        int minSz = min(dCert->deviceTypeSz, EXTERNAL_SERIAL_SIZE);
        if (minSz > 0) {
            x509->deviceTypeSz = minSz;
            XMEMCPY(x509->deviceType, dCert->deviceType, minSz);
        }
        else
            x509->deviceTypeSz = 0;
        minSz = min(dCert->hwTypeSz, EXTERNAL_SERIAL_SIZE);
        if (minSz != 0) {
            x509->hwTypeSz = minSz;
            XMEMCPY(x509->hwType, dCert->hwType, minSz);
        }
        else
            x509->hwTypeSz = 0;
        minSz = min(dCert->hwSerialNumSz, EXTERNAL_SERIAL_SIZE);
        if (minSz != 0) {
            x509->hwSerialNumSz = minSz;
            XMEMCPY(x509->hwSerialNum, dCert->hwSerialNum, minSz);
        }
        else
            x509->hwSerialNumSz = 0;
    }
#endif /* WOLFSSL_SEP */
    {
        int minSz = min(dCert->beforeDateLen, MAX_DATE_SZ);
        if (minSz != 0) {
            x509->notBeforeSz = minSz;
            XMEMCPY(x509->notBefore, dCert->beforeDate, minSz);
        }
        else
            x509->notBeforeSz = 0;
        minSz = min(dCert->afterDateLen, MAX_DATE_SZ);
        if (minSz != 0) {
            x509->notAfterSz = minSz;
            XMEMCPY(x509->notAfter, dCert->afterDate, minSz);
        }
        else
            x509->notAfterSz = 0;
    }

    if (dCert->publicKey != NULL && dCert->pubKeySize != 0) {
        x509->pubKey.buffer = (byte*)XMALLOC(
                              dCert->pubKeySize, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        if (x509->pubKey.buffer != NULL) {
            x509->pubKeyOID = dCert->keyOID;
            x509->pubKey.length = dCert->pubKeySize;
            XMEMCPY(x509->pubKey.buffer, dCert->publicKey, dCert->pubKeySize);
        }
        else
            ret = MEMORY_E;
    }

    if (dCert->signature != NULL && dCert->sigLength != 0) {
        x509->sig.buffer = (byte*)XMALLOC(
                                dCert->sigLength, NULL, DYNAMIC_TYPE_SIGNATURE);
        if (x509->sig.buffer == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(x509->sig.buffer, dCert->signature, dCert->sigLength);
            x509->sig.length = dCert->sigLength;
            x509->sigOID = dCert->signatureOID;
        }
    }

    /* store cert for potential retrieval */
    x509->derCert.buffer = (byte*)XMALLOC(dCert->maxIdx, NULL,
                                          DYNAMIC_TYPE_CERT);
    if (x509->derCert.buffer == NULL) {
        ret = MEMORY_E;
    }
    else {
        XMEMCPY(x509->derCert.buffer, dCert->source, dCert->maxIdx);
        x509->derCert.length = dCert->maxIdx;
    }

    x509->altNames       = dCert->altNames;
    dCert->weOwnAltNames = 0;
    x509->altNamesNext   = x509->altNames;  /* index hint */

    x509->isCa = dCert->isCA;
#ifdef OPENSSL_EXTRA
    x509->pathLength = dCert->pathLength;
    x509->keyUsage = dCert->extKeyUsage;

    x509->basicConstSet = dCert->extBasicConstSet;
    x509->basicConstCrit = dCert->extBasicConstCrit;
    x509->basicConstPlSet = dCert->extBasicConstPlSet;
    x509->subjAltNameSet = dCert->extSubjAltNameSet;
    x509->subjAltNameCrit = dCert->extSubjAltNameCrit;
    x509->authKeyIdSet = dCert->extAuthKeyIdSet;
    x509->authKeyIdCrit = dCert->extAuthKeyIdCrit;
    if (dCert->extAuthKeyIdSrc != NULL && dCert->extAuthKeyIdSz != 0) {
        x509->authKeyId = (byte*)XMALLOC(dCert->extAuthKeyIdSz, NULL, 0);
        if (x509->authKeyId != NULL) {
            XMEMCPY(x509->authKeyId,
                                 dCert->extAuthKeyIdSrc, dCert->extAuthKeyIdSz);
            x509->authKeyIdSz = dCert->extAuthKeyIdSz;
        }
        else
            ret = MEMORY_E;
    }
    x509->subjKeyIdSet = dCert->extSubjKeyIdSet;
    x509->subjKeyIdCrit = dCert->extSubjKeyIdCrit;
    if (dCert->extSubjKeyIdSrc != NULL && dCert->extSubjKeyIdSz != 0) {
        x509->subjKeyId = (byte*)XMALLOC(dCert->extSubjKeyIdSz, NULL, 0);
        if (x509->subjKeyId != NULL) {
            XMEMCPY(x509->subjKeyId,
                                 dCert->extSubjKeyIdSrc, dCert->extSubjKeyIdSz);
            x509->subjKeyIdSz = dCert->extSubjKeyIdSz;
        }
        else
            ret = MEMORY_E;
    }
    x509->keyUsageSet = dCert->extKeyUsageSet;
    x509->keyUsageCrit = dCert->extKeyUsageCrit;
    #ifdef WOLFSSL_SEP
        x509->certPolicySet = dCert->extCertPolicySet;
        x509->certPolicyCrit = dCert->extCertPolicyCrit;
    #endif /* WOLFSSL_SEP */
#endif /* OPENSSL_EXTRA */
#ifdef HAVE_ECC
    x509->pkCurveOID = dCert->pkCurveOID;
#endif /* HAVE_ECC */

    return ret;
}

#endif /* KEEP_PEER_CERT || SESSION_CERTS */

#endif /* !NO_CERTS */


/* Make sure no duplicates, no fast forward, or other problems; 0 on success */
int SanityCheckMsgReceived(WOLFSSL* ssl, byte type)
{
    /* verify not a duplicate, mark received, check state */
    switch (type) {

#ifndef NO_WOLFSSL_CLIENT
        case hello_request:
            if (ssl->msgsReceived.got_hello_request) {
                WOLFSSL_MSG("Duplicate HelloRequest received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_hello_request = 1;

            break;
#endif

#ifndef NO_WOLFSSL_SERVER
        case HST_CLIENT_HELLO:
            if (ssl->msgsReceived.got_client_hello) {
                WOLFSSL_MSG("Duplicate ClientHello received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_client_hello = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case server_hello:
            if (ssl->msgsReceived.got_server_hello) {
                WOLFSSL_MSG("Duplicate ServerHello received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_hello = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case hello_verify_request:
            if (ssl->msgsReceived.got_hello_verify_request) {
                WOLFSSL_MSG("Duplicate HelloVerifyRequest received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_hello_verify_request = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case session_ticket:
            if (ssl->msgsReceived.got_session_ticket) {
                WOLFSSL_MSG("Duplicate SessionTicket received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_session_ticket = 1;

            break;
#endif

        case certificate:
            if (ssl->msgsReceived.got_certificate) {
                WOLFSSL_MSG("Duplicate Certificate received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate = 1;

#ifndef NO_WOLFSSL_CLIENT
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                if ( ssl->msgsReceived.got_server_hello == 0) {
                    WOLFSSL_MSG("No ServerHello before Cert");
                    return OUT_OF_ORDER_E;
                }
            }
#endif
#ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                if ( ssl->msgsReceived.got_client_hello == 0) {
                    WOLFSSL_MSG("No ClientHello before Cert");
                    return OUT_OF_ORDER_E;
                }
            }
#endif
            break;

#ifndef NO_WOLFSSL_CLIENT
        case server_key_exchange:
            if (ssl->msgsReceived.got_server_key_exchange) {
                WOLFSSL_MSG("Duplicate ServerKeyExchange received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_key_exchange = 1;

            if ( ssl->msgsReceived.got_server_hello == 0) {
                WOLFSSL_MSG("No ServerHello before Cert");
                return OUT_OF_ORDER_E;
            }

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case certificate_request:
            if (ssl->msgsReceived.got_certificate_request) {
                WOLFSSL_MSG("Duplicate CertificateRequest received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate_request = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case server_hello_done:
            if (ssl->msgsReceived.got_server_hello_done) {
                WOLFSSL_MSG("Duplicate ServerHelloDone received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_hello_done = 1;

            if (ssl->msgsReceived.got_certificate == 0) {
                if (ssl->specs.kea == psk_kea ||
                    ssl->specs.kea == dhe_psk_kea ||
                    ssl->options.usingAnon_cipher) {
                    WOLFSSL_MSG("No Cert required");
                } else {
                    WOLFSSL_MSG("No Certificate before ServerHelloDone");
                    return OUT_OF_ORDER_E;
                }
            }
            if (ssl->msgsReceived.got_server_key_exchange == 0) {
                if (ssl->specs.static_ecdh == 1 ||
                    ssl->specs.kea == rsa_kea ||
                    ssl->specs.kea == ntru_kea) {
                    WOLFSSL_MSG("No KeyExchange required");
                } else {
                    WOLFSSL_MSG("No ServerKeyExchange before ServerDone");
                    return OUT_OF_ORDER_E;
                }
            }
            break;
#endif

#ifndef NO_WOLFSSL_SERVER
        case certificate_verify:
            if (ssl->msgsReceived.got_certificate_verify) {
                WOLFSSL_MSG("Duplicate CertificateVerify received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate_verify = 1;

            if ( ssl->msgsReceived.got_certificate == 0) {
                WOLFSSL_MSG("No Cert before CertVerify");
                return OUT_OF_ORDER_E;
            }
            break;
#endif

#ifndef NO_WOLFSSL_SERVER
        case client_key_exchange:
            if (ssl->msgsReceived.got_client_key_exchange) {
                WOLFSSL_MSG("Duplicate ClientKeyExchange received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_client_key_exchange = 1;

            if (ssl->msgsReceived.got_client_hello == 0) {
                WOLFSSL_MSG("No ClientHello before ClientKeyExchange");
                return OUT_OF_ORDER_E;
            }
            break;
#endif

        case finished:
            if (ssl->msgsReceived.got_finished) {
                WOLFSSL_MSG("Duplicate Finished received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_finished = 1;

            if (ssl->msgsReceived.got_change_cipher == 0) {
                WOLFSSL_MSG("Finished received before ChangeCipher");
                return NO_CHANGE_CIPHER_E;
            }

            break;

        case change_cipher_hs:
            if (ssl->msgsReceived.got_change_cipher) {
                WOLFSSL_MSG("Duplicate ChangeCipher received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_change_cipher = 1;

#ifndef NO_WOLFSSL_CLIENT
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                if (!ssl->options.resuming &&
                                 ssl->msgsReceived.got_server_hello_done == 0) {
                    WOLFSSL_MSG("No ServerHelloDone before ChangeCipher");
                    return OUT_OF_ORDER_E;
                }
            }
#endif
#ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                if (!ssl->options.resuming &&
                               ssl->msgsReceived.got_client_key_exchange == 0) {
                    WOLFSSL_MSG("No ClientKeyExchange before ChangeCipher");
                    return OUT_OF_ORDER_E;
                }
            }
#endif

            break;

        default:
            WOLFSSL_MSG("Unknown message type");
            return SANITY_MSG_E;
    }

    return 0;
}


#ifdef WOLFSSL_DTLS

static INLINE int DtlsCheckWindow(DtlsState* state)
{
    word32 cur;
    word32 next;
    DtlsSeq window;

    if (state->curEpoch == state->nextEpoch) {
        next = state->nextSeq;
        window = state->window;
    }
    else if (state->curEpoch < state->nextEpoch) {
        next = state->prevSeq;
        window = state->prevWindow;
    }
    else {
        return 0;
    }

    cur = state->curSeq;

    if ((next > DTLS_SEQ_BITS) && (cur < next - DTLS_SEQ_BITS)) {
        return 0;
    }
    else if ((cur < next) && (window & ((DtlsSeq)1 << (next - cur - 1)))) {
        return 0;
    }

    return 1;
}


static INLINE int DtlsUpdateWindow(DtlsState* state)
{
    word32 cur;
    word32* next;
    DtlsSeq* window;

    if (state->curEpoch == state->nextEpoch) {
        next = &state->nextSeq;
        window = &state->window;
    }
    else {
        next = &state->prevSeq;
        window = &state->prevWindow;
    }

    cur = state->curSeq;

    if (cur < *next) {
        *window |= ((DtlsSeq)1 << (*next - cur - 1));
    }
    else {
        *window <<= (1 + cur - *next);
        *window |= 1;
        *next = cur + 1;
    }

    return 1;
}


static int DtlsMsgDrain(WOLFSSL* ssl)
{
    DtlsMsg* item = ssl->dtls_msg_list;
    int ret = 0;

    /* While there is an item in the store list, and it is the expected
     * message, and it is complete, and there hasn't been an error in the
     * last messge... */
    while (item != NULL &&
            ssl->keys.dtls_expected_peer_handshake_number == item->seq &&
            item->fragSz == item->sz &&
            ret == 0) {
        word32 idx = 0;
        ssl->keys.dtls_expected_peer_handshake_number++;
        ret = DoHandShakeMsgType(ssl, item->msg,
                                 &idx, item->type, item->sz, item->sz);
        ssl->dtls_msg_list = item->next;
        DtlsMsgDelete(item, ssl->heap);
        item = ssl->dtls_msg_list;
    }

    return ret;
}


static int DoDtlsHandShakeMsg(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                          word32 totalSz)
{
    byte type;
    word32 size;
    word32 fragOffset, fragSz;
    int ret = 0;

    if (GetDtlsHandShakeHeader(ssl, input, inOutIdx, &type,
                               &size, &fragOffset, &fragSz, totalSz) != 0)
        return PARSE_ERROR;

    if (*inOutIdx + fragSz > totalSz)
        return INCOMPLETE_DATA;

    /* Check the handshake sequence number first. If out of order,
     * add the current message to the list. If the message is in order,
     * but it is a fragment, add the current message to the list, then
     * check the head of the list to see if it is complete, if so, pop
     * it out as the current message. If the message is complete and in
     * order, process it. Check the head of the list to see if it is in
     * order, if so, process it. (Repeat until list exhausted.) If the
     * head is out of order, return for more processing.
     */
    if (ssl->keys.dtls_peer_handshake_number >
                                ssl->keys.dtls_expected_peer_handshake_number) {
        /* Current message is out of order. It will get stored in the list.
         * Storing also takes care of defragmentation. */
        ssl->dtls_msg_list = DtlsMsgStore(ssl->dtls_msg_list,
                        ssl->keys.dtls_peer_handshake_number, input + *inOutIdx,
                        size, type, fragOffset, fragSz, ssl->heap);
        *inOutIdx += fragSz;
        ret = 0;
    }
    else if (ssl->keys.dtls_peer_handshake_number <
                                ssl->keys.dtls_expected_peer_handshake_number) {
        /* Already saw this message and processed it. It can be ignored. */
        *inOutIdx += fragSz;
        ret = 0;
    }
    else if (fragSz < size) {
        /* Since this branch is in order, but fragmented, dtls_msg_list will be
         * pointing to the message with this fragment in it. Check it to see
         * if it is completed. */
        ssl->dtls_msg_list = DtlsMsgStore(ssl->dtls_msg_list,
                        ssl->keys.dtls_peer_handshake_number, input + *inOutIdx,
                        size, type, fragOffset, fragSz, ssl->heap);
        *inOutIdx += fragSz;
        ret = 0;
        if (ssl->dtls_msg_list != NULL &&
            ssl->dtls_msg_list->fragSz >= ssl->dtls_msg_list->sz)
            ret = DtlsMsgDrain(ssl);
    }
    else {
        /* This branch is in order next, and a complete message. */
        ssl->keys.dtls_expected_peer_handshake_number++;
        ret = DoHandShakeMsgType(ssl, input, inOutIdx, type, size, totalSz);
        if (ret == 0 && ssl->dtls_msg_list != NULL)
            ret = DtlsMsgDrain(ssl);
    }

    WOLFSSL_LEAVE( ret);
    return ret;
}
#endif


#if 1//!defined(NO_OLD_TLS) || defined(HAVE_CHACHA) || defined(HAVE_AESCCM) || defined(HAVE_AESGCM)
word32 GetSEQIncrement(WOLFSSL* ssl, int verify)
{
#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        if (verify)
            return ssl->keys.dtls_state.curSeq; /* explicit from peer */
        else
            return ssl->keys.dtls_sequence_number - 1; /* already incremented */
    }
#endif
    if (verify)
        return ssl->keys.peer_sequence_number++;
    else
        return ssl->keys.sequence_number++;
}
#endif


#ifdef HAVE_AEAD
static INLINE void AeadIncrementExpIV(WOLFSSL* ssl)
{
    int i;
    for (i = AEAD_EXP_IV_SZ-1; i >= 0; i--) {
        if (++ssl->keys.aead_exp_IV[i]) return;
    }
}


#if defined(HAVE_POLY1305) && defined(HAVE_CHACHA)
/*more recent rfc's concatonate input for poly1305 differently*/
static int Poly1305Tag(WOLFSSL* ssl, byte* additional, const byte* out,
                       byte* cipher, word16 sz, byte* tag)
{
    int ret       = 0;
    int paddingSz = 0;
    int msglen    = (sz - ssl->specs.aead_mac_size);
    word32 keySz  = 32;
    int blockSz   = 16;
    byte padding[16];

    if (msglen < 0)
        return INPUT_CASE_ERROR;

    XMEMSET(padding, 0, sizeof(padding));

    if ((ret = wc_Poly1305SetKey(ssl->auth.poly1305, cipher, keySz)) != 0)
        return ret;

    /* additional input to poly1305 */
    if ((ret = wc_Poly1305Update(ssl->auth.poly1305, additional, blockSz)) != 0)
        return ret;

    /* cipher input */
    if ((ret = wc_Poly1305Update(ssl->auth.poly1305, out, msglen)) != 0)
        return ret;

    /* handle padding for cipher input to make it 16 bytes long */
    if (msglen % 16 != 0) {
          paddingSz = (16 - (sz - ssl->specs.aead_mac_size) % 16);
          if (paddingSz < 0)
              return INPUT_CASE_ERROR;

          if ((ret = wc_Poly1305Update(ssl->auth.poly1305, padding, paddingSz))
                 != 0)
              return ret;
    }

    /* add size of AD and size of cipher to poly input */
    XMEMSET(padding, 0, sizeof(padding));
    padding[0] = blockSz;

    /* 32 bit size of cipher to 64 bit endian */
    padding[8]  =  msglen       & 0xff;
    padding[9]  = (msglen >> 8) & 0xff;
    padding[10] = (msglen >>16) & 0xff;
    padding[11] = (msglen >>24) & 0xff;
    if ((ret = wc_Poly1305Update(ssl->auth.poly1305, padding, sizeof(padding)))
                != 0)
        return ret;

    /* generate tag */
    if ((ret = wc_Poly1305Final(ssl->auth.poly1305, tag)) != 0)
        return ret;

    return ret;
}


/* Used for the older version of creating AEAD tags with Poly1305 */
static int Poly1305TagOld(WOLFSSL* ssl, byte* additional, const byte* out,
                       byte* cipher, word16 sz, byte* tag)
{
    int ret       = 0;
    int msglen    = (sz - ssl->specs.aead_mac_size);
    word32 keySz  = 32;
    byte padding[8]; /* used to temporarly store lengths */

#ifdef CHACHA_AEAD_TEST
      printf("Using old version of poly1305 input.\n");
#endif

    if (msglen < 0)
        return INPUT_CASE_ERROR;

    if ((ret = wc_Poly1305SetKey(ssl->auth.poly1305, cipher, keySz)) != 0)
        return ret;

    /* add TLS compressed length and additional input to poly1305 */
    additional[AEAD_AUTH_DATA_SZ - 2] = (msglen >> 8) & 0xff;
    additional[AEAD_AUTH_DATA_SZ - 1] =  msglen       & 0xff;
    if ((ret = wc_Poly1305Update(ssl->auth.poly1305, additional,
                   AEAD_AUTH_DATA_SZ)) != 0)
        return ret;

    /* length of additional input plus padding */
    XMEMSET(padding, 0, sizeof(padding));
    padding[0] = AEAD_AUTH_DATA_SZ;
    if ((ret = wc_Poly1305Update(ssl->auth.poly1305, padding,
                    sizeof(padding))) != 0)
        return ret;


    /* add cipher info and then its length */
    XMEMSET(padding, 0, sizeof(padding));
    if ((ret = wc_Poly1305Update(ssl->auth.poly1305, out, msglen)) != 0)
        return ret;

    /* 32 bit size of cipher to 64 bit endian */
    padding[0] =  msglen        & 0xff;
    padding[1] = (msglen >>  8) & 0xff;
    padding[2] = (msglen >> 16) & 0xff;
    padding[3] = (msglen >> 24) & 0xff;
    if ((ret = wc_Poly1305Update(ssl->auth.poly1305, padding, sizeof(padding)))
        != 0)
        return ret;

    /* generate tag */
    if ((ret = wc_Poly1305Final(ssl->auth.poly1305, tag)) != 0)
        return ret;

    return ret;
}


static int  ChachaAEADEncrypt(WOLFSSL* ssl, byte* out, const byte* input,
                              word16 sz)
{
    const byte* additionalSrc = input - RECORD_HEADER_SZ;
    int ret = 0;
    byte tag[POLY1305_AUTH_SZ];
    byte additional[CHACHA20_BLOCK_SIZE];
    byte nonce[AEAD_NONCE_SZ];
    byte cipher[CHACHA20_256_KEY_SIZE]; /* generated key for poly1305 */
    #ifdef CHACHA_AEAD_TEST
        int i;
    #endif

    XMEMSET(tag, 0, sizeof(tag));
    XMEMSET(nonce, 0, AEAD_NONCE_SZ);
    XMEMSET(cipher, 0, sizeof(cipher));
    XMEMSET(additional, 0, CHACHA20_BLOCK_SIZE);

    /* get nonce */
    c32toa(ssl->keys.sequence_number, nonce + AEAD_IMP_IV_SZ
           + AEAD_SEQ_OFFSET);

    /* opaque SEQ number stored for AD */
    c32toa(GetSEQIncrement(ssl, 0), additional + AEAD_SEQ_OFFSET);

    /* Store the type, version. Unfortunately, they are in
     * the input buffer ahead of the plaintext. */
    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            c16toa(ssl->keys.dtls_epoch, additional);
            additionalSrc -= DTLS_HANDSHAKE_EXTRA;
        }
    #endif

    XMEMCPY(additional + AEAD_TYPE_OFFSET, additionalSrc, 3);

    #ifdef CHACHA_AEAD_TEST
        printf("Encrypt Additional : ");
        for (i = 0; i < CHACHA20_BLOCK_SIZE; i++) {
            printf("%02x", additional[i]);
        }
        printf("\n\n");
        printf("input before encryption :\n");
        for (i = 0; i < sz; i++) {
            printf("%02x", input[i]);
            if ((i + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n");
    #endif

    /* set the nonce for chacha and get poly1305 key */
    if ((ret = wc_Chacha_SetIV(ssl->encrypt.chacha, nonce, 0)) != 0)
        return ret;

        if ((ret = wc_Chacha_Process(ssl->encrypt.chacha, cipher,
                    cipher, sizeof(cipher))) != 0)
        return ret;

    /* encrypt the plain text */
    if ((ret = wc_Chacha_Process(ssl->encrypt.chacha, out, input,
                   sz - ssl->specs.aead_mac_size)) != 0)
        return ret;

    /* get the tag : future use of hmac could go here*/
    if (ssl->options.oldPoly == 1) {
        if ((ret = Poly1305TagOld(ssl, additional, (const byte* )out,
                    cipher, sz, tag)) != 0)
            return ret;
    }
    else {
        if ((ret = Poly1305Tag(ssl, additional, (const byte* )out,
                    cipher, sz, tag)) != 0)
            return ret;
    }

    /* append tag to ciphertext */
    XMEMCPY(out + sz - ssl->specs.aead_mac_size, tag, sizeof(tag));

    AeadIncrementExpIV(ssl);
    ForceZero(nonce, AEAD_NONCE_SZ);

    #ifdef CHACHA_AEAD_TEST
       printf("mac tag :\n");
        for (i = 0; i < 16; i++) {
           printf("%02x", tag[i]);
           if ((i + 1) % 16 == 0)
               printf("\n");
        }
       printf("\n\noutput after encrypt :\n");
        for (i = 0; i < sz; i++) {
           printf("%02x", out[i]);
           if ((i + 1) % 16 == 0)
               printf("\n");
        }
        printf("\n");
    #endif

    return ret;
}


static int ChachaAEADDecrypt(WOLFSSL* ssl, byte* plain, const byte* input,
                           word16 sz)
{
    byte additional[CHACHA20_BLOCK_SIZE];
    byte nonce[AEAD_NONCE_SZ];
    byte tag[POLY1305_AUTH_SZ];
    byte cipher[CHACHA20_256_KEY_SIZE]; /* generated key for mac */
    int ret = 0;

    XMEMSET(tag, 0, sizeof(tag));
    XMEMSET(cipher, 0, sizeof(cipher));
    XMEMSET(nonce, 0, AEAD_NONCE_SZ);
    XMEMSET(additional, 0, CHACHA20_BLOCK_SIZE);

    #ifdef CHACHA_AEAD_TEST
       int i;
       printf("input before decrypt :\n");
        for (i = 0; i < sz; i++) {
           printf("%02x", input[i]);
           if ((i + 1) % 16 == 0)
               printf("\n");
        }
        printf("\n");
    #endif

    /* get nonce */
    c32toa(ssl->keys.peer_sequence_number, nonce + AEAD_IMP_IV_SZ
            + AEAD_SEQ_OFFSET);

    /* sequence number field is 64-bits, we only use 32-bits */
    c32toa(GetSEQIncrement(ssl, 1), additional + AEAD_SEQ_OFFSET);

    /* get AD info */
    additional[AEAD_TYPE_OFFSET] = ssl->curRL.type;
    additional[AEAD_VMAJ_OFFSET] = ssl->curRL.pvMajor;
    additional[AEAD_VMIN_OFFSET] = ssl->curRL.pvMinor;

    /* Store the type, version. */
    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls)
            c16toa(ssl->keys.dtls_state.curEpoch, additional);
    #endif

    #ifdef CHACHA_AEAD_TEST
        printf("Decrypt Additional : ");
        for (i = 0; i < CHACHA20_BLOCK_SIZE; i++) {
            printf("%02x", additional[i]);
        }
        printf("\n\n");
    #endif

    /* set nonce and get poly1305 key */
    if ((ret = wc_Chacha_SetIV(ssl->decrypt.chacha, nonce, 0)) != 0)
        return ret;

    if ((ret = wc_Chacha_Process(ssl->decrypt.chacha, cipher,
                    cipher, sizeof(cipher))) != 0)
        return ret;

    /* get the tag : future use of hmac could go here*/
    if (ssl->options.oldPoly == 1) {
        if ((ret = Poly1305TagOld(ssl, additional, input, cipher,
                        sz, tag)) != 0)
            return ret;
    }
    else {
        if ((ret = Poly1305Tag(ssl, additional, input, cipher,
                        sz, tag)) != 0)
            return ret;
    }

    /* check mac sent along with packet */
    if (ConstantCompare(input + sz - ssl->specs.aead_mac_size, tag,
                ssl->specs.aead_mac_size) != 0) {
        WOLFSSL_MSG("Mac did not match");
        SendAlert(ssl, alert_fatal, bad_record_mac);
        ForceZero(nonce, AEAD_NONCE_SZ);
        return VERIFY_MAC_ERROR;
    }

    /* if mac was good decrypt message */
    if ((ret = wc_Chacha_Process(ssl->decrypt.chacha, plain, input,
                   sz - ssl->specs.aead_mac_size)) != 0)
        return ret;

    #ifdef CHACHA_AEAD_TEST
       printf("plain after decrypt :\n");
        for (i = 0; i < sz; i++) {
           printf("%02x", plain[i]);
           if ((i + 1) % 16 == 0)
               printf("\n");
        }
        printf("\n");
    #endif

    return ret;
}
#endif /* HAVE_CHACHA && HAVE_POLY1305 */
#endif /* HAVE_AEAD */

/* called after received application data */
int DoApplicationData(WOLFSSL* ssl, byte* input, word32* inOutIdx)
{
	word32 msgSz   = ssl->keys.encryptSz;
	word32 idx     = *inOutIdx;
	int    dataSz;
	int    ivExtra = 0;
	byte*  rawData = input + idx;  /* keep current  for hmac */
#ifdef HAVE_LIBZ
	byte   decomp[MAX_RECORD_SIZE + MAX_COMP_EXTRA];
#endif

	if (ssl->options.handShakeDone == 0) {
		WOLFSSL_MSG("Received App data before a handshake completed");
		SendAlert(ssl, alert_fatal, unexpected_message);
		return OUT_OF_ORDER_E;
	}

	if (ssl->specs.cipher_type == block)
	{
		if (ssl->options.tls1_1)
			ivExtra = ssl->specs.block_size;
	}
	else if (ssl->specs.cipher_type == aead) {
		if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
			ivExtra = AEAD_EXP_IV_SZ;
	}

	dataSz = msgSz - ivExtra - ssl->keys.padSz;
	if (dataSz < 0) {
		WOLFSSL_MSG("App data buffer error, malicious input?");
		return BUFFER_ERROR;
	}

	/* read data */
	if (dataSz) {
		int rawSz = dataSz;       /* keep raw size for idx adjustment */

#ifdef HAVE_LIBZ
		if (ssl->options.usingCompression) {
			dataSz = myDeCompress(ssl, rawData, dataSz, decomp, sizeof(decomp));
			if (dataSz < 0) return dataSz;
		}
#endif
		idx += rawSz;

		ssl->buffers.clearOutputBuffer.buffer = rawData;
		ssl->buffers.clearOutputBuffer.length = dataSz;
	}

	idx += ssl->keys.padSz;

#ifdef HAVE_LIBZ
	/* decompress could be bigger, overwrite after verify */
	if (ssl->options.usingCompression)
		XMEMMOVE(rawData, decomp, dataSz);
#endif

	*inOutIdx = idx;
	return 0;
}


void PickHashSigAlgo(WOLFSSL* ssl, const byte* hashSigAlgo, word32 hashSigAlgoSz)
{
    word32 i;

    ssl->suites->sigAlgo = ssl->specs.sig_algo;
    ssl->suites->hashAlgo = sha_mac;

    /* i+1 since peek a byte ahead for type */
    for (i = 0; (i+1) < hashSigAlgoSz; i += 2) {
        if (hashSigAlgo[i+1] == ssl->specs.sig_algo) {
            if (hashSigAlgo[i] == sha_mac) {
                break;
            }
            #ifndef NO_SHA256
            else if (hashSigAlgo[i] == sha256_mac) {
                ssl->suites->hashAlgo = sha256_mac;
                break;
            }
            #endif
            #ifdef WOLFSSL_SHA384
            else if (hashSigAlgo[i] == sha384_mac) {
                ssl->suites->hashAlgo = sha384_mac;
                break;
            }
            #endif
            #ifdef WOLFSSL_SHA512
            else if (hashSigAlgo[i] == sha512_mac) {
                ssl->suites->hashAlgo = sha512_mac;
                break;
            }
            #endif
        }
    }
}


