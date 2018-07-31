/* API declarations for SSL internal modules
 */


#ifndef __WSI_APIS_H__
#define __WSI_APIS_H__

#ifdef __cplusplus
    extern "C" {
#endif

WOLFSSL_LOCAL ProtocolVersion MakeSSLv3(void);
WOLFSSL_LOCAL ProtocolVersion MakeTLSv1(void);
WOLFSSL_LOCAL ProtocolVersion MakeTLSv1_1(void);
WOLFSSL_LOCAL ProtocolVersion MakeTLSv1_2(void);

#ifdef WOLFSSL_DTLS
    WOLFSSL_LOCAL ProtocolVersion MakeDTLSv1(void);
    WOLFSSL_LOCAL ProtocolVersion MakeDTLSv1_2(void);
#endif


WOLFSSL_LOCAL int CM_SaveCertCache(WOLFSSL_CERT_MANAGER*, const char*);
WOLFSSL_LOCAL int CM_RestoreCertCache(WOLFSSL_CERT_MANAGER*, const char*);
WOLFSSL_LOCAL int CM_MemSaveCertCache(WOLFSSL_CERT_MANAGER*, void*, int, int*);
WOLFSSL_LOCAL int CM_MemRestoreCertCache(WOLFSSL_CERT_MANAGER*, const void*, int);
WOLFSSL_LOCAL int CM_GetCertCacheMemSize(WOLFSSL_CERT_MANAGER*);

#ifdef HAVE_TLS_EXTENSIONS
WOLFSSL_LOCAL TLSX*  TLSX_Find(TLSX* list, TLSX_Type type);
WOLFSSL_LOCAL void   TLSX_FreeAll(TLSX* list);
WOLFSSL_LOCAL int    TLSX_SupportExtensions(WOLFSSL* ssl);

#ifndef NO_WOLFSSL_CLIENT
WOLFSSL_LOCAL word16 TLSX_GetRequestSize(WOLFSSL* ssl);
WOLFSSL_LOCAL word16 TLSX_WriteRequest(WOLFSSL* ssl, byte* output);
#endif

#ifndef NO_WOLFSSL_SERVER
WOLFSSL_LOCAL word16 TLSX_GetResponseSize(WOLFSSL* ssl);
WOLFSSL_LOCAL word16 TLSX_WriteResponse(WOLFSSL* ssl, byte* output);
#endif

WOLFSSL_LOCAL int    TLSX_Parse(WOLFSSL* ssl, byte* input, word16 length,
                                                byte isRequest, Suites *suites);


WOLFSSL_LOCAL int TLSX_UseSNI(TLSX** extensions, byte type, const void* data, word16 size);

#ifndef NO_WOLFSSL_SERVER
WOLFSSL_LOCAL void   TLSX_SNI_SetOptions(TLSX* extensions, byte type, byte options);
WOLFSSL_LOCAL byte   TLSX_SNI_Status(TLSX* extensions, byte type);
WOLFSSL_LOCAL word16 TLSX_SNI_GetRequest(TLSX* extensions, byte type, void** data);
WOLFSSL_LOCAL int    TLSX_SNI_GetFromBuffer(const byte* buffer, word32 bufferSz, byte type, byte* sni, word32* inOutSz);
#endif

/* Maximum Fragment Length */
#ifdef HAVE_MAX_FRAGMENT
WOLFSSL_LOCAL int TLSX_UseMaxFragment(TLSX** extensions, byte mfl);
#endif /* HAVE_MAX_FRAGMENT */

#ifdef HAVE_TRUNCATED_HMAC
WOLFSSL_LOCAL int TLSX_UseTruncatedHMAC(TLSX** extensions);
#endif /* HAVE_TRUNCATED_HMAC */


WOLFSSL_LOCAL int TLSX_UseSupportedCurve(TLSX** extensions, word16 name);

#ifndef NO_WOLFSSL_SERVER
WOLFSSL_LOCAL int TLSX_ValidateEllipticCurves(WOLFSSL* ssl, byte first, byte second);
#endif

WOLFSSL_LOCAL int TLSX_UseSecureRenegotiation(TLSX** extensions);


#ifdef HAVE_SESSION_TICKET

WOLFSSL_LOCAL int  TLSX_UseSessionTicket(TLSX** extensions, SessionTicket* ticket);
WOLFSSL_LOCAL SessionTicket* TLSX_SessionTicket_Create(word32 lifetime, byte* data, word16 size);
WOLFSSL_LOCAL void TLSX_SessionTicket_Free(SessionTicket* ticket);
#endif /* HAVE_SESSION_TICKET */

#endif	/* TLS extension */


WOLFSSL_LOCAL void InitCiphers(WOLFSSL* ssl);
WOLFSSL_LOCAL void FreeCiphers(WOLFSSL* ssl);


WOLFSSL_LOCAL int  InitSSL(WOLFSSL*, WOLFSSL_CTX*);
WOLFSSL_LOCAL void FreeSSL(WOLFSSL*);
WOLFSSL_API void SSL_ResourceFree(WOLFSSL*);   /* Micrium uses */


/* internal functions */
WOLFSSL_LOCAL int SendChangeCipher(WOLFSSL*);
WOLFSSL_LOCAL int SendTicket(WOLFSSL*);
WOLFSSL_LOCAL int DoClientTicket(WOLFSSL*, const byte*, word32);
WOLFSSL_LOCAL int SendCertificate(WOLFSSL*);
WOLFSSL_LOCAL int SendCertificateRequest(WOLFSSL*);
WOLFSSL_LOCAL int SendServerKeyExchange(WOLFSSL*);
WOLFSSL_LOCAL int SendBuffered(WOLFSSL*);
WOLFSSL_LOCAL int SendFinished(WOLFSSL*);
WOLFSSL_LOCAL int SendAlert(WOLFSSL*, int, int);
WOLFSSL_LOCAL int ProcessReply(WOLFSSL*);

WOLFSSL_LOCAL int SetCipherSpecs(WOLFSSL*);
WOLFSSL_LOCAL int MakeMasterSecret(WOLFSSL*);

WOLFSSL_LOCAL int  AddSession(WOLFSSL*);
WOLFSSL_LOCAL int  DeriveKeys(WOLFSSL* ssl);
WOLFSSL_LOCAL int  StoreKeys(WOLFSSL* ssl, const byte* keyData);

WOLFSSL_LOCAL int IsTLS(const WOLFSSL* ssl);
WOLFSSL_LOCAL int IsAtLeastTLSv1_2(const WOLFSSL* ssl);

WOLFSSL_LOCAL void FreeHandshakeResources(WOLFSSL* ssl);
WOLFSSL_LOCAL void ShrinkInputBuffer(WOLFSSL* ssl, int forcedFree);
WOLFSSL_LOCAL void ShrinkOutputBuffer(WOLFSSL* ssl);

WOLFSSL_LOCAL int VerifyClientSuite(WOLFSSL* ssl);
#ifndef NO_CERTS
    WOLFSSL_LOCAL Signer* GetCA(void* cm, byte* hash);
    #ifndef NO_SKID
        WOLFSSL_LOCAL Signer* GetCAByName(void* cm, byte* hash);
    #endif
#endif
WOLFSSL_LOCAL int  BuildTlsFinished(WOLFSSL* ssl, Hashes* hashes,
                                   const byte* sender);
WOLFSSL_LOCAL void FreeArrays(WOLFSSL* ssl, int keep);
WOLFSSL_LOCAL  int CheckAvailableSize(WOLFSSL *ssl, int size);
WOLFSSL_LOCAL  int GrowInputBuffer(WOLFSSL* ssl, int size, int usedLength);

#ifndef NO_TLS
    WOLFSSL_LOCAL int  MakeTlsMasterSecret(WOLFSSL*);
    WOLFSSL_LOCAL int  TLS_hmac(WOLFSSL* ssl, byte* digest, const byte* in,
                               word32 sz, int content, int verify);
#endif

#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_LOCAL int SendClientHello(WOLFSSL*);
    WOLFSSL_LOCAL int SendClientKeyExchange(WOLFSSL*);
    WOLFSSL_LOCAL int SendCertificateVerify(WOLFSSL*);
#endif /* NO_WOLFSSL_CLIENT */

#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_LOCAL int SendServerHello(WOLFSSL*);
    WOLFSSL_LOCAL int SendServerHelloDone(WOLFSSL*);
    #ifdef WOLFSSL_DTLS
        WOLFSSL_LOCAL int SendHelloVerifyRequest(WOLFSSL*);
    #endif
#endif /* NO_WOLFSSL_SERVER */

#ifdef WOLFSSL_DTLS
    WOLFSSL_LOCAL int  DtlsPoolInit(WOLFSSL*);
    WOLFSSL_LOCAL int  DtlsPoolSave(WOLFSSL*, const byte*, int);
    WOLFSSL_LOCAL int  DtlsPoolTimeout(WOLFSSL*);
    WOLFSSL_LOCAL int  DtlsPoolSend(WOLFSSL*);
    WOLFSSL_LOCAL void DtlsPoolReset(WOLFSSL*);

    WOLFSSL_LOCAL DtlsMsg* DtlsMsgNew(word32, void*);
    WOLFSSL_LOCAL void DtlsMsgDelete(DtlsMsg*, void*);
    WOLFSSL_LOCAL void DtlsMsgListDelete(DtlsMsg*, void*);
    WOLFSSL_LOCAL void DtlsMsgSet(DtlsMsg*, word32, const byte*, byte,
                                                             word32, word32);
    WOLFSSL_LOCAL DtlsMsg* DtlsMsgFind(DtlsMsg*, word32);
    WOLFSSL_LOCAL DtlsMsg* DtlsMsgStore(DtlsMsg*, word32, const byte*, word32,
                                                byte, word32, word32, void*);
    WOLFSSL_LOCAL DtlsMsg* DtlsMsgInsert(DtlsMsg*, DtlsMsg*);
#endif /* WOLFSSL_DTLS */

#ifndef NO_TLS
    

#endif /* NO_TLS */


WOLFSSL_LOCAL word32  LowResTimer(void);

WOLFSSL_LOCAL void InitX509Name(WOLFSSL_X509_NAME*, int);
WOLFSSL_LOCAL void FreeX509Name(WOLFSSL_X509_NAME* name);
WOLFSSL_LOCAL void InitX509(WOLFSSL_X509*, int);
WOLFSSL_LOCAL void FreeX509(WOLFSSL_X509*);
#ifndef NO_CERTS
    WOLFSSL_LOCAL int  CopyDecodedToX509(WOLFSSL_X509*, DecodedCert*);
#endif

/* used by ssl.c and wolfssl_int.c */
WOLFSSL_LOCAL void c32to24(word32 in, word24 out);

WOLFSSL_LOCAL const char* const* GetCipherNames(void);
WOLFSSL_LOCAL int GetCipherNamesSize(void);



WOLFSSL_LOCAL WOLFSSL_SESSION* GetSession(WOLFSSL*, byte*);
WOLFSSL_LOCAL int          SetSession(WOLFSSL*, WOLFSSL_SESSION*);

#ifndef NO_CLIENT_CACHE
    WOLFSSL_SESSION* GetSessionClient(WOLFSSL*, const byte*, int);
#endif
#ifndef NO_CERTS
    WOLFSSL_LOCAL int PemToDer(const unsigned char* buff, long sz, int type,
                              buffer* der, void* heap, EncryptedInfo* info,
                              int* eccKey);

    WOLFSSL_LOCAL int ProcessFile(WOLFSSL_CTX* ctx, const char* fname, int format,
                                 int type, WOLFSSL* ssl, int userChain,
                                WOLFSSL_CRL* crl);
#endif


#ifdef WOLFSSL_CALLBACKS
    WOLFSSL_LOCAL void InitHandShakeInfo(HandShakeInfo*);
    WOLFSSL_LOCAL void FinishHandShakeInfo(HandShakeInfo*, const WOLFSSL*);
    WOLFSSL_LOCAL void AddPacketName(const char*, HandShakeInfo*);

    WOLFSSL_LOCAL  void InitTimeoutInfo(TimeoutInfo*);
    WOLFSSL_LOCAL void FreeTimeoutInfo(TimeoutInfo*, void*);
    WOLFSSL_LOCAL void AddPacketInfo(const char*, TimeoutInfo*, const byte*, int, void*);
    WOLFSSL_LOCAL void AddLateName(const char*, TimeoutInfo*);
    WOLFSSL_LOCAL void AddLateRecordHeader(const RecordLayerHeader* rl, TimeoutInfo* info);
#endif


WOLFSSL_LOCAL int InitSSL_Ctx(WOLFSSL_CTX*, WOLFSSL_METHOD*);
WOLFSSL_LOCAL void FreeSSL_Ctx(WOLFSSL_CTX*);
WOLFSSL_LOCAL void SSL_CtxResourceFree(WOLFSSL_CTX*);

WOLFSSL_LOCAL int DeriveTlsKeys(WOLFSSL* ssl);
WOLFSSL_LOCAL int ProcessOldClientHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                          word32 inSz, word16 sz);
#ifndef NO_CERTS
    WOLFSSL_LOCAL int AddCA(WOLFSSL_CERT_MANAGER* ctx, buffer der, int type, int verify);
    WOLFSSL_LOCAL
    int AlreadySigner(WOLFSSL_CERT_MANAGER* cm, byte* hash);
#endif

WOLFSSL_LOCAL int SetKeysSide(WOLFSSL*, enum encrypt_side);


int BuildMessage(WOLFSSL* ssl, byte* output, int outSz, const byte* input, int inSz, int type);

#ifndef NO_WOLFSSL_CLIENT
    int _doHelloVerifyRequest(WOLFSSL* ssl, const byte* input, word32*,
                                                                        word32);
    int _doServerHello(WOLFSSL* ssl, const byte* input, word32*, word32);
    int _doServerKeyExchange(WOLFSSL* ssl, const byte* input, word32*,
                                                                        word32);
    #ifndef NO_CERTS
        int _doCertificateRequest(WOLFSSL* ssl, const byte* input, word32*,
                                                                        word32);
    #endif
    #ifdef HAVE_SESSION_TICKET
        int DoSessionTicket(WOLFSSL* ssl, const byte* input, word32*, word32);
    #endif
#endif


#ifndef NO_WOLFSSL_SERVER
    int _doClientHello(WOLFSSL* ssl, const byte* input, word32*, word32);
    int _doClientKeyExchange(WOLFSSL* ssl, byte* input, word32*, word32);
    #if !defined(NO_RSA) || defined(HAVE_ECC)
        int _doCertificateVerify(WOLFSSL* ssl, byte*, word32*, word32);
    #endif
#endif


#ifdef WOLFSSL_DTLS
    INLINE int DtlsCheckWindow(DtlsState* state);
    INLINE int DtlsUpdateWindow(DtlsState* state);
#endif

#ifndef NO_OLD_TLS
int SSL_hmac(WOLFSSL* ssl, byte* digest, const byte* in, word32 sz, int content, int verify);
#endif


/* for sniffer */
WOLFSSL_LOCAL int DoFinished(WOLFSSL* ssl, const byte* input, word32* inOutIdx, word32 size, word32 totalSz, int sniff);
WOLFSSL_LOCAL int DoApplicationData(WOLFSSL* ssl, byte* input, word32* inOutIdx);


#ifndef NO_CERTS
int BuildCertHashes(WOLFSSL* ssl, Hashes* hashes);
#endif

void PickHashSigAlgo(WOLFSSL* ssl, const byte* hashSigAlgo, word32 hashSigAlgoSz);


WOLFSSL_LOCAL void InitSuites(Suites*, ProtocolVersion, word16, word16, word16, word16, word16, word16, int);

#ifdef HAVE_NETX
    WOLFSSL_LOCAL int NetX_Receive(WOLFSSL *ssl, char *buf, int sz, void *ctx);
    WOLFSSL_LOCAL int NetX_Send(WOLFSSL *ssl, char *buf, int sz, void *ctx);
#endif /* HAVE_NETX */



void AddRecordHeader(byte* output, word32 length, HAND_SHAKE_TYPE_T type, WOLFSSL* ssl);
void AddHeaders(byte	*output, word32 length, HAND_SHAKE_TYPE_T type, WOLFSSL* ssl);
int CipherRequires(byte first, byte second, int requirement);
word32 GetSEQIncrement(WOLFSSL* ssl, int verify);
int HashOutput(WOLFSSL* ssl, const byte* output, int sz, int ivSz);

int Encrypt(WOLFSSL* ssl, byte* out, const byte* input, word16 sz);



#ifdef HAVE_OCSP
WOLFSSL_LOCAL int  InitOCSP(WOLFSSL_OCSP*, WOLFSSL_CERT_MANAGER*);
WOLFSSL_LOCAL void FreeOCSP(WOLFSSL_OCSP*, int dynamic);
WOLFSSL_LOCAL int  CheckCertOCSP(WOLFSSL_OCSP*, DecodedCert*);
#endif


#ifdef __cplusplus
    }
#endif

#endif

