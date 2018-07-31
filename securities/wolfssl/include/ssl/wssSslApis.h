
/* wolfSSL API functions declarations */

#ifndef __WSS_SSL_APIS_H__
#define __WSS_SSL_APIS_H__


#ifdef __cplusplus
    extern "C" {
#endif


WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_server_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_client_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_server_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_client_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_server_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_client_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_server_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_client_method(void);

#ifdef WOLFSSL_DTLS
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_client_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_server_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_client_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_server_method(void);
#endif

#ifdef HAVE_POLY1305
    WOLFSSL_API int wolfSSL_use_old_poly(WOLFSSL*, int);
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)

WOLFSSL_API int wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX *ctx, const char*, int);
WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX*, const char*, int);
WOLFSSL_API int wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX*, const char*,
                                                const char*);
WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX *,
                                                     const char *file);
WOLFSSL_API int wolfSSL_CTX_use_RSAPrivateKey_file(WOLFSSL_CTX*, const char*, int);

WOLFSSL_API long wolfSSL_get_verify_depth(WOLFSSL* ssl);
WOLFSSL_API long wolfSSL_CTX_get_verify_depth(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_use_certificate_file(WOLFSSL*, const char*, int);
WOLFSSL_API int wolfSSL_use_PrivateKey_file(WOLFSSL*, const char*, int);
WOLFSSL_API int wolfSSL_use_certificate_chain_file(WOLFSSL*, const char *file);
WOLFSSL_API int wolfSSL_use_RSAPrivateKey_file(WOLFSSL*, const char*, int);

#ifdef WOLFSSL_DER_LOAD
    WOLFSSL_API int wolfSSL_CTX_der_load_verify_locations(WOLFSSL_CTX*,
                                                    const char*, int);
#endif

#ifdef HAVE_NTRU
    WOLFSSL_API int wolfSSL_CTX_use_NTRUPrivateKey_file(WOLFSSL_CTX*, const char*);
    /* load NTRU private key blob */
#endif

#ifndef WOLFSSL_PEMCERT_TODER_DEFINED
    WOLFSSL_API int wolfSSL_PemCertToDer(const char*, unsigned char*, int);
    #define WOLFSSL_PEMCERT_TODER_DEFINED
#endif

#endif /* !NO_FILESYSTEM && !NO_CERTS */


WOLFSSL_API WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD*);
WOLFSSL_API WOLFSSL* wolfSSL_new(WOLFSSL_CTX*);
WOLFSSL_API int  wolfSSL_set_fd (WOLFSSL*, int);
WOLFSSL_API char* wolfSSL_get_cipher_list(int priority);
WOLFSSL_API int  wolfSSL_get_ciphers(char*, int);
WOLFSSL_API int  wolfSSL_get_fd(const WOLFSSL*);
WOLFSSL_API void wolfSSL_set_using_nonblock(WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_get_using_nonblock(WOLFSSL*);
WOLFSSL_API int  wolfSSL_connect(WOLFSSL*);     /* please see note at top of README
                                             if you get an error from connect */
WOLFSSL_API int  wolfSSL_write(WOLFSSL*, const void*, int);
WOLFSSL_API int  wolfSSL_read(WOLFSSL*, void*, int);
WOLFSSL_API int  wolfSSL_peek(WOLFSSL*, void*, int);
WOLFSSL_API int  wolfSSL_accept(WOLFSSL*);
WOLFSSL_API void wolfSSL_CTX_free(WOLFSSL_CTX*);
WOLFSSL_API void wolfSSL_free(WOLFSSL*);
WOLFSSL_API int  wolfSSL_shutdown(WOLFSSL*);
WOLFSSL_API int  wolfSSL_send(WOLFSSL*, const void*, int sz, int flags);
WOLFSSL_API int  wolfSSL_recv(WOLFSSL*, void*, int sz, int flags);

WOLFSSL_API void wolfSSL_CTX_set_quiet_shutdown(WOLFSSL_CTX*, int);
WOLFSSL_API void wolfSSL_set_quiet_shutdown(WOLFSSL*, int);

WOLFSSL_API int  wolfSSL_get_error(WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_get_alert_history(WOLFSSL*, WOLFSSL_ALERT_HISTORY *);

WOLFSSL_API int        wolfSSL_set_session(WOLFSSL* ssl,WOLFSSL_SESSION* session);
WOLFSSL_API long       wolfSSL_SSL_SESSION_set_timeout(WOLFSSL_SESSION* session, long t);
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_get_session(WOLFSSL* ssl);
WOLFSSL_API void       wolfSSL_flush_sessions(WOLFSSL_CTX *ctx, long tm);
WOLFSSL_API int        wolfSSL_SetServerID(WOLFSSL* ssl, const unsigned char*,
                                         int, int);

#ifdef SESSION_INDEX
WOLFSSL_API int wolfSSL_GetSessionIndex(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_GetSessionAtIndex(int index, WOLFSSL_SESSION* session);
#endif /* SESSION_INDEX */

#if defined(SESSION_INDEX) && defined(SESSION_CERTS)
WOLFSSL_API
    WOLFSSL_X509_CHAIN* wolfSSL_SESSION_get_peer_chain(WOLFSSL_SESSION* session);
#endif /* SESSION_INDEX && SESSION_CERTS */

WOLFSSL_API void wolfSSL_CTX_set_verify(WOLFSSL_CTX*, int,
                                      VerifyCallback verify_callback);
WOLFSSL_API void wolfSSL_set_verify(WOLFSSL*, int, VerifyCallback verify_callback);
WOLFSSL_API void wolfSSL_SetCertCbCtx(WOLFSSL*, void*);

WOLFSSL_API int  wolfSSL_pending(WOLFSSL*);

WOLFSSL_API int  wolfSSL_library_init(void);
WOLFSSL_API long wolfSSL_CTX_set_session_cache_mode(WOLFSSL_CTX*, long);

#ifdef HAVE_SECRET_CALLBACK
WOLFSSL_API int  wolfSSL_set_session_secret_cb(WOLFSSL*, SessionSecretCb, void*);
#endif /* HAVE_SECRET_CALLBACK */

/* session cache persistence */
WOLFSSL_API int  wolfSSL_save_session_cache(const char*);
WOLFSSL_API int  wolfSSL_restore_session_cache(const char*);
WOLFSSL_API int  wolfSSL_memsave_session_cache(void*, int);
WOLFSSL_API int  wolfSSL_memrestore_session_cache(const void*, int);
WOLFSSL_API int  wolfSSL_get_session_cache_memsize(void);

/* certificate cache persistence, uses ctx since certs are per ctx */
WOLFSSL_API int  wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX*, const char*);
WOLFSSL_API int  wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX*, const char*);
WOLFSSL_API int  wolfSSL_CTX_memsave_cert_cache(WOLFSSL_CTX*, void*, int, int*);
WOLFSSL_API int  wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX*, const void*, int);
WOLFSSL_API int  wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX*);

/* only supports full name from cipher_name[] delimited by : */
WOLFSSL_API int  wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX*, const char*);
WOLFSSL_API int  wolfSSL_set_cipher_list(WOLFSSL*, const char*);

/* Nonblocking DTLS helper functions */
WOLFSSL_API int  wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int);
WOLFSSL_API int  wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int);
WOLFSSL_API int  wolfSSL_dtls_got_timeout(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_dtls(WOLFSSL* ssl);

WOLFSSL_API int  wolfSSL_dtls_set_peer(WOLFSSL*, void*, unsigned int);
WOLFSSL_API int  wolfSSL_dtls_get_peer(WOLFSSL*, void*, unsigned int*);

WOLFSSL_API int   wolfSSL_ERR_GET_REASON(int err);
WOLFSSL_API char* wolfSSL_ERR_error_string(unsigned long,char*);
WOLFSSL_API void  wolfSSL_ERR_error_string_n(unsigned long e, char* buf,
                                           unsigned long sz);


WOLFSSL_API int  wolfSSL_set_ex_data(WOLFSSL*, int, void*);
WOLFSSL_API int  wolfSSL_get_shutdown(const WOLFSSL*);
WOLFSSL_API int  wolfSSL_set_rfd(WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_set_wfd(WOLFSSL*, int);
WOLFSSL_API void wolfSSL_set_shutdown(WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_set_session_id_context(WOLFSSL*, const unsigned char*,
                                           unsigned int);
WOLFSSL_API void wolfSSL_set_connect_state(WOLFSSL*);
WOLFSSL_API void wolfSSL_set_accept_state(WOLFSSL*);
WOLFSSL_API int  wolfSSL_session_reused(WOLFSSL*);
WOLFSSL_API void wolfSSL_SESSION_free(WOLFSSL_SESSION* session);
WOLFSSL_API int  wolfSSL_is_init_finished(WOLFSSL*);

WOLFSSL_API const char*  wolfSSL_get_version(WOLFSSL*);
WOLFSSL_API int  wolfSSL_get_current_cipher_suite(WOLFSSL* ssl);
WOLFSSL_API WOLFSSL_CIPHER*  wolfSSL_get_current_cipher(WOLFSSL*);
WOLFSSL_API char*        wolfSSL_CIPHER_description(WOLFSSL_CIPHER*, char*, int);
WOLFSSL_API const char*  wolfSSL_CIPHER_get_name(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API const char*  wolfSSL_get_cipher(WOLFSSL*);
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_get1_session(WOLFSSL* ssl);
                           /* what's ref count */

WOLFSSL_API void wolfSSL_X509_free(WOLFSSL_X509*);
WOLFSSL_API void wolfSSL_OPENSSL_free(void*);

WOLFSSL_API int wolfSSL_OCSP_parse_url(char* url, char** host, char** port,
                                     char** path, int* ssl);

WOLFSSL_API WOLFSSL_METHOD* wolfSSLv23_client_method(void);
WOLFSSL_API WOLFSSL_METHOD* wolfSSLv2_client_method(void);
WOLFSSL_API WOLFSSL_METHOD* wolfSSLv2_server_method(void);

WOLFSSL_API void wolfSSL_MD4_Init(WOLFSSL_MD4_CTX*);
WOLFSSL_API void wolfSSL_MD4_Update(WOLFSSL_MD4_CTX*, const void*, unsigned long);
WOLFSSL_API void wolfSSL_MD4_Final(unsigned char*, WOLFSSL_MD4_CTX*);


WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new(WOLFSSL_BIO_METHOD*);
WOLFSSL_API int  wolfSSL_BIO_free(WOLFSSL_BIO*);
WOLFSSL_API int  wolfSSL_BIO_free_all(WOLFSSL_BIO*);
WOLFSSL_API int  wolfSSL_BIO_read(WOLFSSL_BIO*, void*, int);
WOLFSSL_API int  wolfSSL_BIO_write(WOLFSSL_BIO*, const void*, int);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_push(WOLFSSL_BIO*, WOLFSSL_BIO* append);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_pop(WOLFSSL_BIO*);
WOLFSSL_API int  wolfSSL_BIO_flush(WOLFSSL_BIO*);
WOLFSSL_API int  wolfSSL_BIO_pending(WOLFSSL_BIO*);

WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_buffer(void);
WOLFSSL_API long wolfSSL_BIO_set_write_buffer_size(WOLFSSL_BIO*, long size);
WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_ssl(void);
WOLFSSL_API WOLFSSL_BIO*        wolfSSL_BIO_new_socket(int sfd, int flag);
WOLFSSL_API int         wolfSSL_BIO_eof(WOLFSSL_BIO*);

WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_s_mem(void);
WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_base64(void);
WOLFSSL_API void wolfSSL_BIO_set_flags(WOLFSSL_BIO*, int);

WOLFSSL_API int wolfSSL_BIO_get_mem_data(WOLFSSL_BIO* bio,const unsigned char** p);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new_mem_buf(void* buf, int len);


WOLFSSL_API long        wolfSSL_BIO_set_ssl(WOLFSSL_BIO*, WOLFSSL*, int flag);
WOLFSSL_API void        wolfSSL_set_bio(WOLFSSL*, WOLFSSL_BIO* rd, WOLFSSL_BIO* wr);

WOLFSSL_API int  wolfSSL_add_all_algorithms(void);

WOLFSSL_API void        wolfSSL_RAND_screen(void);
WOLFSSL_API const char* wolfSSL_RAND_file_name(char*, unsigned long);
WOLFSSL_API int         wolfSSL_RAND_write_file(const char*);
WOLFSSL_API int         wolfSSL_RAND_load_file(const char*, long);
WOLFSSL_API int         wolfSSL_RAND_egd(const char*);
WOLFSSL_API int         wolfSSL_RAND_seed(const void*, int);
WOLFSSL_API void        wolfSSL_RAND_add(const void*, int, double);

WOLFSSL_API WOLFSSL_COMP_METHOD* wolfSSL_COMP_zlib(void);
WOLFSSL_API WOLFSSL_COMP_METHOD* wolfSSL_COMP_rle(void);
WOLFSSL_API int wolfSSL_COMP_add_compression_method(int, void*);

WOLFSSL_API int wolfSSL_get_ex_new_index(long, void*, void*, void*, void*);

WOLFSSL_API void wolfSSL_set_id_callback(unsigned long (*f)(void));
WOLFSSL_API void wolfSSL_set_locking_callback(void (*f)(int, int, const char*,
                                                      int));
WOLFSSL_API void wolfSSL_set_dynlock_create_callback(WOLFSSL_dynlock_value* (*f)
                                                   (const char*, int));
WOLFSSL_API void wolfSSL_set_dynlock_lock_callback(void (*f)(int,
                                      WOLFSSL_dynlock_value*, const char*, int));
WOLFSSL_API void wolfSSL_set_dynlock_destroy_callback(void (*f)
                                     (WOLFSSL_dynlock_value*, const char*, int));
WOLFSSL_API int  wolfSSL_num_locks(void);

WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get_current_cert(
                                                        WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API int   wolfSSL_X509_STORE_CTX_get_error(WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API int   wolfSSL_X509_STORE_CTX_get_error_depth(WOLFSSL_X509_STORE_CTX*);

WOLFSSL_API char*       wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME*, char*, int);
WOLFSSL_API WOLFSSL_X509_NAME*  wolfSSL_X509_get_issuer_name(WOLFSSL_X509*);
WOLFSSL_API WOLFSSL_X509_NAME*  wolfSSL_X509_get_subject_name(WOLFSSL_X509*);
WOLFSSL_API int  wolfSSL_X509_ext_isSet_by_NID(WOLFSSL_X509*, int);
WOLFSSL_API int  wolfSSL_X509_ext_get_critical_by_NID(WOLFSSL_X509*, int);
WOLFSSL_API int  wolfSSL_X509_get_isCA(WOLFSSL_X509*);
WOLFSSL_API int  wolfSSL_X509_get_isSet_pathLength(WOLFSSL_X509*);
WOLFSSL_API unsigned int wolfSSL_X509_get_pathLength(WOLFSSL_X509*);
WOLFSSL_API unsigned int wolfSSL_X509_get_keyUsage(WOLFSSL_X509*);
WOLFSSL_API unsigned char* wolfSSL_X509_get_authorityKeyID(
                                            WOLFSSL_X509*, unsigned char*, int*);
WOLFSSL_API unsigned char* wolfSSL_X509_get_subjectKeyID(
                                            WOLFSSL_X509*, unsigned char*, int*);
WOLFSSL_API int wolfSSL_X509_NAME_entry_count(WOLFSSL_X509_NAME*);
WOLFSSL_API int wolfSSL_X509_NAME_get_text_by_NID(
                                            WOLFSSL_X509_NAME*, int, char*, int);
WOLFSSL_API int         wolfSSL_X509_verify_cert(WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API const char* wolfSSL_X509_verify_cert_error_string(long);
WOLFSSL_API int wolfSSL_X509_get_signature_type(WOLFSSL_X509*);
WOLFSSL_API int wolfSSL_X509_get_signature(WOLFSSL_X509*, unsigned char*, int*);

WOLFSSL_API int wolfSSL_X509_LOOKUP_add_dir(WOLFSSL_X509_LOOKUP*,const char*,long);
WOLFSSL_API int wolfSSL_X509_LOOKUP_load_file(WOLFSSL_X509_LOOKUP*, const char*,
                                            long);
WOLFSSL_API WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_hash_dir(void);
WOLFSSL_API WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_file(void);

WOLFSSL_API WOLFSSL_X509_LOOKUP* wolfSSL_X509_STORE_add_lookup(WOLFSSL_X509_STORE*,
                                                    WOLFSSL_X509_LOOKUP_METHOD*);
WOLFSSL_API WOLFSSL_X509_STORE*  wolfSSL_X509_STORE_new(void);
WOLFSSL_API void         wolfSSL_X509_STORE_free(WOLFSSL_X509_STORE*);
WOLFSSL_API int          wolfSSL_X509_STORE_add_cert(
                                              WOLFSSL_X509_STORE*, WOLFSSL_X509*);
WOLFSSL_API int          wolfSSL_X509_STORE_set_default_paths(WOLFSSL_X509_STORE*);
WOLFSSL_API int          wolfSSL_X509_STORE_get_by_subject(WOLFSSL_X509_STORE_CTX*,
                                   int, WOLFSSL_X509_NAME*, WOLFSSL_X509_OBJECT*);
WOLFSSL_API WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new(void);
WOLFSSL_API int  wolfSSL_X509_STORE_CTX_init(WOLFSSL_X509_STORE_CTX*,
                      WOLFSSL_X509_STORE*, WOLFSSL_X509*, STACK_OF(WOLFSSL_X509)*);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_free(WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_cleanup(WOLFSSL_X509_STORE_CTX*);

WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_lastUpdate(WOLFSSL_X509_CRL*);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_nextUpdate(WOLFSSL_X509_CRL*);

WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_X509_get_pubkey(WOLFSSL_X509*);
WOLFSSL_API int       wolfSSL_X509_CRL_verify(WOLFSSL_X509_CRL*, WOLFSSL_EVP_PKEY*);
WOLFSSL_API void      wolfSSL_X509_STORE_CTX_set_error(WOLFSSL_X509_STORE_CTX*,
                                                     int);
WOLFSSL_API void      wolfSSL_X509_OBJECT_free_contents(WOLFSSL_X509_OBJECT*);
WOLFSSL_API void      wolfSSL_EVP_PKEY_free(WOLFSSL_EVP_PKEY*);
WOLFSSL_API int       wolfSSL_X509_cmp_current_time(const WOLFSSL_ASN1_TIME*);
WOLFSSL_API int       wolfSSL_sk_X509_REVOKED_num(WOLFSSL_X509_REVOKED*);

WOLFSSL_API WOLFSSL_X509_REVOKED* wolfSSL_X509_CRL_get_REVOKED(WOLFSSL_X509_CRL*);
WOLFSSL_API WOLFSSL_X509_REVOKED* wolfSSL_sk_X509_REVOKED_value(
                                                      WOLFSSL_X509_REVOKED*,int);
WOLFSSL_API WOLFSSL_ASN1_INTEGER* wolfSSL_X509_get_serialNumber(WOLFSSL_X509*);

WOLFSSL_API int wolfSSL_ASN1_TIME_print(WOLFSSL_BIO*, const WOLFSSL_ASN1_TIME*);

WOLFSSL_API int  wolfSSL_ASN1_INTEGER_cmp(const WOLFSSL_ASN1_INTEGER*,
                                       const WOLFSSL_ASN1_INTEGER*);
WOLFSSL_API long wolfSSL_ASN1_INTEGER_get(const WOLFSSL_ASN1_INTEGER*);

WOLFSSL_API STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_load_client_CA_file(const char*);

WOLFSSL_API void  wolfSSL_CTX_set_client_CA_list(WOLFSSL_CTX*,
                                               STACK_OF(WOLFSSL_X509_NAME)*);
WOLFSSL_API void* wolfSSL_X509_STORE_CTX_get_ex_data(WOLFSSL_X509_STORE_CTX*, int);
WOLFSSL_API int   wolfSSL_get_ex_data_X509_STORE_CTX_idx(void);
WOLFSSL_API void* wolfSSL_get_ex_data(const WOLFSSL*, int);

WOLFSSL_API void wolfSSL_CTX_set_default_passwd_cb_userdata(WOLFSSL_CTX*,
                                                          void* userdata);
WOLFSSL_API void wolfSSL_CTX_set_default_passwd_cb(WOLFSSL_CTX*, pem_password_cb);


WOLFSSL_API void wolfSSL_CTX_set_info_callback(WOLFSSL_CTX*, void (*)(void));

WOLFSSL_API unsigned long wolfSSL_ERR_peek_error(void);
WOLFSSL_API int           wolfSSL_GET_REASON(int);

WOLFSSL_API char* wolfSSL_alert_type_string_long(int);
WOLFSSL_API char* wolfSSL_alert_desc_string_long(int);
WOLFSSL_API char* wolfSSL_state_string_long(WOLFSSL*);

#if 0
WOLFSSL_API WOLFSSL_RSA* wolfSSL_RSA_generate_key(int, unsigned long,
                                               void(*)(int, int, void*), void*);
WOLFSSL_API void wolfSSL_CTX_set_tmp_rsa_callback(WOLFSSL_CTX*,
                                             WOLFSSL_RSA*(*)(WOLFSSL*, int, int));
#endif

WOLFSSL_API int wolfSSL_PEM_def_callback(char*, int num, int w, void* key);

WOLFSSL_API long wolfSSL_CTX_sess_accept(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_connect(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_accept_good(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_connect_good(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_accept_renegotiate(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_connect_renegotiate(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_hits(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_cb_hits(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_cache_full(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_misses(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_timeouts(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_number(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_get_cache_size(WOLFSSL_CTX*);




#ifndef NO_PSK
    WOLFSSL_API void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX*,
                                                    psk_client_callback);
    WOLFSSL_API void wolfSSL_set_psk_client_callback(WOLFSSL*,psk_client_callback);

    WOLFSSL_API const char* wolfSSL_get_psk_identity_hint(const WOLFSSL*);
    WOLFSSL_API const char* wolfSSL_get_psk_identity(const WOLFSSL*);

    WOLFSSL_API int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX*, const char*);
    WOLFSSL_API int wolfSSL_use_psk_identity_hint(WOLFSSL*, const char*);

    WOLFSSL_API void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX*,
                                                    psk_server_callback);
    WOLFSSL_API void wolfSSL_set_psk_server_callback(WOLFSSL*,psk_server_callback);

    #define PSK_TYPES_DEFINED
#endif /* NO_PSK */


#ifdef HAVE_ANON
    WOLFSSL_API int wolfSSL_CTX_allow_anon_cipher(WOLFSSL_CTX*);
#endif /* HAVE_ANON */


WOLFSSL_API unsigned long wolfSSL_ERR_get_error_line_data(const char**, int*,
                                                 const char**, int *);

WOLFSSL_API unsigned long wolfSSL_ERR_get_error(void);
WOLFSSL_API void          wolfSSL_ERR_clear_error(void);


WOLFSSL_API int  wolfSSL_RAND_status(void);
WOLFSSL_API int  wolfSSL_RAND_bytes(unsigned char* buf, int num);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_server_method(void);
WOLFSSL_API long wolfSSL_CTX_set_options(WOLFSSL_CTX*, long);
#ifndef NO_CERTS
  WOLFSSL_API int  wolfSSL_CTX_check_private_key(WOLFSSL_CTX*);
#endif /* !NO_CERTS */

#ifdef OPENSSL_EXTRA

WOLFSSL_API void wolfSSL_ERR_free_strings(void);
WOLFSSL_API void wolfSSL_ERR_remove_state(unsigned long);
WOLFSSL_API void wolfSSL_EVP_cleanup(void);
WOLFSSL_API int  wolfSSL_clear(WOLFSSL* ssl);

WOLFSSL_API void wolfSSL_cleanup_all_ex_data(void);
WOLFSSL_API long wolfSSL_CTX_set_mode(WOLFSSL_CTX* ctx, long mode);
WOLFSSL_API long wolfSSL_CTX_get_mode(WOLFSSL_CTX* ctx);
WOLFSSL_API void wolfSSL_CTX_set_default_read_ahead(WOLFSSL_CTX* ctx, int m);
WOLFSSL_API long wolfSSL_SSL_get_mode(WOLFSSL* ssl);

WOLFSSL_API long wolfSSL_CTX_sess_set_cache_size(WOLFSSL_CTX*, long);

WOLFSSL_API int  wolfSSL_CTX_set_default_verify_paths(WOLFSSL_CTX*);
WOLFSSL_API int  wolfSSL_CTX_set_session_id_context(WOLFSSL_CTX*,
                                            const unsigned char*, unsigned int);
WOLFSSL_API WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL* ssl);

WOLFSSL_API int wolfSSL_want_read(WOLFSSL*);
WOLFSSL_API int wolfSSL_want_write(WOLFSSL*);

WOLFSSL_API int wolfSSL_BIO_printf(WOLFSSL_BIO*, const char*, ...);
WOLFSSL_API int wolfSSL_ASN1_UTCTIME_print(WOLFSSL_BIO*,  const WOLFSSL_ASN1_UTCTIME *tm);
WOLFSSL_API int   wolfSSL_sk_num(WOLFSSL_X509_REVOKED*);
WOLFSSL_API void* wolfSSL_sk_value(WOLFSSL_X509_REVOKED*, int);

/* stunnel 4.28 needs */
WOLFSSL_API void* wolfSSL_CTX_get_ex_data(const WOLFSSL_CTX*, int);
WOLFSSL_API int   wolfSSL_CTX_set_ex_data(WOLFSSL_CTX*, int, void*);
WOLFSSL_API void  wolfSSL_CTX_sess_set_get_cb(WOLFSSL_CTX*,
                       WOLFSSL_SESSION*(*f)(WOLFSSL*, unsigned char*, int, int*));
WOLFSSL_API void  wolfSSL_CTX_sess_set_new_cb(WOLFSSL_CTX*,
                                            int (*f)(WOLFSSL*, WOLFSSL_SESSION*));
WOLFSSL_API void  wolfSSL_CTX_sess_set_remove_cb(WOLFSSL_CTX*,
                                       void (*f)(WOLFSSL_CTX*, WOLFSSL_SESSION*));

WOLFSSL_API int          wolfSSL_i2d_SSL_SESSION(WOLFSSL_SESSION*,unsigned char**);
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_d2i_SSL_SESSION(WOLFSSL_SESSION**,
                                                   const unsigned char**, long);

WOLFSSL_API long wolfSSL_SESSION_get_timeout(const WOLFSSL_SESSION*);
WOLFSSL_API long wolfSSL_SESSION_get_time(const WOLFSSL_SESSION*);
WOLFSSL_API int  wolfSSL_CTX_get_ex_new_index(long, void*, void*, void*, void*);
#endif
/* extra ends */


/* wolfSSL extensions */

/* call before SSL_connect, if verifying will add name check to
   date check and signature check */
WOLFSSL_API int wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn);

/* need to call once to load library (session cache) */
WOLFSSL_API int wolfSSL_Init(void);
/* call when done to cleanup/free session cache mutex / resources  */
WOLFSSL_API int wolfSSL_Cleanup(void);

/* which library version do we have */
WOLFSSL_API const char* wolfSSL_lib_version(void);
/* which library version do we have in hex */
WOLFSSL_API unsigned int wolfSSL_lib_version_hex(void);

/* turn logging on, only if compiled in */
WOLFSSL_API int  wolfSSL_Debugging_ON(void);
/* turn logging off */
WOLFSSL_API void wolfSSL_Debugging_OFF(void);

/* do accept or connect depedning on side */
WOLFSSL_API int wolfSSL_negotiate(WOLFSSL* ssl);
/* turn on wolfSSL data compression */
WOLFSSL_API int wolfSSL_set_compression(WOLFSSL* ssl);

WOLFSSL_API int wolfSSL_set_timeout(WOLFSSL*, unsigned int);
WOLFSSL_API int wolfSSL_CTX_set_timeout(WOLFSSL_CTX*, unsigned int);

#ifdef SESSION_CERTS

/* get wolfSSL peer X509_CHAIN */
WOLFSSL_API WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl);
/* peer chain count */
WOLFSSL_API int  wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN* chain);
/* index cert length */
WOLFSSL_API int  wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN*, int idx);
/* index cert */
WOLFSSL_API unsigned char* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN*, int idx);
/* index cert in X509 */
WOLFSSL_API WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN*, int idx);
/* free X509 */
WOLFSSL_API void wolfSSL_FreeX509(WOLFSSL_X509*);
/* get index cert in PEM */
WOLFSSL_API int  wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN*, int idx,
                                unsigned char* buffer, int inLen, int* outLen);
WOLFSSL_API const unsigned char* wolfSSL_get_sessionID(const WOLFSSL_SESSION* s);
#endif

WOLFSSL_API int  wolfSSL_X509_get_serial_number(WOLFSSL_X509*,unsigned char*,int*);
WOLFSSL_API char*  wolfSSL_X509_get_subjectCN(WOLFSSL_X509*);
WOLFSSL_API const unsigned char* wolfSSL_X509_get_der(WOLFSSL_X509*, int*);
WOLFSSL_API const unsigned char* wolfSSL_X509_notBefore(WOLFSSL_X509*);
WOLFSSL_API const unsigned char* wolfSSL_X509_notAfter(WOLFSSL_X509*);
WOLFSSL_API int wolfSSL_X509_version(WOLFSSL_X509*);

WOLFSSL_API int wolfSSL_cmp_peer_cert_to_file(WOLFSSL*, const char*);

WOLFSSL_API char* wolfSSL_X509_get_next_altname(WOLFSSL_X509*);

WOLFSSL_API WOLFSSL_X509*
    wolfSSL_X509_d2i(WOLFSSL_X509** x509, const unsigned char* in, int len);
#ifndef NO_FILESYSTEM
    #ifndef NO_STDIO_FILESYSTEM
    WOLFSSL_API WOLFSSL_X509*
        wolfSSL_X509_d2i_fp(WOLFSSL_X509** x509, FILE* file);
    #endif
WOLFSSL_API WOLFSSL_X509*
    wolfSSL_X509_load_certificate_file(const char* fname, int format);
#endif

#ifdef WOLFSSL_SEP
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_device_type(WOLFSSL_X509*, unsigned char*, int*);
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_hw_type(WOLFSSL_X509*, unsigned char*, int*);
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_hw_serial_number(WOLFSSL_X509*, unsigned char*, int*);
#endif

/* connect enough to get peer cert */
WOLFSSL_API int  wolfSSL_connect_cert(WOLFSSL* ssl);

#ifndef NO_DH
/* server Diffie-Hellman parameters */
WOLFSSL_API int  wolfSSL_SetTmpDH(WOLFSSL*, const unsigned char* p, int pSz,
                                const unsigned char* g, int gSz);
WOLFSSL_API int  wolfSSL_SetTmpDH_buffer(WOLFSSL*, const unsigned char* b, long sz,
                                       int format);
#ifndef NO_FILESYSTEM
    WOLFSSL_API int  wolfSSL_SetTmpDH_file(WOLFSSL*, const char* f, int format);
#endif

/* server ctx Diffie-Hellman parameters */
WOLFSSL_API int  wolfSSL_CTX_SetTmpDH(WOLFSSL_CTX*, const unsigned char* p,
                                    int pSz, const unsigned char* g, int gSz);
WOLFSSL_API int  wolfSSL_CTX_SetTmpDH_buffer(WOLFSSL_CTX*, const unsigned char* b,
                                           long sz, int format);

#ifndef NO_FILESYSTEM
    WOLFSSL_API int  wolfSSL_CTX_SetTmpDH_file(WOLFSSL_CTX*, const char* f,
                                             int format);
#endif

WOLFSSL_API int wolfSSL_CTX_SetMinDhKey_Sz(WOLFSSL_CTX*, unsigned short);
WOLFSSL_API int wolfSSL_SetMinDhKey_Sz(WOLFSSL*, unsigned short);
WOLFSSL_API int wolfSSL_GetDhKey_Sz(WOLFSSL*);
#endif /* NO_DH */

WOLFSSL_API int  wolfSSL_SetTmpEC_DHE_Sz(WOLFSSL*, unsigned short);
WOLFSSL_API int  wolfSSL_CTX_SetTmpEC_DHE_Sz(WOLFSSL_CTX*, unsigned short);

/* keyblock size in bytes or -1 */
/* need to call wolfSSL_KeepArrays before handshake to save keys */
WOLFSSL_API int wolfSSL_get_keyblock_size(WOLFSSL*);
WOLFSSL_API int wolfSSL_get_keys(WOLFSSL*,unsigned char** ms, unsigned int* msLen,
                                       unsigned char** sr, unsigned int* srLen,
                                       unsigned char** cr, unsigned int* crLen);

/* Computes EAP-TLS and EAP-TTLS keying material from the master_secret. */
WOLFSSL_API int wolfSSL_make_eap_keys(WOLFSSL*, void* key, unsigned int len,
                                                             const char* label);


#ifndef _WIN32
    #ifndef NO_WRITEV
        #ifdef __PPU
            #include <sys/types.h>
            #include <sys/socket.h>
        #elif !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_IAR_ARM) && !defined(WOLFSSL_PICOTCP)
            #include <sys/uio.h>
        #endif
        /* allow writev style writing */
        WOLFSSL_API int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov,
                                     int iovcnt);
    #endif
#endif


#ifndef NO_CERTS
    /* SSL_CTX versions */
    WOLFSSL_API int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX*);
    WOLFSSL_API int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
    WOLFSSL_API int wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
    WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
    WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_buffer(WOLFSSL_CTX*,
                                                    const unsigned char*, long);

    /* SSL versions */
    WOLFSSL_API int wolfSSL_use_certificate_buffer(WOLFSSL*, const unsigned char*,
                                               long, int);
    WOLFSSL_API int wolfSSL_use_PrivateKey_buffer(WOLFSSL*, const unsigned char*,
                                               long, int);
    WOLFSSL_API int wolfSSL_use_certificate_chain_buffer(WOLFSSL*,
                                               const unsigned char*, long);
    WOLFSSL_API int wolfSSL_UnloadCertsKeys(WOLFSSL*);
#endif

WOLFSSL_API int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX*);
WOLFSSL_API int wolfSSL_set_group_messages(WOLFSSL*);



#ifdef HAVE_FUZZER
enum fuzzer_type {
    FUZZ_HMAC      = 0,
    FUZZ_ENCRYPT   = 1,
    FUZZ_SIGNATURE = 2,
    FUZZ_HASH      = 3,
    FUZZ_HEAD      = 4
};
WOLFSSL_API void wolfSSL_SetFuzzerCb(WOLFSSL* ssl, CallbackFuzzer cbf, void* fCtx);
#endif

WOLFSSL_API void wolfSSL_SetIORecv(WOLFSSL_CTX*, CallbackIORecv);
WOLFSSL_API void wolfSSL_SetIOSend(WOLFSSL_CTX*, CallbackIOSend);

WOLFSSL_API void wolfSSL_SetIOReadCtx( WOLFSSL* ssl, void *ctx);
WOLFSSL_API void wolfSSL_SetIOWriteCtx(WOLFSSL* ssl, void *ctx);

WOLFSSL_API void* wolfSSL_GetIOReadCtx( WOLFSSL* ssl);
WOLFSSL_API void* wolfSSL_GetIOWriteCtx(WOLFSSL* ssl);

WOLFSSL_API void wolfSSL_SetIOReadFlags( WOLFSSL* ssl, int flags);
WOLFSSL_API void wolfSSL_SetIOWriteFlags(WOLFSSL* ssl, int flags);


#ifndef WOLFSSL_USER_IO
    /* default IO callbacks */
    WOLFSSL_API int EmbedReceive(WOLFSSL* ssl, char* buf, int sz, void* ctx);
    WOLFSSL_API int EmbedSend(WOLFSSL* ssl, char* buf, int sz, void* ctx);

    #ifdef HAVE_OCSP
        WOLFSSL_API int EmbedOcspLookup(void*, const char*, int, unsigned char*,
                                       int, unsigned char**);
        WOLFSSL_API void EmbedOcspRespFree(void*, unsigned char*);
    #endif

    #ifdef WOLFSSL_DTLS
        WOLFSSL_API int EmbedReceiveFrom(WOLFSSL* ssl, char* buf, int sz, void*);
        WOLFSSL_API int EmbedSendTo(WOLFSSL* ssl, char* buf, int sz, void* ctx);
        WOLFSSL_API int EmbedGenerateCookie(WOLFSSL* ssl, unsigned char* buf,
                                           int sz, void*);
    #endif /* WOLFSSL_DTLS */
#endif /* WOLFSSL_USER_IO */


#ifdef HAVE_NETX
    WOLFSSL_API void wolfSSL_SetIO_NetX(WOLFSSL* ssl, NX_TCP_SOCKET* nxsocket,
                                      ULONG waitoption);
#endif

WOLFSSL_API void  wolfSSL_CTX_SetGenCookie(WOLFSSL_CTX*, CallbackGenCookie);
WOLFSSL_API void  wolfSSL_SetCookieCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetCookieCtx(WOLFSSL* ssl);

WOLFSSL_API int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX* ctx, int version);
WOLFSSL_API int wolfSSL_SetMinVersion(WOLFSSL* ssl, int version);
WOLFSSL_API int wolfSSL_GetObjectSize(void);  /* object size based on build */
WOLFSSL_API int wolfSSL_SetVersion(WOLFSSL* ssl, int version);
WOLFSSL_API int wolfSSL_KeyPemToDer(const unsigned char*, int sz, unsigned char*,
                                  int, const char*);
WOLFSSL_API int wolfSSL_CertPemToDer(const unsigned char*, int sz, unsigned char*,
                                   int, int);

WOLFSSL_API void  wolfSSL_CTX_SetMacEncryptCb(WOLFSSL_CTX*, CallbackMacEncrypt);
WOLFSSL_API void  wolfSSL_SetMacEncryptCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetMacEncryptCtx(WOLFSSL* ssl);

WOLFSSL_API void  wolfSSL_CTX_SetDecryptVerifyCb(WOLFSSL_CTX*,
                                               CallbackDecryptVerify);
WOLFSSL_API void  wolfSSL_SetDecryptVerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetDecryptVerifyCtx(WOLFSSL* ssl);

WOLFSSL_API const unsigned char* wolfSSL_GetMacSecret(WOLFSSL*, int);
WOLFSSL_API const unsigned char* wolfSSL_GetClientWriteKey(WOLFSSL*);
WOLFSSL_API const unsigned char* wolfSSL_GetClientWriteIV(WOLFSSL*);
WOLFSSL_API const unsigned char* wolfSSL_GetServerWriteKey(WOLFSSL*);
WOLFSSL_API const unsigned char* wolfSSL_GetServerWriteIV(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetKeySize(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetIVSize(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetSide(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_IsTLSv1_1(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetBulkCipher(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetCipherBlockSize(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetAeadMacSize(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetHmacSize(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetHmacType(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetCipherType(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_SetTlsHmacInner(WOLFSSL*, unsigned char*,
                                                       unsigned int, int, int);

WOLFSSL_API void  wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX*, CallbackEccSign);
WOLFSSL_API void  wolfSSL_SetEccSignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl);

WOLFSSL_API void  wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX*, CallbackEccVerify);
WOLFSSL_API void  wolfSSL_SetEccVerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl);

WOLFSSL_API void  wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX*, CallbackRsaSign);
WOLFSSL_API void  wolfSSL_SetRsaSignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl);

WOLFSSL_API void  wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX*, CallbackRsaVerify);
WOLFSSL_API void  wolfSSL_SetRsaVerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaVerifyCtx(WOLFSSL* ssl);

/* RSA Public Encrypt cb */
WOLFSSL_API void  wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX*, CallbackRsaEnc);
WOLFSSL_API void  wolfSSL_SetRsaEncCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl);

/* RSA Private Decrypt cb */
WOLFSSL_API void  wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX*, CallbackRsaDec);
WOLFSSL_API void  wolfSSL_SetRsaDecCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl);


#ifndef NO_CERTS
	WOLFSSL_API void wolfSSL_CTX_SetCACb(WOLFSSL_CTX*, CallbackCACache);

    WOLFSSL_API WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew(void);
    WOLFSSL_API void wolfSSL_CertManagerFree(WOLFSSL_CERT_MANAGER*);

    WOLFSSL_API int wolfSSL_CertManagerLoadCA(WOLFSSL_CERT_MANAGER*, const char* f,
                                                                 const char* d);
    WOLFSSL_API int wolfSSL_CertManagerUnloadCAs(WOLFSSL_CERT_MANAGER* cm);
    WOLFSSL_API int wolfSSL_CertManagerVerify(WOLFSSL_CERT_MANAGER*, const char* f,
                                                                    int format);
    WOLFSSL_API int wolfSSL_CertManagerVerifyBuffer(WOLFSSL_CERT_MANAGER* cm,
                                const unsigned char* buff, long sz, int format);
    WOLFSSL_API int wolfSSL_CertManagerCheckCRL(WOLFSSL_CERT_MANAGER*,
                                                        unsigned char*, int sz);
    WOLFSSL_API int wolfSSL_CertManagerEnableCRL(WOLFSSL_CERT_MANAGER*,
                                                                   int options);
    WOLFSSL_API int wolfSSL_CertManagerDisableCRL(WOLFSSL_CERT_MANAGER*);
    WOLFSSL_API int wolfSSL_CertManagerLoadCRL(WOLFSSL_CERT_MANAGER*, const char*,
                                                                      int, int);
    WOLFSSL_API int wolfSSL_CertManagerSetCRL_Cb(WOLFSSL_CERT_MANAGER*,
                                                                  CbMissingCRL);
    WOLFSSL_API int wolfSSL_CertManagerCheckOCSP(WOLFSSL_CERT_MANAGER*,
                                                        unsigned char*, int sz);
    WOLFSSL_API int wolfSSL_CertManagerEnableOCSP(WOLFSSL_CERT_MANAGER*,
                                                                   int options);
    WOLFSSL_API int wolfSSL_CertManagerDisableOCSP(WOLFSSL_CERT_MANAGER*);
    WOLFSSL_API int wolfSSL_CertManagerSetOCSPOverrideURL(WOLFSSL_CERT_MANAGER*,
                                                                   const char*);
    WOLFSSL_API int wolfSSL_CertManagerSetOCSP_Cb(WOLFSSL_CERT_MANAGER*,
                                               CbOCSPIO, CbOCSPRespFree, void*);

    WOLFSSL_API int wolfSSL_EnableCRL(WOLFSSL* ssl, int options);
    WOLFSSL_API int wolfSSL_DisableCRL(WOLFSSL* ssl);
    WOLFSSL_API int wolfSSL_LoadCRL(WOLFSSL*, const char*, int, int);
    WOLFSSL_API int wolfSSL_SetCRL_Cb(WOLFSSL*, CbMissingCRL);
    WOLFSSL_API int wolfSSL_EnableOCSP(WOLFSSL*, int options);
    WOLFSSL_API int wolfSSL_DisableOCSP(WOLFSSL*);
    WOLFSSL_API int wolfSSL_SetOCSP_OverrideURL(WOLFSSL*, const char*);
    WOLFSSL_API int wolfSSL_SetOCSP_Cb(WOLFSSL*, CbOCSPIO, CbOCSPRespFree, void*);

    WOLFSSL_API int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options);
    WOLFSSL_API int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx);
    WOLFSSL_API int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX*, const char*, int, int);
    WOLFSSL_API int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX*, CbMissingCRL);
    WOLFSSL_API int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX*, int options);
    WOLFSSL_API int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX*);
    WOLFSSL_API int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX*, const char*);
    WOLFSSL_API int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX*,
                                               CbOCSPIO, CbOCSPRespFree, void*);
#endif /* !NO_CERTS */

/* end of handshake frees temporary arrays, if user needs for get_keys or
   psk hints, call KeepArrays before handshake and then FreeArrays when done
   if don't want to wait for object free */
WOLFSSL_API void wolfSSL_KeepArrays(WOLFSSL*);
WOLFSSL_API void wolfSSL_FreeArrays(WOLFSSL*);


/* cavium additions */
WOLFSSL_API int wolfSSL_UseCavium(WOLFSSL*, int devId);
WOLFSSL_API int wolfSSL_CTX_UseCavium(WOLFSSL_CTX*, int devId);


/* Server Name Indication */
#ifdef HAVE_SNI

WOLFSSL_API int wolfSSL_UseSNI(WOLFSSL* ssl, unsigned char type, const void* data,
                                                           unsigned short size);
WOLFSSL_API int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, unsigned char type,
                                         const void* data, unsigned short size);

#ifndef NO_WOLFSSL_SERVER


WOLFSSL_API void wolfSSL_SNI_SetOptions(WOLFSSL* ssl, unsigned char type,
                                                         unsigned char options);
WOLFSSL_API void wolfSSL_CTX_SNI_SetOptions(WOLFSSL_CTX* ctx, unsigned char type,
                                                         unsigned char options);

WOLFSSL_API unsigned char wolfSSL_SNI_Status(WOLFSSL* ssl, unsigned char type);

WOLFSSL_API unsigned short wolfSSL_SNI_GetRequest(WOLFSSL *ssl, unsigned char type,
                                                                   void** data);
WOLFSSL_API int wolfSSL_SNI_GetFromBuffer(
                 const unsigned char* clientHello, unsigned int helloSz,
                 unsigned char type, unsigned char* sni, unsigned int* inOutSz);

#endif
#endif

/* Maximum Fragment Length */
#ifdef HAVE_MAX_FRAGMENT

#ifndef NO_WOLFSSL_CLIENT

WOLFSSL_API int wolfSSL_UseMaxFragment(WOLFSSL* ssl, unsigned char mfl);
WOLFSSL_API int wolfSSL_CTX_UseMaxFragment(WOLFSSL_CTX* ctx, unsigned char mfl);

#endif
#endif

/* Truncated HMAC */
#ifdef HAVE_TRUNCATED_HMAC
#ifndef NO_WOLFSSL_CLIENT

WOLFSSL_API int wolfSSL_UseTruncatedHMAC(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_UseTruncatedHMAC(WOLFSSL_CTX* ctx);

#endif
#endif


#ifdef HAVE_SUPPORTED_CURVES
#ifndef NO_WOLFSSL_CLIENT

WOLFSSL_API int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, unsigned short name);
WOLFSSL_API int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx,
                                                           unsigned short name);

#endif
#endif

/* Secure Renegotiation */
#ifdef HAVE_SECURE_RENEGOTIATION

WOLFSSL_API int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_Rehandshake(WOLFSSL* ssl);

#endif

/* Session Ticket */
#ifdef HAVE_SESSION_TICKET

#ifndef NO_WOLFSSL_CLIENT
WOLFSSL_API int wolfSSL_UseSessionTicket(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_get_SessionTicket(WOLFSSL*, unsigned char*, unsigned int*);
WOLFSSL_API int wolfSSL_set_SessionTicket(WOLFSSL*, unsigned char*, unsigned int);
typedef int (*CallbackSessionTicket)(WOLFSSL*, const unsigned char*, int, void*);
WOLFSSL_API int wolfSSL_set_SessionTicket_cb(WOLFSSL*,
                                                  CallbackSessionTicket, void*);
#endif /* NO_WOLFSSL_CLIENT */

#ifndef NO_WOLFSSL_SERVER

WOLFSSL_API int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx,
                                            SessionTicketEncCb);
WOLFSSL_API int wolfSSL_CTX_set_TicketHint(WOLFSSL_CTX* ctx, int);
WOLFSSL_API int wolfSSL_CTX_set_TicketEncCtx(WOLFSSL_CTX* ctx, void*);

#endif /* NO_WOLFSSL_SERVER */

#endif /* HAVE_SESSION_TICKET */

#ifdef WOLFSSL_CALLBACKS


/* wolfSSL connect extension allowing HandShakeCallBack and/or TimeoutCallBack
   for diagnostics */
WOLFSSL_API int wolfSSL_connect_ex(WOLFSSL*, HandShakeCallBack, TimeoutCallBack, Timeval);
WOLFSSL_API int wolfSSL_accept_ex(WOLFSSL*, HandShakeCallBack, TimeoutCallBack, Timeval);

#endif /* WOLFSSL_CALLBACKS */


/* notify user the hanshake is done */
WOLFSSL_API int wolfSSL_SetHsDoneCb(WOLFSSL*, HandShakeDoneCb, void*);


WOLFSSL_API int wolfSSL_PrintSessionStats(void);
WOLFSSL_API int wolfSSL_get_session_stats(unsigned int* active,
                                          unsigned int* total,
                                          unsigned int* peak,
                                          unsigned int* maxSessions);
/* External facing KDF */
WOLFSSL_API int wolfSSL_MakeTlsMasterSecret(unsigned char* ms, unsigned int msLen,
                               const unsigned char* pms, unsigned int pmsLen,
                               const unsigned char* cr, const unsigned char* sr,
                               int tls1_2, int hash_type);

WOLFSSL_API int wolfSSL_DeriveTlsKeys(unsigned char* key_data, unsigned int keyLen,
                               const unsigned char* ms, unsigned int msLen,
                               const unsigned char* sr, const unsigned char* cr,
                               int tls1_2, int hash_type);


#ifdef WOLFSSL_HAVE_WOLFSCEP
    WOLFSSL_API void wolfSSL_wolfSCEP(void);
#endif /* WOLFSSL_HAVE_WOLFSCEP */

#ifdef WOLFSSL_HAVE_CERT_SERVICE
    WOLFSSL_API void wolfSSL_cert_service(void);
#endif



#ifdef __cplusplus
    }
#endif

#endif

