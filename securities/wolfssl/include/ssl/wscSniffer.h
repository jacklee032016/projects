/* sniffer.h
 *
 */


#ifndef __WSC_SNIFFER_H__
#define 	__WSC_SNIFFER_H__


#ifdef _WIN32
    #ifdef SSL_SNIFFER_EXPORTS
        #define SSL_SNIFFER_API __declspec(dllexport)
    #else
        #define SSL_SNIFFER_API __declspec(dllimport)
    #endif
#else
    #define SSL_SNIFFER_API
#endif /* _WIN32 */


#ifdef __cplusplus
    extern "C" {
#endif

/* @param typeK: (formerly keyType) was shadowing a global declaration in 
 *                wolfssl/wolfcrypt/asn.h line 175
 */
WOLFSSL_API SSL_SNIFFER_API int ssl_SetPrivateKey(const char* address, int port,
                                      const char* keyFile, int typeK,
                                      const char* password, char* error);

WOLFSSL_API SSL_SNIFFER_API int ssl_SetNamedPrivateKey(const char* name,
                                           const char* address, int port,
                                           const char* keyFile, int typeK,
                                           const char* password, char* error);

WOLFSSL_API SSL_SNIFFER_API int ssl_DecodePacket(const unsigned char* packet, int length,
                                     unsigned char* data, char* error);

WOLFSSL_API SSL_SNIFFER_API int ssl_Trace(const char* traceFile, char* error);
        
WOLFSSL_API void ssl_InitSniffer(void);
        
WOLFSSL_API void ssl_FreeSniffer(void);

        
/* ssl_SetPrivateKey typeKs */
enum {
    FILETYPE_PEM = 1,
    FILETYPE_DER = 2,
};


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* wolfSSL_SNIFFER_H */

