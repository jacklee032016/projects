/*
 */

#include "crypto.h"
 
/**
* Initialize the SHA384 context 
*/
 EXP_FUNC void STDCALL SHA384_Init(SHA384_CTX *ctx)
 {
    //Set initial hash value
    ctx->h_dig.h[0] = 0xCBBB9D5DC1059ED8;
    ctx->h_dig.h[1] = 0x629A292A367CD507;
    ctx->h_dig.h[2] = 0x9159015A3070DD17;
    ctx->h_dig.h[3] = 0x152FECD8F70E5939;
    ctx->h_dig.h[4] = 0x67332667FFC00B31;
    ctx->h_dig.h[5] = 0x8EB44A8768581511;
    ctx->h_dig.h[6] = 0xDB0C2E0D64F98FA7;
    ctx->h_dig.h[7] = 0x47B5481DBEFA4FA4;
 
    // Number of bytes in the buffer
    ctx->size = 0;
    // Total length of the message
    ctx->totalSize = 0;
 }
 
/**
* Accepts an array of octets as the next portion of the message.
*/
EXP_FUNC void STDCALL SHA384_Update(SHA384_CTX *ctx, const uint8_t * msg, int len)
{
    // The function is defined in the exact same manner as SHA-512
    SHA512_Update(ctx, msg, len);
}
 
/**
* Return the 384-bit message digest into the user's array
*/
EXP_FUNC void STDCALL SHA384_Final(uint8_t *digest, SHA384_CTX *ctx)
{
    // The function is defined in the exact same manner as SHA-512
    SHA512_Final(NULL, ctx);
 
    // Copy the resulting digest
    if (digest != NULL)
        memcpy(digest, ctx->h_dig.digest, HASH_MD_LENGTH_SHA384);
}
 
