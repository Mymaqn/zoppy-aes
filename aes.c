#include "aes.h"

extern void* AES_gen_roundkey(const uint8_t* key, uint8_t* roundkey);
extern void* AES_encrypt_block(uint8_t* state, uint8_t* roundkey);
extern void* AES_inverse_roundkey(const uint8_t* roundkey, uint8_t* invroundkey);
extern void* AES_decrypt_block(uint8_t* state, uint8_t* invroundkey);

void AES_init_ctx(AES_ctx* ctx, const uint8_t* key){
    AES_gen_roundkey(key,ctx->RoundKey);
    AES_inverse_roundkey(ctx->RoundKey,ctx->InvRoundKey);
}

void AES_ECB_encrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len){
    uint8_t *tmpbuf = buf;
    unsigned int i = 0;
    while(i<len){
        AES_encrypt_block(tmpbuf,ctx->RoundKey);
        tmpbuf+=16;
        i+=16;
    }
}

void AES_ECB_decrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len){
    uint8_t *tmpbuf = buf;
    unsigned int i = 0;
    while(i<len){
        AES_decrypt_block(tmpbuf,ctx->InvRoundKey);
        tmpbuf+=16;
        i+=16;
    }
}