#ifndef __AES__H
#define __AES__H

#include <stdint.h>


#define AES_KEY_EXP_SIZE 176
#define AES_BLOCK_SIZE 16
typedef struct{
   uint8_t RoundKey[AES_KEY_EXP_SIZE];
   uint8_t InvRoundKey[AES_KEY_EXP_SIZE];
   uint8_t iv[AES_BLOCK_SIZE];
}AES_ctx;

void AES_init_ctx(AES_ctx* ctx, const uint8_t* key);
void AES_ECB_encrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len);
void AES_ECB_decrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len);

#endif