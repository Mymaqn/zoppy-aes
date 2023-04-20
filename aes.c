/*
This file is part of zoppy-aes.
aes.c is the general code and implementation of the AES algorithm for the zoppy-aes library

Copyright (C) 2023 Jens Nielsen

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/. 
*/

#include "aes.h"

extern void* AES_gen_roundkey(const uint8_t* key, uint8_t* roundkey); //returns a pointer to roundkey
extern void* AES_encrypt_block(uint8_t* state, uint8_t* roundkey); //returns a pointer to state
extern void* AES_inverse_roundkey(const uint8_t* roundkey, uint8_t* invroundkey); //returns a pointer to invroundkey
extern void* AES_decrypt_block(uint8_t* state, uint8_t* invroundkey); //returns a pointer to state
extern void AES128_memcpy(void* s1, void* s2); //fast 128 bit memcpy
extern void AES128_xor(void* s1, void* s2); //Fast 128 bit xor result is stored in s1

void AES_init_ctx(AES_ctx* ctx, const uint8_t* key){
    AES_gen_roundkey(key,ctx->RoundKey);
    AES_inverse_roundkey(ctx->RoundKey,ctx->InvRoundKey);
}

void AES_init_ctx_iv(AES_ctx* ctx, const uint8_t* key, uint8_t* iv){
    AES_gen_roundkey(key,ctx->RoundKey);
    AES_inverse_roundkey(ctx->RoundKey, ctx->InvRoundKey);
    AES128_memcpy(ctx->iv,iv);
}

void AES_ctx_set_iv(AES_ctx* ctx, uint8_t* iv){
    AES128_memcpy(ctx->iv,iv);
}

void AES_ECB_encrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len){
    for(unsigned int i = 0; i<len; i+=AES_BLOCK_SIZE){
        AES_encrypt_block(&(buf[i]), ctx->RoundKey);
    }
}

void AES_ECB_decrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len){
    for(unsigned int i = 0; i<len; i+=AES_BLOCK_SIZE){
        AES_decrypt_block(&(buf[i]),ctx->InvRoundKey);
    }
}

void AES_CBC_encrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len){
    uint8_t* IV = ctx->iv;
    for(unsigned int i = 0; i<len; i+=AES_BLOCK_SIZE){
        AES128_xor(&(buf[i]),IV);
        AES_encrypt_block(&(buf[i]),ctx->RoundKey);
        IV = &(buf[i]);
    }
    AES128_memcpy(ctx->iv, IV);
}

void AES_CBC_decrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len){
    uint8_t n_iv[AES_BLOCK_SIZE];
    for(unsigned int i = 0; i<len; i+=AES_BLOCK_SIZE){
        AES128_memcpy(n_iv, &(buf[i]));
        AES_decrypt_block(&(buf[i]),ctx->InvRoundKey);
        AES128_xor(&(buf[i]),ctx->iv);
        AES128_memcpy(ctx->iv,n_iv);
    }
}