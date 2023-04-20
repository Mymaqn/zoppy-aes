/*
This file is part of zoppy-aes.
aes.h is the header file for the implementation of the AES algorithm for the zoppy-aes library

Copyright (C) 2023 Jens Nielsen

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/. 
*/

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
void AES_init_ctx_iv(AES_ctx* ctx, const uint8_t* key, uint8_t* iv);
void AES_ctx_set_iv(AES_ctx* ctx, uint8_t* iv);

void AES_ECB_encrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len);
void AES_ECB_decrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len);

void AES_CBC_encrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len);
void AES_CBC_decrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len);

#endif