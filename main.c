#include <stdio.h>
#include <assert.h>
#include "aes.h"

#define AES_KEYLEN 16   // Key length in bytes
#define AES_keyExpSize 176


void print_as_hex(unsigned char* str, int len){
    // printf("CT:\n");
    for(int i = 0; i<len;i++){
        printf("%02x ",str[i]);
    }
    printf("\n");
}



int main(void){
    for(int i = 0; i<100000000; i++){
        uint8_t *key = "some_random_key1";
        uint8_t data[16] = "ABCDEFGHIJKLMNOP";
        AES_ctx ctx;
        AES_init_ctx(&ctx,key);
        AES_ECB_encrypt(&ctx, data, 16);
        AES_ECB_decrypt(&ctx, data, 16);
        assert(data[0] == 'A');
    }
}