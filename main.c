#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "aes.h"

#define AES_KEYLEN 16   // Key length in bytes
#define AES_keyExpSize 176


void print_as_hex(unsigned char* str, int len){
    // printf("CT:\n");
    for(int i = 0; i<len;i++){
        printf("%02x",str[i]);
    }
    printf("\n");
}



int main(void){

    for(unsigned int i = 0; i<100000000;i++){
        AES_ctx ctx;
        AES_ctx ctx2;
        uint8_t *key = "some_random_key1";
        uint8_t data[32] = "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP";
        uint8_t iv[16] = "AAAAAAAAAAAAAAAA";
        AES_init_ctx_iv(&ctx,key,iv);
        AES_CBC_encrypt(&ctx,data,32);
        AES_init_ctx_iv(&ctx2,key,iv);
        AES_CBC_decrypt(&ctx2,data,32);
        assert(data[0] == 'A' && data[16] == 'A');
    }

}