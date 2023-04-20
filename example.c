#include <stdio.h>
#include "aes.h"


void print_as_hex(unsigned char* str, int len){
    for(int i = 0; i<len;i++){
        printf("%02x",str[i]);
    }
    printf("\n");
}



int main(void){
    AES_ctx ctx;
    uint8_t *key = "some_random_key1";
    uint8_t data[32] = "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP";
    uint8_t iv[16] = "AAAAAAAAAAAAAAAA";
    
    AES_init_ctx_iv(&ctx,key,iv);
    AES_CBC_encrypt(&ctx,data,32);

    printf("CT:\n");
    print_as_hex(data,32);

    AES_ctx_set_iv(&ctx, iv);
    AES_CBC_decrypt(&ctx,data,32);

    printf("PT:\n");
    printf("%.32s\n",data);
}