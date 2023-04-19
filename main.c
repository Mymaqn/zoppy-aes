#include <stdio.h>
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define AES_KEYLEN 16   // Key length in bytes
#define AES_keyExpSize 176

extern void* AES_gen_roundkey(unsigned char* key, unsigned char* roundkey);
extern void* AES_encrypt_block(unsigned char* state, unsigned char* roundkey);
extern void* AES_inverse_roundkey(unsigned char* roundkey, unsigned char* invroundkey);
extern void* AES_decrypt_block(unsigned char* state, unsigned char* invroundkey);


void print_as_hex(unsigned char* str, int len){
    // printf("CT:\n");
    for(int i = 0; i<len;i++){
        printf("%02x ",str[i]);
    }
    printf("\n");
}



int main(void){
    unsigned char key[AES_KEYLEN] = "some_random_key1";
    unsigned char state[17] = "ABCDEFGHIJKLMNOP\x00";
    unsigned char RoundKeys[AES_keyExpSize] = {0};
    unsigned char InvRoundKeys[AES_keyExpSize] = {0};
    AES_gen_roundkey(key, RoundKeys);
    AES_encrypt_block(state, RoundKeys);
    AES_inverse_roundkey(RoundKeys,InvRoundKeys);
    AES_decrypt_block(state,InvRoundKeys);

    printf("%s\n",state);


}