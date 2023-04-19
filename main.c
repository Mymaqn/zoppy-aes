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


void do_enc_round(uint8_t* state, uint8_t* roundkey){
    __m128 state_128 = *(__m128*)state;
    __m128 roundkey_128 = *(__m128*)roundkey;
    __m128 tmp;
    asm(
        "movups xmm6, %1\n"
        "movups xmm7, %2\n"
        "aesenc xmm6, xmm7\n"
        "movups %0, xmm6\n"
        : "=m"(tmp)
        : "m"(state_128), "m"(roundkey_128)
        : "xmm6","xmm7");

    memcpy(state,&tmp,16);
}

void do_lastenc_round(uint8_t* state, uint8_t* roundkey){
    __m128 state_128 = *(__m128*)state;
    __m128 roundkey_128 = *(__m128*)roundkey;
    __m128 tmp;
    asm(
        "movups xmm6, %1\n"
        "movups xmm7, %2\n"
        "aesenclast xmm6, xmm7\n"
        "movups %0, xmm6\n"
        : "=m"(tmp)
        : "m"(state_128), "m"(roundkey_128)
        : "xmm6","xmm7");

    memcpy(state,&tmp,16);
}


void gen_Roundkey(uint8_t* key, uint8_t* RoundKey, int roundidx){
    __m128 key_128 = *(__m128*)key;
    __m128 roundkey_128;
    asm (
        "movups xmm6, %0\n"
        :
        :"m"(key_128)
        :
    );
    switch(roundidx){
        case 0:
            memcpy(RoundKey,key,16);
            return;
        case 1:
            asm(
                "aeskeygenassist xmm7, xmm6, 0x1\n"
            );
            break;
        case 2:
            asm(
                "aeskeygenassist xmm7, xmm6, 0x2\n"
            );
            break;
        case 3:
            asm(
                "aeskeygenassist xmm7, xmm6, 0x4\n"
            );
            break;
        case 4:
            asm(
                "aeskeygenassist xmm7, xmm6, 0x8\n"
            );
            break;
        case 5:
            asm(
                "aeskeygenassist xmm7, xmm6, 0x10\n"
            );
            break;
        case 6:
            asm(
                "aeskeygenassist xmm7, xmm6, 0x20\n"
            );
            break;
        case 7:
            asm(
                "aeskeygenassist xmm7, xmm6, 0x40\n"
            );
            break;
        case 8:
            asm(
                "aeskeygenassist xmm7, xmm6, 0x80\n"
            );
            break;
        case 9:
            asm(
                "aeskeygenassist xmm7, xmm6, 0x1b\n"
            );
            break;
        case 10:
            asm(
                "aeskeygenassist xmm7, xmm6, 0x36\n"
            );
            break;
    }
    
    asm(
        "pshufd xmm7, xmm7, 0xff\n"    
        "movdqa xmm8, xmm6\n"
        "pslldq xmm8, 0x4\n"
        "pxor xmm6, xmm8\n"
        
        "pslldq xmm8, 0x4\n"
        "pxor xmm6, xmm8\n"

        "pslldq xmm8, 0x4\n"
        "pxor xmm6, xmm8\n"
        "pxor xmm6, xmm7\n"

        "movups %0, xmm6\n"
        :
        :"m"(roundkey_128)
        :"xmm6"
    );
    memcpy(RoundKey,&roundkey_128,16);
}

void InvRoundKey(uint8_t* RoundKey){
    uint8_t* tmprkey = RoundKey+16;

    for(int i = 1; i<10; i++){
        __m128 roundkey_128 = *(__m128*)tmprkey;
        __m128 tmp_inv;
        asm (
            "movups xmm6, %1\n"
            "aesimc xmm7, xmm6\n"
            "movups %0, xmm7\n"
            :"=m"(tmp_inv)
            :"m"(roundkey_128)
            :
        );
        memcpy(tmprkey,&tmp_inv,16);
        tmprkey+=16;
    }
}

void gen_RoundKeys(uint8_t *key, uint8_t* RoundKeys){
    uint8_t* curr_key = key;
    gen_Roundkey(curr_key,RoundKeys,0);
    RoundKeys+=16;
    for(int i = 1; i<11; i++){
        gen_Roundkey(curr_key,RoundKeys,i);
        curr_key = RoundKeys;
        RoundKeys+=16;
    }
    return;
}

void do_whitening(uint8_t *state, uint8_t *RoundKeys){
    __m128 state_128 = *(__m128*)state;
    __m128 roundkey_128 = *(__m128*)RoundKeys;
    __m128 tmp;
    asm(
        "movups xmm6, %1\n"
        "movups xmm7, %2\n"
        "pxor xmm6, xmm7\n"
        "movups %0, xmm6\n"
        : "=m"(tmp)
        : "m"(state_128), "m"(roundkey_128)
        : "xmm6","xmm7");
    memcpy(state,&tmp,16);
    return;
}

void encrypt_block(uint8_t *state, uint8_t *RoundKeys){
    uint8_t* tmprkeys = RoundKeys;
    do_whitening(state,tmprkeys);
    tmprkeys+=16;
    for(int i = 1; i<10; i++){
        do_enc_round(state,tmprkeys);
        tmprkeys+=16;
    }
    do_lastenc_round(state,tmprkeys);
}



int main(void){
    for(int i = 0; i<10000000; i++){
        uint8_t key[AES_KEYLEN] = "some_random_key1";
        uint8_t state[16] = "ABCDEFGHIJLMNOPQ";
        uint8_t RoundKeys[AES_keyExpSize] = {0};
        gen_RoundKeys(key,RoundKeys);
        encrypt_block(state,RoundKeys);
    }

}