# Zoppy-AES

Fast AES implementation using the AES specific intel instructions

Currently only support for AES128 in CBC and EBC mode.

## Functions
```C
void AES_init_ctx(AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(AES_ctx* ctx, const uint8_t* key, uint8_t* iv);
void AES_ctx_set_iv(AES_ctx* ctx, uint8_t* iv);

void AES_ECB_encrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len);
void AES_ECB_decrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len);

void AES_CBC_encrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len);
void AES_CBC_decrypt(AES_ctx* ctx, uint8_t* buf, unsigned int len);
```

Padding needs to be done yourself. If no padding is specified the algorithm will just use whatever is left in memory for it, or go out of bounds.

## Example usage:

```C
#include "aes.h"

int main(void){
    AES_ctx ctx;
    uint8_t *key = "some_random_key1";
    uint8_t data[32] = "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP";
    uint8_t iv[16] = "AAAAAAAAAAAAAAAA";
    AES_init_ctx_iv(&ctx,key,iv);
    AES_CBC_encrypt(&ctx,data,32);
    AES_ctx_set_iv(&ctx, iv);
    AES_CBC_decrypt(&ctx,data,32);
}
```

For best results, compile with -O3

## Performance

From own tests performs ~10-30 times better that tiny-aes-c

However since this is a hardware specific implementation, it's an unfair comparison.

100 million iterations of AES128 CBC encryption and decryption on a 32-byte buffer with -O3 flag, takes around 6 seconds.

## Compilation

Example of doing a compilation for maximum performance:

```
gcc -O3 program.c AES.S aes.c aes.h -masm=intel -s -o example
```

## QA

Q: Why does this only work on Intel/AMD CPU's?

A: The implementation uses the Intel/AMD specific instructions of aeskeygenassist, aesenc, aesdec, aesenclast, aesdeclast, aesimc. These instructions are not available on all CPUs. For more information check here: https://en.wikipedia.org/wiki/AES_instruction_set

Q: Will you implement X next?

A: I'm currently thinking of extending it to AES256 and AES192. But I won't guarantee anything. I usually pickup projects and leave them as I see fit. You're welcome to fork the repository and implement these variations yourself

Q: Can I make a pull request to implement X?

A: Yes. But chances are I will deny your pull request or won't ever check it.



