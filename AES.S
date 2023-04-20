/*
This file is part of zoppy-aes.
AES.S is the implementation of AES in the zoppy-aes library

Copyright (C) 2023 Jens Nielsen

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/. 
*/

.intel_syntax noprefix
.text
    .globl AES_gen_roundkey, AES_encrypt_block, AES_inverse_roundkey, AES_decrypt_block, AES128_memcpy, AES128_xor

    AES_gen_roundkey:
        #Key in RDI and output buffer in RSI
        movups xmm1, [rdi]
        
        #Round 1
        movups [rsi], xmm1

        #Round 2
        aeskeygenassist xmm2, xmm1, 0x1
        pshufd xmm2, xmm2, 0xff
        movdqa xmm3, xmm1
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pxor xmm1, xmm2
        movups [rsi+16], xmm1

        #Round 3
        aeskeygenassist xmm2, xmm1, 0x2
        pshufd xmm2, xmm2, 0xff
        movdqa xmm3, xmm1
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pxor xmm1, xmm2
        movups [rsi+32], xmm1

        #Round 4
        aeskeygenassist xmm2, xmm1, 0x4
        pshufd xmm2, xmm2, 0xff
        movdqa xmm3, xmm1
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pxor xmm1, xmm2
        movups [rsi+48], xmm1

        #Round 5
        aeskeygenassist xmm2, xmm1, 0x8
        pshufd xmm2, xmm2, 0xff
        movdqa xmm3, xmm1
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pxor xmm1, xmm2
        movups [rsi+64], xmm1

        #Round 6
        aeskeygenassist xmm2, xmm1, 0x10
        pshufd xmm2, xmm2, 0xff
        movdqa xmm3, xmm1
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pxor xmm1, xmm2
        movups [rsi+80], xmm1
        
        #Round 7
        aeskeygenassist xmm2, xmm1, 0x20
        pshufd xmm2, xmm2, 0xff
        movdqa xmm3, xmm1
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pxor xmm1, xmm2
        movups [rsi+96], xmm1

        #Round 8
        aeskeygenassist xmm2, xmm1, 0x40
        pshufd xmm2, xmm2, 0xff
        movdqa xmm3, xmm1
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pxor xmm1, xmm2
        movups [rsi+112], xmm1

        #Round 9
        aeskeygenassist xmm2, xmm1, 0x80
        pshufd xmm2, xmm2, 0xff
        movdqa xmm3, xmm1
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pxor xmm1, xmm2
        movups [rsi+128], xmm1

        #Round 10
        aeskeygenassist xmm2, xmm1, 0x1b
        pshufd xmm2, xmm2, 0xff
        movdqa xmm3, xmm1
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pxor xmm1, xmm2
        movups [rsi+144], xmm1

        #Round 11
        aeskeygenassist xmm2, xmm1, 0x36
        pshufd xmm2, xmm2, 0xff
        movdqa xmm3, xmm1
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pslldq xmm3, 0x4
        pxor xmm1, xmm3
        pxor xmm1, xmm2
        movups [rsi+160], xmm1

        mov rax, rsi
        ret

    AES_inverse_roundkey:
        #Roundkey in RDI and inverse roundkey in RSI
        movups xmm0, [rdi]
        movups xmm1, [rdi+16]
        movups xmm2, [rdi+32]
        movups xmm3, [rdi+48]
        movups xmm4, [rdi+64]
        movups xmm5, [rdi+80]
        movups xmm6, [rdi+96]
        movups xmm7, [rdi+112]
        movups xmm8, [rdi+128]
        movups xmm9, [rdi+144]
        movups xmm10, [rdi+160]

        aesimc xmm1, xmm1
        aesimc xmm2, xmm2
        aesimc xmm3, xmm3
        aesimc xmm4, xmm4
        aesimc xmm5, xmm5
        aesimc xmm6, xmm6
        aesimc xmm7, xmm7
        aesimc xmm8, xmm8
        aesimc xmm9, xmm9

        movups [rsi], xmm0
        movups [rsi+16], xmm1
        movups [rsi+32], xmm2
        movups [rsi+48], xmm3
        movups [rsi+64], xmm4
        movups [rsi+80], xmm5
        movups [rsi+96], xmm6
        movups [rsi+112], xmm7
        movups [rsi+128], xmm8
        movups [rsi+144], xmm9
        movups [rsi+160], xmm10

        mov rax, rsi
        ret
        
    AES_encrypt_block:
        #State in RDI and Roundkeys in RSI
        movups xmm0, [rdi]
        movups xmm1, [rsi]
        movups xmm2, [rsi+16]
        movups xmm3, [rsi+32]
        movups xmm4, [rsi+48]
        movups xmm5, [rsi+64]
        movups xmm6, [rsi+80]
        movups xmm7, [rsi+96]
        movups xmm8, [rsi+112]
        movups xmm9, [rsi+128]
        movups xmm10, [rsi+144]
        movups xmm11, [rsi+160]

        #Round 1 (whitening)
        pxor xmm0, xmm1

        #Rounds 1-10
        aesenc xmm0, xmm2
        aesenc xmm0, xmm3
        aesenc xmm0, xmm4
        aesenc xmm0, xmm5
        aesenc xmm0, xmm6
        aesenc xmm0, xmm7
        aesenc xmm0, xmm8
        aesenc xmm0, xmm9
        aesenc xmm0, xmm10

        #Last round
        aesenclast xmm0, xmm11

        movups [rdi], xmm0
        mov rax, rdi
        ret
    
    AES_decrypt_block:
        #State in RDI and roundkeys in RSI
        movups xmm0, [rdi]
        movups xmm1, [rsi+160]
        movups xmm2, [rsi+144]
        movups xmm3, [rsi+128]
        movups xmm4, [rsi+112]
        movups xmm5, [rsi+96]
        movups xmm6, [rsi+80]
        movups xmm7, [rsi+64]
        movups xmm8, [rsi+48]
        movups xmm9, [rsi+32]
        movups xmm10, [rsi+16]
        movups xmm11, [rsi]

        #Round 1 (whitening)
        pxor xmm0, xmm1

        #Rounds 1-10
        aesdec xmm0, xmm2
        aesdec xmm0, xmm3
        aesdec xmm0, xmm4
        aesdec xmm0, xmm5
        aesdec xmm0, xmm6
        aesdec xmm0, xmm7
        aesdec xmm0, xmm8
        aesdec xmm0, xmm9
        aesdec xmm0, xmm10
    
        #Last round
        aesdeclast xmm0, xmm11
    
        movups [rdi], xmm0
        mov rax, rdi
        ret

    AES128_memcpy:
        # s1 in rdi and s2 in rsi
        movups xmm0, [rsi]
        movups [rdi], xmm0
        ret
    AES128_xor:
        # s1 in rdi and s2 in rsi
        movups xmm0, [rdi]
        movups xmm1, [rsi]
        pxor xmm0, xmm1
        movups [rdi],xmm0
        ret





