#!/bin/bash
gcc -O3 example.c AES.S aes.c aes.h -masm=intel -g -o example
