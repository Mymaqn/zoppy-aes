#!/bin/bash
gcc -O3 main.c AES.S aes.c aes.h -masm=intel -g -o main
