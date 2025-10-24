#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>


// 使用SM4 CBC做示例，演示EVP_CIPHER_CTX_copy的用法

#define SM4_KEY_SIZE 16
#define SM4_BLOCK_SIZE 16
#define SM4_IV_SIZE 16

int main(int argc, char *argv[]) {
    int ret = 0;

    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx1 = NULL;
    EVP_CIPHER_CTX *ctx2 = NULL;

    unsigned char key[SM4_KEY_SIZE] = {0};
    unsigned char iv[SM4_IV_SIZE] = {0};
    unsigned char plaintext1[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    unsigned char plaintext2[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    unsigned char ciphertext[32] = {0};
    unsigned char ciphertext2[16] = {0};
    int len = 0;
    int i = 0;

    cipher = EVP_sm4_cbc();
    if (!cipher) {
        fprintf(stderr, "Failed to get SM4-CBC cipher: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 1. Create and initialize the first context
    ctx1 = EVP_CIPHER_CTX_new();
    if (!ctx1) {
        fprintf(stderr, "Failed to create cipher context 1: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (1 != EVP_EncryptInit_ex(ctx1, cipher, NULL, NULL, NULL)) {
        fprintf(stderr, "Failed to initialize cipher context 1: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 1.1 Enable padding for CBC mode
    if (1 != EVP_CIPHER_CTX_set_padding(ctx1, 1)) {
        fprintf(stderr, "Failed to enable padding for context 1: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 1.2 (Optional) You can perform some encryption operations here with ctx1
    // encrypt first block
    if (1 != EVP_EncryptInit_ex(ctx1, NULL, NULL, key, iv)) {
        fprintf(stderr, "Failed to set key and IV for context 1: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (1 != EVP_EncryptUpdate(ctx1, ciphertext, &len, plaintext1, sizeof(plaintext1))) {
        fprintf(stderr, "Failed to encrypt data with context 1: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 1.3 print ciphertext of first block
    printf("Ciphertext after first block encryption:\n");
    for (i = 0; i < len; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    // 2. Create the second context
    ctx2 = EVP_CIPHER_CTX_new();
    if (!ctx2) {
        fprintf(stderr, "Failed to create cipher context 2: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    // 3. Copy the state from ctx1 to ctx2
    if (1 != EVP_CIPHER_CTX_copy(ctx2, ctx1)) {
        fprintf(stderr, "Failed to copy cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. Now ctx2 can continue encryption from the state of ctx1
    if (1 != EVP_EncryptUpdate(ctx2, ciphertext + len, &len, plaintext2, sizeof(plaintext2))) {
        fprintf(stderr, "Failed to encrypt data with context 2: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    // print ciphertext of second block
    printf("Ciphertext after second block encryption with context 2:\n");
    for (i = 0; i < len; i++) {
        printf("%02x ", ciphertext[len + i]);
    }
    printf("\n");

    // 5. use ctx1 encrypt plain2 again to verify both ctx1 and ctx2 are in same state
    int len2 = 0;
    if (1 != EVP_EncryptUpdate(ctx1, ciphertext2, &len2, plaintext2, sizeof(plaintext2))) {
        fprintf(stderr, "Failed to encrypt data with context 1 again: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    // print ciphertext2
    printf("Ciphertext after second block encryption with context 1 again:\n");
    for (i = 0; i < len2; i++) {
        printf("%02x ", ciphertext2[i]);
    }
    printf("\n");

    // 6. Compare ciphertext from both contexts
    // Note: After EVP_CIPHER_CTX_copy, both contexts should be in the same state
    // and produce identical output for the same input
    if (len != len2 || memcmp(ciphertext + sizeof(plaintext1), ciphertext2, len) != 0) {
        fprintf(stderr, "Ciphertexts do not match, context copy failed\n");
        ret = -1;
        goto out;
    } else {
        printf("Ciphertexts match, context copy succeeded\n");
        printf("This confirms that EVP_CIPHER_CTX_copy correctly duplicates the cipher state\n");
    }

    // 7. finalize both contexts
    if (1 != EVP_EncryptFinal_ex(ctx1, ciphertext + sizeof(plaintext1) + len, &len)) {
        fprintf(stderr, "Failed to finalize encryption with context 1: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (1 != EVP_EncryptFinal_ex(ctx2, ciphertext2 + len2, &len2)) {
        fprintf(stderr, "Failed to finalize encryption with context 2: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }


out:
    if (ctx1) {
        EVP_CIPHER_CTX_free(ctx1);
    }
    if (ctx2) {
        EVP_CIPHER_CTX_free(ctx2);
    }
    return ret;
}