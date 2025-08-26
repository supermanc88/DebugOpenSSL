#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define SM4_KEY_SIZE 16
#define SM4_BLOCK_SIZE 16
#define SM4_IV_SIZE 16

int call_sm4_cfb_encrypt(unsigned char *key,
                         unsigned char *iv,
                         unsigned char *in, size_t inlen,
                         unsigned char *out, size_t *outlen) {
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int ciphertext_len = 0;
    int len = 0;

    // Get the SM4 CFB cipher, we can use EVP_sm4_cfb128() directly
    cipher = EVP_sm4_cfb128();
    if (!cipher) {
        fprintf(stderr, "Failed to get SM4-CFB cipher: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        fprintf(stderr, "Failed to initialize encryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // CFB mode does not require padding
    if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        fprintf(stderr, "Failed to disable padding: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Provide the message to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, out, &len, in, inlen)) {
        fprintf(stderr, "Failed to encrypt data: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, out + len, &len)) {
        fprintf(stderr, "Failed to finalize encryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ciphertext_len += len;

    // Set the output length
    *outlen = ciphertext_len;
    ret = 0;
out:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}

int call_sm4_cfb_decrypt(unsigned char *key,
                         unsigned char *iv,
                         unsigned char *in, size_t in_len,
                         unsigned char *out, size_t *out_len) {
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int len = 0;
    int plaintext_len = 0;

    // get the cipher, for CFB mode, we can use EVP_sm4_cfb128() directly
    cipher = EVP_sm4_cfb128();
    if (!cipher) {
        fprintf(stderr, "Failed to get SM4-CFB cipher: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        fprintf(stderr, "Failed to initialize decryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // CFB mode does not require padding
    if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        fprintf(stderr, "Failed to disable padding: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Provide the message to be decrypted, and obtain the plaintext output
    if (1 != EVP_DecryptUpdate(ctx, out, &len, in, in_len)) {
        fprintf(stderr, "Failed to decrypt data: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    plaintext_len = len;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, out + len, &len)) {
        fprintf(stderr, "Failed to finalize decryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    plaintext_len += len;

    // Set the output length
    *out_len = plaintext_len;
    ret = 0;
out:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}


int main(int argc, char *argv[]) {
    int ret = 0;

    unsigned char key[SM4_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char iv[SM4_IV_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char plaintext[] = "Hello, this is a test message for SM4 CFB mode encryption!";
    unsigned char ciphertext[128] = {0};
    unsigned char decryptedtext[128] = {0};
    size_t outlen = 0;

    ret = call_sm4_cfb_encrypt(key, iv, plaintext, strlen((char *)plaintext), ciphertext, &outlen);
    if (ret != 0) {
        fprintf(stderr, "SM4 CFB encryption failed\n");
        return ret;
    }
    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < outlen; i++) {
        printf("%02x", ciphertext[i]);
    }

    ret = call_sm4_cfb_decrypt(key, iv, ciphertext, outlen, decryptedtext, &outlen);
    if (ret != 0) {
        fprintf(stderr, "SM4 CFB decryption failed\n");
        return ret;
    }
    decryptedtext[outlen] = '\0'; // Null-terminate the decrypted string
    printf("\nDecrypted text: %s\n", decryptedtext);

    return ret;
}