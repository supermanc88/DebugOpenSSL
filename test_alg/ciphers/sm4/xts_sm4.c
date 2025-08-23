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

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define XTS_SM4_KEY_SIZE (SM4_KEY_SIZE * 2)
#define XTS_SM4_TWEAK_SIZE 16
#define SM4_IV_SIZE 16


int call_xts_sm4_encrypt(unsigned char *key, unsigned char *iv,
                         unsigned char *in, size_t in_len,
                         unsigned char *out, int *out_len) {
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;
    EVP_CIPHER *cipher = NULL;

    // get the cipher
    cipher = EVP_CIPHER_fetch(NULL, "SM4-XTS", NULL);
    if (!cipher) {
        fprintf(stderr, "Failed to get SM4-XTS cipher: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Initialize the encryption operation with XTS mode
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        fprintf(stderr, "Failed to initialize encryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Provide the message to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, out, &len, in, in_len)) {
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

    *out_len = ciphertext_len;

    ret = 0;

out:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}

int call_xtx_sm4_decrypt(unsigned char *key, unsigned char *iv,
                         unsigned char *in, size_t in_len,
                         unsigned char *out, int *out_len) {
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int plaintext_len = 0;
    EVP_CIPHER *cipher = NULL;

    // get the cipher
    cipher = EVP_CIPHER_fetch(NULL, "SM4-XTS", NULL);
    if (!cipher) {
        fprintf(stderr, "Failed to get SM4-XTS cipher: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Initialize the decryption operation with XTS mode
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        fprintf(stderr, "Failed to initialize decryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
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

    unsigned char key[XTS_SM4_KEY_SIZE] = {0}; // double length for XTS mode
    unsigned char iv[XTS_SM4_TWEAK_SIZE] = {0}; // SM4 IV size is 16 bytes
    unsigned char data[] = "Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!"; // Example data to be processed
    size_t data_len = sizeof(data) - 1; // Exclude null terminator
    unsigned char cipher_out[sizeof(data)] = {0};
    int cipher_out_len = 0;
    unsigned char plain_out[sizeof(data)] = {0};
    int plain_out_len = 0;

    // Encrypt the data
    call_xts_sm4_encrypt(key, iv, data, data_len, cipher_out, &cipher_out_len);
    // print the resulting ciphertext
    printf("SM4 XTS Ciphertext: ");
    for (int i = 0; i < cipher_out_len; i++) {
        printf("%02x", cipher_out[i]);
    }
    printf("\n");

    // Decrypt the data
    call_xtx_sm4_decrypt(key, iv, cipher_out, cipher_out_len, plain_out, &plain_out_len);
    // print the resulting plaintext
    printf("SM4 XTS Decrypted Plaintext: ");
    for (int i = 0; i < plain_out_len; i++) {
        printf("%c", plain_out[i]);
    }
    printf("\n");

    return ret;
}