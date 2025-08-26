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
#define SM4_IV_SIZE 16
#define CTR_NONCE_LEN 16

int call_ctr_sm4_encrypt(unsigned char *key, unsigned char *iv,
                         unsigned char *in, size_t in_len,
                         unsigned char *out, int *out_len) {
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int len = 0;
    int ciphertext_len = 0;

    // get the cipher, for CTR mode, we can use EVP_sm4_ctr() directly
    cipher = EVP_sm4_ctr();
    if (!cipher) {
        fprintf(stderr, "Failed to get SM4-CTR cipher: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

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

    // ctr mode does not require padding
    if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        fprintf(stderr, "Failed to disable padding: %s\n", ERR_error_string(ERR_get_error(), NULL));
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
};

int call_ctr_sm4_decrypt(unsigned char *key, unsigned char *iv,
                         unsigned char *in, size_t in_len,
                         unsigned char *out, int *out_len) {
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int len = 0;
    int plaintext_len = 0;

    // get the cipher, for CTR mode, we can use EVP_sm4_ctr() directly
    cipher = EVP_sm4_ctr();
    if (!cipher) {
        fprintf(stderr, "Failed to get SM4-CTR cipher: %s\n", ERR_error_string(ERR_get_error(), NULL));
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

    // ctr mode does not require padding
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
};



int main(int argc, char *argv[]) {
    int ret = 0;

    unsigned char key[SM4_KEY_SIZE] = {0}; // SM4 key size is 16 bytes
    unsigned char iv[SM4_IV_SIZE] = {0};   // SM4 block size is 16 bytes
    unsigned char plaintext[128] = "This is a test message for SM4 CTR mode encryption and decryption.";
    unsigned char ciphertext[128] = {0};
    unsigned char decryptedtext[128] = {0};
    int decryptedtext_len = 0;
    int ciphertext_len = 0;
    size_t plaintext_len = strlen((char *)plaintext);
    int i;
    printf("Plaintext: %s\n", plaintext);

    ret = call_ctr_sm4_encrypt(key, iv, plaintext, plaintext_len, ciphertext, &ciphertext_len);
    if (ret != 0) {
        fprintf(stderr, "SM4 CTR encryption failed\n");
        return ret;
    }
    // print the resulting ciphertext
    printf("SM4 CTR Ciphertext: ");
    for (i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    ret = call_ctr_sm4_decrypt(key, iv, ciphertext, ciphertext_len, decryptedtext, &decryptedtext_len);
    if (ret != 0) {
        fprintf(stderr, "SM4 CTR decryption failed\n");
    }
    decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted string
    printf("Decrypted text: %s\n", decryptedtext);

    return ret;
}