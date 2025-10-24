#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define AES128_KEY_SIZE 16
#define AES192_KEY_SIZE 24
#define AES256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_IV_SIZE 16
#define PLAINTEXT_SIZE 64

unsigned char aes128_key[AES128_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

unsigned char aes192_key[AES192_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
};

unsigned char aes256_key[AES256_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

unsigned char aes_iv[AES_IV_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

unsigned char plain_text[PLAINTEXT_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};

unsigned char aes128_ciphertext[PLAINTEXT_SIZE] = {
	0x0a, 0x95, 0x09, 0xb6, 0x45, 0x6b, 0xf6, 0x42, 
	0xf9, 0xca, 0x9e, 0x53, 0xca, 0x5e, 0xe4, 0x55, 
	0x12, 0x72, 0xfe, 0x87, 0x72, 0x0d, 0x64, 0x81, 
	0x82, 0xc3, 0xe7, 0x14, 0x57, 0xb9, 0x11, 0xc3, 
	0x3a, 0x0c, 0xb6, 0x90, 0x35, 0x39, 0x83, 0xdf, 
	0x95, 0xeb, 0xe2, 0x66, 0xe0, 0x04, 0xc2, 0x68, 
	0x7d, 0x3a, 0x99, 0xe1, 0xad, 0x6a, 0xa9, 0x30, 
	0x5a, 0x1a, 0x1e, 0x53, 0x7b, 0x88, 0xed, 0x31, 
};

unsigned char aes192_ciphertext[PLAINTEXT_SIZE] = {
	0x00, 0x61, 0xbd, 0xfd, 0x42, 0x86, 0x4d, 0xbf, 
	0xd2, 0x55, 0xf3, 0xad, 0x13, 0xff, 0x2e, 0xa1, 
	0x39, 0xe6, 0x71, 0xfb, 0xb5, 0x60, 0xd0, 0xa8, 
	0xbd, 0x4d, 0x8e, 0x92, 0x0e, 0x99, 0x5b, 0xea, 
	0x73, 0xe6, 0x32, 0xda, 0xd8, 0x01, 0xda, 0xc6, 
	0xb3, 0x66, 0xb2, 0x1c, 0x17, 0xec, 0xc2, 0x00, 
	0x23, 0x7c, 0x22, 0x37, 0x39, 0x15, 0x8a, 0x6f, 
	0x16, 0xef, 0x1b, 0xe3, 0xb7, 0x6f, 0xbe, 0x16, 
};

unsigned char aes256_ciphertext[PLAINTEXT_SIZE] = {
	0x5a, 0x6f, 0x06, 0x54, 0x0c, 0xfe, 0x77, 0x91, 
	0xf8, 0x27, 0x5f, 0x36, 0x0e, 0xce, 0xa8, 0x9d, 
	0x70, 0xe2, 0x02, 0xc6, 0xd7, 0x90, 0x4e, 0x4a, 
	0x4d, 0x0f, 0xe1, 0x4a, 0x6e, 0xf8, 0x3e, 0xd0, 
	0x3c, 0x44, 0x55, 0x78, 0x1e, 0xe0, 0xea, 0x83, 
	0x93, 0xc8, 0x21, 0x8e, 0xc9, 0x3c, 0xe9, 0xbd, 
	0xa6, 0xfa, 0x35, 0x41, 0x1c, 0xa5, 0x91, 0xd8, 
	0x51, 0x79, 0x67, 0x2b, 0xc5, 0x59, 0xd3, 0x62, 
};



// 辅助函数：以十六进制格式打印缓冲区内容
int dump_hex(const char *title, const unsigned char *buf, size_t len) {
    if (title) {
        printf("%s\n", title);
    }
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    return 0;
}

EVP_CIPHER *get_aes_ctr_cipher(int key_size) {
    switch (key_size) {
        case 16:
            return EVP_aes_128_ctr();
        case 24:
            return EVP_aes_192_ctr();
        case 32:
            return EVP_aes_256_ctr();
        default:
            return NULL;
    }
}

unsigned int aes_key_size[] = {16, 24, 32};


int main(int argc, char *argv[])
{
    int ret = 0;

    // test AES Encryption in CTR mode with different key sizes
    for (int i = 0; i < 3; i++) {
        int key_size = aes_key_size[i];
        EVP_CIPHER *cipher = get_aes_ctr_cipher(key_size);
        EVP_CIPHER_CTX *ctx = NULL;
        unsigned char *key = NULL;
        unsigned char ciphertext[PLAINTEXT_SIZE] = {0};
        unsigned char *expected_ciphertext = NULL;

        if (!cipher) {
            fprintf(stderr, "Unsupported AES key size: %d\n", key_size);
            ret = -1;
            continue;
        }

        switch (key_size) {
            case 16:
                key = aes128_key;
                expected_ciphertext = aes128_ciphertext;
                break;
            case 24:
                key = aes192_key;
                expected_ciphertext = aes192_ciphertext;
                break;
            case 32:
                key = aes256_key;
                expected_ciphertext = aes256_ciphertext;
                break;
        }

        // Create and initialize the context
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            continue;
        }

        if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, aes_iv)) {
            fprintf(stderr, "Failed to initialize cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
            fprintf(stderr, "Failed to disable padding: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // Encrypt the plaintext
        int len = 0;
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain_text, sizeof(plain_text))) {
            fprintf(stderr, "Failed to encrypt data: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // Finalize encryption
        int final_len = 0;
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len)) {
            fprintf(stderr, "Failed to finalize encryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }
        len += final_len;

        // Print the ciphertext
        char title[64];
        snprintf(title, sizeof(title), "AES-%d-CTR Ciphertext:", key_size * 8);
        dump_hex(title, ciphertext, len);

        // compare with expected ciphertext
        if (memcmp(ciphertext, expected_ciphertext, PLAINTEXT_SIZE) != 0) {
            fprintf(stderr, "AES-%d-CTR encryption failed: ciphertext does not match expected value\n", key_size * 8);
            ret = -1;
        } else {
            printf("AES-%d-CTR encryption succeeded: ciphertext matches expected value\n", key_size * 8);
        }

        EVP_CIPHER_CTX_free(ctx);
    }

    // test AES Decryption in CTR mode with different key sizes
    for (int i = 0; i < 3; i++) {
        int key_size = aes_key_size[i];
        EVP_CIPHER *cipher = get_aes_ctr_cipher(key_size);
        EVP_CIPHER_CTX *ctx = NULL;
        unsigned char *key = NULL;
        unsigned char decrypted_text[PLAINTEXT_SIZE] = {0};
        unsigned char *expected_plaintext = NULL;
        unsigned char *expected_ciphertext = NULL;

        if (!cipher) {
            fprintf(stderr, "Unsupported AES key size: %d\n", key_size);
            ret = -1;
            continue;
        }

        switch (key_size) {
            case 16:
                key = aes128_key;
                expected_plaintext = plain_text;
                expected_ciphertext = aes128_ciphertext;
                break;
            case 24:
                key = aes192_key;
                expected_plaintext = plain_text;
                expected_ciphertext = aes192_ciphertext;
                break;
            case 32:
                key = aes256_key;
                expected_plaintext = plain_text;
                expected_ciphertext = aes256_ciphertext;
                break;
        }

        // Create and initialize the context
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            continue;
        }

        if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, aes_iv)) {
            fprintf(stderr, "Failed to initialize cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
            fprintf(stderr, "Failed to disable padding: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // Decrypt the ciphertext
        int len = 0;
        if (1 != EVP_DecryptUpdate(ctx, decrypted_text, &len, expected_ciphertext, PLAINTEXT_SIZE)) {
            fprintf(stderr, "Failed to decrypt data: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // Finalize decryption
        int final_len = 0;
        if (1 != EVP_DecryptFinal_ex(ctx, decrypted_text + len, &final_len)) {
            fprintf(stderr, "Failed to finalize decryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }
        len += final_len;

        // Print the decrypted text
        char title[64];
        snprintf(title, sizeof(title), "AES-%d-CTR Decrypted Text:", key_size * 8);
        dump_hex(title, decrypted_text, len);

        // compare with original plaintext
        if (memcmp(decrypted_text, expected_plaintext, PLAINTEXT_SIZE) != 0) {
            fprintf(stderr, "AES-%d-CTR decryption failed: decrypted text does not match original plaintext\n", key_size * 8);
            ret = -1;
        } else {
            printf("AES-%d-CTR decryption succeeded: decrypted text matches original plaintext\n", key_size * 8);
        }

        EVP_CIPHER_CTX_free(ctx);
    }

    return ret;
}