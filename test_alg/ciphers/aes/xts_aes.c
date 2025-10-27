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
#define AES256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_IV_SIZE 16
#define PLAINTEXT_SIZE 64

// XTS mode requires double-length keys (one for encryption, one for tweak)
unsigned char aes128_xts_key[AES128_KEY_SIZE * 2] = {
    // First 128 bits for encryption
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    // Second 128 bits for tweak
    0xbf, 0xbe, 0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8,
    0xb7, 0xb6, 0xb5, 0xb4, 0xb3, 0xb2, 0xb1, 0xb0
};

unsigned char aes256_xts_key[AES256_KEY_SIZE * 2] = {
    // First 256 bits for encryption
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    // Second 256 bits for tweak
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
    0xbf, 0xbe, 0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8,
    0xb7, 0xb6, 0xb5, 0xb4, 0xb3, 0xb2, 0xb1, 0xb0
};

// XTS uses the IV as a "tweak" value, typically representing a sector number
unsigned char aes_xts_tweak[AES_IV_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
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

// Expected ciphertext for AES-128-XTS
unsigned char aes128_xts_ciphertext[PLAINTEXT_SIZE] = {
	0xbf, 0x5e, 0x67, 0xa9, 0xc0, 0xe5, 0xbc, 0x07, 
	0x70, 0xd1, 0x6a, 0x1c, 0xbe, 0x52, 0xe9, 0x60, 
	0x76, 0xba, 0xbb, 0xcb, 0xe5, 0x59, 0x28, 0x22, 
	0x9e, 0x8d, 0x83, 0x70, 0x7a, 0x21, 0x73, 0xbc, 
	0xed, 0xd3, 0x3d, 0x4c, 0x47, 0x80, 0xcf, 0x30, 
	0x48, 0x64, 0xe8, 0x0e, 0xb7, 0x4f, 0x45, 0x21, 
	0x8b, 0x9b, 0xc5, 0x8e, 0xc4, 0x0a, 0x4c, 0xc8, 
	0x0e, 0x6f, 0x9f, 0x25, 0x06, 0x91, 0xe2, 0xe8, 
};


// Expected ciphertext for AES-256-XTS
unsigned char aes256_xts_ciphertext[PLAINTEXT_SIZE] = {
	0x41, 0x4d, 0xf8, 0x7f, 0x7b, 0x66, 0x40, 0x47, 
	0x88, 0x21, 0x58, 0xbe, 0x40, 0xd3, 0x4e, 0x39, 
	0x91, 0xee, 0xb7, 0xd0, 0x83, 0x2a, 0x33, 0x97, 
	0x65, 0x58, 0x00, 0x74, 0x24, 0x82, 0x35, 0xff, 
	0xcb, 0xb5, 0x3e, 0xd2, 0xde, 0x88, 0xd4, 0x44, 
	0xb2, 0x37, 0xac, 0xe6, 0x68, 0x92, 0x99, 0x41, 
	0xde, 0x99, 0xc2, 0xb7, 0x42, 0x7f, 0xe7, 0x0d, 
	0x8a, 0xa7, 0x04, 0x1b, 0x11, 0x52, 0xc2, 0x02, 
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

const EVP_CIPHER *get_aes_xts_cipher(int key_size) {
    switch (key_size) {
        case 16:
            return EVP_aes_128_xts();
        case 32:
            return EVP_aes_256_xts();
        default:
            return NULL;
    }
}

unsigned int aes_key_size[] = {16, 32};  // XTS only supports 128-bit and 256-bit


int main(int argc, char *argv[])
{
    int ret = 0;

    printf("=== Testing AES-XTS Encryption ===\n\n");
    // test AES Encryption in XTS mode with different key sizes
    for (int i = 0; i < 2; i++) {
        int key_size = aes_key_size[i];
        const EVP_CIPHER *cipher = get_aes_xts_cipher(key_size);
        EVP_CIPHER_CTX *ctx = NULL;
        unsigned char *key = NULL;
        unsigned char ciphertext[PLAINTEXT_SIZE] = {0};
        unsigned char *expected_ciphertext = NULL;
        int len = 0;

        if (!cipher) {
            fprintf(stderr, "Unsupported AES key size: %d\n", key_size);
            ret = -1;
            continue;
        }

        switch (key_size) {
            case 16:
                key = aes128_xts_key;
                expected_ciphertext = aes128_xts_ciphertext;
                break;
            case 32:
                key = aes256_xts_key;
                expected_ciphertext = aes256_xts_ciphertext;
                break;
        }

        // Create and initialize the context
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            continue;
        }

        // XTS mode requires double-length keys
        if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, aes_xts_tweak)) {
            fprintf(stderr, "Failed to initialize cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // XTS mode does not use padding
        if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
            fprintf(stderr, "Failed to disable padding: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // Encrypt the plaintext
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain_text, sizeof(plain_text))) {
            fprintf(stderr, "Failed to encrypt data: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // if (1 != EVP_EncryptUpdate(ctx, ciphertext + len, &len, plain_text + len, sizeof(plain_text) / 2)) {
        //     fprintf(stderr, "Failed to encrypt data: %s\n", ERR_error_string(ERR_get_error(), NULL));
        //     EVP_CIPHER_CTX_free(ctx);
        //     ret = -1;
        //     continue;
        // }

        // Finalize encryption
        int final_len = 0;
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + 64, &final_len)) {
            fprintf(stderr, "Failed to finalize encryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }
        len += final_len;

        // Print the ciphertext
        char title[64];
        snprintf(title, sizeof(title), "AES-%d-XTS Ciphertext:", key_size * 8);
        dump_hex(title, ciphertext, 64);

        // compare with expected ciphertext
        if (memcmp(ciphertext, expected_ciphertext, PLAINTEXT_SIZE) != 0) {
            fprintf(stderr, "AES-%d-XTS encryption failed: ciphertext does not match expected value\n", key_size * 8);
            ret = -1;
        } else {
            printf("AES-%d-XTS encryption succeeded: ciphertext matches expected value\n", key_size * 8);
        }

        printf("AES-%d-XTS encryption completed\n\n", key_size * 8);

        EVP_CIPHER_CTX_free(ctx);
    }

    // test AES Decryption in XTS mode with different key sizes
    printf("\n=== Testing AES-XTS Decryption ===\n\n");
    for (int i = 0; i < 2; i++) {
        int key_size = aes_key_size[i];
        const EVP_CIPHER *cipher = get_aes_xts_cipher(key_size);
        EVP_CIPHER_CTX *ctx = NULL;
        unsigned char *key = NULL;
        unsigned char decrypted_text[PLAINTEXT_SIZE] = {0};
        unsigned char *expected_ciphertext = NULL;

        int len = 0;

        if (!cipher) {
            fprintf(stderr, "Unsupported AES key size: %d\n", key_size);
            ret = -1;
            continue;
        }

        switch (key_size) {
            case 16:
                key = aes128_xts_key;
                expected_ciphertext = aes128_xts_ciphertext;
                break;
            case 32:
                key = aes256_xts_key;
                expected_ciphertext = aes256_xts_ciphertext;
                break;
        }

        // Create and initialize the context
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            continue;
        }

        // XTS mode requires double-length keys
        if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, aes_xts_tweak)) {
            fprintf(stderr, "Failed to initialize cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // XTS mode does not use padding
        if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
            fprintf(stderr, "Failed to disable padding: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // Decrypt the ciphertext
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
        snprintf(title, sizeof(title), "AES-%d-XTS Decrypted Text:", key_size * 8);
        dump_hex(title, decrypted_text, len);

        // compare with original plaintext
        if (memcmp(decrypted_text, plain_text, PLAINTEXT_SIZE) != 0) {
            fprintf(stderr, "AES-%d-XTS decryption failed: decrypted text does not match original plaintext\n", key_size * 8);
            ret = -1;
        } else {
            printf("AES-%d-XTS decryption succeeded: decrypted text matches original plaintext\n\n", key_size * 8);
        }

        EVP_CIPHER_CTX_free(ctx);
    }

    return ret;
}