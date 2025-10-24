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
	0x93, 0x6d, 0xa5, 0xcd, 0x62, 0x1e, 0xf1, 0x53, 
	0x43, 0xdb, 0x6b, 0x81, 0x3a, 0xae, 0x7e, 0x07, 
	0xa3, 0x37, 0x08, 0xf5, 0x47, 0xf8, 0xeb, 0xe1, 
	0xfe, 0x38, 0xeb, 0x36, 0x08, 0x59, 0xbc, 0x73, 
	0xa5, 0x85, 0xf9, 0xd4, 0xd0, 0xa5, 0x91, 0xc4, 
	0x68, 0xdd, 0x23, 0xcc, 0xec, 0xa4, 0xf9, 0xbd, 
	0xfc, 0xae, 0x26, 0xc3, 0x30, 0xb2, 0x00, 0x4c, 
	0x16, 0x77, 0x48, 0xe9, 0x96, 0x71, 0x28, 0xdb, 
};



unsigned char aes192_ciphertext[PLAINTEXT_SIZE] = {
	0xe6, 0xf8, 0x20, 0x98, 0x9d, 0xbc, 0xcf, 0x09, 
	0xd8, 0x3a, 0xd6, 0x89, 0xf3, 0xa4, 0xd2, 0x7f, 
	0x1e, 0x8e, 0x21, 0x18, 0x2c, 0xb4, 0x40, 0xa9, 
	0x67, 0x46, 0x71, 0x23, 0xd1, 0x8b, 0x3f, 0x43, 
	0xf7, 0x55, 0xd5, 0x52, 0x3e, 0x79, 0x2b, 0x2c, 
	0xdb, 0x8e, 0x3b, 0x4f, 0x58, 0xbf, 0x52, 0x47, 
	0x4e, 0xeb, 0xe8, 0x57, 0xb2, 0x74, 0xf8, 0xdd, 
	0x7a, 0x1d, 0xed, 0x94, 0xe4, 0x93, 0x48, 0x38, 
};



unsigned char aes256_ciphertext[PLAINTEXT_SIZE] = {
	0x47, 0x03, 0xd4, 0x18, 0xc1, 0xe0, 0xc4, 0x1c, 
	0x85, 0x48, 0x9d, 0x80, 0xbd, 0xe4, 0x76, 0x62, 
	0x93, 0xc7, 0x95, 0x27, 0xe4, 0x6e, 0x49, 0x6b, 
	0x20, 0x7e, 0xff, 0x9e, 0x01, 0x74, 0x1e, 0xad, 
	0x21, 0x31, 0x8c, 0xdf, 0x8b, 0xe4, 0x34, 0xbf, 
	0x5c, 0x8d, 0x55, 0xc6, 0xa4, 0xaa, 0x06, 0x17, 
	0xde, 0x68, 0x52, 0xbe, 0x6e, 0xe3, 0x95, 0xed, 
	0x07, 0xae, 0x10, 0x22, 0x24, 0xde, 0xcb, 0xd1, 
};



unsigned char aes128_tag[16] = {
	0x29, 0x20, 0xd6, 0x70, 0x9d, 0x8b, 0xb9, 0x8c, 
	0x33, 0xb4, 0xda, 0xd4, 0x6d, 0xd9, 0xcf, 0x08, 
};


unsigned char aes192_tag[16] = {
	0x1a, 0x03, 0xc7, 0x85, 0xda, 0x76, 0x8b, 0x6b, 
	0x5b, 0x39, 0x69, 0xdb, 0xad, 0xb0, 0xd1, 0x88, 
};


unsigned char aes256_tag[16] = {
	0xa3, 0x30, 0x8b, 0x10, 0xc4, 0x98, 0x73, 0x0e, 
	0xe5, 0xe4, 0xfe, 0xdd, 0x95, 0xd3, 0x17, 0xfe, 
};



unsigned char aes_gcm_nonce[12] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b
};

unsigned char aes_gcm_aad[20] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13
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

EVP_CIPHER *get_aes_gcm_cipher(int key_size) {
    switch (key_size) {
        case 16:
            return EVP_aes_128_gcm();
        case 24:
            return EVP_aes_192_gcm();
        case 32:
            return EVP_aes_256_gcm();
        default:
            return NULL;
    }
}

unsigned int aes_key_size[] = {16, 24, 32};


int main(int argc, char *argv[])
{
    int ret = 0;

    // test AES Encryption in GCM mode with different key sizes
    for (int i = 0; i < 3; i++) {
        int key_size = aes_key_size[i];
        EVP_CIPHER *cipher = get_aes_gcm_cipher(key_size);
        EVP_CIPHER_CTX *ctx = NULL;
        unsigned char *key = NULL;
        unsigned char ciphertext[PLAINTEXT_SIZE] = {0};
        unsigned char *expected_ciphertext = NULL;
        unsigned char *expected_tag = NULL;
        int len = 0;

        if (!cipher) {
            fprintf(stderr, "Unsupported AES key size: %d\n", key_size);
            ret = -1;
            continue;
        }

        switch (key_size) {
            case 16:
                key = aes128_key;
                expected_ciphertext = aes128_ciphertext;
                expected_tag = aes128_tag;
                break;
            case 24:
                key = aes192_key;
                expected_ciphertext = aes192_ciphertext;
                expected_tag = aes192_tag;
                break;
            case 32:
                key = aes256_key;
                expected_ciphertext = aes256_ciphertext;
                expected_tag = aes256_tag;
                break;
        }

        // Create and initialize the context
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            continue;
        }

        if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
            fprintf(stderr, "Failed to initialize cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(aes_gcm_nonce), NULL)) {
            fprintf(stderr, "Failed to set IV length: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL)) {
        //     fprintf(stderr, "Failed to set tag length: %s\n", ERR_error_string(ERR_get_error(), NULL));
        //     EVP_CIPHER_CTX_free(ctx);
        //     ret = -1;
        //     continue;
        // }

        if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, aes_gcm_nonce)) {
            fprintf(stderr, "Failed to set key and IV: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // // GCM mode requires setting the plaintext length before encryption
        // if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, sizeof(plain_text))) {
        //     fprintf(stderr, "Failed to set plaintext length: %s\n", ERR_error_string(ERR_get_error(), NULL));
        //     EVP_CIPHER_CTX_free(ctx);
        //     ret = -1;
        //     continue;
        // }

        // Set AAD (Additional Authenticated Data)
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aes_gcm_aad, sizeof(aes_gcm_aad))) {
            fprintf(stderr, "Failed to add AAD data: %s\n", ERR_error_string(ERR_get_error(), NULL));
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

        // Finalize encryption
        int final_len = 0;
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len)) {
            fprintf(stderr, "Failed to finalize encryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }
        len += final_len;

        // Get the tag
        unsigned char tag[16];
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sizeof(tag), tag)) {
            fprintf(stderr, "Failed to get tag: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // Print the ciphertext
        char title[64];
        snprintf(title, sizeof(title), "AES-%d-GCM Ciphertext:", key_size * 8);
        dump_hex(title, ciphertext, len);
        dump_hex("Generated Tag:", tag, sizeof(tag));

        // compare with expected ciphertext
        if (memcmp(ciphertext, expected_ciphertext, PLAINTEXT_SIZE) != 0) {
            fprintf(stderr, "AES-%d-GCM encryption failed: ciphertext does not match expected value\n", key_size * 8);
            ret = -1;
        } else {
            printf("AES-%d-GCM encryption succeeded: ciphertext matches expected value\n", key_size * 8);
        }

        EVP_CIPHER_CTX_free(ctx);
    }

    // test AES Decryption in GCM mode with different key sizes
    printf("\n=== Testing AES-GCM Decryption ===\n\n");
    for (int i = 0; i < 3; i++) {
        int key_size = aes_key_size[i];
        EVP_CIPHER *cipher = get_aes_gcm_cipher(key_size);
        EVP_CIPHER_CTX *ctx = NULL;
        unsigned char *key = NULL;
        unsigned char decrypted_text[PLAINTEXT_SIZE] = {0};
        unsigned char *expected_plaintext = NULL;
        unsigned char *expected_ciphertext = NULL;
        unsigned char *expected_tag = NULL;

        int len = 0;

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
                expected_tag = aes128_tag;
                break;
            case 24:
                key = aes192_key;
                expected_plaintext = plain_text;
                expected_ciphertext = aes192_ciphertext;
                expected_tag = aes192_tag;
                break;
            case 32:
                key = aes256_key;
                expected_plaintext = plain_text;
                expected_ciphertext = aes256_ciphertext;
                expected_tag = aes256_tag;
                break;
        }

        // Create and initialize the context
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            continue;
        }

        if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
            fprintf(stderr, "Failed to initialize cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(aes_gcm_nonce), NULL)) {
            fprintf(stderr, "Failed to set IV length: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, expected_tag)) {
            fprintf(stderr, "Failed to set expected tag: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, aes_gcm_nonce)) {
            fprintf(stderr, "Failed to set key and IV: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // GCM mode does NOT require setting the ciphertext length before decryption
        // This is different from CCM mode

        // Set AAD (Additional Authenticated Data)
        if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aes_gcm_aad, sizeof(aes_gcm_aad))) {
            fprintf(stderr, "Failed to add AAD data: %s\n", ERR_error_string(ERR_get_error(), NULL));
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

        // Finalize decryption (this will verify the tag)
        int final_len = 0;
        if (1 != EVP_DecryptFinal_ex(ctx, decrypted_text + len, &final_len)) {
            fprintf(stderr, "Failed to finalize decryption (tag verification failed): %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }
        len += final_len;

        // Print the decrypted text
        char title[64];
        snprintf(title, sizeof(title), "AES-%d-GCM Decrypted Text:", key_size * 8);
        dump_hex(title, decrypted_text, len);

        // compare with original plaintext
        if (memcmp(decrypted_text, expected_plaintext, PLAINTEXT_SIZE) != 0) {
            fprintf(stderr, "AES-%d-GCM decryption failed: decrypted text does not match original plaintext\n", key_size * 8);
            ret = -1;
        } else {
            printf("AES-%d-GCM decryption succeeded: decrypted text matches original plaintext\n", key_size * 8);
        }

        EVP_CIPHER_CTX_free(ctx);
    }

    return ret;
}