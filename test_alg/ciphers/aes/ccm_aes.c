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
	0x33, 0x14, 0xf1, 0x64, 0xd8, 0x85, 0xc2, 0xb6, 
	0x79, 0x1a, 0xc3, 0xeb, 0x0e, 0xe7, 0x8b, 0x8f, 
	0x7c, 0x47, 0x0b, 0x21, 0xdf, 0x11, 0xa1, 0x2f, 
	0x56, 0x7e, 0x56, 0x86, 0xec, 0x3d, 0xb5, 0xae, 
	0xd2, 0x64, 0x6b, 0x3e, 0x30, 0xbb, 0x28, 0x2a, 
	0x47, 0x19, 0x65, 0xf1, 0x98, 0x18, 0xc5, 0xf6, 
	0x98, 0x4f, 0xe5, 0x8b, 0xc3, 0x92, 0x95, 0x31, 
	0x82, 0x58, 0xfb, 0xc4, 0xe1, 0x4b, 0x0f, 0x87, 
};


unsigned char aes192_ciphertext[PLAINTEXT_SIZE] = {
	0x1f, 0x94, 0xe0, 0xc0, 0x48, 0xb9, 0xdb, 0xb9, 
	0x1d, 0xbc, 0x2c, 0x30, 0xa5, 0xec, 0xca, 0xe6, 
	0xda, 0xbc, 0x92, 0xec, 0x11, 0x5b, 0xa3, 0xad, 
	0xee, 0x47, 0x40, 0x85, 0xf0, 0x0c, 0x4f, 0xb6, 
	0xce, 0x8c, 0x37, 0xe0, 0x6f, 0xf1, 0xe4, 0xfc, 
	0x6a, 0x8e, 0x11, 0xf4, 0x75, 0x8a, 0x83, 0xfc, 
	0xe5, 0x0a, 0x38, 0x81, 0xbf, 0x95, 0x0e, 0x33, 
	0xaf, 0xb0, 0x97, 0x57, 0xd7, 0xa9, 0x0f, 0xc4, 
};


unsigned char aes256_ciphertext[PLAINTEXT_SIZE] = {
	0x8a, 0xd4, 0xba, 0x15, 0x3a, 0x2a, 0xcf, 0x90, 
	0xa4, 0xc0, 0xbb, 0x28, 0x01, 0x3d, 0x52, 0x4b, 
	0x2d, 0x65, 0x04, 0x66, 0x2d, 0x60, 0x4e, 0xae, 
	0x7d, 0xbc, 0x99, 0x4e, 0x89, 0x05, 0x3c, 0x6c, 
	0xe5, 0xed, 0xe8, 0x57, 0x96, 0xfd, 0xe7, 0xa3, 
	0xcb, 0xa9, 0x21, 0x3d, 0xea, 0x94, 0xb9, 0x70, 
	0x55, 0xfa, 0x4e, 0x40, 0xa8, 0x10, 0x85, 0x4f, 
	0x48, 0xf9, 0x71, 0x48, 0xf1, 0xe9, 0x19, 0x3e, 
};


unsigned char aes128_tag[16] = {
	0x3b, 0x17, 0xbf, 0xff, 0x50, 0xee, 0x5c, 0xbc, 
	0x22, 0xf6, 0x24, 0xf5, 0x59, 0xbe, 0x19, 0x5b, 
};

unsigned char aes192_tag[16] = {
	0x49, 0x88, 0x51, 0x08, 0x6c, 0xfb, 0xad, 0x35, 
	0x59, 0x82, 0xfe, 0xd1, 0xbf, 0xb1, 0x82, 0x1b, 
};

unsigned char aes256_tag[16] = {
	0x20, 0x27, 0xe9, 0x64, 0x20, 0xf6, 0xfb, 0xb5, 
	0x16, 0x78, 0xc1, 0x54, 0xa7, 0x1b, 0xee, 0x6f, 
};


unsigned char aes_ccm_nonce[12] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b
};

unsigned char aes_ccm_aad[20] = {
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

EVP_CIPHER *get_aes_ccm_cipher(int key_size) {
    switch (key_size) {
        case 16:
            return EVP_aes_128_ccm();
        case 24:
            return EVP_aes_192_ccm();
        case 32:
            return EVP_aes_256_ccm();
        default:
            return NULL;
    }
}

unsigned int aes_key_size[] = {16, 24, 32};


int main(int argc, char *argv[])
{
    int ret = 0;

    // test AES Encryption in CCM mode with different key sizes
    for (int i = 0; i < 1; i++) {
        int key_size = aes_key_size[i];
        EVP_CIPHER *cipher = get_aes_ccm_cipher(key_size);
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

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(aes_ccm_nonce), NULL)) {
            fprintf(stderr, "Failed to set IV length: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL)) {
            fprintf(stderr, "Failed to set tag length: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, aes_ccm_nonce)) {
            fprintf(stderr, "Failed to set key and IV: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // CCM mode requires setting the plaintext length before encryption
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, sizeof(plain_text))) {
            fprintf(stderr, "Failed to set plaintext length: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);
            ret = -1;
            continue;
        }

        // Set AAD (Additional Authenticated Data)
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aes_ccm_aad, sizeof(aes_ccm_aad))) {
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
        snprintf(title, sizeof(title), "AES-%d-CCM Ciphertext:", key_size * 8);
        dump_hex(title, ciphertext, len);
        dump_hex("Generated Tag:", tag, sizeof(tag));

        // compare with expected ciphertext
        if (memcmp(ciphertext, expected_ciphertext, PLAINTEXT_SIZE) != 0) {
            fprintf(stderr, "AES-%d-CCM encryption failed: ciphertext does not match expected value\n", key_size * 8);
            ret = -1;
        } else {
            printf("AES-%d-CCM encryption succeeded: ciphertext matches expected value\n", key_size * 8);
        }

        EVP_CIPHER_CTX_free(ctx);
    }
    //
    // // test AES Decryption in CCM mode with different key sizes
    // printf("\n=== Testing AES-CCM Decryption ===\n\n");
    // for (int i = 0; i < 3; i++) {
    //     int key_size = aes_key_size[i];
    //     EVP_CIPHER *cipher = get_aes_ccm_cipher(key_size);
    //     EVP_CIPHER_CTX *ctx = NULL;
    //     unsigned char *key = NULL;
    //     unsigned char decrypted_text[PLAINTEXT_SIZE] = {0};
    //     unsigned char *expected_plaintext = NULL;
    //     unsigned char *expected_ciphertext = NULL;
    //     unsigned char *expected_tag = NULL;
    //
    //     int len = 0;
    //
    //     if (!cipher) {
    //         fprintf(stderr, "Unsupported AES key size: %d\n", key_size);
    //         ret = -1;
    //         continue;
    //     }
    //
    //     switch (key_size) {
    //         case 16:
    //             key = aes128_key;
    //             expected_plaintext = plain_text;
    //             expected_ciphertext = aes128_ciphertext;
    //             expected_tag = aes128_tag;
    //             break;
    //         case 24:
    //             key = aes192_key;
    //             expected_plaintext = plain_text;
    //             expected_ciphertext = aes192_ciphertext;
    //             expected_tag = aes192_tag;
    //             break;
    //         case 32:
    //             key = aes256_key;
    //             expected_plaintext = plain_text;
    //             expected_ciphertext = aes256_ciphertext;
    //             expected_tag = aes256_tag;
    //             break;
    //     }
    //
    //     // Create and initialize the context
    //     ctx = EVP_CIPHER_CTX_new();
    //     if (!ctx) {
    //         fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
    //         ret = -1;
    //         continue;
    //     }
    //
    //     if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
    //         fprintf(stderr, "Failed to initialize cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
    //         EVP_CIPHER_CTX_free(ctx);
    //         ret = -1;
    //         continue;
    //     }
    //
    //     if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(aes_ccm_nonce), NULL)) {
    //         fprintf(stderr, "Failed to set IV length: %s\n", ERR_error_string(ERR_get_error(), NULL));
    //         EVP_CIPHER_CTX_free(ctx);
    //         ret = -1;
    //         continue;
    //     }
    //
    //     if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, expected_tag)) {
    //         fprintf(stderr, "Failed to set expected tag: %s\n", ERR_error_string(ERR_get_error(), NULL));
    //         EVP_CIPHER_CTX_free(ctx);
    //         ret = -1;
    //         continue;
    //     }
    //
    //     if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, aes_ccm_nonce)) {
    //         fprintf(stderr, "Failed to set key and IV: %s\n", ERR_error_string(ERR_get_error(), NULL));
    //         EVP_CIPHER_CTX_free(ctx);
    //         ret = -1;
    //         continue;
    //     }
    //
    //     // CCM mode requires setting the ciphertext length before decryption
    //     if (1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, PLAINTEXT_SIZE)) {
    //         fprintf(stderr, "Failed to set ciphertext length: %s\n", ERR_error_string(ERR_get_error(), NULL));
    //         EVP_CIPHER_CTX_free(ctx);
    //         ret = -1;
    //         continue;
    //     }
    //
    //     // Set AAD (Additional Authenticated Data)
    //     if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aes_ccm_aad, sizeof(aes_ccm_aad))) {
    //         fprintf(stderr, "Failed to add AAD data: %s\n", ERR_error_string(ERR_get_error(), NULL));
    //         EVP_CIPHER_CTX_free(ctx);
    //         ret = -1;
    //         continue;
    //     }
    //
    //     // Decrypt the ciphertext
    //     if (1 != EVP_DecryptUpdate(ctx, decrypted_text, &len, expected_ciphertext, PLAINTEXT_SIZE)) {
    //         fprintf(stderr, "Failed to decrypt data: %s\n", ERR_error_string(ERR_get_error(), NULL));
    //         EVP_CIPHER_CTX_free(ctx);
    //         ret = -1;
    //         continue;
    //     }
    //
    //     // Finalize decryption (this will verify the tag)
    //     int final_len = 0;
    //     if (1 != EVP_DecryptFinal_ex(ctx, decrypted_text + len, &final_len)) {
    //         fprintf(stderr, "Failed to finalize decryption (tag verification failed): %s\n", ERR_error_string(ERR_get_error(), NULL));
    //         EVP_CIPHER_CTX_free(ctx);
    //         ret = -1;
    //         continue;
    //     }
    //     len += final_len;
    //
    //     // Print the decrypted text
    //     char title[64];
    //     snprintf(title, sizeof(title), "AES-%d-CCM Decrypted Text:", key_size * 8);
    //     dump_hex(title, decrypted_text, len);
    //
    //     // compare with original plaintext
    //     if (memcmp(decrypted_text, expected_plaintext, PLAINTEXT_SIZE) != 0) {
    //         fprintf(stderr, "AES-%d-CCM decryption failed: decrypted text does not match original plaintext\n", key_size * 8);
    //         ret = -1;
    //     } else {
    //         printf("AES-%d-CCM decryption succeeded: decrypted text matches original plaintext\n", key_size * 8);
    //     }
    //
    //     EVP_CIPHER_CTX_free(ctx);
    // }

    return ret;
}