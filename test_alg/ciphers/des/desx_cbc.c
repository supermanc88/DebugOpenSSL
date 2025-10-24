#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#define DESX_KEY_SIZE 24  // DESX 使用 24 字节密钥
#define DES_BLOCK_SIZE 8
#define DES_IV_SIZE 8
#define PLAINTEXT_SIZE 64

// DESX 密钥：8字节 DES 密钥 + 16字节额外密钥材料
unsigned char desx_key[DESX_KEY_SIZE] = {
    // DES 密钥 (8字节)
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    // 额外密钥材料 (16字节)
    0xf1, 0xe0, 0xd3, 0xc2, 0xb5, 0xa4, 0x97, 0x86,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

unsigned char des_iv[DES_IV_SIZE] = {
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
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

int main(int argc, char *argv[])
{
    int ret = 0;
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    if (!legacy || !deflt) {
        fprintf(stderr, "Failed to load providers\n");
        return -1;
    }

    const EVP_CIPHER *cipher = EVP_desx_cbc();
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ciphertext[PLAINTEXT_SIZE + DES_BLOCK_SIZE] = {0};
    unsigned char decryptedtext[PLAINTEXT_SIZE + DES_BLOCK_SIZE] = {0};
    int len = 0;
    int ciphertext_len = 0;
    int decryptedtext_len = 0;

    printf("========== DESX-CBC 加密测试 ==========\n");
    printf("DESX (DES-X) 是 DES 的增强版本\n");
    printf("- 使用 24 字节密钥（8字节DES密钥 + 16字节额外密钥材料）\n");
    printf("- 通过白化技术增强安全性\n");
    printf("- 比 DES 更安全，但比 3DES 快\n");
    printf("- 有效密钥长度：约 120 位\n\n");

    // Create and initialize the context for encryption
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create cipher context\n");
        ret = -1;
        goto cleanup;
    }

    // Initialize encryption
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, desx_key, des_iv)) {
        fprintf(stderr, "Failed to initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        ret = -1;
        goto cleanup;
    }

    // CBC 模式使用 PKCS7 填充
    EVP_CIPHER_CTX_set_padding(ctx, 1);

    dump_hex("DESX密钥 (192位):", desx_key, sizeof(desx_key));
    dump_hex("IV:", des_iv, sizeof(des_iv));
    dump_hex("明文:", plain_text, sizeof(plain_text));

    // Encrypt the plaintext
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain_text, sizeof(plain_text))) {
        fprintf(stderr, "Failed to encrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        ret = -1;
        goto cleanup;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fprintf(stderr, "Failed to finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        ret = -1;
        goto cleanup;
    }
    ciphertext_len += len;

    dump_hex("密文:", ciphertext, ciphertext_len);
    printf("密文长度: %d 字节\n\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    // ========== 解密测试 ==========
    printf("========== DESX-CBC 解密测试 ==========\n");

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create cipher context for decryption\n");
        ret = -1;
        goto cleanup;
    }

    // Initialize decryption (使用相同的密钥和 IV)
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, desx_key, des_iv)) {
        fprintf(stderr, "Failed to initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        ret = -1;
        goto cleanup;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 1);

    // Decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "Failed to decrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        ret = -1;
        goto cleanup;
    }
    decryptedtext_len = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) {
        fprintf(stderr, "Failed to finalize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        ret = -1;
        goto cleanup;
    }
    decryptedtext_len += len;

    dump_hex("解密后明文:", decryptedtext, decryptedtext_len);
    printf("解密后明文长度: %d 字节\n\n", decryptedtext_len);

    // Verify
    if (decryptedtext_len == sizeof(plain_text) &&
        memcmp(plain_text, decryptedtext, sizeof(plain_text)) == 0) {
        printf("✅ 验证成功：解密结果与原始明文一致\n");
        ret = 0;
    } else {
        printf("❌ 验证失败：解密结果与原始明文不一致\n");
        ret = -1;
    }

    EVP_CIPHER_CTX_free(ctx);

cleanup:
    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(deflt);
    return ret;
}
