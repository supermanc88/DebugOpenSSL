#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#define DES_KEY_SIZE 8
#define DES_BLOCK_SIZE 8
#define DES_IV_SIZE 8
#define PLAINTEXT_SIZE 64

unsigned char des_key[DES_KEY_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

unsigned char des_iv[DES_IV_SIZE] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
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

void test_cfb_mode(const char *mode_name, const EVP_CIPHER *cipher) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ciphertext[PLAINTEXT_SIZE] = {0};
    unsigned char decryptedtext[PLAINTEXT_SIZE] = {0};
    int len = 0;
    int ciphertext_len = 0;
    int decryptedtext_len = 0;

    printf("\n========== %s 加密测试 ==========\n", mode_name);

    // 加密
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || 1 != EVP_EncryptInit_ex(ctx, cipher, NULL, des_key, des_iv)) {
        fprintf(stderr, "Failed to initialize encryption for %s\n", mode_name);
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    dump_hex("明文:", plain_text, sizeof(plain_text));

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain_text, sizeof(plain_text))) {
        fprintf(stderr, "Failed to encrypt data for %s\n", mode_name);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fprintf(stderr, "Failed to finalize encryption for %s\n", mode_name);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += len;

    dump_hex("密文:", ciphertext, ciphertext_len);
    printf("密文长度: %d 字节\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    // 解密
    printf("\n========== %s 解密测试 ==========\n", mode_name);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || 1 != EVP_DecryptInit_ex(ctx, cipher, NULL, des_key, des_iv)) {
        fprintf(stderr, "Failed to initialize decryption for %s\n", mode_name);
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "Failed to decrypt data for %s\n", mode_name);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    decryptedtext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) {
        fprintf(stderr, "Failed to finalize decryption for %s\n", mode_name);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    decryptedtext_len += len;

    dump_hex("解密后明文:", decryptedtext, decryptedtext_len);
    printf("解密后明文长度: %d 字节\n", decryptedtext_len);

    // 验证
    if (decryptedtext_len == sizeof(plain_text) &&
        memcmp(plain_text, decryptedtext, sizeof(plain_text)) == 0) {
        printf("✅ 验证成功：解密结果与原始明文一致\n");
    } else {
        printf("❌ 验证失败：解密结果与原始明文不一致\n");
    }

    EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char *argv[])
{
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    if (!legacy || !deflt) {
        fprintf(stderr, "Failed to load providers\n");
        return -1;
    }

    printf("========================================\n");
    printf("DES CFB 模式变体测试\n");
    printf("========================================\n");
    printf("CFB1: 1位反馈（每次处理1位）\n");
    printf("CFB8: 8位反馈（每次处理1字节）\n");
    printf("CFB64: 64位反馈（每次处理8字节，标准CFB）\n");
    printf("========================================\n");

    dump_hex("密钥:", des_key, sizeof(des_key));
    dump_hex("IV:", des_iv, sizeof(des_iv));

    // 测试 CFB1
    test_cfb_mode("DES-CFB1", EVP_des_cfb1());

    // 测试 CFB8
    test_cfb_mode("DES-CFB8", EVP_des_cfb8());

    // 测试 CFB64（与之前的 cfb_des.c 相同）
    test_cfb_mode("DES-CFB64", EVP_des_cfb64());

    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(deflt);
    return 0;
}
