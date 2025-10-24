/**
 * 2-key 3DES (DES-EDE) 模式测试
 * 
 * 2-key 3DES 使用 128 位密钥（两个 DES 密钥）
 * 实际有效密钥长度：112 位（每个 DES 密钥 56 位）
 * 
 * 加密过程：E(K1) -> D(K2) -> E(K1)
 * 解密过程：D(K1) -> E(K2) -> D(K1)
 * 
 * 注意：2-key 3DES 比 3-key 3DES 弱，但比单 DES 强
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

// 通用测试函数
void test_des_ede_mode(const char *mode_name, const EVP_CIPHER *cipher, int needs_padding) {
    printf("\n========== %s 加密测试 ==========\n", mode_name);
    
    // 2-key 3DES: 16 字节（128 位）
    // K1 + K2，加密时会自动扩展为 K1+K2+K1
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,  // K1
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10   // K2
    };
    
    // IV（如果需要）
    unsigned char iv[8] = {
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
    };
    
    // 测试数据
    unsigned char plaintext[64];
    for (int i = 0; i < 64; i++) {
        plaintext[i] = i;
    }
    
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int len, ciphertext_len, decrypted_len;
    
    // 加密
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    // 判断是否需要 IV
    int iv_length = EVP_CIPHER_iv_length(cipher);
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv_length > 0 ? iv : NULL);
    
    if (needs_padding) {
        EVP_CIPHER_CTX_set_padding(ctx, 1);
    } else {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }
    
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    
    printf("明文:\n");
    for (int i = 0; i < 64; i++) {
        printf("%02x", plaintext[i]);
    }
    printf("\n密文:\n");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n密文长度: %d 字节\n", ciphertext_len);
    
    // 解密
    printf("\n========== %s 解密测试 ==========\n", mode_name);
    
    EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv_length > 0 ? iv : NULL);
    
    if (needs_padding) {
        EVP_CIPHER_CTX_set_padding(ctx, 1);
    } else {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }
    
    EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext, ciphertext_len);
    decrypted_len = len;
    EVP_DecryptFinal_ex(ctx, decrypted + len, &len);
    decrypted_len += len;
    
    printf("解密后明文:\n");
    for (int i = 0; i < decrypted_len; i++) {
        printf("%02x", decrypted[i]);
    }
    printf("\n解密后明文长度: %d 字节\n", decrypted_len);
    
    // 验证
    if (decrypted_len == 64 && memcmp(plaintext, decrypted, 64) == 0) {
        printf("✅ 验证成功：解密结果与原始明文一致\n");
    } else {
        printf("❌ 验证失败：解密结果与原始明文不一致\n");
    }
    
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    // 加载 legacy provider（支持 DES）
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    
    if (legacy == NULL) {
        printf("错误：无法加载 legacy provider\n");
        return 1;
    }
    
    printf("========================================\n");
    printf("2-key 3DES (DES-EDE) 模式测试\n");
    printf("========================================\n");
    printf("密钥长度：128 位（16 字节）\n");
    printf("有效强度：112 位\n");
    printf("加密流程：E(K1) -> D(K2) -> E(K1)\n");
    printf("========================================\n");
    printf("2-key 密钥:\n");
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    for (int i = 0; i < 16; i++) {
        printf("%02x", key[i]);
    }
    printf("\nIV:\n");
    unsigned char iv[8] = {
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
    };
    for (int i = 0; i < 8; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");
    
    // 测试各种模式
    test_des_ede_mode("DES-EDE-ECB", EVP_des_ede_ecb(), 1);
    test_des_ede_mode("DES-EDE-CBC", EVP_des_ede_cbc(), 1);
    test_des_ede_mode("DES-EDE-OFB", EVP_des_ede_ofb(), 0);
    test_des_ede_mode("DES-EDE-CFB64", EVP_des_ede_cfb64(), 0);
    
    printf("\n========================================\n");
    printf("注意事项\n");
    printf("========================================\n");
    printf("1. 2-key 3DES 使用 16 字节密钥 (K1 + K2)\n");
    printf("2. 加密: E(K1) -> D(K2) -> E(K1)\n");
    printf("3. 有效密钥长度: 112 位 (56 + 56)\n");
    printf("4. 比单 DES 安全，但比 3-key 3DES 弱\n");
    printf("5. 已被 NIST 逐步淘汰，建议使用 AES\n");
    printf("========================================\n");
    
    // 清理
    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(deflt);
    
    return 0;
}
