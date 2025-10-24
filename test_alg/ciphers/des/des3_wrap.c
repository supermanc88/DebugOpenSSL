/**
 * 3DES Key Wrapping 模式测试
 * 
 * 3DES Key Wrapping (DES-EDE3-WRAP) 是一种特殊的密钥包裹算法
 * 用于安全地传输或存储其他密钥
 * 
 * 标准：RFC 3217 - Triple-DES and RC2 Key Wrapping
 * 
 * 特点：
 * - 输入必须是 8 字节的倍数
 * - 自动添加完整性校验值（ICV）
 * - 提供密钥的机密性和完整性保护
 * - 常用于密钥管理系统
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) {
            printf("\n%*s", (int)strlen(label), "");
        }
    }
    printf("\n");
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
    printf("3DES Key Wrapping 测试\n");
    printf("========================================\n");
    printf("标准：RFC 3217\n");
    printf("用途：安全地包裹其他密钥\n");
    printf("特点：提供机密性 + 完整性保护\n");
    printf("========================================\n\n");
    
    // Key Encryption Key (KEK) - 用于包裹其他密钥的密钥
    unsigned char kek[24] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,  // K1
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,  // K2
        0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67   // K3
    };
    
    print_hex("Key Encryption Key (KEK):\n", kek, 24);
    printf("\n");
    
    // 要包裹的密钥（例如一个 AES-128 密钥）
    unsigned char key_to_wrap[16];
    RAND_bytes(key_to_wrap, sizeof(key_to_wrap));
    
    print_hex("要包裹的密钥 (16字节 AES密钥):\n", key_to_wrap, 16);
    printf("\n");
    
    // 包裹后的密钥缓冲区
    unsigned char wrapped_key[128];
    unsigned char unwrapped_key[128];
    int wrapped_len, unwrapped_len;
    
    // ========== Key Wrapping 测试 ==========
    printf("========== Key Wrapping ==========\n");
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_des_ede3_wrap();
    
    // 初始化包裹操作
    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, kek, NULL)) {
        printf("❌ 包裹初始化失败\n");
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        OSSL_PROVIDER_unload(deflt);
        return 1;
    }
    
    // 包裹密钥
    if (!EVP_EncryptUpdate(ctx, wrapped_key, &wrapped_len, key_to_wrap, sizeof(key_to_wrap))) {
        printf("❌ 密钥包裹失败\n");
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        OSSL_PROVIDER_unload(deflt);
        return 1;
    }
    
    int final_len;
    if (!EVP_EncryptFinal_ex(ctx, wrapped_key + wrapped_len, &final_len)) {
        printf("❌ 包裹完成失败\n");
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        OSSL_PROVIDER_unload(deflt);
        return 1;
    }
    wrapped_len += final_len;
    
    print_hex("包裹后的密钥:\n", wrapped_key, wrapped_len);
    printf("包裹后长度: %d 字节 (原长度 %d 字节)\n", wrapped_len, 16);
    printf("✅ 密钥包裹成功\n\n");
    
    // ========== Key Unwrapping 测试 ==========
    printf("========== Key Unwrapping ==========\n");
    
    // 初始化解包裹操作
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, kek, NULL)) {
        printf("❌ 解包裹初始化失败\n");
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        OSSL_PROVIDER_unload(deflt);
        return 1;
    }
    
    // 解包裹密钥
    if (!EVP_DecryptUpdate(ctx, unwrapped_key, &unwrapped_len, wrapped_key, wrapped_len)) {
        printf("❌ 密钥解包裹失败\n");
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        OSSL_PROVIDER_unload(deflt);
        return 1;
    }
    
    if (!EVP_DecryptFinal_ex(ctx, unwrapped_key + unwrapped_len, &final_len)) {
        printf("❌ 解包裹完成失败（可能是完整性校验失败）\n");
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        OSSL_PROVIDER_unload(deflt);
        return 1;
    }
    unwrapped_len += final_len;
    
    print_hex("解包裹后的密钥:\n", unwrapped_key, unwrapped_len);
    printf("解包裹后长度: %d 字节\n", unwrapped_len);
    
    // 验证
    if (unwrapped_len == sizeof(key_to_wrap) && 
        memcmp(key_to_wrap, unwrapped_key, sizeof(key_to_wrap)) == 0) {
        printf("✅ 验证成功：解包裹后的密钥与原始密钥一致\n");
    } else {
        printf("❌ 验证失败：解包裹后的密钥与原始密钥不一致\n");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // ========== 完整性保护测试 ==========
    printf("\n========== 完整性保护测试 ==========\n");
    printf("测试：篡改包裹后的密钥\n");
    
    // 篡改包裹后的密钥
    wrapped_key[5] ^= 0xFF;
    printf("已篡改包裹密钥的第 6 个字节\n");
    
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, kek, NULL);
    
    int result = EVP_DecryptUpdate(ctx, unwrapped_key, &unwrapped_len, wrapped_key, wrapped_len);
    if (result && EVP_DecryptFinal_ex(ctx, unwrapped_key + unwrapped_len, &final_len)) {
        printf("⚠️  解包裹成功（意外）\n");
    } else {
        printf("✅ 解包裹失败（预期行为）- 完整性校验成功检测到篡改\n");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // ========== 说明 ==========
    printf("\n========================================\n");
    printf("技术说明\n");
    printf("========================================\n");
    printf("1. Key Wrapping 自动添加完整性校验值\n");
    printf("2. 包裹后长度 = 原长度 + 8 字节（ICV + padding）\n");
    printf("3. 任何篡改都会导致解包裹失败\n");
    printf("4. 输入长度必须是 8 字节的倍数\n");
    printf("5. 符合 RFC 3217 标准\n");
    printf("\n");
    printf("使用场景：\n");
    printf("- 密钥分发系统\n");
    printf("- 密钥备份\n");
    printf("- PKI 系统中的密钥传输\n");
    printf("- HSM (硬件安全模块) 密钥导入/导出\n");
    printf("\n");
    printf("⚠️  注意：虽然提供完整性保护，但 3DES 本身\n");
    printf("    已被认为不够安全，推荐使用 AES Key Wrap (RFC 3394)\n");
    printf("========================================\n");
    
    // 清理
    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(deflt);
    
    return 0;
}
