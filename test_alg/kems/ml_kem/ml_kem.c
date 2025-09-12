#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

/* Function to check OpenSSL version and ML-KEM support */
int check_ml_kem_support(void)
{
    printf("OpenSSL Version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("OpenSSL Build Info: %s\n", OpenSSL_version(OPENSSL_BUILT_ON));
    
    /* Check if we have at least OpenSSL 3.5.0 for ML-KEM support */
    if (OPENSSL_VERSION_NUMBER < 0x30500000L) {
        printf("WARNING: OpenSSL version may be too old for ML-KEM support.\n");
        printf("ML-KEM requires OpenSSL 3.5.0 or later.\n");
        printf("Current version: 0x%08lx\n", OPENSSL_VERSION_NUMBER);
        return -1;
    }
    
    /* Try to create a context for ML-KEM-512 to test support */
    EVP_PKEY_CTX *test_ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-512", NULL);
    if (!test_ctx) {
        printf("ERROR: ML-KEM-512 is not supported in this OpenSSL build.\n");
        printf("Please ensure you have a FIPS-enabled or post-quantum-enabled OpenSSL build.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    EVP_PKEY_CTX_free(test_ctx);
    printf("✓ ML-KEM support confirmed!\n\n");
    return 1; 
}

// ML-KEM 密钥解封装函数
int call_ml_kem_decap(const char *algo_name, EVP_PKEY *priv_key, unsigned char *ciphertext, size_t ciphertext_len, unsigned char **shared_secret, size_t *shared_secret_len) {
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;
    size_t secret_len = 0;
    unsigned char *secret = NULL;
    
    printf("\n=== 测试 ML-KEM 密钥解封装 (%s) ===\n", algo_name);
    
    // 1. 创建密钥解封装上下文
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        printf("错误: 无法创建密钥解封装上下文\n");
        goto cleanup;
    }
    
    // 2. 初始化解封装操作
    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        printf("错误: 无法初始化密钥解封装\n");
        goto cleanup;
    }
    
    // 3. 首先获取共享密钥长度
    if (EVP_PKEY_decapsulate(ctx, NULL, &secret_len, ciphertext, ciphertext_len) <= 0) {
        printf("错误: 无法获取共享密钥长度\n");
        goto cleanup;
    }
    
    printf("共享密钥长度: %zu bytes\n", secret_len);
    
    // 4. 分配共享密钥缓冲区
    secret = OPENSSL_malloc(secret_len);
    if (!secret) {
        printf("错误: 无法分配共享密钥缓冲区\n");
        goto cleanup;
    }
    
    // 5. 执行密钥解封装
    if (EVP_PKEY_decapsulate(ctx, secret, &secret_len, ciphertext, ciphertext_len) <= 0) {
        printf("错误: 密钥解封装失败\n");
        goto cleanup;
    }
    
    printf("密钥解封装成功！\n");
    printf("共享密钥: ");
    for (size_t i = 0; i < secret_len; i++) {
        printf("%02x", secret[i]);
    }
    printf("\n");
    
    // 6. 输出结果
    *shared_secret = secret;
    *shared_secret_len = secret_len;
    secret = NULL; // 防止被释放
    ret = 1;
    
cleanup:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (secret) {
        OPENSSL_free(secret);
    }
    
    return ret;
}

// 简化的密钥生成函数，返回EVP_PKEY
int call_ml_kem_gen_key_simple(const char *algo_name, EVP_PKEY **pkey_out) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;
    
    printf("\n=== 测试 ML-KEM 密钥生成 (%s) ===\n", algo_name);
    
    // 1. 创建密钥生成上下文
    ctx = EVP_PKEY_CTX_new_from_name(NULL, algo_name, NULL);
    if (!ctx) {
        printf("错误: 无法创建 %s 密钥生成上下文\n", algo_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 2. 初始化密钥生成
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("错误: 无法初始化 %s 密钥生成\n", algo_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 3. 生成密钥对
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("错误: 无法生成 %s 密钥对\n", algo_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    printf("密钥生成成功！\n");
    *pkey_out = pkey;
    pkey = NULL; // 防止被释放
    ret = 1;
    
cleanup:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    
    return ret;
}

int call_ml_kem_gen_key(const char *alg_name,
                        unsigned char **pub_key, int *pub_key_len,
                        unsigned char **priv_key, int *priv_key_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = -1;
    size_t pub_len = 0, priv_len = 0;

    /* Create context for key generation */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create context for %s\n", alg_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Initialize key generation */
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize key generation for %s\n", alg_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Generate key pair */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate key pair for %s\n", alg_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Get public key */
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len) != 1) {
        fprintf(stderr, "Failed to get public key length\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    *pub_key = (unsigned char *)malloc(pub_len);
    if (!*pub_key) {
        fprintf(stderr, "Failed to allocate memory for public key\n");
        goto cleanup;
    }

    if (EVP_PKEY_get_raw_public_key(pkey, *pub_key, &pub_len) != 1) {
        fprintf(stderr, "Failed to get raw public key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    *pub_key_len = (int)pub_len;

    /* Get private key */
    if (EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len) != 1) {
        fprintf(stderr, "Failed to get private key length\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    *priv_key = (unsigned char *)malloc(priv_len);
    if (!*priv_key) {
        fprintf(stderr, "Failed to allocate memory for private key\n");
        goto cleanup;
    }

    if (EVP_PKEY_get_raw_private_key(pkey, *priv_key, &priv_len) != 1) {
        fprintf(stderr, "Failed to get raw private key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    *priv_key_len = (int)priv_len;

    printf("Key generation successful for %s:\n", alg_name);
    printf("  Public key length: %d bytes\n", *pub_key_len);
    printf("  Private key length: %d bytes\n", *priv_key_len);

    ret = 0;

cleanup:
    if (ret != 0) {
        if (*pub_key) {
            free(*pub_key);
            *pub_key = NULL;
        }
        if (*priv_key) {
            free(*priv_key);
            *priv_key = NULL;
        }
    }
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

int call_ml_kem_encap(const char *alg_name,
                      const unsigned char *pub_key, int pub_key_len,
                      unsigned char **shared_secret, int *shared_secret_len,
                      unsigned char **ciphertext, int *ciphertext_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t secret_len = 0, cipher_len = 0;
    int ret = -1;

    /* Create PKEY from raw public key */
    pkey = EVP_PKEY_new_raw_public_key_ex(NULL, alg_name, NULL, pub_key, pub_key_len);
    if (!pkey) {
        fprintf(stderr, "Failed to create PKEY from raw public key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Create encapsulation context */
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create encapsulation context\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Initialize encapsulation */
    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        fprintf(stderr, "Failed to initialize encapsulation\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Get lengths for shared secret and ciphertext */
    if (EVP_PKEY_encapsulate(ctx, NULL, &secret_len, NULL, &cipher_len) <= 0) {
        fprintf(stderr, "Failed to get lengths for encapsulation\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Allocate memory for shared secret */
    *shared_secret = (unsigned char *)malloc(secret_len);
    if (!*shared_secret) {
        fprintf(stderr, "Failed to allocate memory for shared secret\n");
        goto cleanup;
    }

    /* Allocate memory for ciphertext */
    *ciphertext = (unsigned char *)malloc(cipher_len);
    if (!*ciphertext) {
        fprintf(stderr, "Failed to allocate memory for ciphertext\n");
        goto cleanup;
    }

    /* Perform encapsulation */
    if (EVP_PKEY_encapsulate(ctx, *shared_secret, &secret_len, *ciphertext, &cipher_len) <= 0) {
        fprintf(stderr, "Failed to perform encapsulation\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    *shared_secret_len = (int)secret_len;
    *ciphertext_len = (int)cipher_len;

    printf("Encapsulation successful for %s:\n", alg_name);
    printf("  Shared secret length: %d bytes\n", *shared_secret_len);
    printf("  Ciphertext length: %d bytes\n", *ciphertext_len);

    ret = 0;

cleanup:
    if (ret != 0) {
        if (*shared_secret) {
            free(*shared_secret);
            *shared_secret = NULL;
            *shared_secret_len = 0;
        }
    }
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    return ret;
}

// 简化的密钥封装函数，接受EVP_PKEY
int call_ml_kem_encap_simple(const char *algo_name, EVP_PKEY *pkey, unsigned char **ciphertext, size_t *ciphertext_len, unsigned char **shared_secret, size_t *shared_secret_len) {
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;
    size_t secret_len = 0, cipher_len = 0;
    unsigned char *secret = NULL;
    unsigned char *cipher = NULL;
    
    printf("\n=== 测试 ML-KEM 密钥封装 (%s) ===\n", algo_name);
    
    // 1. 创建密钥封装上下文
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        printf("错误: 无法创建密钥封装上下文\n");
        goto cleanup;
    }
    
    // 2. 初始化封装操作
    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        printf("错误: 无法初始化密钥封装\n");
        goto cleanup;
    }
    
    // 3. 首先获取输出长度
    if (EVP_PKEY_encapsulate(ctx, NULL, &cipher_len, NULL, &secret_len) <= 0) {
        printf("错误: 无法获取封装输出长度\n");
        goto cleanup;
    }
    
    printf("密文长度: %zu bytes\n", cipher_len);
    printf("共享密钥长度: %zu bytes\n", secret_len);
    
    // 4. 分配内存
    cipher = OPENSSL_malloc(cipher_len);
    secret = OPENSSL_malloc(secret_len);
    if (!cipher || !secret) {
        printf("错误: 无法分配内存\n");
        goto cleanup;
    }
    
    // 5. 执行密钥封装
    if (EVP_PKEY_encapsulate(ctx, cipher, &cipher_len, secret, &secret_len) <= 0) {
        printf("错误: 密钥封装失败\n");
        goto cleanup;
    }
    
    printf("密钥封装成功！\n");
    printf("密文: ");
    for (size_t i = 0; i < (cipher_len > 32 ? 32 : cipher_len); i++) {
        printf("%02x", cipher[i]);
    }
    if (cipher_len > 32) printf("...");
    printf("\n");
    
    printf("共享密钥: ");
    for (size_t i = 0; i < secret_len; i++) {
        printf("%02x", secret[i]);
    }
    printf("\n");
    
    // 6. 输出结果
    *ciphertext = cipher;
    *ciphertext_len = cipher_len;
    *shared_secret = secret;
    *shared_secret_len = secret_len;
    cipher = NULL; // 防止被释放
    secret = NULL; // 防止被释放
    ret = 1;
    
cleanup:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (cipher) {
        OPENSSL_free(cipher);
    }
    if (secret) {
        OPENSSL_free(secret);
    }
    
    return ret;
}

// 测试ML-KEM完整流程的函数
int test_ml_kem_full_flow(const char *algo_name) {
    EVP_PKEY *pkey = NULL;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    unsigned char *shared_secret1 = NULL;
    unsigned char *shared_secret2 = NULL;
    size_t shared_secret1_len = 0;
    size_t shared_secret2_len = 0;
    int ret = 0;
    
    printf("\n========================================\n");
    printf("开始测试 %s 完整流程\n", algo_name);
    printf("========================================\n");
    
    // 1. 生成密钥对
    if (!call_ml_kem_gen_key_simple(algo_name, &pkey)) {
        printf("错误: 密钥生成失败\n");
        goto cleanup;
    }
    
    // 2. 进行密钥封装
    if (!call_ml_kem_encap_simple(algo_name, pkey, &ciphertext, &ciphertext_len, &shared_secret1, &shared_secret1_len)) {
        printf("错误: 密钥封装失败\n");
        goto cleanup;
    }
    
    // 3. 进行密钥解封装
    if (!call_ml_kem_decap(algo_name, pkey, ciphertext, ciphertext_len, &shared_secret2, &shared_secret2_len)) {
        printf("错误: 密钥解封装失败\n");
        goto cleanup;
    }
    
    // 4. 验证共享密钥是否一致
    printf("\n=== 验证共享密钥一致性 ===\n");
    if (shared_secret1_len != shared_secret2_len) {
        printf("错误: 共享密钥长度不匹配 (%zu vs %zu)\n", shared_secret1_len, shared_secret2_len);
        goto cleanup;
    }
    
    if (memcmp(shared_secret1, shared_secret2, shared_secret1_len) != 0) {
        printf("错误: 共享密钥内容不匹配\n");
        goto cleanup;
    }
    
    printf("✓ 共享密钥一致性验证成功！\n");
    printf("共享密钥长度: %zu bytes\n", shared_secret1_len);
    
    ret = 1;
    printf("\n%s 测试完成 - 成功!\n", algo_name);
    
cleanup:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (ciphertext) {
        OPENSSL_free(ciphertext);
    }
    if (shared_secret1) {
        OPENSSL_free(shared_secret1);
    }
    if (shared_secret2) {
        OPENSSL_free(shared_secret2);
    }
    
    return ret;
}

int main() {
    printf("ML-KEM (Module Lattice Key Encapsulation Mechanism) 测试程序\n");
    printf("使用 OpenSSL 3.5+ 的后量子密钥封装算法\n");
    printf("==============================================\n");
    
    // 1. 检查OpenSSL版本
    printf("OpenSSL 版本: %s\n", OPENSSL_VERSION_TEXT);
    
    // 2. 检查ML-KEM算法支持
    if (!check_ml_kem_support()) {
        printf("错误: 当前OpenSSL版本不支持ML-KEM算法\n");
        return 1;
    }
    
    int success_count = 0;
    int total_count = 3;
    
    // 3. 测试所有ML-KEM变种
    const char *ml_kem_algorithms[] = {
        "ML-KEM-512",
        "ML-KEM-768", 
        "ML-KEM-1024"
    };
    
    for (int i = 0; i < 3; i++) {
        if (test_ml_kem_full_flow(ml_kem_algorithms[i])) {
            success_count++;
        }
    }
    
    // 4. 打印总结
    printf("\n==============================================\n");
    printf("测试总结:\n");
    printf("成功: %d/%d\n", success_count, total_count);
    
    if (success_count == total_count) {
        printf("✓ 所有ML-KEM算法测试通过!\n");
        return 0;
    } else {
        printf("✗ 部分测试失败\n");
        return 1;
    }
}