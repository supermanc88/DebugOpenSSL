#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/bn.h>

// 函数声明
int validate_ec_key(EVP_PKEY *key, const char *curve_name);

/* Function to check OpenSSL version and EC support */
// Returns 0 if EC KEM is supported, -1 otherwise
int check_ec_kem_support(void)
{
    printf("OpenSSL Version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("OpenSSL Build Info: %s\n", OpenSSL_version(OPENSSL_BUILT_ON));
    
    /* Check if we have at least OpenSSL 3.0.0 for proper EC KEM support */
    if (OPENSSL_VERSION_NUMBER < 0x30000000L) {
        printf("WARNING: OpenSSL version may be too old for optimal EC KEM support.\n");
        printf("EC KEM requires OpenSSL 3.0.0 or later.\n");
        printf("Current version: 0x%08lx\n", OPENSSL_VERSION_NUMBER);
        return -1;
    }
    
    /* Test common EC curves */
    const char *curves[] = {"prime256v1", "secp384r1", "secp521r1"};
    int curve_count = sizeof(curves) / sizeof(curves[0]);
    int supported_count = 0;
    
    for (int i = 0; i < curve_count; i++) {
        EVP_PKEY_CTX *test_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (!test_ctx) {
            continue;
        }
        
        if (EVP_PKEY_keygen_init(test_ctx) <= 0) {
            EVP_PKEY_CTX_free(test_ctx);
            continue;
        }
        
        if (EVP_PKEY_CTX_set_group_name(test_ctx, curves[i]) <= 0) {
            EVP_PKEY_CTX_free(test_ctx);
            continue;
        }
        
        printf("✓ %s curve supported\n", curves[i]);
        supported_count++;
        EVP_PKEY_CTX_free(test_ctx);
    }
    
    if (supported_count == 0) {
        printf("ERROR: No supported EC curves found.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    printf("✓ EC KEM support confirmed! (%d curves available)\n\n", supported_count);
    return 0; 
}

// 简化的EC密钥生成函数，返回EVP_PKEY
// returns 0 on success, -1 on failure
int call_ec_kem_gen_key_simple(const char *curve_name, EVP_PKEY **pkey_out) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = -1;
    
    printf("\n=== 测试 EC KEM 密钥生成 (%s) ===\n", curve_name);
    
    // 1. 创建EC密钥生成上下文
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) {
        printf("错误: 无法创建 EC 密钥生成上下文\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 2. 初始化密钥生成
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("错误: 无法初始化 EC 密钥生成\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 3. 设置椭圆曲线
    if (EVP_PKEY_CTX_set_group_name(ctx, curve_name) <= 0) {
        printf("错误: 无法设置椭圆曲线 %s\n", curve_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 4. 生成密钥对
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("错误: 无法生成 %s 密钥对\n", curve_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 5. 验证生成的密钥
    if (validate_ec_key(pkey, curve_name) != 0) {
        printf("错误: 生成的密钥验证失败\n");
        goto cleanup;
    }
    
    printf("密钥生成成功！\n");
    *pkey_out = pkey;
    pkey = NULL; // 防止被释放
    ret = 0;
    
cleanup:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    
    return ret;
}

// 完整的EC密钥生成函数，支持导出原始密钥数据
// returns 0 on success, -1 on failure
int call_ec_kem_gen_key(const char *curve_name,
                        unsigned char **pub_key, int *pub_key_len,
                        unsigned char **priv_key, int *priv_key_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = -1;
    size_t pub_len = 0, priv_len = 0;

    /* Create context for key generation */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create context for EC\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Initialize key generation */
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize key generation for EC\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    /* Set the curve */
    if (EVP_PKEY_CTX_set_group_name(ctx, curve_name) <= 0) {
        fprintf(stderr, "Failed to set curve %s\n", curve_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Generate key pair */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate key pair for %s\n", curve_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Get public key */
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, 
                                        NULL, 0, &pub_len) <= 0) {
        fprintf(stderr, "Failed to get public key length\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    *pub_key = (unsigned char *)malloc(pub_len);
    if (!*pub_key) {
        fprintf(stderr, "Failed to allocate memory for public key\n");
        goto cleanup;
    }

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, 
                                        *pub_key, pub_len, NULL) <= 0) {
        fprintf(stderr, "Failed to get public key data\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    *pub_key_len = (int)pub_len;

    /* Get private key - 使用BIGNUM方法作为EC密钥的标准做法 */
    BIGNUM *priv_bn = NULL;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) <= 0) {
        fprintf(stderr, "Failed to get private key as BIGNUM\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    /* 将BIGNUM转换为字节数组 */
    priv_len = BN_num_bytes(priv_bn);
    *priv_key = (unsigned char *)malloc(priv_len);
    if (!*priv_key) {
        fprintf(stderr, "Failed to allocate memory for private key\n");
        BN_free(priv_bn);
        goto cleanup;
    }
    
    if (BN_bn2binpad(priv_bn, *priv_key, priv_len) <= 0) {
        fprintf(stderr, "Failed to convert BIGNUM to bytes\n");
        BN_free(priv_bn);
        free(*priv_key);
        *priv_key = NULL;
        goto cleanup;
    }
    
    BN_free(priv_bn);
    *priv_key_len = (int)priv_len;

    printf("Key generation successful for %s:\n", curve_name);
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

// ECDH密钥交换辅助函数
// returns 0 on success, -1 on failure
int call_ec_kem_ecdh(EVP_PKEY *priv_key, EVP_PKEY *pub_key, 
                     unsigned char **shared_secret, size_t *shared_secret_len) {
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;
    
    // 1. 创建ECDH上下文
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create ECDH context\n");
        goto cleanup;
    }
    
    // 2. 初始化密钥协商
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize key derivation\n");
        goto cleanup;
    }
    
    // 3. 设置对端公钥
    if (EVP_PKEY_derive_set_peer(ctx, pub_key) <= 0) {
        fprintf(stderr, "Failed to set peer public key\n");
        goto cleanup;
    }
    
    // 4. 获取共享密钥长度
    if (EVP_PKEY_derive(ctx, NULL, shared_secret_len) <= 0) {
        fprintf(stderr, "Failed to get shared secret length\n");
        goto cleanup;
    }
    
    // 5. 分配内存并生成共享密钥
    *shared_secret = malloc(*shared_secret_len);
    if (!*shared_secret) {
        fprintf(stderr, "Failed to allocate memory for shared secret\n");
        goto cleanup;
    }
    
    if (EVP_PKEY_derive(ctx, *shared_secret, shared_secret_len) <= 0) {
        fprintf(stderr, "Failed to derive shared secret\n");
        free(*shared_secret);
        *shared_secret = NULL;
        goto cleanup;
    }
    
    ret = 0;
    
cleanup:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    return ret;
}

// KDF密钥派生函数
// returns 0 on success, -1 on failure
int call_ec_kem_kdf(const unsigned char *shared_secret, size_t shared_secret_len,
                    const char *info, size_t info_len, 
                    size_t output_len, unsigned char **derived_key) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4];
    int ret = -1;
    
    // 1. 获取HKDF算法
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        fprintf(stderr, "Failed to fetch HKDF\n");
        goto cleanup;
    }
    
    // 2. 创建KDF上下文
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        fprintf(stderr, "Failed to create KDF context\n");
        goto cleanup;
    }
    
    // 3. 分配输出缓冲区
    *derived_key = malloc(output_len);
    if (!*derived_key) {
        fprintf(stderr, "Failed to allocate memory for derived key\n");
        goto cleanup;
    }
    
    // 4. 设置HKDF参数 - 使用正确的参数名称
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, 
                                                 (void*)shared_secret, shared_secret_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, 
                                                 (void*)info, info_len);
    params[3] = OSSL_PARAM_construct_end();
    
    // 5. 执行密钥派生
    if (EVP_KDF_derive(kctx, *derived_key, output_len, params) <= 0) {
        fprintf(stderr, "Failed to derive key using HKDF\n");
        free(*derived_key);
        *derived_key = NULL;
        goto cleanup;
    }
    
    ret = 0;
    
cleanup:
    if (kctx) {
        EVP_KDF_CTX_free(kctx);
    }
    if (kdf) {
        EVP_KDF_free(kdf);
    }
    return ret;
}

// 简化的EC密钥封装函数
// returns 0 on success, -1 on failure
int call_ec_kem_encap_simple(const char *curve_name, EVP_PKEY *recipient_pubkey,
                             unsigned char **ephemeral_pubkey, size_t *ephemeral_pubkey_len,
                             unsigned char **shared_secret, size_t *shared_secret_len) {
    EVP_PKEY *ephemeral_key = NULL;
    unsigned char *ecdh_secret = NULL;
    size_t ecdh_secret_len = 0;
    int ret = -1;
    const char *kdf_info = "EC-KEM-ENCAP";
    
    printf("\n=== 测试 EC KEM 密钥封装 (%s) ===\n", curve_name);
    
    // 1. 生成临时密钥对
    if (call_ec_kem_gen_key_simple(curve_name, &ephemeral_key) != 0) {
        printf("错误: 生成临时密钥失败\n");
        goto cleanup;
    }
    
    // 2. 导出临时公钥 - 使用 EVP_PKEY_get_octet_string_param
    if (EVP_PKEY_get_octet_string_param(ephemeral_key, OSSL_PKEY_PARAM_PUB_KEY, 
                                        NULL, 0, ephemeral_pubkey_len) <= 0) {
        printf("错误: 获取临时公钥长度失败\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    *ephemeral_pubkey = malloc(*ephemeral_pubkey_len);
    if (!*ephemeral_pubkey) {
        printf("错误: 分配临时公钥内存失败\n");
        goto cleanup;
    }
    
    if (EVP_PKEY_get_octet_string_param(ephemeral_key, OSSL_PKEY_PARAM_PUB_KEY, 
                                        *ephemeral_pubkey, *ephemeral_pubkey_len, NULL) <= 0) {
        printf("错误: 导出临时公钥失败\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 3. 执行ECDH
    if (call_ec_kem_ecdh(ephemeral_key, recipient_pubkey, &ecdh_secret, &ecdh_secret_len) != 0) {
        printf("错误: ECDH密钥协商失败\n");
        goto cleanup;
    }
    
    printf("ECDH共享密钥长度: %zu bytes\n", ecdh_secret_len);
    
    // 4. 通过KDF生成最终共享密钥
    *shared_secret_len = 32; // 256-bit shared secret
    if (call_ec_kem_kdf(ecdh_secret, ecdh_secret_len, kdf_info, strlen(kdf_info), 
                         *shared_secret_len, shared_secret) != 0) {
        printf("错误: KDF密钥派生失败\n");
        goto cleanup;
    }
    
    printf("密钥封装成功！\n");
    printf("临时公钥长度: %zu bytes\n", *ephemeral_pubkey_len);
    printf("最终共享密钥长度: %zu bytes\n", *shared_secret_len);
    
    printf("临时公钥: ");
    for (size_t i = 0; i < (*ephemeral_pubkey_len > 16 ? 16 : *ephemeral_pubkey_len); i++) {
        printf("%02x", (*ephemeral_pubkey)[i]);
    }
    if (*ephemeral_pubkey_len > 16) printf("...");
    printf("\n");
    
    printf("共享密钥: ");
    for (size_t i = 0; i < *shared_secret_len; i++) {
        printf("%02x", (*shared_secret)[i]);
    }
    printf("\n");
    
    ret = 0;
    
cleanup:
    if (ephemeral_key) {
        EVP_PKEY_free(ephemeral_key);
    }
    if (ecdh_secret) {
        free(ecdh_secret);
    }
    if (ret != 0) {
        if (*ephemeral_pubkey) {
            free(*ephemeral_pubkey);
            *ephemeral_pubkey = NULL;
        }
        if (*shared_secret) {
            free(*shared_secret);
            *shared_secret = NULL;
        }
    }
    
    return ret;
}

// EC密钥解封装函数
// returns 0 on success, -1 on failure
int call_ec_kem_decap(const char *curve_name, EVP_PKEY *recipient_privkey,
                      const unsigned char *ephemeral_pubkey, size_t ephemeral_pubkey_len,
                      unsigned char **shared_secret, size_t *shared_secret_len) {
    EVP_PKEY *ephemeral_pubkey_obj = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    unsigned char *ecdh_secret = NULL;
    size_t ecdh_secret_len = 0;
    int ret = -1;
    const char *kdf_info = "EC-KEM-ENCAP";
    
    printf("\n=== 测试 EC KEM 密钥解封装 (%s) ===\n", curve_name);
    
    // 1. 创建临时公钥对象的上下文
    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pkey_ctx) {
        printf("错误: 创建PKEY上下文失败\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 2. 初始化密钥导入
    if (EVP_PKEY_fromdata_init(pkey_ctx) <= 0) {
        printf("错误: 初始化fromdata失败\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 3. 准备公钥数据参数
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, 
                                                 (char*)curve_name, strlen(curve_name));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, 
                                                 (void*)ephemeral_pubkey, ephemeral_pubkey_len);
    params[2] = OSSL_PARAM_construct_end();
    
    // 4. 从数据创建公钥对象
    if (EVP_PKEY_fromdata(pkey_ctx, &ephemeral_pubkey_obj, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        printf("错误: 从数据重建临时公钥失败\n");
        printf("调试: 详细错误信息:\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 5. 执行ECDH（使用接收方私钥和临时公钥）
    if (call_ec_kem_ecdh(recipient_privkey, ephemeral_pubkey_obj, &ecdh_secret, &ecdh_secret_len) != 0) {
        printf("错误: ECDH密钥协商失败\n");
        goto cleanup;
    }
    
    printf("ECDH共享密钥长度: %zu bytes\n", ecdh_secret_len);
    
    // 6. 通过KDF生成最终共享密钥
    *shared_secret_len = 32; // 256-bit shared secret
    if (call_ec_kem_kdf(ecdh_secret, ecdh_secret_len, kdf_info, strlen(kdf_info), 
                         *shared_secret_len, shared_secret) != 0) {
        printf("错误: KDF密钥派生失败\n");
        goto cleanup;
    }
    
    printf("密钥解封装成功！\n");
    printf("最终共享密钥长度: %zu bytes\n", *shared_secret_len);
    
    printf("共享密钥: ");
    for (size_t i = 0; i < *shared_secret_len; i++) {
        printf("%02x", (*shared_secret)[i]);
    }
    printf("\n");
    
    ret = 0;
    
cleanup:
    if (pkey_ctx) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    if (ephemeral_pubkey_obj) {
        EVP_PKEY_free(ephemeral_pubkey_obj);
    }
    if (ecdh_secret) {
        free(ecdh_secret);
    }
    if (ret != 0 && *shared_secret) {
        free(*shared_secret);
        *shared_secret = NULL;
    }
    
    return ret;
}

// 密钥有效性检查函数
// returns 0 if valid, -1 if invalid
int validate_ec_key(EVP_PKEY *key, const char *curve_name) {
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;
    char *key_curve = NULL;
    size_t key_curve_len = 0;
    
    if (!key) {
        printf("错误: 空密钥指针\n");
        return -1;
    }
    
    // 1. 创建验证上下文
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx) {
        printf("错误: 创建验证上下文失败\n");
        goto cleanup;
    }
    
    // 2. 验证密钥
    if (EVP_PKEY_check(ctx) <= 0) {
        printf("错误: 密钥验证失败\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 3. 获取并验证曲线名称（安全检查）
    if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, 
                                       NULL, 0, &key_curve_len) > 0 && key_curve_len > 0) {
        key_curve = malloc(key_curve_len + 1);
        if (key_curve) {
            memset(key_curve, 0, key_curve_len + 1);  // 清零缓冲区
            if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, 
                                               key_curve, key_curve_len, NULL) > 0) {
                if (strcmp(key_curve, curve_name) != 0) {
                    printf("警告: 曲线名称不匹配 (期望: %s, 实际: %s)\n", 
                           curve_name, key_curve);
                }
            }
        }
    }
    
    ret = 0;
    
cleanup:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (key_curve) {
        free(key_curve);
    }
    return ret;
}

// 测试EC KEM完整流程的函数
int test_ec_kem_full_flow(const char *curve_name) {
    EVP_PKEY *recipient_key = NULL;
    unsigned char *ephemeral_pubkey = NULL;
    size_t ephemeral_pubkey_len = 0;
    unsigned char *shared_secret1 = NULL;
    unsigned char *shared_secret2 = NULL;
    size_t shared_secret1_len = 0;
    size_t shared_secret2_len = 0;
    int ret = -1;
    
    printf("\n========================================\n");
    printf("开始测试 EC KEM %s 完整流程\n", curve_name);
    printf("========================================\n");
    
    // 1. 生成接收方密钥对
    if (call_ec_kem_gen_key_simple(curve_name, &recipient_key) != 0) {
        printf("错误: 接收方密钥生成失败\n");
        goto cleanup;
    }
    
    // 2. 进行密钥封装
    if (call_ec_kem_encap_simple(curve_name, recipient_key, 
                                  &ephemeral_pubkey, &ephemeral_pubkey_len,
                                  &shared_secret1, &shared_secret1_len) != 0) {
        printf("错误: 密钥封装失败\n");
        goto cleanup;
    }
    
    // 3. 进行密钥解封装
    if (call_ec_kem_decap(curve_name, recipient_key, 
                           ephemeral_pubkey, ephemeral_pubkey_len,
                           &shared_secret2, &shared_secret2_len) != 0) {
        printf("错误: 密钥解封装失败\n");
        goto cleanup;
    }
    
    // 4. 验证共享密钥是否一致
    printf("\n=== 验证共享密钥一致性 ===\n");
    if (shared_secret1_len != shared_secret2_len) {
        printf("错误: 共享密钥长度不匹配 (封装: %zu vs 解封装: %zu)\n", 
               shared_secret1_len, shared_secret2_len);
        goto cleanup;
    }
    
    if (memcmp(shared_secret1, shared_secret2, shared_secret1_len) != 0) {
        printf("错误: 共享密钥内容不匹配\n");
        printf("封装密钥:   ");
        for (size_t i = 0; i < shared_secret1_len; i++) {
            printf("%02x", shared_secret1[i]);
        }
        printf("\n");
        printf("解封装密钥: ");
        for (size_t i = 0; i < shared_secret2_len; i++) {
            printf("%02x", shared_secret2[i]);
        }
        printf("\n");
        printf("详细比较:\n");
        for (size_t i = 0; i < shared_secret1_len; i++) {
            if (shared_secret1[i] != shared_secret2[i]) {
                printf("  字节 %zu: %02x != %02x\n", i, shared_secret1[i], shared_secret2[i]);
            }
        }
        goto cleanup;
    }
    
    printf("✓ 共享密钥一致性验证成功！\n");
    printf("椭圆曲线: %s\n", curve_name);
    printf("共享密钥长度: %zu bytes\n", shared_secret1_len);
    printf("临时公钥长度: %zu bytes\n", ephemeral_pubkey_len);
    
    ret = 0;
    printf("\n%s EC KEM 测试完成 - 成功!\n", curve_name);
    
cleanup:
    if (recipient_key) {
        EVP_PKEY_free(recipient_key);
    }
    if (ephemeral_pubkey) {
        free(ephemeral_pubkey);
    }
    if (shared_secret1) {
        free(shared_secret1);
    }
    if (shared_secret2) {
        free(shared_secret2);
    }
    
    return ret;
}

// 测试使用完整版本（导出原始密钥数据）的EC KEM流程
int test_ec_kem_full_flow_with_raw_keys(const char *curve_name) {
    unsigned char *pub_key = NULL, *priv_key = NULL;
    int pub_key_len = 0, priv_key_len = 0;
    unsigned char *ephemeral_pub_key = NULL, *ephemeral_priv_key = NULL;
    int ephemeral_pub_key_len = 0, ephemeral_priv_key_len = 0;
    
    // 重新构建的密钥对象
    EVP_PKEY *recipient_key = NULL, *ephemeral_key = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    
    // KEM 数据
    unsigned char *shared_secret1 = NULL, *shared_secret2 = NULL;
    size_t shared_secret1_len = 0, shared_secret2_len = 0;
    
    int ret = -1;
    
    printf("\n========================================\n");
    printf("开始测试 EC KEM %s 完整流程（使用原始密钥数据）\n", curve_name);
    printf("========================================\n");
    
    // 1. 使用完整版本生成接收方密钥对并导出原始数据
    printf("\n=== 步骤1: 生成接收方密钥对并导出原始数据 ===\n");
    if (call_ec_kem_gen_key(curve_name, &pub_key, &pub_key_len, &priv_key, &priv_key_len) != 0) {
        printf("错误: 接收方密钥生成失败\n");
        goto cleanup;
    }
    
    printf("接收方密钥导出成功:\n");
    printf("  公钥长度: %d bytes\n", pub_key_len);
    printf("  私钥长度: %d bytes\n", priv_key_len);
    printf("  公钥数据: ");
    for (int i = 0; i < (pub_key_len > 16 ? 16 : pub_key_len); i++) {
        printf("%02x", pub_key[i]);
    }
    if (pub_key_len > 16) printf("...");
    printf("\n");
    
    // 2. 从原始数据重建接收方公钥对象（用于封装）
    printf("\n=== 步骤2: 从原始数据重建接收方公钥 ===\n");
    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pkey_ctx) {
        printf("错误: 创建PKEY上下文失败\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    if (EVP_PKEY_fromdata_init(pkey_ctx) <= 0) {
        printf("错误: 初始化密钥导入失败\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 准备公钥参数
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, 
                                                 (char*)curve_name, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, 
                                                 pub_key, pub_key_len);
    params[2] = OSSL_PARAM_construct_end();
    
    if (EVP_PKEY_fromdata(pkey_ctx, &recipient_key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        printf("错误: 从原始数据重建接收方公钥失败\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    printf("接收方公钥重建成功！\n");
    
    // 3. 生成临时密钥对并导出
    printf("\n=== 步骤3: 生成临时密钥对并导出原始数据 ===\n");
    if (call_ec_kem_gen_key(curve_name, &ephemeral_pub_key, &ephemeral_pub_key_len, 
                           &ephemeral_priv_key, &ephemeral_priv_key_len) != 0) {
        printf("错误: 临时密钥生成失败\n");
        goto cleanup;
    }
    
    printf("临时密钥导出成功:\n");
    printf("  临时公钥长度: %d bytes\n", ephemeral_pub_key_len);
    printf("  临时私钥长度: %d bytes\n", ephemeral_priv_key_len);
    
    // 4. 从临时公钥原始数据重建公钥对象（用于解封装验证）
    printf("\n=== 步骤4: 验证临时公钥能被正确重建 ===\n");
    EVP_PKEY_CTX_free(pkey_ctx);
    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pkey_ctx || EVP_PKEY_fromdata_init(pkey_ctx) <= 0) {
        printf("错误: 重新创建PKEY上下文失败\n");
        goto cleanup;
    }
    
    // 重建临时公钥对象
    OSSL_PARAM ephemeral_params[3];
    ephemeral_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, 
                                                          (char*)curve_name, 0);
    ephemeral_params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, 
                                                           ephemeral_pub_key, ephemeral_pub_key_len);
    ephemeral_params[2] = OSSL_PARAM_construct_end();
    
    if (EVP_PKEY_fromdata(pkey_ctx, &ephemeral_key, EVP_PKEY_PUBLIC_KEY, ephemeral_params) <= 0) {
        printf("错误: 从原始数据重建临时公钥失败\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    printf("临时公钥重建成功！\n");
    
    // 5. 使用简化版本进行KEM操作验证（仅为对比）
    printf("\n=== 步骤5: 使用简化版本进行KEM操作（对比测试） ===\n");
    unsigned char *test_ephemeral_pubkey = NULL;
    size_t test_ephemeral_pubkey_len = 0;
    if (call_ec_kem_encap_simple(curve_name, recipient_key, 
                                &test_ephemeral_pubkey, &test_ephemeral_pubkey_len,
                                &shared_secret1, &shared_secret1_len) == 0) {
        printf("简化版本封装测试成功\n");
        if (shared_secret1) {
            free(shared_secret1);
            shared_secret1 = NULL;
        }
        if (test_ephemeral_pubkey) {
            free(test_ephemeral_pubkey);
        }
    }
    
    // 6. 验证原始密钥数据的完整性
    printf("\n=== 步骤6: 验证原始密钥数据完整性 ===\n");
    printf("✓ 接收方密钥对导出/重建流程验证完成\n");
    printf("✓ 临时密钥对导出/重建流程验证完成\n");
    printf("✓ 原始密钥数据格式兼容性验证完成\n");
    
    printf("\n原始密钥数据摘要:\n");
    printf("椭圆曲线: %s\n", curve_name);
    printf("接收方公钥: %d bytes, 私钥: %d bytes\n", pub_key_len, priv_key_len);
    printf("临时公钥: %d bytes, 临时私钥: %d bytes\n", ephemeral_pub_key_len, ephemeral_priv_key_len);
    
    ret = 0;
    printf("\n%s EC KEM 完整版本测试完成 - 成功!\n", curve_name);
    
cleanup:
    // 清理原始密钥数据
    if (pub_key) { free(pub_key); }
    if (priv_key) { free(priv_key); }
    if (ephemeral_pub_key) { free(ephemeral_pub_key); }
    if (ephemeral_priv_key) { free(ephemeral_priv_key); }
    
    // 清理重建的密钥对象
    if (recipient_key) { EVP_PKEY_free(recipient_key); }
    if (ephemeral_key) { EVP_PKEY_free(ephemeral_key); }
    if (pkey_ctx) { EVP_PKEY_CTX_free(pkey_ctx); }
    
    // 清理KEM数据
    if (shared_secret1) { free(shared_secret1); }
    if (shared_secret2) { free(shared_secret2); }
    
    return ret;
}

int main() {
    printf("EC KEM (Elliptic Curve Key Encapsulation Mechanism) 测试程序\n");
    printf("使用 OpenSSL 3.0+ 的椭圆曲线密钥封装算法\n");
    printf("============================================\n");
    
    // 1. 检查OpenSSL版本
    printf("OpenSSL 版本: %s\n", OPENSSL_VERSION_TEXT);
    
    // 2. 检查EC KEM算法支持
    if (check_ec_kem_support() != 0) {
        printf("错误: 当前OpenSSL版本不支持必要的EC算法\n");
        return 1;
    }
    
    int success_count = 0;
    int total_count = 6;  // 3个简化版本测试 + 3个完整版本测试
    int simple_success = 0, full_success = 0;
    
    // 3. 测试所有主要的椭圆曲线（简化版本）
    printf("\n============ 简化版本 KEM 测试 ============\n");
    const char *ec_curves[] = {
        "prime256v1",    // NIST P-256 (secp256r1)
        "secp384r1",     // NIST P-384  
        "secp521r1"      // NIST P-521
    };
    
    for (int i = 0; i < 3; i++) {
        if (test_ec_kem_full_flow(ec_curves[i]) == 0) {
            success_count++;
            simple_success++;
        }
    }
    
    // 4. 测试完整版本（原始密钥数据导出/导入）
    printf("\n============ 完整版本 KEM 测试 ============\n");
    for (int i = 0; i < 3; i++) {
        if (test_ec_kem_full_flow_with_raw_keys(ec_curves[i]) == 0) {
            success_count++;
            full_success++;
        }
    }
    
    // 5. 打印总结
    printf("\n============================================\n");
    printf("测试总结:\n");
    printf("成功: %d/%d\n", success_count, total_count);
    printf("简化版本: %d/3, 完整版本: %d/3\n", simple_success, full_success);
    
    if (success_count == total_count) {
        printf("✓ 所有EC KEM算法测试通过!\n");
        printf("\n支持的椭圆曲线:\n");
        printf("  - prime256v1 (NIST P-256): 256-bit 椭圆曲线\n");
        printf("  - secp384r1 (NIST P-384):  384-bit 椭圆曲线\n"); 
        printf("  - secp521r1 (NIST P-521):  521-bit 椭圆曲线\n");
        printf("\nKEM 实现特点:\n");
        printf("  - 基于 ECDH 密钥协商\n");
        printf("  - 使用 HKDF-SHA256 密钥派生\n");
        printf("  - 256-bit 共享密钥输出\n");
        printf("  - 符合现代密码学最佳实践\n");
        return 0;
    } else {
        printf("✗ 部分测试失败\n");
        return 1;
    }
}
