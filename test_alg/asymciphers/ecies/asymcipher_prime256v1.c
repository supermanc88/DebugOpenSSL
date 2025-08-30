#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>

/**
 * ECIES 实现
 * 这是一个基于 OpenSSL 的 ECIES 实现示例，使用 prime256v1 曲线作为示例。
 * 结合：
 * 1. ECDH密钥交换
 * 2. KDF密钥派生
 * 3. AES对称加密
 * 4. HMAC消息认证
 */

typedef struct {
    unsigned char *ephemeral_pubkey; // 临时公钥
    int ephemeral_pubkey_len;
    unsigned char *ciphertext;       // 密文
    int ciphertext_len;
    unsigned char *mac;              // 消息认证码
    int mac_len;
} ECIES_Ciphertext;


// 实现ECDH密钥交换，生成共享密钥
/**
 *
 * @param privkey 临时私钥
 * @param pubkey 对端公钥
 * @param shared_secret 输出的共享密钥
 * @param shared_secret_len 输出的共享密钥长度
 * @return 0成功，非0失败
 */
int call_ecies_ECDH(EVP_PKEY *privkey, EVP_PKEY *pubkey,
                    unsigned char **shared_secret, size_t *shared_secret_len) {
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Initialize the context for key derivation
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Set the peer public key
    if (EVP_PKEY_derive_set_peer(ctx, pubkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Determine buffer length for shared secret
    if (EVP_PKEY_derive(ctx, NULL, shared_secret_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive (get length) failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Allocate memory for shared secret
    *shared_secret = (unsigned char *)malloc(*shared_secret_len);
    if (!*shared_secret) {
        fprintf(stderr, "malloc for shared_secret failed\n");
        ret = -1;
        goto out;
    }

    // Derive the shared secret
    if (EVP_PKEY_derive(ctx, *shared_secret, shared_secret_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(*shared_secret);
        *shared_secret = NULL;
        ret = -1;
        goto out;
    }

    ret = 0;

out:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    return ret;
}


// 实现KDF密钥派生
/**
 *
 * @param privkey 本文私钥
 * @param md KDF使用的hash算法
 * @param shared_secret 输入的共享密钥
 * @param shared_secret_len 共享密钥长度
 * @param enc_key_len 要生成的加密密钥长度
 * @param enc_key 生成的加密密钥
 * @param mac_key_len 要生成的MAC密钥长度
 * @param mac_key 生成的MAC密钥
 * @return 0成功，非0失败
 */
int call_ecies_KDF(const char *KDF, const char *hash_alg,
                   const unsigned char *shared_secret, size_t shared_secret_len,
                   const unsigned char *otherinfo, size_t otherinfo_len,
                   size_t enc_key_len, unsigned char *enc_key,
                   size_t mac_key_len, unsigned char *mac_key) {
    int ret = 0;

    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5] = {0};
    size_t key_len = enc_key_len + mac_key_len;
    unsigned char *key_material = NULL;

    kdf = EVP_KDF_fetch(NULL, KDF, NULL);
    if (!kdf) {
        fprintf(stderr, "EVP_KDF_fetch failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Create a KDF context
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        fprintf(stderr, "EVP_KDF_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_DIGEST, (char *)hash_alg, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)shared_secret, shared_secret_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)otherinfo, otherinfo_len);
    params[3] = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &key_len);
    params[4] = OSSL_PARAM_construct_end();

    key_material = (unsigned char *)malloc(key_len);
    if (!key_material) {
        fprintf(stderr, "malloc for key_material failed\n");
        ret = -1;
        goto out;
    }

    ret = EVP_KDF_derive(kctx, key_material, key_len, params);
    if (ret <= 0) {
        fprintf(stderr, "EVP_KDF_derive failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(key_material);
        ret = -1;
        goto out;
    }

    memcpy(enc_key, key_material, enc_key_len);
    memcpy(mac_key, key_material + enc_key_len, mac_key_len);

    ret = 0;

out:
    if (key_material) {
        OPENSSL_cleanse(key_material, key_len); // 安全清除敏感数据
        free(key_material);
    }
    if (kdf) {
        EVP_KDF_free(kdf);
    }
    if (kctx) {
        EVP_KDF_CTX_free(kctx);
    }
    return ret;
}

// 直接派生密钥
int call_ecies_derive_key_v1(EVP_PKEY *privkey, EVP_PKEY *pubkey,
                       const char *KDF, const char *hash_alg,
                       size_t enc_key_len, unsigned char *enc_key,
                       size_t mac_key_len, unsigned char *mac_key) {
    int ret = 0;
    unsigned char *shared_secret = NULL;
    size_t shared_secret_len = 0;

    // 1. ECDH密钥交换，生成共享密钥
    ret = call_ecies_ECDH(privkey, pubkey, &shared_secret, &shared_secret_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecies_ECDH failed\n");
        goto out;
    }

    // 2. KDF密钥派生，生成加密密钥和MAC密钥
    ret = call_ecies_KDF(KDF, hash_alg,
                         shared_secret, shared_secret_len,
                         NULL, 0,
                         enc_key_len, enc_key,
                         mac_key_len, mac_key);
    if (ret != 0) {
        fprintf(stderr, "call_ecies_KDF failed\n");
        goto out;
    }
    ret = 0;
out:
    if (shared_secret) {
        OPENSSL_cleanse(shared_secret, shared_secret_len); // 安全清除敏感数据
        free(shared_secret);
    }
    return ret;
}

int call_ecies_derive_key_v2(EVP_PKEY *privkey, EVP_PKEY *pubkey,
                       const unsigned char *otherinfo, size_t otherinfo_len,
                       size_t enc_key_len, unsigned char *enc_key,
                       size_t mac_key_len, unsigned char *mac_key) {
    int ret = 0;
    EVP_PKEY_CTX *pctx = NULL;
    size_t key_len = enc_key_len + mac_key_len;
    unsigned char *key_material = NULL;
    OSSL_PARAM params[5] = {0};

    pctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (EVP_PKEY_derive_set_peer(pctx, pubkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE,
                                                 "X963KDF", 0);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST,
                                                 "SHA256", 0);
    params[2] = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
                                            &key_len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                 (void *)otherinfo, otherinfo_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_params failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    key_material = (unsigned char *)malloc(key_len);
    if (!key_material) {
        fprintf(stderr, "malloc for key_material failed\n");
        ret = -1;
        goto out;
    }

    if (EVP_PKEY_derive(pctx, key_material, &key_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(key_material);
        ret = -1;
        goto out;
    }

    memcpy(enc_key, key_material, enc_key_len);
    memcpy(mac_key, key_material + enc_key_len, mac_key_len);

    ret = 0;
out:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (key_material) {
        OPENSSL_cleanse(key_material, key_len); // 安全清除敏感数据
        free(key_material);
    }
    return ret;
}

// 在传统ECIES中，使用对称加密算法（如AES）对消息进行加密，如AES-CBC或AES-CTR
// 使用MAC算法（如HMAC-SHA256）对密文进行消息认证
/**
 *
 * @param cipher_alg 对称加密算法
 * @param key 输入的对称加密密钥
 * @param iv 输入的初始向量
 * @param plaintext 输入的明文
 * @param plaintext_len 输入的明文长度
 * @param ciphertext 输出的密文
 * @param ciphertext_len 输出的密文长度
 * @return 0成功，非0失败
 */
int call_ecies_symm_encrypt(const char *cipher_alg,
                            unsigned char *key, unsigned char *iv,
                            const unsigned char *plaintext, int plaintext_len,
                            unsigned char **ciphertext, int *ciphertext_len) {
    int ret = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_buffer_len = 0;
    int final_len = 0;

    // 1. Fetch the cipher
    cipher = EVP_CIPHER_fetch(NULL, cipher_alg, NULL);
    if (!cipher) {
        fprintf(stderr, "EVP_CIPHER_fetch failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 2. Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. Initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. judge cipher alg to set padding, if contains "CBC", enable padding
    if (strstr(cipher_alg, "CBC")) {
        EVP_CIPHER_CTX_set_padding(ctx, 1);
        ciphertext_buffer_len = (plaintext_len + EVP_CIPHER_block_size(cipher)) / EVP_CIPHER_block_size(cipher) * EVP_CIPHER_block_size(cipher);
        *ciphertext = (unsigned char *)malloc(ciphertext_buffer_len);
        if (!*ciphertext) {
            fprintf(stderr, "malloc for ciphertext failed\n");
            ret = -1;
            goto out;
        }
        memset(*ciphertext, 0, ciphertext_buffer_len);
    } else {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        // 为非CBC模式也分配内存
        *ciphertext = (unsigned char *)malloc(plaintext_len);
        if (!*ciphertext) {
            fprintf(stderr, "malloc for ciphertext failed\n");
            ret = -1;
            goto out;
        }
        memset(*ciphertext, 0, plaintext_len);
    }

    // 5. Provide the message to be encrypted, and obtain the encrypted output
    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *ciphertext_len = len;
    // 6. Finalize the encryption
    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &final_len) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *ciphertext_len += final_len;

    ret = 0;
out:
    if (cipher) {
        EVP_CIPHER_free(cipher);
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    // 在错误情况下释放已分配的ciphertext
    if (ret != 0 && *ciphertext) {
        free(*ciphertext);
        *ciphertext = NULL;
    }
    return ret;
}


int call_ecies_symm_decrypt(const char *cipher_alg,
                            unsigned char *key, unsigned char *iv,
                            const unsigned char *ciphertext, int ciphertext_len,
                            unsigned char **plaintext, int *plaintext_len) {
    int ret = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int final_len = 0;

    // 1. Fetch the cipher
    cipher = EVP_CIPHER_fetch(NULL, cipher_alg, NULL);
    if (!cipher) {
        fprintf(stderr, "EVP_CIPHER_fetch failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 2. Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. Initialize the decryption operation
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_DecryptInit_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. judge cipher alg to set padding, if contains "CBC", enable padding
    if (strstr(cipher_alg, "CBC")) {
        EVP_CIPHER_CTX_set_padding(ctx, 1);
    } else {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    *plaintext = (unsigned char *)malloc(ciphertext_len);
    if (!*plaintext) {
        fprintf(stderr, "malloc for plaintext failed\n");
        ret = -1;
        goto out;
    }
    memset(*plaintext, 0, ciphertext_len);

    // 5. Provide the message to be decrypted, and obtain the plaintext output
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "EVP_DecryptUpdate failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *plaintext_len = len;

    // 6. Finalize the decryption
    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &final_len) != 1) {
        fprintf(stderr, "EVP_DecryptFinal_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *plaintext_len += final_len;
    ret = 0;
out:
    if (cipher) {
        EVP_CIPHER_free(cipher);
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (ret != 0 && *plaintext) {
        free(*plaintext);
        *plaintext = NULL;
    }
    return ret;
}


// 计算HMAC
int call_ecies_hmac(const char *hash_alg,
                     unsigned char *key, int key_len,
                     const unsigned char *data, int data_len,
                     unsigned char **mac, int *mac_len) {
    int ret = 0;
    EVP_MD *md = NULL;
    HMAC_CTX *ctx = NULL;
    unsigned int len = 0;

    // 1. Fetch the digest
    md = EVP_MD_fetch(NULL, hash_alg, NULL);
    if (!md) {
        fprintf(stderr, "EVP_MD_fetch failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 2. Create and initialize the HMAC context
    ctx = HMAC_CTX_new();
    if (!ctx) {
        fprintf(stderr, "HMAC_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. Initialize the HMAC operation
    if (1 != HMAC_Init_ex(ctx, key, key_len, md, NULL)) {
        fprintf(stderr, "HMAC_Init_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. Provide the data to be hashed
    if (1 != HMAC_Update(ctx, data, data_len)) {
        fprintf(stderr, "HMAC_Update failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 5. Finalize the HMAC operation
    *mac = (unsigned char *)malloc(EVP_MD_get_size(md));
    if (!*mac) {
        fprintf(stderr, "malloc for mac failed\n");
        ret = -1;
        goto out;
    }
    if (1 != HMAC_Final(ctx, *mac, &len)) {
        fprintf(stderr, "HMAC_Final failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(*mac);
        *mac = NULL;
        ret = -1;
        goto out;
    }
    *mac_len = len;

    ret = 0;
out:
    if (md) {
        EVP_MD_free(md);
    }
    if (ctx) {
        HMAC_CTX_free(ctx);
    }
    return ret;
}


int call_ecies_prime256v1_genkey(unsigned char **pubkey, int *pubkey_len,
                                 unsigned char **privkey, int *privkey_len) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EC_KEY *eckey = NULL;
    size_t pri_len = 0, pub_len = 0;
    unsigned char *temp_pri = NULL, *temp_pub = NULL;
    BIGNUM *priv_bn = NULL; // 用于存储私钥的BIGNUM

    // 1. create context
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_id failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 2. initialize context
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. set the curve
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. generate key
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 5. extract EC_KEY
    eckey = EVP_PKEY_get1_EC_KEY(pkey);
    if (!eckey) {
        fprintf(stderr, "EVP_PKEY_get1_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 6. allocate memory for private key
    // set privkey not contain public key
    EC_KEY_set_enc_flags(eckey, EC_PKEY_NO_PUBKEY);
    pri_len = i2d_ECPrivateKey(eckey, NULL);
    if (pri_len <= 0) {
        fprintf(stderr, "i2d_ECPrivateKey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *privkey = (unsigned char *)malloc(pri_len);
    if (!*privkey) {
        fprintf(stderr, "malloc for privkey failed\n");
        ret = -1;
        goto out;
    }
    temp_pri = *privkey;
    pri_len = i2d_ECPrivateKey(eckey, &temp_pri);
    if (pri_len <= 0) {
        fprintf(stderr, "i2d_ECPrivateKey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *privkey_len = pri_len;

    priv_bn = EC_KEY_get0_private_key(eckey);
    if (priv_bn) {
        char *priv_hex = BN_bn2hex(priv_bn);
        if (priv_hex) {
            printf("Naked Private Key (%d bytes):\n", (int)strlen(priv_hex) / 2);
            printf(priv_hex);
            printf("\n");
            OPENSSL_free(priv_hex);
        }
    }

    // 7. allocate memory for public key
    pub_len = i2o_ECPublicKey(eckey, NULL);
    if (pub_len <= 0) {
        fprintf(stderr, "i2o_ECPublicKey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *pubkey = (unsigned char *)malloc(pub_len);
    if (!*pubkey) {
        fprintf(stderr, "malloc for pubkey failed\n");
        ret = -1;
        goto out;
    }
    temp_pub = *pubkey;
    pub_len = i2o_ECPublicKey(eckey, &temp_pub);
    if (pub_len <= 0) {
        fprintf(stderr, "i2o_ECPublicKey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *pubkey_len = pub_len;

    ret = 0;

out:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (eckey) {
        // 是否需要在这里释放 EC_KEY 取决于 EVP_PKEY_get1_EC_KEY 的实现，可能pkey被释放时会自动释放eckey
        EC_KEY_free(eckey);
    }
    // 错误时清理已分配的内存
    if (ret != 0) {
        if (*privkey) {
            OPENSSL_cleanse(*privkey, *privkey_len); // 安全清除私钥
            free(*privkey);
            *privkey = NULL;
        }
        if (*pubkey) {
            free(*pubkey);
            *pubkey = NULL;
        }
    }
    return ret;
}

int call_ecies_prime256v1_encrypt(const unsigned char *plaintext, int plaintext_len,
    const unsigned char *pubkey, int pubkey_len,
    unsigned char **ciphertext, int *ciphertext_len) {
    int ret = 0;
    // 测试使用，对称算法固定AES-128-CBC
    // HMAC算法固定HMAC-SHA256
    const char *cipher_alg = "AES-128-CBC";
    const char *hash_alg = "SHA256";
    unsigned char enc_key[16] = { 0 }; // AES-128
    unsigned char mac_key[16] = { 0 }; // HMAC-SHA256
    unsigned char iv[16] = { 0 };      // AES block size
    unsigned char *shared_secret = NULL;
    size_t shared_secret_len = 0;
    unsigned char *ephemeral_pubkey = NULL;
    int ephemeral_pubkey_len = 0;
    unsigned char *symm_ciphertext = NULL;
    int symm_ciphertext_len = 0;
    unsigned char *mac = NULL;
    int mac_len = 0;
    char *p = NULL;

    *ciphertext = malloc(sizeof(ECIES_Ciphertext));
    if (!*ciphertext) {
        fprintf(stderr, "malloc for ciphertext failed\n");
        ret = -1;
        goto out;
    }
    memset(*ciphertext, 0, sizeof(ECIES_Ciphertext));
    *ciphertext_len = sizeof(ECIES_Ciphertext);

    // 1. 生成临时密钥对
    unsigned char *ephemeral_privkey = NULL;
    int ephemeral_privkey_len = 0;
    EVP_PKEY *ephemeral_priv = NULL, *peer_pub = NULL;
    EC_KEY *ec_peer_pubkey = NULL, *ec_ephemeral_privkey = NULL;
    ret = call_ecies_prime256v1_genkey(&ephemeral_pubkey, &ephemeral_pubkey_len,
                                       &ephemeral_privkey, &ephemeral_privkey_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecies_sm2p256v1_genkey failed\n");
        goto out;
    }
    // 1.1 将临时公钥数据配置到结构体中
    ((ECIES_Ciphertext *)(*ciphertext))->ephemeral_pubkey = ephemeral_pubkey;
    ((ECIES_Ciphertext *)(*ciphertext))->ephemeral_pubkey_len = ephemeral_pubkey_len;

    // 2. 从字节加载参数中的公钥和临时私钥
    p = ephemeral_privkey;
    ec_ephemeral_privkey = d2i_ECPrivateKey(NULL, (const unsigned char **)&p, ephemeral_privkey_len);
    if (!ec_ephemeral_privkey) {
        fprintf(stderr, "d2i_ECPrivateKey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ephemeral_priv = EVP_PKEY_new();
    if (!ephemeral_priv) {
        fprintf(stderr, "EVP_PKEY_new failed\n");
        ret = -1;
        goto out;
    }
    if (EVP_PKEY_set1_EC_KEY(ephemeral_priv, ec_ephemeral_privkey) != 1) {
        fprintf(stderr, "EVP_PKEY_set1_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    p = (char *)pubkey;
    ec_peer_pubkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_peer_pubkey) {
        fprintf(stderr, "EC_KEY_new_by_curve_name failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (EC_KEY_oct2key(ec_peer_pubkey, pubkey, pubkey_len, NULL) != 1) {
        fprintf(stderr, "EC_KEY_oct2key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    peer_pub = EVP_PKEY_new();
    if (!peer_pub) {
        fprintf(stderr, "EVP_PKEY_new failed\n");
        ret = -1;
        goto out;
    }
    if (EVP_PKEY_set1_EC_KEY(peer_pub, ec_peer_pubkey) != 1) {
        fprintf(stderr, "EVP_PKEY_set1_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. ECDH密钥交换，生成共享密钥
    ret = call_ecies_ECDH(ephemeral_priv, peer_pub, &shared_secret, &shared_secret_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecies_ECDH failed\n");
        goto out;
    }

    // 4. KDF密钥派生，生成加密密钥和MAC密钥
    ret = call_ecies_KDF("X963KDF", hash_alg,
                         shared_secret, shared_secret_len,
                         NULL, 0,
                         sizeof(enc_key), enc_key,
                         sizeof(mac_key), mac_key);
    if (ret != 0) {
        fprintf(stderr, "call_ecies_KDF failed\n");
        goto out;
    }

    // 5. 对消息进行对称加密
    ret = call_ecies_symm_encrypt(cipher_alg, enc_key, iv,
                                  plaintext, plaintext_len,
                                  &symm_ciphertext, &symm_ciphertext_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecies_symm_encrypt failed\n");
        goto out;
    }
    // 5.1 将对称加密的密文配置到结构体中
    ((ECIES_Ciphertext *)(*ciphertext))->ciphertext = symm_ciphertext;
    ((ECIES_Ciphertext *)(*ciphertext))->ciphertext_len = symm_ciphertext_len;

    // 6. 对密文进行HMAC计算
    ret = call_ecies_hmac(hash_alg, mac_key, sizeof(mac_key),
                          symm_ciphertext, symm_ciphertext_len,
                          &mac, &mac_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecies_hmac failed\n");
        goto out;
    }
    // 6.1 将HMAC值配置到结构体中
    ((ECIES_Ciphertext *)(*ciphertext))->mac = mac;
    ((ECIES_Ciphertext *)(*ciphertext))->mac_len = mac_len;

    ret = 0;
out:
    if (peer_pub) {
        EVP_PKEY_free(peer_pub);
    }
    if (ec_peer_pubkey) {
        EC_KEY_free(ec_peer_pubkey);
    }
    if (ephemeral_priv) {
        EVP_PKEY_free(ephemeral_priv);
    }
    if (ec_ephemeral_privkey) {
        EC_KEY_free(ec_ephemeral_privkey);
    }
    if (ephemeral_privkey) {
        OPENSSL_cleanse(ephemeral_privkey, ephemeral_privkey_len); // 安全清除私钥
        free(ephemeral_privkey);
    }
    if (shared_secret) {
        OPENSSL_cleanse(shared_secret, shared_secret_len); // 安全清除共享密钥
        free(shared_secret);
    }
    if (ret != 0 && *ciphertext) {
        free(*ciphertext);
        *ciphertext = NULL;
        *ciphertext_len = 0;
    }
    if (ret != 0 && mac) {
        free(mac);
    }
    return ret;
}


int call_ecies_prime256v1_decrypt(const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *privkey, int privkey_len,
    unsigned char **plaintext, int *plaintext_len) {
    int ret = 0;
    // 测试使用，对称算法固定AES-128-CBC
    // HMAC算法固定HMAC-SHA256
    const char *cipher_alg = "AES-128-CBC";
    const char *hash_alg = "SHA256";
    unsigned char enc_key[16] = { 0 }; // AES-128
    unsigned char mac_key[16] = { 0 }; // HMAC-SHA256
    unsigned char iv[16] = { 0 };      // AES block size
    unsigned char *shared_secret = NULL;
    size_t shared_secret_len = 0;
    unsigned char *symm_ciphertext = NULL;
    int symm_ciphertext_len = 0;
    unsigned char *mac = NULL;
    int mac_len = 0;
    unsigned char *calculated_mac = NULL;
    int calculated_mac_len = 0;
    char *p = NULL;
    ECIES_Ciphertext *ecies_ct = (ECIES_Ciphertext *)ciphertext;
    EVP_PKEY *priv = NULL, *ephemeral_pub = NULL;
    EC_KEY *ec_privkey = NULL, *ec_ephemeral_pubkey = NULL;

    // 1. 从字节加载参数中的私钥和临时公钥
    p = (char *)privkey;
    ec_privkey = d2i_ECPrivateKey(NULL, (const unsigned char **)&p, privkey_len);
    if (!ec_privkey) {
        fprintf(stderr, "d2i_ECPrivateKey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    priv = EVP_PKEY_new();
    if (!priv) {
        fprintf(stderr, "EVP_PKEY_new failed\n");
        ret = -1;
        goto out;
    }
    if (EVP_PKEY_set1_EC_KEY(priv, ec_privkey) != 1) {
        fprintf(stderr, "EVP_PKEY_set1_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ec_ephemeral_pubkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_ephemeral_pubkey) {
        fprintf(stderr, "EC_KEY_new_by_curve_name failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (EC_KEY_oct2key(ec_ephemeral_pubkey, ecies_ct->ephemeral_pubkey, ecies_ct->ephemeral_pubkey_len, NULL) != 1) {
        fprintf(stderr, "EC_KEY_oct2key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ephemeral_pub = EVP_PKEY_new();
    if (!ephemeral_pub) {
        fprintf(stderr, "EVP_PKEY_new failed\n");
        ret = -1;
        goto out;
    }
    if (EVP_PKEY_set1_EC_KEY(ephemeral_pub, ec_ephemeral_pubkey) != 1) {
        fprintf(stderr, "EVP_PKEY_set1_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    symm_ciphertext = ecies_ct->ciphertext;
    symm_ciphertext_len = ecies_ct->ciphertext_len;
    mac = ecies_ct->mac;
    mac_len = ecies_ct->mac_len;

    // 2. ECDH密钥交换，生成共享密钥
    ret = call_ecies_ECDH(priv, ephemeral_pub, &shared_secret, &shared_secret_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecies_ECDH failed\n");
        goto out;
    }

    // 3. KDF密钥派生，生成加密密钥和MAC密钥
    ret = call_ecies_KDF("X963KDF", hash_alg,
                         shared_secret, shared_secret_len,
                         NULL, 0,
                         sizeof(enc_key), enc_key,
                         sizeof(mac_key), mac_key);
    if (ret != 0) {
        fprintf(stderr, "call_ecies_KDF failed\n");
        goto out;
    }

    // 4. 计算HMAC值，并与接收到的HMAC值进行比较
    ret = call_ecies_hmac(hash_alg, mac_key, sizeof(mac_key),
                          symm_ciphertext, symm_ciphertext_len,
                          &calculated_mac, &calculated_mac_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecies_hmac failed\n");
        goto out;
    }
    if (mac_len != calculated_mac_len || memcmp(mac, calculated_mac, mac_len) != 0) {
        fprintf(stderr, "HMAC verification failed\n");
        ret = -1;
        goto out;
    }
    free(calculated_mac);
    calculated_mac = NULL;
    calculated_mac_len = 0;

    // 5. 对密文进行对称解密
    ret = call_ecies_symm_decrypt(cipher_alg, enc_key, iv,
                                  symm_ciphertext, symm_ciphertext_len,
                                  plaintext, plaintext_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecies_symm_decrypt failed\n");
        goto out;
    }

    ret = 0;
out:
    if (ec_privkey) {
        EC_KEY_free(ec_privkey);
    }
    if (priv) {
        EVP_PKEY_free(priv);
    }
    if (ec_ephemeral_pubkey) {
        EC_KEY_free(ec_ephemeral_pubkey);
    }
    if (ephemeral_pub) {
        EVP_PKEY_free(ephemeral_pub);
    }
    if (shared_secret) {
        OPENSSL_cleanse(shared_secret, shared_secret_len); // 安全清除共享密钥
        free(shared_secret);
    }
    return ret;
}

int main(int argc, char *argv[]) {
    int ret = 0;
    unsigned char *pubkey = NULL, *privkey = NULL;
    int pubkey_len = 0, privkey_len = 0;
    unsigned char *ciphertext = NULL, *decryptedtext = NULL;
    int ciphertext_len = 0, decryptedtext_len = 0;
    unsigned char plaintext[] = "Hello, this is a test message for ECIES encryption!";
    int plaintext_len = strlen((char *)plaintext);

    // test drive key
    EVP_PKEY *priv = NULL, *pub = NULL;

    if (0) {
        unsigned char enc_key[16]; // AES-128
        unsigned char mac_key[16]; // HMAC-SHA256
        unsigned char *p = NULL;
        EC_KEY *ec_pubkey = NULL, *ec_privkey = NULL;
        ec_pubkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

        priv = EVP_PKEY_new();
        pub = EVP_PKEY_new();
        if (!priv || !pub) {
            fprintf(stderr, "EVP_PKEY_new failed\n");
            ret = -1;
            goto out;
        }

        // 1. 生成密钥对
        ret = call_ecies_prime256v1_genkey(&pubkey, &pubkey_len, &privkey, &privkey_len);
        if (ret != 0) {
            fprintf(stderr, "call_ecies_sm2p256v1_genkey failed\n");
            goto out;
        }

        // 2. 从字节加载公钥和私钥
        p = privkey;
        ec_privkey = d2i_ECPrivateKey(NULL, &p, privkey_len);
        if (!ec_privkey) {
            fprintf(stderr, "d2i_AutoPrivateKey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }
        if (EVP_PKEY_set1_EC_KEY(priv, ec_privkey) != 1) {
            fprintf(stderr, "EVP_PKEY_set1_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        if (EC_KEY_oct2key(ec_pubkey, pubkey, pubkey_len, NULL) != 1) {
            fprintf(stderr, "EC_KEY_oct2key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }
        if (EVP_PKEY_set1_EC_KEY(pub, ec_pubkey) != 1) {
            fprintf(stderr, "EVP_PKEY_set1_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }


        // 3. 派生密钥 v1
        ret = call_ecies_derive_key_v1(priv, pub,
                                       "X963KDF", "SHA256",
                                       sizeof(enc_key), enc_key,
                                       sizeof(mac_key), mac_key);
        if (ret != 0) {
            fprintf(stderr, "call_ecies_derive_key_v1 failed\n");
            goto out;
        }
        printf("Derived Encryption Key (v1):\n");
        for (int i = 0; i < sizeof(enc_key); i++) {
            printf("%02X", enc_key[i]);
        }
        printf("\n");
        printf("Derived MAC Key (v1):\n");
        for (int i = 0; i < sizeof(mac_key); i++) {
            printf("%02X", mac_key[i]);
        }
        printf("\n");

        // 4. 派生密钥 v2
        unsigned char *otherinfo;
        ret = call_ecies_derive_key_v2(priv, pub,
                                       otherinfo, 0,
                                       sizeof(enc_key), enc_key,
                                       sizeof(mac_key), mac_key);
        if (ret != 0) {
            fprintf(stderr, "call_ecies_derive_key_v2 failed\n");
            goto out;
        }
        printf("Derived Encryption Key (v2):\n");
        for (int i = 0; i < sizeof(enc_key); i++) {
            printf("%02X", enc_key[i]);
        }
        printf("\n");
        printf("Derived MAC Key (v2):\n");
        for (int i = 0; i < sizeof(mac_key); i++) {
            printf("%02X", mac_key[i]);
        }
        printf("\n");
    }


    if (1){
        ret = call_ecies_prime256v1_genkey(&pubkey, &pubkey_len, &privkey, &privkey_len);
        if (ret != 0) {
            fprintf(stderr, "call_ecies_sm2p256v1_genkey failed\n");
            goto out;
        }
        printf("Public Key (%d bytes):\n", pubkey_len);
        for (int i = 0; i < pubkey_len; i++) {
            printf("%02X", pubkey[i]);
        }
        printf("\n");
        printf("Private Key (%d bytes):\n", privkey_len);
        for (int i = 0; i < privkey_len; i++) {
            printf("%02X", privkey[i]);
        }
        printf("\n");

        ret = call_ecies_prime256v1_encrypt(plaintext, plaintext_len, pubkey, pubkey_len, &ciphertext, &ciphertext_len);
        if (ret != 0) {
            fprintf(stderr, "call_ecies_sm2p256v1_encrypt failed\n");
            goto out;
        }
        printf("Ciphertext (%d bytes):\n", ciphertext_len);
        for (int i = 0; i < ciphertext_len; i++) {
            printf("%02X", ciphertext[i]);
        }
        printf("\n");

        ret = call_ecies_prime256v1_decrypt(ciphertext, ciphertext_len, privkey, privkey_len, &decryptedtext, &decryptedtext_len);
        if (ret != 0) {
            fprintf(stderr, "call_ecies_sm2p256v1_decrypt failed\n");
            goto out;
        }
        printf("Decrypted Text (%d bytes):\n", decryptedtext_len);
        for (int i = 0; i < decryptedtext_len; i++) {
            printf("%c", decryptedtext[i]);
        }
        printf("\n");
    }

out:
    if (pubkey) {
        free(pubkey);
    }
    if (privkey) {
        free(privkey);
    }
    if (ciphertext) {
        free(((ECIES_Ciphertext *)ciphertext)->ephemeral_pubkey);
        free(((ECIES_Ciphertext *)ciphertext)->ciphertext);
        free(((ECIES_Ciphertext *)ciphertext)->mac);
        free(ciphertext);
    }
    if (decryptedtext) {
        free(decryptedtext);
    }
    return ret;
}