#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

int call_blake2_mac(const char *alg_name,           // "BLAKE2BMAC" 或 "BLAKE2SMAC"
    const unsigned char *key, size_t keylen,
    const unsigned char *in, size_t inlen,
    unsigned char *tag, size_t taglen) {
    int ret = 0;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    // Fetch the MAC algorithm
    mac = EVP_MAC_fetch(NULL, alg_name, NULL);
    if (!mac) {
        fprintf(stderr, "EVP_MAC_fetch failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    // Create a MAC context
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        fprintf(stderr, "EVP_MAC_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Set the output length parameter
    params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &taglen);
    params[1] = OSSL_PARAM_construct_end(); // End of parameters

    if (1 != EVP_MAC_init(ctx, key, keylen, params)) {
        fprintf(stderr, "EVP_MAC_init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (1 != EVP_MAC_update(ctx, in, inlen)) {
        fprintf(stderr, "EVP_MAC_update failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (1 != EVP_MAC_final(ctx, tag, &taglen, taglen)) {
        fprintf(stderr, "EVP_MAC_final failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ret = 0;

out:
    if (ctx) {
        EVP_MAC_CTX_free(ctx);
    }
    if (mac) {
        EVP_MAC_free(mac);
    }
    return ret;
}

const char *blake2_macs_ciphers[] = {
    "BLAKE2BMAC",
    "BLAKE2SMAC",
    NULL
};

int main(int argc, char *argv[]) {
    int ret = 0;

    unsigned char key_2b[32] = {0};
    unsigned char key_2s[16] = {0};
    unsigned char in[] = "This is a test message for BLAKE2 MAC.";
    size_t inlen = strlen((char *)in);
    unsigned char tag_2b[64] = {0};
    unsigned char tag_2s[32] = {0};
    size_t tag_2b_len = 32;   // BLAKE2BMAC 输出长度可变，范围为1-64字节
    size_t tag_2s_len = 16;   // BLAKE2SMAC 输出长度可变，范围为1-32字节
    int i = 0;

    // 随机生成密钥
    if (RAND_bytes(key_2b, sizeof(key_2b)) != 1) {
        fprintf(stderr, "RAND_bytes key_2b failed\n");
        ret = -1;
        goto out;
    }
    if (RAND_bytes(key_2s, sizeof(key_2s)) != 1) {
        fprintf(stderr, "RAND_bytes key_2s failed\n");
        ret = -1;
        goto out;
    }

    while (blake2_macs_ciphers[i]) {
        const char *alg = blake2_macs_ciphers[i];
        if (strcmp(alg, "BLAKE2BMAC") == 0) {
            ret = call_blake2_mac(alg, key_2b, sizeof(key_2b), in, inlen, tag_2b, tag_2b_len);
            if (ret != 0) {
                fprintf(stderr, "call_blake2_mac %s failed\n", alg);
                goto out;
            }
            printf("%s tag: ", alg);
            for (size_t j = 0; j < tag_2b_len; j++) {
                printf("%02x", tag_2b[j]);
            }
            printf("\n");
        } else if (strcmp(alg, "BLAKE2SMAC") == 0) {
            ret = call_blake2_mac(alg, key_2s, sizeof(key_2s), in, inlen, tag_2s, tag_2s_len);
            if (ret != 0) {
                fprintf(stderr, "call_blake2_mac %s failed\n", alg);
                goto out;
            }
            printf("%s tag: ", alg);
            for (size_t j = 0; j < tag_2s_len; j++) {
                printf("%02x", tag_2s[j]);
            }
            printf("\n");
        } else {
            fprintf(stderr, "Unknown algorithm: %s\n", alg);
            ret = -1;
            goto out;
        }
        i++;
    }

out:
    return ret;
}