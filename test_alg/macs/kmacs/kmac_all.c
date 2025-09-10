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

typedef struct {
    EVP_MAC     *mac;   // fetched "KMAC128"/"KMAC256"
    EVP_MAC_CTX *ctx;
    size_t outlen;      // desired tag length (bytes)
} KMAC_CTX;

static void kmac_print_err(const char *where) {
    fprintf(stderr, "%s: ", where);
    ERR_print_errors_fp(stderr);
}

KMAC_CTX *KMAC_CTX_new(void) {
    KMAC_CTX *k = (KMAC_CTX*)OPENSSL_zalloc(sizeof(*k));
    return k;
}

void KMAC_CTX_free(KMAC_CTX *k) {
    if (!k) return;
    EVP_MAC_CTX_free(k->ctx);
    EVP_MAC_free(k->mac);
    OPENSSL_free(k);
}

/**
 * alg: "KMAC128" 或 "KMAC256"
 * key/keylen: KMAC 密钥
 * custom: customization string，可为 "" 或 NULL
 * outlen: 期望的 MAC 长度（任意字节数，双方约定即可）
 */
int KMAC_Init(KMAC_CTX *k,
              const char *alg,
              const unsigned char *key, size_t keylen,
              const char *custom,
              size_t outlen)
{
    if (!k) return 0;

    k->mac = EVP_MAC_fetch(NULL, alg, NULL);
    if (!k->mac) { kmac_print_err("EVP_MAC_fetch"); return 0; }

    k->ctx = EVP_MAC_CTX_new(k->mac);
    if (!k->ctx) { kmac_print_err("EVP_MAC_CTX_new"); return 0; }

    k->outlen = outlen;

    OSSL_PARAM params[3], *p = params;
    *p++ = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, (size_t*)&k->outlen);
    if (custom) {
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CUSTOM, (char*)custom, 0);
    }
    *p++ = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(k->ctx, key, keylen, params) != 1) {
        kmac_print_err("EVP_MAC_init");
        return 0;
    }
    return 1;
}

int KMAC_Update(KMAC_CTX *k, const unsigned char *data, size_t len) {
    if (!k || !k->ctx) return 0;
    if (EVP_MAC_update(k->ctx, data, len) != 1) {
        kmac_print_err("EVP_MAC_update");
        return 0;
    }
    return 1;
}

int KMAC_Final(KMAC_CTX *k, unsigned char *out, size_t *outlen /*可为NULL*/) {
    if (!k || !k->ctx) return 0;
    size_t got = 0;
    if (EVP_MAC_final(k->ctx, out, &got, k->outlen) != 1) {
        kmac_print_err("EVP_MAC_final");
        return 0;
    }
    if (outlen) *outlen = got;
    return 1;
}

int call_kmac_test(const char *alg,
                   const unsigned char *key, size_t keylen,
                   const unsigned char *msg, size_t msglen,
                   unsigned char *tag, size_t taglen)
{
    int ret = 0;
    KMAC_CTX *k = NULL;
    size_t outlen = 0;

    k = KMAC_CTX_new();
    if (!k) {
        fprintf(stderr, "KMAC_CTX_new failed\n");
        ret = -1;
        goto out;
    }
    if (1 != KMAC_Init(k, alg, key, keylen, "MyApp", taglen)) {
        fprintf(stderr, "KMAC_Init failed\n");
        ret = -1;
        goto out;
    }
    if (1 != KMAC_Update(k, msg, msglen)) {
        fprintf(stderr, "KMAC_Update failed\n");
        ret = -1;
        goto out;
    }
    if (1 != KMAC_Final(k, tag, &outlen)) {
        fprintf(stderr, "KMAC_Final failed\n");
        ret = -1;
        goto out;
    }
    if (outlen != taglen) {
        fprintf(stderr, "KMAC tag length mismatch: expected %zu, got %zu\n", taglen, outlen);
        ret = -1;
        goto out;
    }

    ret = 0;
out:
    if (k) {
        KMAC_CTX_free(k);
    }
    return ret;
}

char *kmac_ciphers[] = {
    "KMAC128",
    "KMAC256",
    NULL
};

int main(int argc, char *argv[]) {
    int ret = 0;
    const unsigned char key128[] = { // demo：16字节 key
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F
    };
    const unsigned char msg[] = "Message to be authenticated";
    const char *custom = "MyApp"; // 可以为空："" 或传 NULL
    unsigned char tag[32];        // 这里要和 outlen 对齐
    size_t taglen = 0;
    int i = 0;

    while (kmac_ciphers[i]) {
        printf("Testing KMAC with algorithm: %s\n", kmac_ciphers[i]);
        if (strcmp(kmac_ciphers[i], "KMAC128") == 0) {
            taglen = 16; // KMAC128，输出16字节
            ret = call_kmac_test(kmac_ciphers[i], key128, sizeof(key128),
                                 msg, strlen((char*)msg),
                                 tag, taglen);
        } else if (strcmp(kmac_ciphers[i], "KMAC256") == 0) {
            taglen = 32; // KMAC256，输出32字节
            ret = call_kmac_test(kmac_ciphers[i], key128, sizeof(key128),
                                 msg, strlen((char*)msg),
                                 tag, taglen);
        } else {
            fprintf(stderr, "Unknown algorithm: %s\n", kmac_ciphers[i]);
            ret = -1;
            goto end;
        }

        if (ret != 0) {
            fprintf(stderr, "KMAC test failed for %s\n", kmac_ciphers[i]);
            goto end;
        } else {
            printf("KMAC test passed for %s\n", kmac_ciphers[i]);
            // print the resulting tag
            printf("KMAC Tag: ");
            for (size_t j = 0; j < taglen; j++) {
                printf("%02x", tag[j]);
            }
            printf("\n");
        }
        i++;
    }




end:
    return ret;
}

