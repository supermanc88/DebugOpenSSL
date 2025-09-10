#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/cmac.h>
#include <openssl/provider.h>

int call_cmac_test(EVP_CIPHER *cipher,
    unsigned char *key, int keylen,
    unsigned char *msg, int msglen,
    unsigned char *tag, int taglen) {
    int ret = 0;
    CMAC_CTX *ctx = NULL;
    size_t outlen = 0;

    ctx = CMAC_CTX_new();
    if (!ctx) {
        fprintf(stderr, "CMAC_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (1 != CMAC_Init(ctx, key, keylen, cipher, NULL)) {
        fprintf(stderr, "CMAC_Init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (1 != CMAC_Update(ctx, msg, msglen)) {
        fprintf(stderr, "CMAC_Update failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (1 != CMAC_Final(ctx, tag, &outlen)) {
        fprintf(stderr, "CMAC_Final failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (outlen != taglen) {
        fprintf(stderr, "CMAC tag length mismatch: expected %d, got %zu\n", taglen, outlen);
        ret = -1;
        goto out;
    }

    ret = 0;
out:
    if (ctx) {
        CMAC_CTX_free(ctx);
    }
    return ret;
}

const char *cmac_ciphers[] = {
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
    "DES-CBC",
    "DES-EDE3-CBC",
    "SM4-CBC",
    NULL
};

int main(int argc, char *argv[]) {
    int ret = 0;
    EVP_CIPHER *cipher = NULL;
    unsigned char key[32] = {0};
    unsigned char msg[] = "Message to be authenticated";
    unsigned char tag[16] = {0};
    int keylen = 16; // default to AES-128
    int msglen = strlen((char *)msg);
    int taglen = 16; // standard tag length
    int i = 0;
    OSSL_PROVIDER *prov_default = NULL;
    OSSL_PROVIDER *prov_legacy = NULL;

    // fill key with some values
    for (int j = 0; j < sizeof(key); j++) {
        key[j] = (unsigned char)j;
    }

    // des and 3des not support in default provider,so we need to load legacy provider
    if (1 != OPENSSL_init_crypto(0, NULL)) {
        fprintf(stderr, "OPENSSL_init_crypto failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    prov_default = OSSL_PROVIDER_load(NULL, "default");
    if (!prov_default) {
        fprintf(stderr, "Failed to load default provider: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    prov_legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (!prov_legacy) {
        fprintf(stderr, "Failed to load legacy provider: %s\n", ERR_error_string(ERR_get_error(), NULL));
        OSSL_PROVIDER_unload(prov_default);
        return -1;
    }

    while (cmac_ciphers[i]) {
        printf("Testing CMAC with cipher: %s\n", cmac_ciphers[i]);
        cipher = EVP_CIPHER_fetch(NULL, cmac_ciphers[i], NULL);
        if (!cipher) {
            fprintf(stderr, "EVP_CIPHER_fetch failed for %s: %s\n", cmac_ciphers[i], ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto end;
        }
        keylen = EVP_CIPHER_key_length(cipher);
        if (keylen > sizeof(key)) {
            fprintf(stderr, "Key length %d is too large for buffer\n", keylen);
            EVP_CIPHER_free(cipher);
            ret = -1;
            goto end;
        }
        taglen = EVP_CIPHER_block_size(cipher);
        if (taglen > sizeof(tag)) {
            fprintf(stderr, "Tag length %d is too large for buffer\n", taglen);
            EVP_CIPHER_free(cipher);
            ret = -1;
            goto end;
        }
        // call the cmac test function
        ret = call_cmac_test(cipher, key, keylen, msg, msglen, tag, taglen);
        if (ret != 0) {
            fprintf(stderr, "CMAC test failed for %s\n", cmac_ciphers[i]);
            EVP_CIPHER_free(cipher);
            goto end;
        } else {
            printf("CMAC test passed for %s\n", cmac_ciphers[i]);
            // print the resulting tag
            printf("CMAC Tag: ");
            for (int j = 0; j < taglen; j++) {
                printf("%02x", tag[j]);
            }
            printf("\n");
        }
        EVP_CIPHER_free(cipher);
        i++;
    }

    ret = 0;
end:
    if (!prov_legacy) {
        OSSL_PROVIDER_unload(prov_legacy);
    }
    if (!prov_default) {
        OSSL_PROVIDER_unload(prov_default);
    }
    return ret;
}
