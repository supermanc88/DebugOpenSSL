#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "openssl/core_names.h"

int call_gmac_test(EVP_CIPHER *cipher, unsigned char *key, int keylen,
                   unsigned char *iv, int ivlen,
                   unsigned char *aad, int aadlen,
                   // unsigned char *msg, int msglen,          // gmac does not encrypt message
                   unsigned char *tag, int taglen) {
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    ret = EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    if (ret != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Set key and IV length
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL);
    if (ret != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (set IV length) failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Initialize key and IV
    ret = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    if (ret != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (set key and IV) failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // set additional authenticated data
    if (aad && aadlen > 0) {
        ret = EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen);
        if (ret != 1) {
            fprintf(stderr, "EVP_EncryptUpdate (AAD) failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }
    }

    // Encrypt the message
    // if (msg && msglen > 0) {
    //     ret = EVP_EncryptUpdate(ctx, NULL, &len, msg, msglen);
    //     if (ret != 1) {
    //         fprintf(stderr, "EVP_EncryptUpdate (message) failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    //         ret = -1;
    //         goto out;
    //     }
    //     ciphertext_len = len;
    // }

    // Finalize encryption
    ret = EVP_EncryptFinal_ex(ctx, NULL, &len);
    if (ret != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ciphertext_len += len;

    // Get the tag
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, taglen, tag);
    if (ret != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (get tag) failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    ret = 0;

out:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}


int call_gmac_test_use_EVP_MAC(char *cipher_name,
    unsigned char *key, int keylen,
    unsigned char *iv, int ivlen,
    unsigned char *aad, int addlen,
    unsigned char *tag, int taglen) {
    int ret = 0;

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[4];
    size_t outlen = taglen;
    size_t outsize = taglen;

    mac = EVP_MAC_fetch(NULL, "GMAC", NULL);
    if (!mac) {
        fprintf(stderr, "EVP_MAC_fetch failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        fprintf(stderr, "EVP_MAC_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher_name, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV, iv, ivlen);
    params[2] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &outlen);
    params[3] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, keylen, params) != 1) {
        fprintf(stderr, "EVP_MAC_init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (aad && addlen > 0) {
        if (EVP_MAC_update(ctx, aad, addlen) != 1) {
            fprintf(stderr, "EVP_MAC_update (AAD) failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }
    }

    if (EVP_MAC_final(ctx, tag, &outsize, outlen) != 1) {
        fprintf(stderr, "EVP_MAC_final failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (outsize != outlen) {
        fprintf(stderr, "EVP_MAC_final output size mismatch: expected %zu, got %zu\n", outlen, outsize);
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


char *gmac_ciphers[] = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "sm4-gcm",
    NULL
};

int main(int argc, char *argv[]) {
    int ret = 0;

    EVP_CIPHER *cipher = NULL;
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};
    unsigned char aad[] = "Additional Authenticated Data";
    unsigned char msg[] = "Message to be authenticated";
    unsigned char tag[16] = {0};
    int keylen = 16; // default to AES-128
    int ivlen = 12; // standard IV length for GCM
    int aadlen = strlen((char *)aad);
    // int msglen = strlen((char *)msg);
    int taglen = 16; // standard tag length

    int i = 0;
    while (gmac_ciphers[i]) {
        printf("Testing GMAC with cipher: %s\n", gmac_ciphers[i]);
        cipher = EVP_CIPHER_fetch(NULL, gmac_ciphers[i], NULL);
        if (!cipher) {
            fprintf(stderr, "EVP_CIPHER_fetch failed for %s: %s\n", gmac_ciphers[i], ERR_error_string(ERR_get_error(), NULL));
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
        if (ivlen > sizeof(iv)) {
            fprintf(stderr, "IV length %d is too large for buffer\n", ivlen);
            EVP_CIPHER_free(cipher);
            ret = -1;
            goto end;
        }
        // Fill key and iv with some data
        for (int j = 0; j < keylen; j++) {
            key[j] = j;
        }
        for (int j = 0; j < ivlen; j++) {
            iv[j] = j + 1;
        }
        ret = call_gmac_test(cipher, key, keylen, iv, ivlen, aad, aadlen,
            // msg, msglen,
            tag, taglen);
        if (ret != 0) {
            fprintf(stderr, "GMAC test failed for cipher %s\n", gmac_ciphers[i]);
            EVP_CIPHER_free(cipher);
            goto end;
        }
        printf("GMAC tag: ");
        for (int j = 0; j < taglen; j++) {
            printf("%02x", tag[j]);
        }
        printf("\n");
        EVP_CIPHER_free(cipher);

        ret = call_gmac_test_use_EVP_MAC(gmac_ciphers[i], key, keylen, iv, ivlen, aad, aadlen, tag, taglen);
        if (ret != 0) {
            fprintf(stderr, "GMAC test using EVP_MAC failed for cipher %s\n", gmac_ciphers[i]);
            goto end;
        }
        printf("GMAC tag using EVP_MAC: ");
        for (int j = 0; j < taglen; j++) {
            printf("%02x", tag[j]);
        }
        printf("\n");
        i++;

        printf("--------------------------------------------------\n");
    }

    ret = 0;
end:
    return ret;
}
