#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int call_gmac_test(EVP_CIPHER *cipher, unsigned char *key, int keylen,
    unsigned char *iv, int ivlen,
    unsigned char *aad, int aadlen,
    unsigned char *msg, int msglen,
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
    if (msg && msglen > 0) {
        ret = EVP_EncryptUpdate(ctx, NULL, &len, msg, msglen);
        if (ret != 1) {
            fprintf(stderr, "EVP_EncryptUpdate (message) failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }
        ciphertext_len = len;
    }

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
    int msglen = strlen((char *)msg);
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
        ret = call_gmac_test(cipher, key, keylen, iv, ivlen, aad, aadlen, msg, msglen, tag, taglen);
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
        i++;
    }

    ret = 0;
end:
    return ret;
}
