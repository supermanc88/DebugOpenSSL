#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

int call_hmac_sha512(unsigned char *key, int keylen,
                    unsigned char *data, int datalen,
                    unsigned char *out_data, int *out_datalen) {
    int ret = 0;
    HMAC_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned int len = 0;

    // Get the sha512 digest
    md = EVP_sha512();
    if (!md) {
        fprintf(stderr, "Failed to get SHA512 digest: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Create and initialize the HMAC context
    ctx = HMAC_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create HMAC context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Initialize the HMAC operation
    if (1 != HMAC_Init_ex(ctx, key, keylen, md, NULL)) {
        fprintf(stderr, "Failed to initialize HMAC: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Provide the data to be hashed
    if (1 != HMAC_Update(ctx, data, datalen)) {
        fprintf(stderr, "Failed to update HMAC: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Finalize the HMAC operation
    if (1 != HMAC_Final(ctx, out_data, &len)) {
        fprintf(stderr, "Failed to finalize HMAC: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *out_datalen = len;

    ret = 0;


out:
    if (ctx) {
        HMAC_CTX_free(ctx);
    }
    return ret;
}

int main(int argc, char *argv[]) {
    int ret = 0;

    unsigned char key[16] = "0123456789abcdef";
    unsigned char data[] = "The quick brown fox jumps over the lazy dog";
    unsigned char out_data[EVP_MAX_MD_SIZE] = {0};
    int out_datalen = 0;
    int i = 0;

    ret = call_hmac_sha512(key, strlen((char *)key), data, strlen((char *)data), out_data, &out_datalen);
    if (ret != 0) {
        fprintf(stderr, "HMAC-SHA512 computation failed\n");
        return ret;
    }
    printf("HMAC-SHA512: ");
    for (i = 0; i < out_datalen; i++) {
        printf("%02x", out_data[i]);
    }
    printf("\n");


    return ret;
}