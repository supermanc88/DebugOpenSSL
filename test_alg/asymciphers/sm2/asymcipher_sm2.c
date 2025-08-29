#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

int call_sm2_gen_via_evp(unsigned char **pub, size_t *publen,
    unsigned char **pri, size_t *prilen) {

    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIO *bio_pub = NULL, *bio_pri = NULL;
    char *bio_buf_pub = NULL, *bio_buf_pri = NULL;
    size_t bio_len_pub = 0, bio_len_pri = 0;

    // 1. create context for SM2
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (!ctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_id failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 2. initialize key generation
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. generate key
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. extract public key
    bio_pub = BIO_new(BIO_s_mem());
    if (!bio_pub) {
        fprintf(stderr, "BIO_new for pub failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (i2d_PUBKEY_bio(bio_pub, pkey) <= 0) {
        fprintf(stderr, "i2d_PUBKEY_bio failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    bio_len_pub = BIO_get_mem_data(bio_pub, &bio_buf_pub);
    *pub = (unsigned char *)malloc(bio_len_pub);
    if (!*pub) {
        fprintf(stderr, "malloc for pub failed\n");
        ret = -1;
        goto out;
    }
    memcpy(*pub, bio_buf_pub, bio_len_pub);
    *publen = bio_len_pub;

    // 5. extract private key
    bio_pri = BIO_new(BIO_s_mem());
    if (!bio_pri) {
        fprintf(stderr, "BIO_new for pri failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (i2d_PrivateKey_bio(bio_pri, pkey) <= 0) {
        fprintf(stderr, "i2d_PrivateKey_bio failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    bio_len_pri = BIO_get_mem_data(bio_pri, &bio_buf_pri);
    *pri = (unsigned char *)malloc(bio_len_pri);
    if (!*pri) {
        fprintf(stderr, "malloc for pri failed\n");
        ret = -1;
        goto out;
    }
    memcpy(*pri, bio_buf_pri, bio_len_pri);
    *prilen = bio_len_pri;

    ret = 0;

out:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (bio_pub) {
        BIO_free(bio_pub);
    }
    if (bio_pri) {
        BIO_free(bio_pri);
    }
    return ret;
}

int main(int argc, char *argv[]) {
    int ret = 0;
    unsigned char *pub = NULL, *pri = NULL;
    size_t publen = 0, prilen = 0;
    int i = 0;

    ret = call_sm2_gen_via_evp(&pub, &publen, &pri, &prilen);
    if (ret != 0) {
        fprintf(stderr, "call_sm2_gen_via_evp failed\n");
        return ret;
    }

    // print public key
    printf("Public Key (%zu bytes):\n", publen);
    for (i = 0; i < publen; i++) {
        printf("%02X", pub[i]);
    }
    printf("\n");

    // print private key
    printf("Private Key (%zu bytes):\n", prilen);
    for (i = 0; i < prilen; i++) {
        printf("%02X", pri[i]);
    }
    printf("\n");


    return ret;
}