#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int call_ecdsa_genkey(int curve_nid,
    unsigned char **pubkey, int *pubkey_len,
    unsigned char **privkey, int *privkey_len) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EC_KEY *eckey = NULL;
    size_t pri_len = 0, pub_len = 0;
    unsigned char *temp_pri = NULL, *temp_pub = NULL;

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
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid) <= 0) {
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
    // set private key not contains public key, only private key
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
    return ret;
}

int ec_nids [] = {
    NID_X9_62_prime192v1,   // also known as NID_secp192r1
    NID_secp192k1,
    NID_secp224r1,
    NID_secp224k1,
    NID_X9_62_prime256v1,   // also known as NID_secp256r1
    NID_secp256k1,
    NID_secp384r1,
    NID_secp521r1,
};


int main(int argc, char *argv[]) {
    int ret = 0;
    unsigned char *pubkey = NULL, *privkey = NULL;
    int pubkey_len = 0, privkey_len = 0;
    int curve_nid = 0;
    int i = 0;
    for (i = 0; i < sizeof(ec_nids)/sizeof(ec_nids[0]); i++) {
        curve_nid = ec_nids[i];
        printf("Generating key for curve NID %d... %s\n", curve_nid, OBJ_nid2sn(curve_nid));
        ret = call_ecdsa_genkey(curve_nid, &pubkey, &pubkey_len, &privkey, &privkey_len);
        if (ret != 0) {
            fprintf(stderr, "call_ecdsa_genkey failed for curve NID %d\n", curve_nid);
            continue;
        }
        printf("Private Key (%d bytes):\n", privkey_len);
        for (int j = 0; j < privkey_len; j++) {
            printf("%02X", privkey[j]);
        }
        printf("\n");
        printf("Public Key (%d bytes):\n", pubkey_len);
        for (int j = 0; j < pubkey_len; j++) {
            printf("%02X", pubkey[j]);
        }
        printf("\n");

        free(pubkey);
        free(privkey);
        pubkey = NULL;
        privkey = NULL;
    }

    return ret;
}