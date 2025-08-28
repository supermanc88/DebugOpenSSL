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

int call_ecdsa_sm2p256v1_genkey(unsigned char **pubkey, int *pubkey_len,
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

int call_ecdsa_sm2p256v1_signdata(const unsigned char *msg, int msg_len,
    const unsigned char *privkey, int privkey_len,
    unsigned char **sig, int *sig_len) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EC_KEY *eckey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    const unsigned char *temp_priv = privkey;
    size_t slen = 0;

    // 1. convert DER encoded private key to EC_KEY
    eckey = d2i_ECPrivateKey(NULL, &temp_priv, privkey_len);
    if (!eckey) {
        fprintf(stderr, "d2i_ECPrivateKey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 2. create EVP_PKEY from EC_KEY
    pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "EVP_PKEY_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (EVP_PKEY_set1_EC_KEY(pkey, eckey) <= 0) {
        fprintf(stderr, "EVP_PKEY_set1_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. create context for signing
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. initialize signing
    if (EVP_PKEY_sign_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 5. initialize digest context
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey) <= 0) {
        fprintf(stderr, "EVP_DigestSignInit failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 6. determine buffer length
    if (EVP_DigestSign(mdctx, NULL, &slen, msg, msg_len) <= 0) {
        fprintf(stderr, "EVP_DigestSign (get length) failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *sig = (unsigned char *)malloc(slen);
    if (!*sig) {
        fprintf(stderr, "malloc for sig failed\n");
        ret = -1;
        goto out;
    }

    // 7. sign the message
    if (EVP_DigestSign(mdctx, *sig, &slen, msg, msg_len) <= 0) {
        fprintf(stderr, "EVP_DigestSign failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(*sig);
        *sig = NULL;
        ret = -1;
        goto out;
    }

    *sig_len = slen;

    ret = 0;
out:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (eckey) {
        EC_KEY_free(eckey);
    }
    return ret;
}


int call_ecdsa_sm2p256v1_verifydata(const unsigned char *msg, int msg_len,
    const unsigned char *sig, int sig_len,
    const unsigned char *pubkey, int pubkey_len) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EC_KEY *eckey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    const unsigned char *temp_pub = pubkey;

    // new eckey via set nid
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!eckey) {
        fprintf(stderr, "EC_KEY_new_by_curve_name failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 1. set public key to EC_KEY
    if (EC_KEY_oct2key(eckey, temp_pub, pubkey_len, NULL) != 1) {
        fprintf(stderr, "ec_key_oct2key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 2. create EVP_PKEY from EC_KEY
    pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "EVP_PKEY_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (EVP_PKEY_set1_EC_KEY(pkey, eckey) <= 0) {
        fprintf(stderr, "EVP_PKEY_set1_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. create context for verification
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. initialize verification
    if (EVP_PKEY_verify_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 5. initialize digest context
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), NULL, pkey) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyInit failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 6. verify signature
    ret = EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
    if (ret < 0) {
        fprintf(stderr, "EVP_DigestVerify failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    ret = 0;

out:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (eckey) {
        EC_KEY_free(eckey);
    }
    return ret;
}


int call_ecdsa_prime256v1_signhash(const unsigned char *hash, int hash_len,
    const unsigned char *privkey, int privkey_len,
    unsigned char **sig, int *sig_len) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EC_KEY *eckey = NULL;
    const unsigned char *temp_priv = privkey;
    size_t slen = 0;

    // 1. convert DER encoded private key to EC_KEY
    eckey = d2i_ECPrivateKey(NULL, &temp_priv, privkey_len);
    if (!eckey) {
        fprintf(stderr, "d2i_ECPrivateKey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 2. create EVP_PKEY from EC_KEY
    pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "EVP_PKEY_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (EVP_PKEY_set1_EC_KEY(pkey, eckey) <= 0) {
        fprintf(stderr, "EVP_PKEY_set1_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. create context for signing
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. initialize signing
    if (EVP_PKEY_sign_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 5. set digest algorithm
    if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_signature_md failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 6. determine buffer length
    if (EVP_PKEY_sign(pctx, NULL, &slen, hash, hash_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign (get length) failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *sig = (unsigned char *)malloc(slen);
    if (!*sig) {
        fprintf(stderr, "malloc for sig failed\n");
        ret = -1;
        goto out;
    }

    // 7. sign the hash
    if (EVP_PKEY_sign(pctx, *sig, &slen, hash, hash_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(*sig);
        *sig = NULL;
        ret = -1;
        goto out;
    }
    *sig_len = slen;
    ret = 0;

out:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (eckey) {
        EC_KEY_free(eckey);
    }
    return ret;
}

int call_ecdsa_prime256v1_verifyhash(const unsigned char *hash, int hash_len,
    const unsigned char *sig, int sig_len,
    const unsigned char *pubkey, int pubkey_len) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EC_KEY *eckey = NULL;
    const unsigned char *temp_pub = pubkey;

    // new eckey via set nid
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!eckey) {
        fprintf(stderr, "EC_KEY_new_by_curve_name failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    // 1. set public key to EC_KEY
    if (EC_KEY_oct2key(eckey, temp_pub, pubkey_len, NULL) != 1) {
        fprintf(stderr, "ec_key_oct2key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 2. create EVP_PKEY from EC_KEY
    pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "EVP_PKEY_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. set EC_KEY to EVP_PKEY
    if (EVP_PKEY_set1_EC_KEY(pkey, eckey) <= 0) {
        fprintf(stderr, "EVP_PKEY_set1_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. create context for verification
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 5. initialize verification
    if (EVP_PKEY_verify_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_init failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 6. set digest algorithm
    if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_signature_md failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 7. verify signature
    ret = EVP_PKEY_verify(pctx, sig, sig_len, hash, hash_len);
    if (ret < 0) {
        fprintf(stderr, "EVP_PKEY_verify failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ret = 0;


out:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (eckey) {
        EC_KEY_free(eckey);
    }
    return ret;
}


int main(int argc, char *argv[]) {
    int ret = 0;
    unsigned char *pubkey = NULL, *privkey = NULL;
    int pubkey_len = 0, privkey_len = 0;
    unsigned char *sig = NULL;
    int sig_len = 0;

    ret = call_ecdsa_sm2p256v1_genkey(&pubkey, &pubkey_len, &privkey, &privkey_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecdsa_sm2p256v1_genkey failed\n");
        return -1;
    }
    printf("Private Key (%d bytes):\n", privkey_len);
    for (int i = 0; i < privkey_len; i++) {
        printf("%02X", privkey[i]);
    }
    printf("\n");
    printf("Public Key (%d bytes):\n", pubkey_len);
    for (int i = 0; i < pubkey_len; i++) {
        printf("%02X", pubkey[i]);
    }
    printf("\n");

    printf("call ecdsa_sm2p256v1_signdata ...\n");
    ret = call_ecdsa_sm2p256v1_signdata((const unsigned char *)"hello, world", strlen("hello, world"),
        privkey, privkey_len, &sig, &sig_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecdsa_sm2p256v1_sign failed\n");
        return -1;
    }
    printf("Signature (%d bytes):\n", sig_len);
    for (int i = 0; i < sig_len; i++) {
        printf("%02X", sig[i]);
    }
    printf("\n");

    ret = call_ecdsa_sm2p256v1_verifydata((const unsigned char *)"hello, world", strlen("hello, world"),
        sig, sig_len, pubkey, pubkey_len);
    if (ret != 0) {
        printf("Signature is invalid\n");
    } else {
        printf("Signature is valid\n");
    }

    free(sig);
    sig = NULL;
    sig_len = 0;


    printf("call ecdsa_prime256v1_signhash ...\n");
    unsigned char hash[32] = {0};
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, "hello, world", strlen("hello, world"));
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    ret = call_ecdsa_prime256v1_signhash(hash, sizeof(hash),
        privkey, privkey_len, &sig, &sig_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecdsa_prime256v1_signhash failed\n");
        return -1;
    }
    printf("Signature (%d bytes):\n", sig_len);
    for (int i = 0; i < sig_len; i++) {
        printf("%02X", sig[i]);
    }
    printf("\n");

    ret = call_ecdsa_prime256v1_verifyhash(hash, sizeof(hash),
        sig, sig_len, pubkey, pubkey_len);
    if (ret != 0) {
        printf("Signature is invalid\n");
    } else {
        printf("Signature is valid\n");
    }

    free(privkey);
    free(pubkey);
    free(sig);

    return ret;
}