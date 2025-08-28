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

int call_ecdsa_ed25519_genkey(
    unsigned char **pubkey, int *pubkey_len,
    unsigned char **privkey, int *privkey_len) {

    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t pri_len = 0, pub_len = 0;
    unsigned char *temp_pri = NULL, *temp_pub = NULL;
    unsigned char *naked_priv = NULL; // 用于存储裸私钥
    size_t naked_priv_len = 0;
    unsigned char * p = NULL;

    // 1. create context
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
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

    // 3. generate key
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. extract private key
    pri_len = i2d_PrivateKey(pkey, NULL);
    if (pri_len <= 0) {
        fprintf(stderr, "i2d_PrivateKey failed to get length: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    temp_pri = (unsigned char *)malloc(pri_len);
    if (!temp_pri) {
        fprintf(stderr, "malloc for private key failed\n");
        ret = -1;
        goto out;
    }
    p = temp_pri;
    pri_len = i2d_PrivateKey(pkey, &p);
    if (pri_len <= 0) {
        fprintf(stderr, "i2d_PrivateKey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *privkey = temp_pri;
    *privkey_len = pri_len;
    temp_pri = NULL; // ownership transferred

    if (EVP_PKEY_get_raw_private_key(pkey, NULL, &naked_priv_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_get_raw_private_key failed to get length: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    naked_priv = (unsigned char *)malloc(naked_priv_len);
    if (!naked_priv) {
        fprintf(stderr, "malloc for naked private key failed\n");
        ret = -1;
        goto out;
    }
    if (EVP_PKEY_get_raw_private_key(pkey, naked_priv, &naked_priv_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_get_raw_private_key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    // Print naked private key
    printf("Naked Private Key (%zu bytes):\n", naked_priv_len);
    for (size_t j = 0; j < naked_priv_len; j++) {
        printf("%02X", naked_priv[j]);
    }
    printf("\n");
    free(naked_priv);
    naked_priv = NULL;


    // 5. extract public key
    pub_len = i2d_PUBKEY(pkey, NULL);
    if (pub_len <= 0) {
        fprintf(stderr, "i2d_PUBKEY failed to get length: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    temp_pub = (unsigned char *)malloc(pub_len);
    if (!temp_pub) {
        fprintf(stderr, "malloc for public key failed\n");
        ret = -1;
        goto out;
    }
    p = temp_pub;
    pub_len = i2d_PUBKEY(pkey, &p);
    if (pub_len <= 0) {
        fprintf(stderr, "i2d_PUBKEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *pubkey = temp_pub;
    *pubkey_len = pub_len;
    temp_pub = NULL; // ownership transferred
    ret = 0;
out:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return ret;
}

int call_ecdsa_ed25519_signdata(
    const unsigned char *msg, int msg_len,
    const unsigned char *privkey, int privkey_len,
    unsigned char **sig, int *sig_len) {

    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    size_t slen = 0;
    const unsigned char *p = privkey;

    // 1. create EVP_PKEY from private key
    pkey = d2i_PrivateKey(EVP_PKEY_ED25519, NULL, &p, privkey_len);
    if (!pkey) {
        fprintf(stderr, "d2i_PrivateKey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 2. create pctx for signing
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. create mdctx for signing
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. initialize signing
    if (EVP_DigestSignInit(mdctx, &pctx, NULL, NULL, pkey) <= 0) {
        fprintf(stderr, "EVP_DigestSignInit failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 5. call EVP_DigestSign to get signature length
    if (EVP_DigestSign(mdctx, NULL, &slen, msg, msg_len) <= 0) {
        fprintf(stderr, "EVP_DigestSign failed to get length: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *sig = (unsigned char *)malloc(slen);
    if (!*sig) {
        fprintf(stderr, "malloc for sig failed\n");
        ret = -1;
        goto out;
    }

    // 6. call EVP_DigestSign to get signature
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
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return ret;
}


int call_ecdsa_ed25519_verifydata(
    const unsigned char *msg, int msg_len,
    const unsigned char *sig, int sig_len,
    const unsigned char *pubkey, int pubkey_len) {

    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    const unsigned char *p = pubkey;

    // 1. create EVP_PKEY from public key
    pkey = d2i_PUBKEY(NULL, &p, pubkey_len);
    if (!pkey) {
        fprintf(stderr, "d2i_PUBKEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 2. create mdctx for verifying
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 3. initialize verifying
    if (EVP_DigestVerifyInit(mdctx, &pctx, NULL, NULL, pkey) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyInit failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. call EVP_DigestVerify to verify signature
    ret = EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
    if (ret < 0) {
        fprintf(stderr, "EVP_DigestVerify failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ret = 0;

out:
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return ret;
}

int main(int argc, char *argv[]) {
    int ret = 0;
    unsigned char *prikey = NULL, *pubkey = NULL;
    int prikey_len = 0, pubkey_len = 0;
    unsigned char *sig = NULL;
    int sig_len = 0;

    ret = call_ecdsa_ed25519_genkey(&pubkey, &pubkey_len, &prikey, &prikey_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecdsa_ed25519_genkey failed\n");
        ret = -1;
        goto out;
    }
    // Print keys
    printf("Private Key (%d bytes):\n", prikey_len);
    for (int j = 0; j < prikey_len; j++) {
        printf("%02X", prikey[j]);
    }
    printf("\n");
    printf("Public Key (%d bytes):\n", pubkey_len);
    for (int j = 0; j < pubkey_len; j++) {
        printf("%02X", pubkey[j]);
    }
    printf("\n");

    ret = call_ecdsa_ed25519_signdata(
        (const unsigned char *)"hello, world", strlen("hello, world"),
        prikey, prikey_len, &sig, &sig_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecdsa_ed25519_signdata failed\n");
        ret = -1;
        goto out;
    }
    // Print signature
    printf("Signature (%d bytes):\n", sig_len);
    for (int j = 0; j < sig_len; j++) {
        printf("%02X", sig[j]);
    }
    printf("\n");

    ret = call_ecdsa_ed25519_verifydata(
        (const unsigned char *)"hello, world", strlen("hello, world"),
        sig, sig_len, pubkey, pubkey_len);
    if (ret != 0) {
        fprintf(stderr, "call_ecdsa_ed25519_verifydata failed\n");
        ret = -1;
        goto out;
    }
    printf("Signature verified successfully\n");
    ret = 0;

out:
    if (prikey) {
        free(prikey);
    }
    if (pubkey) {
        free(pubkey);
    }
    if (sig) {
        free(sig);
    }
    return ret;
}
