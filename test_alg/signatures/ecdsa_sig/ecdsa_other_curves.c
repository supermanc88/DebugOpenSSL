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
    BIGNUM *priv_bn = NULL; // 用于存储私钥的BIGNUM

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

    priv_bn = EC_KEY_get0_private_key(eckey);
    if (priv_bn) {
        char *priv_hex = BN_bn2hex(priv_bn);
        if (priv_hex) {
            printf("Naked Private Key (%d bytes):\n", (int)strlen(priv_hex) / 2);
            printf(priv_hex);
            printf("\n");
            OPENSSL_free(priv_hex);
        }
    }

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

int call_ecdsa_signdata( EVP_MD *md,
    const unsigned char *msg, int msg_len,
    const unsigned char *privkey, int privkey_len,
    unsigned char **sig, int *sig_len) {
    int ret = 0;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EC_KEY *eckey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char *temp_pri = NULL;
    size_t slen = 0;

    // 1. ec_key from private key
    const unsigned char *temp_priv = privkey;
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

    // 3. create pctx for signing
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. create mdctx for signing
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 5. initialize signing
    if (EVP_DigestSignInit(mdctx, &pctx, md, NULL, pkey) <= 0) {
        fprintf(stderr, "EVP_DigestSignInit failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 6. call EVP_DigestSign to get signature length
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

    // 7. call EVP_DigestSign to get signature
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
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (eckey) {
        EC_KEY_free(eckey);
    }
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    return ret;
}

int call_ecdsa_verifydata( int curve_nid,
    EVP_MD *md,
    const unsigned char *msg, int msg_len,
    const unsigned char *sig, int sig_len,
    const unsigned char *pubkey, int pubkey_len) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EC_KEY *eckey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    const unsigned char *temp_pub = pubkey;

    // 1. ec_key from public key
    eckey = EC_KEY_new_by_curve_name(curve_nid);
    if (!eckey) {
        fprintf(stderr, "EC_KEY_new_by_curve_name failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
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

    // 3. create mdctx for verifying
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 4. initialize verifying
    if (EVP_DigestVerifyInit(mdctx, &pctx, md, NULL, pkey) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyInit failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // 5. call EVP_DigestVerify to verify signature
    ret = EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
    if (ret < 0) {
        fprintf(stderr, "EVP_DigestVerify failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ret = 0;

out:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (eckey) {
        EC_KEY_free(eckey);
    }
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    return ret;
}

typedef struct {
    int nid;
    char *md_name;
} EC_CURVE;

EC_CURVE ec_nids [] = {
    // =================== prime curves ===================
    {NID_X9_62_prime192v1,   // also known as NID_secp192r1
     "SHA256"},
    {NID_secp192k1,
        "SHA256"},
    {NID_secp224r1,
        "SHA256"},
    {NID_secp224k1,
        "SHA256"},
    {NID_X9_62_prime256v1,   // also known as NID_secp256r1
        "SHA256"},
    {NID_secp256k1,
        "SHA256"},
    {NID_secp384r1,
        "SHA384"},
    {NID_secp521r1,
        "SHA512"},
    // =================== brainpool curves ===================
    {NID_brainpoolP160r1,
        "SHA256"},
    {NID_brainpoolP192r1,
        "SHA256"},
    {NID_brainpoolP224r1,
        "SHA256"},
    {NID_brainpoolP256r1,
        "SHA256"},
    {NID_brainpoolP320r1,
        "SHA384"},
    {NID_brainpoolP384r1,
        "SHA384"},
    {NID_brainpoolP512r1,
        "SHA512"},
    // =================== sect curves ===================
    {NID_sect163k1,
        "SHA256"},
    {NID_sect163r2,
        "SHA256"},
    {NID_sect193r1,
    "SHA256"},
    {NID_sect193r2,
    "SHA256"},
    {NID_sect233k1,
    "SHA256"},
    {NID_sect233r1,
        "SHA256"},
    {NID_sect239k1,
        "SHA256"},
    {NID_sect283k1,
        "SHA256"},
    {NID_sect283r1,
        "SHA256"},
    {NID_sect409k1,
        "SHA512"},
    {NID_sect409r1,
        "SHA512"},
    {NID_sect571k1,
        "SHA512"},
    {NID_sect571r1,
        "SHA512"},
};

int main(int argc, char *argv[]) {
    int ret = 0;
    unsigned char *pubkey = NULL, *privkey = NULL;
    int pubkey_len = 0, privkey_len = 0;
    int curve_nid = 0;
    int i = 0;
    unsigned char *sig = NULL;
    int sig_len = 0;
    for (i = 0; i < sizeof(ec_nids)/sizeof(ec_nids[0]); i++) {
        printf("========================================\n");
        curve_nid = ec_nids[i].nid;
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

        char *md_name = ec_nids[i].md_name;
        const EVP_MD *md = EVP_MD_fetch(NULL, md_name, NULL);
        if (!md) {
            fprintf(stderr, "EVP_MD_fetch failed for %s\n", md_name);
            ret = -1;
            return ret;
        }

        ret = call_ecdsa_signdata(md,
        (const unsigned char *)"hello, world", strlen("hello, world"),
            privkey, privkey_len, &sig, &sig_len);
        if (ret != 0) {
            fprintf(stderr, "call_ecdsa_signdata failed for curve NID %d\n", curve_nid);
            EVP_MD_free(md);
            free(pubkey);
            free(privkey);
            pubkey = NULL;
            privkey = NULL;
            pubkey_len = 0;
            privkey_len = 0;
            continue;
        }
        printf("Signature (%d bytes):\n", sig_len);
        for (int j = 0; j < sig_len; j++) {
            printf("%02X", sig[j]);
        }
        printf("\n");
        ret = call_ecdsa_verifydata(curve_nid, md,
            (const unsigned char *)"hello, world", strlen("hello, world"),
            sig, sig_len, pubkey, pubkey_len);
        if (ret != 0) {
            printf("Signature is invalid for curve NID %d, %s\n", curve_nid, OBJ_nid2sn(curve_nid));
        } else {
            printf("Signature is valid for curve NID %d, %s\n", curve_nid, OBJ_nid2sn(curve_nid));
        }

        EVP_MD_free(md);
        free(pubkey);
        free(privkey);
        free(sig);
        pubkey = NULL;
        privkey = NULL;
        pubkey_len = 0;
        privkey_len = 0;
        sig_len = 0;
    }

    return ret;
}