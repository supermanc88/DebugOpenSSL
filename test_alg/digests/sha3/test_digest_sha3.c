#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

int call_digest_sha3(const char *md_string, const char *msg, unsigned char *md_value, unsigned int *md_len) {
    int ret = 0;
    EVP_MD const *md = NULL;
    EVP_MD_CTX *mdctx = NULL;
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Get the message digest algorithm by name
    md = EVP_get_digestbyname(md_string);
    if (md == NULL) {
        fprintf(stderr, "Unknown message digest %s\n", md_string);
        ret = -1;
        goto out;
    }

    // Initialize the digest context
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Update the digest with the message
    if (EVP_DigestUpdate(mdctx, msg, strlen(msg)) != 1) {
        fprintf(stderr, "EVP_DigestUpdate failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Finalize the digest
    if (EVP_DigestFinal_ex(mdctx, md_value, md_len) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    ret = 0;

out:
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    return ret;
}


int call_digest_shake_truncate_length(const char *md_string, const char *msg,
    size_t truncate_len,
    unsigned char *md_value, unsigned int *md_len) {
    int ret = 0;
    EVP_MD const *md = NULL;
    EVP_MD_CTX *mdctx = NULL;
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Get the message digest algorithm by name
    md = EVP_get_digestbyname(md_string);
    if (md == NULL) {
        fprintf(stderr, "Unknown message digest %s\n", md_string);
        ret = -1;
        goto out;
    }

    // Initialize the digest context
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Update the digest with the message
    if (EVP_DigestUpdate(mdctx, msg, strlen(msg)) != 1) {
        fprintf(stderr, "EVP_DigestUpdate failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Finalize the digest
    if (EVP_DigestFinalXOF(mdctx, md_value, truncate_len) != 1) {
        fprintf(stderr, "EVP_DigestFinalXOF failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *md_len = truncate_len;

    ret = 0;

    out:
        if (mdctx) {
            EVP_MD_CTX_free(mdctx);
        }
    return ret;
}

typedef struct {
    char *md_string;
    size_t md_len;
} md_vector_t;

md_vector_t md_vectors[] = {
    {"SHA3-224", SHA224_DIGEST_LENGTH},
    {"SHA3-256", SHA256_DIGEST_LENGTH},
    {"SHA3-384", SHA384_DIGEST_LENGTH},
    {"SHA3-512", SHA512_DIGEST_LENGTH},
    {NULL, 0}
};

md_vector_t md_shake_vectors[] = {
    {"SHAKE128", 32},
    {"SHAKE256", 64},
    {NULL, 0}
};

int main(int argc, char *argv[]) {
    int ret = 0;
    int i = 0;
    const char *msg = "abc";
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    md_vector_t *md_vec = NULL;

    for (i = 0; md_vectors[i].md_string != NULL; i++) {
        md_vec = &md_vectors[i];
        memset(md_value, 0, sizeof(md_value));
        md_len = 0;

        ret = call_digest_sha3(md_vec->md_string, msg, md_value, &md_len);
        if (ret != 0) {
            fprintf(stderr, "call_digest_sha3 failed for %s\n", md_vec->md_string);
            goto out;
        }

        if (md_len != md_vec->md_len) {
            fprintf(stderr, "Digest length mismatch for %s: expected %zu, got %u\n",
                    md_vec->md_string, md_vec->md_len, md_len);
            ret = -1;
            goto out;
        }

        printf("%s digest, length(%d): ", md_vec->md_string, md_len);
        for (unsigned int j = 0; j < md_len; j++) {
            printf("%02x", md_value[j]);
        }
        printf("\n");
    }

    for (i = 0; md_shake_vectors[i].md_string != NULL; i++) {
        md_vec = &md_shake_vectors[i];
        memset(md_value, 0, sizeof(md_value));
        md_len = 0;

        ret = call_digest_shake_truncate_length(md_vec->md_string, msg, md_vec->md_len, md_value, &md_len);
        if (ret != 0) {
            fprintf(stderr, "call_digest_sha3_truncate_length failed for %s\n", md_vec->md_string);
            goto out;
        }

        if (md_len != md_vec->md_len) {
            fprintf(stderr, "Digest length mismatch for %s: expected %zu, got %u\n",
                    md_vec->md_string, md_vec->md_len, md_len);
            ret = -1;
            goto out;
        }

        printf("%s digest with truncate length %zu: ", md_vec->md_string, md_vec->md_len);
        for (unsigned int j = 0; j < md_len; j++) {
            printf("%02x", md_value[j]);
        }
        printf("\n");
    }

out:
    return ret;
}