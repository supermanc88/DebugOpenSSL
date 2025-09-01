#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int call_digest_blake2(const char *md_name, const unsigned char *data, size_t data_len,
                      unsigned char *md_value, unsigned int *md_len) {
    int ret = 1;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;

    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname(md_name);
    if (md == NULL) {
        fprintf(stderr, "Unknown message digest %s\n", md_name);
        goto out;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
        fprintf(stderr, "EVP_DigestUpdate failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (EVP_DigestFinal_ex(mdctx, md_value, md_len) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    ret = 0; // Success
out:
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    return ret;
}

typedef struct {
    char *md_name;
    size_t md_size;
} blake2_case;

blake2_case blake2_cases[] = {
    {"BLAKE2s256", 32},
    {"BLAKE2b512", 64},
    {NULL, 0}
};

int main(int argc, char *argv[]) {
    int ret = 0;
    unsigned char data[] = "The quick brown fox jumps over the lazy dog";
    size_t data_len = strlen((char *)data);
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    int i;
    blake2_case *case_ptr;
    int truncate_len = 20; // Example truncate length for BLAKE2X

    for (i = 0; blake2_cases[i].md_name != NULL; i++) {
        case_ptr = &blake2_cases[i];
        printf("Testing %s...\n", case_ptr->md_name);
        if (call_digest_blake2(case_ptr->md_name, data, data_len, md_value, &md_len) != 0) {
            fprintf(stderr, "Digest computation failed for %s\n", case_ptr->md_name);
            ret = 1;
            continue;
        }
        if (md_len != case_ptr->md_size) {
            fprintf(stderr, "Unexpected digest size for %s: got %u, expected %zu\n",
                    case_ptr->md_name, md_len, case_ptr->md_size);
            ret = 1;
            continue;
        }
        printf("%s digest: ", case_ptr->md_name);
        for (unsigned int j = 0; j < md_len; j++) {
            printf("%02x", md_value[j]);
        }
        printf("\n");

    }

out:
    return ret;
}