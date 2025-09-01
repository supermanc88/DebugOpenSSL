#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int call_digest_sm3(unsigned char* msg, int msg_len, unsigned char* md, int md_len) {
    int ret = 0;
    EVP_MD *md_type = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned int out_len = 0;

    md_type = EVP_sm3();
    if (md_type == NULL) {
        printf("EVP_sm3 failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Create and initialize the context
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        printf("EVP_MD_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Initialize the digest operation
    if (EVP_DigestInit_ex(md_ctx, md_type, NULL) != 1) {
        printf("EVP_DigestInit_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Update the context with the message
    if (EVP_DigestUpdate(md_ctx, msg, msg_len) != 1) {
        printf("EVP_DigestUpdate failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Finalize the digest operation
    if (EVP_DigestFinal_ex(md_ctx, md, &out_len) != 1) {
        printf("EVP_DigestFinal_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    unsigned char msg[] = "abc";
    unsigned char md[EVP_MAX_MD_SIZE] = {0};
    int md_len = 32; // SM3 produces a 256-bit (32-byte) hash
    int msg_len = strlen((char *)msg);
    int i;
    ret = call_digest_sm3(msg, msg_len, md, md_len);
    if (ret != 0) {
        printf("call_digest_sm3 failed\n");
        goto end;
    }

    // Print the resulting hash
    printf("SM3 Digest: ");
    for (i = 0; i < md_len; i++) {
        printf("%02x", md[i]);
    }
    printf("\n");

    ret = 0;
end:
    return ret;
}