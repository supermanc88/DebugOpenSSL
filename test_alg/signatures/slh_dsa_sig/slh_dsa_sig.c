#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>

/* Function to check OpenSSL version and SLH-DSA support */
int check_slh_dsa_support(void)
{
    printf("OpenSSL Version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("OpenSSL Build Info: %s\n", OpenSSL_version(OPENSSL_BUILT_ON));
    
    /* Check if we have at least OpenSSL 3.5.0 for SLH-DSA support */
    if (OPENSSL_VERSION_NUMBER < 0x30500000L) {
        printf("WARNING: OpenSSL version may be too old for SLH-DSA support.\n");
        printf("SLH-DSA requires OpenSSL 3.5.0 or later.\n");
        printf("Current version: 0x%08lx\n", OPENSSL_VERSION_NUMBER);
        return -1;
    }
    
    /* Try to create a context for SLH-DSA-SHA2-128s to test support */
    EVP_PKEY_CTX *test_ctx = EVP_PKEY_CTX_new_from_name(NULL, "SLH-DSA-SHA2-128s", NULL);
    if (!test_ctx) {
        printf("ERROR: SLH-DSA-SHA2-128s is not supported in this OpenSSL build.\n");
        printf("Please ensure you have a FIPS-enabled or post-quantum-enabled OpenSSL build.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    EVP_PKEY_CTX_free(test_ctx);
    printf("✓ SLH-DSA support confirmed!\n\n");
    return 0;
}

int call_slh_dsa_sig_gen_key(const char *alg_name,
                             unsigned char **pub_key, int *pub_key_len,
                             unsigned char **priv_key, int *priv_key_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = -1;
    size_t pub_len = 0, priv_len = 0;

    /* Create context for key generation */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create context for %s\n", alg_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Initialize key generation */
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize key generation for %s\n", alg_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Generate key pair */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate key pair for %s\n", alg_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Get public key */
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len) != 1) {
        fprintf(stderr, "Failed to get public key length\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    *pub_key = (unsigned char *)malloc(pub_len);
    if (!*pub_key) {
        fprintf(stderr, "Failed to allocate memory for public key\n");
        goto cleanup;
    }

    if (EVP_PKEY_get_raw_public_key(pkey, *pub_key, &pub_len) != 1) {
        fprintf(stderr, "Failed to get raw public key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    *pub_key_len = (int)pub_len;

    /* Get private key */
    if (EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len) != 1) {
        fprintf(stderr, "Failed to get private key length\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    *priv_key = (unsigned char *)malloc(priv_len);
    if (!*priv_key) {
        fprintf(stderr, "Failed to allocate memory for private key\n");
        goto cleanup;
    }

    if (EVP_PKEY_get_raw_private_key(pkey, *priv_key, &priv_len) != 1) {
        fprintf(stderr, "Failed to get raw private key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    *priv_key_len = (int)priv_len;

    printf("Key generation successful for %s:\n", alg_name);
    printf("  Public key length: %d bytes\n", *pub_key_len);
    printf("  Private key length: %d bytes\n", *priv_key_len);

    ret = 0;

cleanup:
    if (ret != 0) {
        if (*pub_key) {
            free(*pub_key);
            *pub_key = NULL;
        }
        if (*priv_key) {
            free(*priv_key);
            *priv_key = NULL;
        }
    }
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

int call_slh_dsa_sig_sign(const char *alg_name,
                          const unsigned char *priv_key, int priv_key_len,
                          const unsigned char *msg, int msg_len,
                          unsigned char **sig, int *sig_len)
{
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t signature_len = 0;
    int ret = -1;

    /* Create PKEY from raw private key */
    pkey = EVP_PKEY_new_raw_private_key_ex(NULL, alg_name, NULL, priv_key, priv_key_len);
    if (!pkey) {
        fprintf(stderr, "Failed to create PKEY from raw private key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Create message digest context for signing */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "Failed to create message digest context\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Initialize signing with no digest (SLH-DSA signs raw messages) */
    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        fprintf(stderr, "Failed to initialize digest signing\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Get signature length */
    if (EVP_DigestSign(md_ctx, NULL, &signature_len, msg, msg_len) <= 0) {
        fprintf(stderr, "Failed to get signature length\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Allocate memory for signature */
    *sig = (unsigned char *)malloc(signature_len);
    if (!*sig) {
        fprintf(stderr, "Failed to allocate memory for signature\n");
        goto cleanup;
    }

    /* Generate signature */
    if (EVP_DigestSign(md_ctx, *sig, &signature_len, msg, msg_len) <= 0) {
        fprintf(stderr, "Failed to generate signature\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    *sig_len = (int)signature_len;

    printf("Signature generation successful for %s:\n", alg_name);
    printf("  Message length: %d bytes\n", msg_len);
    printf("  Signature length: %d bytes\n", *sig_len);

    ret = 0;

cleanup:
    if (ret != 0 && *sig) {
        free(*sig);
        *sig = NULL;
        *sig_len = 0;
    }
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    return ret;
}

int call_slh_dsa_sig_verify(const char *alg_name,
                            const unsigned char *pub_key, int pub_key_len,
                            const unsigned char *msg, int msg_len,
                            const unsigned char *sig, int sig_len)
{
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = -1;

    /* Create PKEY from raw public key */
    pkey = EVP_PKEY_new_raw_public_key_ex(NULL, alg_name, NULL, pub_key, pub_key_len);
    if (!pkey) {
        fprintf(stderr, "Failed to create PKEY from raw public key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Create message digest context for verification */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "Failed to create message digest context\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Initialize verification with no digest (SLH-DSA verifies raw messages) */
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        fprintf(stderr, "Failed to initialize digest verification\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Verify signature */
    int verify_result = EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len);
    if (verify_result == 1) {
        printf("Signature verification successful for %s:\n", alg_name);
        printf("  Message length: %d bytes\n", msg_len);
        printf("  Signature length: %d bytes\n", sig_len);
        printf("  Verification result: VALID\n");
        ret = 0;
    } else if (verify_result == 0) {
        printf("Signature verification failed: INVALID signature\n");
        ret = 1;  /* Invalid signature */
    } else {
        fprintf(stderr, "Signature verification error\n");
        ERR_print_errors_fp(stderr);
        ret = -1;  /* Error during verification */
    }

cleanup:
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    return ret;
}

/* Helper function to print hexadecimal data */
void print_hex(const char *label, const unsigned char *data, int len, int max_display)
{
    printf("%s (%d bytes): ", label, len);
    int display_len = (max_display > 0 && len > max_display) ? max_display : len;
    
    for (int i = 0; i < display_len; i++) {
        printf("%02x", data[i]);
    }
    if (len > display_len) {
        printf("... (truncated, showing first %d bytes)", display_len);
    }
    printf("\n");
}

/* Test function for SLH-DSA algorithms */
int test_slh_dsa_algorithm(const char *alg_name)
{
    printf("\n========================================\n");
    printf("Testing SLH-DSA algorithm: %s\n", alg_name);
    printf("========================================\n");

    unsigned char *pub_key = NULL, *priv_key = NULL;
    int pub_key_len = 0, priv_key_len = 0;
    unsigned char *signature = NULL;
    int sig_len = 0;
    int ret = -1;

    /* Test message */
    const char *test_message = "Hello, this is a test message for SLH-DSA signature!";
    int msg_len = strlen(test_message);

    printf("Test message: \"%s\" (%d bytes)\n\n", test_message, msg_len);

    /* Step 1: Generate key pair */
    printf("Step 1: Generating key pair...\n");
    if (call_slh_dsa_sig_gen_key(alg_name, &pub_key, &pub_key_len, &priv_key, &priv_key_len) != 0) {
        printf("Key generation failed!\n");
        goto cleanup;
    }

    /* Display key information */
    print_hex("Public key", pub_key, pub_key_len, 32);
    print_hex("Private key", priv_key, priv_key_len, 32);
    printf("\n");

    /* Step 2: Sign the message */
    printf("Step 2: Signing message...\n");
    if (call_slh_dsa_sig_sign(alg_name, priv_key, priv_key_len, 
                              (const unsigned char *)test_message, msg_len,
                              &signature, &sig_len) != 0) {
        printf("Signature generation failed!\n");
        goto cleanup;
    }

    /* Display signature */
    print_hex("Signature", signature, sig_len, 64);
    printf("\n");

    /* Step 3: Verify the signature */
    printf("Step 3: Verifying signature...\n");
    int verify_result = call_slh_dsa_sig_verify(alg_name, pub_key, pub_key_len,
                                               (const unsigned char *)test_message, msg_len,
                                               signature, sig_len);
    
    if (verify_result == 0) {
        printf("✓ Signature verification PASSED!\n");
        ret = 0;
    } else if (verify_result == 1) {
        printf("✗ Signature verification FAILED (invalid signature)!\n");
        ret = 1;
    } else {
        printf("✗ Signature verification ERROR!\n");
        ret = -1;
    }

    /* Step 4: Test with modified message (should fail) */
    printf("\nStep 4: Testing with modified message (should fail)...\n");
    const char *modified_message = "Hello, this is a MODIFIED test message for SLH-DSA signature!";
    int modified_msg_len = strlen(modified_message);
    
    int verify_modified = call_slh_dsa_sig_verify(alg_name, pub_key, pub_key_len,
                                                 (const unsigned char *)modified_message, modified_msg_len,
                                                 signature, sig_len);
    
    if (verify_modified == 1) {
        printf("✓ Modified message verification correctly FAILED (as expected)\n");
    } else if (verify_modified == 0) {
        printf("✗ ERROR: Modified message verification unexpectedly PASSED!\n");
        ret = -1;
    } else {
        printf("✗ ERROR during modified message verification\n");
        ret = -1;
    }

cleanup:
    if (pub_key) free(pub_key);
    if (priv_key) free(priv_key);
    if (signature) free(signature);
    
    printf("\n========================================\n");
    printf("Test result for %s: %s\n", alg_name, (ret == 0) ? "PASSED" : "FAILED");
    printf("========================================\n");
    
    return ret;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int overall_result = 0;

    printf("SLH-DSA (SPHINCS+ Post-Quantum Digital Signature Algorithm) Test Program\n");
    printf("========================================================================\n");
    printf("This program demonstrates the SLH-DSA signature algorithms supported in OpenSSL 3.5+\n");
    printf("SLH-DSA is based on the SPHINCS+ algorithm family.\n\n");

    /* Initialize OpenSSL */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* Check SLH-DSA support */
    printf("Checking OpenSSL version and SLH-DSA support...\n");
    if (check_slh_dsa_support() != 0) {
        printf("SLH-DSA support check failed. Exiting...\n");
        ret = -1;
        goto out;
    }

    /* Define SLH-DSA algorithms to test (selecting representative ones) */
    const char *slh_dsa_algorithms[] = {
        "SLH-DSA-SHA2-128s",    /* SHA2 variant, 128-bit security, small signatures */
        "SLH-DSA-SHA2-128f",    /* SHA2 variant, 128-bit security, fast signing */
        "SLH-DSA-SHAKE-128s",   /* SHAKE variant, 128-bit security, small signatures */
        "SLH-DSA-SHA2-192s",    /* SHA2 variant, 192-bit security, small signatures */
        "SLH-DSA-SHA2-256s",    /* SHA2 variant, 256-bit security, small signatures */
        NULL
    };

    /* Test each algorithm */
    for (int i = 0; slh_dsa_algorithms[i] != NULL; i++) {
        printf("\nTesting %s...\n", slh_dsa_algorithms[i]);
        if (test_slh_dsa_algorithm(slh_dsa_algorithms[i]) != 0) {
            printf("%s test failed!\n", slh_dsa_algorithms[i]);
            overall_result = -1;
        }
    }

    /* Summary */
    printf("\n========================================================================\n");
    printf("OVERALL TEST SUMMARY\n");
    printf("========================================================================\n");
    if (overall_result == 0) {
        printf("✓ ALL SLH-DSA tests PASSED successfully!\n");
        printf("All tested SLH-DSA variants are working correctly.\n");
    } else {
        printf("✗ Some SLH-DSA tests FAILED!\n");
        printf("Please check the error messages above.\n");
    }
    printf("========================================================================\n");

    ret = overall_result;

out:
    /* Cleanup OpenSSL */
    EVP_cleanup();
    ERR_free_strings();
    
    return ret;
}