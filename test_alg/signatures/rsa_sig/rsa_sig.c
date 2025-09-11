#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509.h>


int call_rsa_genkey(int bits, unsigned long e,
                    unsigned char **priv, int *privlen,
                    unsigned char **pub, int *publen) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *p_priv = NULL;
    unsigned char *p_pub = NULL;
    size_t priv_len = 0;
    size_t pub_len = 0;
    BIGNUM *bne = NULL;

    // init context for key generation
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    if (1 != EVP_PKEY_keygen_init(ctx)) {
        fprintf(stderr, "Failed to initialize key generation: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // set bits and exponent
    if (1 != EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits)) {
        fprintf(stderr, "Failed to set RSA key size: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    
    bne = BN_new();
    if (!bne) {
        fprintf(stderr, "Failed to create BIGNUM: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (e != 65537 && e != 3) {
        e = RSA_F4; // Default to 65537
    }

    // Set public exponent
    if (BN_set_word(bne, e) != 1) {
        fprintf(stderr, "Failed to set BIGNUM value: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    
    // Note: EVP_PKEY_CTX_set_rsa_keygen_pubexp takes ownership of bne
    if (1 != EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, bne)) {
        fprintf(stderr, "Failed to set RSA public exponent: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    bne = NULL; // ownership transferred to ctx, will be freed when ctx is freed

    // generate key
    if (1 != EVP_PKEY_keygen(ctx, &pkey)) {
        fprintf(stderr, "Failed to generate RSA key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Serialize private key to DER format
    priv_len = i2d_PrivateKey(pkey, NULL);
    if (priv_len <= 0) {
        fprintf(stderr, "Failed to get private key DER length: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    
    *priv = OPENSSL_malloc(priv_len);
    if (!*priv) {
        fprintf(stderr, "Failed to allocate memory for private key\n");
        ret = -1;
        goto out;
    }
    
    p_priv = *priv;
    if (i2d_PrivateKey(pkey, &p_priv) != priv_len) {
        fprintf(stderr, "Failed to serialize private key to DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *privlen = (int)priv_len;

    // Serialize public key to DER format
    pub_len = i2d_PUBKEY(pkey, NULL);
    if (pub_len <= 0) {
        fprintf(stderr, "Failed to get public key DER length: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    
    *pub = OPENSSL_malloc(pub_len);
    if (!*pub) {
        fprintf(stderr, "Failed to allocate memory for public key\n");
        ret = -1;
        goto out;
    }
    
    p_pub = *pub;
    if (i2d_PUBKEY(pkey, &p_pub) != pub_len) {
        fprintf(stderr, "Failed to serialize public key to DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *publen = (int)pub_len;

    ret = 0;

out:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx); // This will also free bne if it was transferred
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    // Note: bne is either freed above (if not transferred) or freed when ctx is freed
    if (bne) {
        BN_free(bne);
    }
    
    // Clean up on error
    if (ret != 0) {
        if (*priv) {
            OPENSSL_free(*priv);
            *priv = NULL;
            *privlen = 0;
        }
        if (*pub) {
            OPENSSL_free(*pub);
            *pub = NULL;
            *publen = 0;
        }
    }
    
    return ret;
}


int call_rsa_sign(unsigned char *priv, int priv_len,
                  int padding_mode,
                  const char *digest,
                  unsigned char *data, int datalen,
                  unsigned char **sig, int *siglen) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    unsigned char *p = priv;
    size_t sig_len = 0;

    // Deserialize private key from DER format
    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, (const unsigned char **)&p, priv_len);
    if (!pkey) {
        fprintf(stderr, "Failed to deserialize private key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    /*
        如果是RSA_PKCS1_PSS_PADDING模式，需要设置额外的参数，比如盐长度和哈希函数
        需要使用EVP_DigestSignInit和EVP_DigestVerifyInit来处理带摘要的签名和验证

        在这里，也对PKCS1_PADDING进行了区分处理，如果digest为NULL，则表示不使用摘要，直接对数据进行PKCS1填充并签名
        如果digest不为NULL，则表示使用摘要算法进行签名，则使用EVP_DigestSign系列函数
    */
    // Distinguish between digest-based signing and raw signing
    if (digest != NULL && padding_mode != RSA_NO_PADDING) {
        // Use digest-based signing (EVP_DigestSign) for PSS or PKCS1 with digest
        md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            fprintf(stderr, "Failed to create MD context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Get the digest algorithm
        const EVP_MD *md = EVP_get_digestbyname(digest);
        if (!md) {
            fprintf(stderr, "Unknown digest algorithm: %s\n", digest);
            ret = -1;
            goto out;
        }

        // Initialize signing operation
        if (1 != EVP_DigestSignInit(md_ctx, &pkey_ctx, md, NULL, pkey)) {
            fprintf(stderr, "Failed to initialize digest signing: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Set padding mode if not default
        if (padding_mode != RSA_PKCS1_PADDING) {
            if (1 != EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode)) {
                fprintf(stderr, "Failed to set RSA padding mode: %s\n", ERR_error_string(ERR_get_error(), NULL));
                ret = -1;
                goto out;
            }

            // If using PSS padding, set additional parameters
            if (padding_mode == RSA_PKCS1_PSS_PADDING) {
                // Set salt length to digest size (recommended)
                if (1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(md))) {
                    fprintf(stderr, "Failed to set PSS salt length: %s\n", ERR_error_string(ERR_get_error(), NULL));
                    ret = -1;
                    goto out;
                }
            }
        }

        // Update with data to be signed
        if (1 != EVP_DigestSignUpdate(md_ctx, data, datalen)) {
            fprintf(stderr, "Failed to update digest signing: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Finalize and get signature length
        if (1 != EVP_DigestSignFinal(md_ctx, NULL, &sig_len)) {
            fprintf(stderr, "Failed to get signature length: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Allocate memory for signature
        *sig = OPENSSL_malloc(sig_len);
        if (!*sig) {
            fprintf(stderr, "Failed to allocate memory for signature\n");
            ret = -1;
            goto out;
        }

        // Generate signature
        if (1 != EVP_DigestSignFinal(md_ctx, *sig, &sig_len)) {
            fprintf(stderr, "Failed to generate signature: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }
        *siglen = (int)sig_len;

    } else {
        /*
            这里使用原始签名（EVP_PKEY_sign）用于RSA_NO_PADDING或PKCS1没有摘要
            需要使用EVP_PKEY_CTX_set_rsa_padding来设置填充模式
            
            如果是PKCS1_PADDING且digest为NULL，表示不使用摘要，直接对数据进行PKCS1填充并签名
            如果是RSA_NO_PADDING，表示不使用任何填充，直接对数据进行原始RSA运算，这要求输入数据的长度必须等于密钥长度
        */
        // Use raw signing (EVP_PKEY_sign) for RSA_NO_PADDING or PKCS1 without digest
        pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pkey_ctx) {
            fprintf(stderr, "Failed to create PKEY context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        if (1 != EVP_PKEY_sign_init(pkey_ctx)) {
            fprintf(stderr, "Failed to initialize signing: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Set padding mode
        if (1 != EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode)) {
            fprintf(stderr, "Failed to set RSA padding mode: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Get signature length
        if (1 != EVP_PKEY_sign(pkey_ctx, NULL, &sig_len, data, datalen)) {
            fprintf(stderr, "Failed to get signature length: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Allocate memory for signature
        *sig = OPENSSL_malloc(sig_len);
        if (!*sig) {
            fprintf(stderr, "Failed to allocate memory for signature\n");
            ret = -1;
            goto out;
        }

        // Generate signature
        if (1 != EVP_PKEY_sign(pkey_ctx, *sig, &sig_len, data, datalen)) {
            fprintf(stderr, "Failed to generate signature: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }
        *siglen = (int)sig_len;
    }

    ret = 0;

out:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (pkey_ctx && !md_ctx) { // Only free if not managed by md_ctx
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (ret != 0 && *sig) {
        OPENSSL_free(*sig);
        *sig = NULL;
        *siglen = 0;
    }
    return ret;
}

int call_rsa_verify(unsigned char *pub, int pub_len,
                    int padding_mode,
                    const char *digest,
                    unsigned char *data, int datalen,
                    unsigned char *sig, int siglen) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    unsigned char *p = pub;

    // Deserialize public key from DER format
    pkey = d2i_PUBKEY(NULL, (const unsigned char **)&p, pub_len);
    if (!pkey) {
        fprintf(stderr, "Failed to deserialize public key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Distinguish between digest-based verification and raw verification
    if (digest != NULL && padding_mode != RSA_NO_PADDING) {
        // Use digest-based verification (EVP_DigestVerify) for PSS or PKCS1 with digest
        md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            fprintf(stderr, "Failed to create MD context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Get the digest algorithm
        const EVP_MD *md = EVP_get_digestbyname(digest);
        if (!md) {
            fprintf(stderr, "Unknown digest algorithm: %s\n", digest);
            ret = -1;
            goto out;
        }

        // Initialize verification operation
        if (1 != EVP_DigestVerifyInit(md_ctx, &pkey_ctx, md, NULL, pkey)) {
            fprintf(stderr, "Failed to initialize digest verification: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Set padding mode if not default
        if (padding_mode != RSA_PKCS1_PADDING) {
            if (1 != EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode)) {
                fprintf(stderr, "Failed to set RSA padding mode: %s\n", ERR_error_string(ERR_get_error(), NULL));
                ret = -1;
                goto out;
            }

            // If using PSS padding, set additional parameters
            if (padding_mode == RSA_PKCS1_PSS_PADDING) {
                // Set salt length to digest size (recommended)
                if (1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(md))) {
                    fprintf(stderr, "Failed to set PSS salt length: %s\n", ERR_error_string(ERR_get_error(), NULL));
                    ret = -1;
                    goto out;
                }
            }
        }

        // Update with data to be verified
        if (1 != EVP_DigestVerifyUpdate(md_ctx, data, datalen)) {
            fprintf(stderr, "Failed to update digest verification: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Verify signature
        int verify_result = EVP_DigestVerifyFinal(md_ctx, sig, siglen);
        if (verify_result == 1) {
            printf("Signature verification: SUCCESS\n");
            ret = 0;
        } else if (verify_result == 0) {
            printf("Signature verification: FAILED (signature does not match)\n");
            ret = 1;  // Verification failed, but no error occurred
        } else {
            fprintf(stderr, "Signature verification: ERROR (%s)\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
        }

    } else {
        // Use raw verification (EVP_PKEY_verify) for RSA_NO_PADDING or PKCS1 without digest
        pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pkey_ctx) {
            fprintf(stderr, "Failed to create PKEY context: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        if (1 != EVP_PKEY_verify_init(pkey_ctx)) {
            fprintf(stderr, "Failed to initialize verification: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Set padding mode
        if (1 != EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode)) {
            fprintf(stderr, "Failed to set RSA padding mode: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
            goto out;
        }

        // Verify signature
        int verify_result = EVP_PKEY_verify(pkey_ctx, sig, siglen, data, datalen);
        if (verify_result == 1) {
            printf("Signature verification: SUCCESS\n");
            ret = 0;
        } else if (verify_result == 0) {
            printf("Signature verification: FAILED (signature does not match)\n");
            ret = 1;  // Verification failed, but no error occurred
        } else {
            fprintf(stderr, "Signature verification: ERROR (%s)\n", ERR_error_string(ERR_get_error(), NULL));
            ret = -1;
        }
    }

out:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (pkey_ctx && !md_ctx) { // Only free if not managed by md_ctx
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return ret;
}

int padding_modes[] = {
    RSA_PKCS1_PADDING,
    RSA_PKCS1_PSS_PADDING,
    RSA_NO_PADDING  // Include RSA_NO_PADDING for completeness
};

// if PKCS1_PSS_PADDING is used, additional parameters like salt length and hash function should be set.
char *pkcs1_pss_digest_ciphers[] = {
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512"
};


int main(int argc, char *argv[]) {
    int ret = 0;

    unsigned char *priv = NULL;
    int privlen = 0;
    unsigned char *pub = NULL;
    int publen = 0;

    {
        // Test RSA key generation
        ret = call_rsa_genkey(2048, 65537, &priv, &privlen, &pub, &publen);
        if (ret != 0) {
            fprintf(stderr, "Failed to generate RSA key pair\n");
            goto out;
        }
        
        printf("RSA key pair generated successfully!\n");
        printf("Private key (%d bytes):\n", privlen);
        for (int i = 0; i < privlen && i < 200; i++) {  // Limit output for readability
            printf("%02x", priv[i]);
            if ((i + 1) % 32 == 0) printf("\n");
        }
        if (privlen > 200) printf("...(truncated)");
        printf("\n\n");
        
        printf("Public key (%d bytes):\n", publen);
        for (int i = 0; i < publen && i < 200; i++) {  // Limit output for readability
            printf("%02x", pub[i]);
            if ((i + 1) % 32 == 0) printf("\n");
        }
        if (publen > 200) printf("...(truncated)");
        printf("\n");
    }

    {
        // Test RSA signing with different padding modes
        const char *message = "The quick brown fox jumps over the lazy dog";
        int message_len = strlen(message);
        
        printf("\n=== Testing RSA Signature with Different Modes ===\n");
        
        for (size_t i = 0; i < sizeof(padding_modes)/sizeof(padding_modes[0]); i++) {
            unsigned char *sig = NULL;
            int siglen = 0;
            unsigned char *sign_data = NULL;
            int sign_datalen = 0;
            const char *digest_alg = NULL;
            
            // Handle different padding modes
            if (padding_modes[i] == RSA_NO_PADDING) {
                // For RSA_NO_PADDING: data must be exactly the key size (256 bytes for 2048-bit key)
                sign_datalen = 256; // 2048 bits / 8 = 256 bytes
                sign_data = OPENSSL_malloc(sign_datalen);
                if (!sign_data) {
                    fprintf(stderr, "Failed to allocate memory for RSA_NO_PADDING data\n");
                    continue;
                }
                
                // Clear the buffer and copy message data
                memset(sign_data, 0, sign_datalen);
                int copy_len = (message_len < sign_datalen - 1) ? message_len : (sign_datalen - 1);
                memcpy(sign_data, message, copy_len);
                
                digest_alg = NULL; // No digest for RSA_NO_PADDING
                printf("\n--- RSA_NO_PADDING (Raw RSA operation) ---\n");
                printf("Note: RSA_NO_PADDING requires input length = key size (%d bytes)\n", sign_datalen);
                
            } else if (padding_modes[i] == RSA_PKCS1_PADDING) {
                // Test both with and without digest
                printf("\n--- RSA_PKCS1_PADDING with SHA256 digest ---\n");
                sign_data = (unsigned char *)message;
                sign_datalen = message_len;
                digest_alg = "SHA256";
                
            } else if (padding_modes[i] == RSA_PKCS1_PSS_PADDING) {
                printf("\n--- RSA_PKCS1_PSS_PADDING with SHA256 digest ---\n");
                sign_data = (unsigned char *)message;
                sign_datalen = message_len;
                digest_alg = "SHA256";
            }
            
            ret = call_rsa_sign(priv, privlen, padding_modes[i],
                                digest_alg,
                                sign_data, sign_datalen,
                                &sig, &siglen);
            if (ret != 0) {
                fprintf(stderr, "Failed to sign message with padding mode %d\n", padding_modes[i]);
                if (padding_modes[i] == RSA_NO_PADDING) {
                    OPENSSL_free(sign_data);
                }
                continue;
            }
            
            printf("Message signed successfully with padding mode %d!\n", padding_modes[i]);
            printf("Signature (%d bytes):\n", siglen);
            for (int j = 0; j < siglen && j < 64; j++) {  // Show first 64 bytes
                printf("%02x", sig[j]);
                if ((j + 1) % 32 == 0) printf("\n");
            }
            if (siglen > 64) printf("...(truncated)");
            printf("\n\n");
            
            // Test signature verification
            printf("Testing signature verification...\n");
            int verify_ret = call_rsa_verify(pub, publen, padding_modes[i],
                                           digest_alg,
                                           sign_data, sign_datalen,
                                           sig, siglen);
            if (verify_ret == 0) {
                printf("✓ Signature verification passed for padding mode %d\n", padding_modes[i]);
            } else if (verify_ret == 1) {
                printf("✗ Signature verification failed for padding mode %d\n", padding_modes[i]);
            } else {
                printf("✗ Signature verification error for padding mode %d\n", padding_modes[i]);
            }
            
            // Clean up
            OPENSSL_free(sig);
            if (padding_modes[i] == RSA_NO_PADDING) {
                OPENSSL_free(sign_data);
            }

            printf("\n----------------------------------------\n");
        }
        
        {
            // Additional test: RSA_PKCS1_PADDING without digest (raw PKCS1 padding)
            printf("\n--- RSA_PKCS1_PADDING without digest (raw padding) ---\n");
            printf("Note: This demonstrates raw PKCS1 padding without hash\n");
            
            unsigned char *sig = NULL;
            int siglen = 0;
            ret = call_rsa_sign(priv, privlen, RSA_PKCS1_PADDING,
                                NULL, // No digest - raw PKCS1 padding
                                (unsigned char *)message, message_len,
                                &sig, &siglen);
            if (ret == 0) {
                printf("Raw PKCS1 padding signature generated successfully!\n");
                printf("Signature (%d bytes): ", siglen);
                for (int j = 0; j < siglen && j < 32; j++) {
                    printf("%02x", sig[j]);
                }
                printf("...\n");
                
                // Verify raw PKCS1 signature
                printf("Verifying raw PKCS1 signature...\n");
                int verify_ret = call_rsa_verify(pub, publen, RSA_PKCS1_PADDING,
                                            NULL,
                                            (unsigned char *)message, message_len,
                                            sig, siglen);
                if (verify_ret == 0) {
                    printf("✓ Raw PKCS1 signature verification passed\n");
                } else {
                    printf("✗ Raw PKCS1 signature verification failed\n");
                }
                
                OPENSSL_free(sig);
            } else {
                fprintf(stderr, "Failed to sign with raw PKCS1 padding\n");
            }
        }
    }

    {
        // Test signature verification with tampered data
        printf("\n=== Testing Signature Verification with Tampered Data ===\n");
        const char *original_message = "The quick brown fox jumps over the lazy dog";
        const char *tampered_message = "The quick brown fox jumps over the lazy cat";
        int original_len = strlen(original_message);
        int tampered_len = strlen(tampered_message);
        
        unsigned char *sig = NULL;
        int siglen = 0;
        
        // Sign the original message
        ret = call_rsa_sign(priv, privlen, RSA_PKCS1_PADDING,
                            "SHA256",
                            (unsigned char *)original_message, original_len,
                            &sig, &siglen);
        if (ret != 0) {
            fprintf(stderr, "Failed to sign original message\n");
            goto out;
        }
        
        printf("Original message: '%s'\n", original_message);
        printf("Tampered message: '%s'\n", tampered_message);
        
        // Verify with original message (should succeed)
        printf("\nVerifying signature with original message:\n");
        call_rsa_verify(pub, publen, RSA_PKCS1_PADDING,
                       "SHA256",
                       (unsigned char *)original_message, original_len,
                       sig, siglen);
        
        // Verify with tampered message (should fail)
        printf("\nVerifying signature with tampered message:\n");
        call_rsa_verify(pub, publen, RSA_PKCS1_PADDING,
                       "SHA256",
                       (unsigned char *)tampered_message, tampered_len,
                       sig, siglen);
        
        OPENSSL_free(sig);
    }

    {
        // Dedicated test for RSA_NO_PADDING with proper data preparation
        printf("\n=== Dedicated RSA_NO_PADDING Test ===\n");
        printf("Demonstrating RSA_NO_PADDING with manually prepared data\n");
        
        const char *test_message = "Hello RSA_NO_PADDING";
        int test_message_len = strlen(test_message);
        
        // For RSA_NO_PADDING, create data that's exactly the key size
        int key_size = 256; // 2048 bits / 8 = 256 bytes
        unsigned char *padded_data = OPENSSL_malloc(key_size);
        if (!padded_data) {
            fprintf(stderr, "Failed to allocate memory for padded data\n");
            goto out;
        }
        
        // Create a simple manual padding (this is just for demonstration)
        // In real applications, you'd use proper padding schemes
        memset(padded_data, 0x00, key_size);
        padded_data[0] = 0x00;  // Leading zero
        padded_data[1] = 0x01;  // Block type for private key operation
        
        // Fill with padding bytes (0xFF for PKCS#1 type 1)
        for (int i = 2; i < key_size - test_message_len - 1; i++) {
            padded_data[i] = 0xFF;
        }
        
        padded_data[key_size - test_message_len - 1] = 0x00; // Separator
        memcpy(padded_data + key_size - test_message_len, test_message, test_message_len);
        
        printf("Manual padding created (%d bytes):\n", key_size);
        for (int i = 0; i < 32; i++) { // Show first 32 bytes
            printf("%02x", padded_data[i]);
        }
        printf("...");
        for (int i = key_size - 16; i < key_size; i++) { // Show last 16 bytes
            printf("%02x", padded_data[i]);
        }
        printf("\n\n");
        
        unsigned char *sig = NULL;
        int siglen = 0;
        
        ret = call_rsa_sign(priv, privlen, RSA_NO_PADDING,
                            NULL, // No digest for RSA_NO_PADDING
                            padded_data, key_size,
                            &sig, &siglen);
        
        if (ret == 0) {
            printf("RSA_NO_PADDING signature generated successfully (%d bytes)\n", siglen);
            
            // Verify the signature
            printf("Verifying RSA_NO_PADDING signature...\n");
            int verify_ret = call_rsa_verify(pub, publen, RSA_NO_PADDING,
                                           NULL,
                                           padded_data, key_size,
                                           sig, siglen);
            if (verify_ret == 0) {
                printf("✓ RSA_NO_PADDING signature verification passed\n");
            } else {
                printf("✗ RSA_NO_PADDING signature verification failed\n");
            }
            
            OPENSSL_free(sig);
        } else {
            fprintf(stderr, "Failed to sign with RSA_NO_PADDING\n");
        }
        
        OPENSSL_free(padded_data);
    }


out:
    // Clean up allocated memory to prevent memory leaks
    if (priv) {
        OPENSSL_free(priv);
        priv = NULL;
    }
    if (pub) {
        OPENSSL_free(pub);
        pub = NULL;
    }
    
    return ret;
}