#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/err.h>

int old_call_cmac() {
    int ret = 0;
    EVP_CIPHER *cipher = NULL;
    CMAC_CTX *cmac_ctx = NULL;
    unsigned char key[32] = {0}; // SM4 key size is 16 bytes
    int key_len = sizeof(key);
    unsigned char data[] = "Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!"; // Example data to be processed
    size_t data_len = sizeof(data) - 1; // Exclude null terminator
    unsigned char mac[EVP_MAX_MD_SIZE];
    size_t mac_len = 0;

    // allocate cmac context
    cmac_ctx = CMAC_CTX_new();
    if (!cmac_ctx) {
        fprintf(stderr, "Failed to create CMAC context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // get the cipher
    cipher = EVP_aes_256_cbc();   // EVP_sm4_cbc();  EVP_aes_128_cbc();  EVP_aes_192_cbc(); EVP_aes_256_cbc();
    if (!cipher) {
        fprintf(stderr, "Failed to get cipher: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // initialize the CMAC context with the cipher
    if (!CMAC_Init(cmac_ctx, key, key_len, cipher, NULL)) {
        fprintf(stderr, "Failed to initialize CMAC context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // update the CMAC context with the data
    if (!CMAC_Update(cmac_ctx, data, data_len)) {
        fprintf(stderr, "Failed to update CMAC context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // finalize the CMAC computation
    if (!CMAC_Final(cmac_ctx, mac, &mac_len)) {
        fprintf(stderr, "Failed to finalize CMAC computation: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    // print the resulting MAC
    printf("SM4 CMAC: ");
    for (size_t i = 0; i < mac_len; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");
    out:
        if (cmac_ctx) {
            CMAC_CTX_free(cmac_ctx);
        }
    return ret;
}

int new_call_cmac() {
    int ret = 0;
    EVP_MAC_CTX *ctx = NULL;
    unsigned char key[16] = {0}; // SM4 key size is 16 bytes
    unsigned char data[] = "Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!"; // Example data to be processed
    size_t data_len = sizeof(data) - 1; // Exclude null terminator
    unsigned char mac[EVP_MAX_MD_SIZE];
    int mac_len = 0;
    OSSL_PARAM params[2];

    EVP_MAC *mac_alg = NULL;
    // load the SM4-CMAC algorithm
    mac_alg = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac_alg) {
        fprintf(stderr, "Failed to fetch SM4-CMAC algorithm: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    // allocate cipher context
    ctx = EVP_MAC_CTX_new(mac_alg);
    if (!ctx) {
        fprintf(stderr, "Failed to create MAC context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // set the parameters for the MAC context
    params[0] = OSSL_PARAM_construct_utf8_string("cipher", "SM4", 0);
    params[1] = OSSL_PARAM_construct_end();

    // initialize the MAC context with the SM4 cipher
    if (EVP_MAC_init(ctx, key, sizeof(key), params) <= 0) {
        fprintf(stderr, "Failed to initialize MAC context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    // update the MAC context with the data
    if (EVP_MAC_update(ctx, data, data_len) <= 0) {
        fprintf(stderr, "Failed to update MAC context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    // finalize the MAC computation
    if (EVP_MAC_final(ctx, mac, &mac_len, sizeof(mac)) <= 0) {
        fprintf(stderr, "Failed to finalize MAC computation: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // print the resulting MAC
    printf("SM4 CMAC: ");
    for (int i = 0; i < mac_len; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");

out:
    if (ctx) {
        EVP_MAC_CTX_free(ctx);
    }
    return ret;
}

int ecb_block_cbc(unsigned char *key, unsigned char *iv, unsigned char *in_data, unsigned int in_len, unsigned char *out_data, unsigned int *out_len) {
    int ret = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int tmp_len = 0;

    cipher = EVP_aes_256_cbc(); // EVP_sm4_cbc();  EVP_aes_128_cbc();  EVP_aes_192_cbc(); EVP_aes_256_cbc();
    if (!cipher) {
        fprintf(stderr, "Failed to get SM4 cipher: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    EVP_CIPHER_CTX_init(ctx);
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) <= 0) {
        fprintf(stderr, "Failed to initialize encryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Set padding to 0 for block mode
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0) {
        fprintf(stderr, "Failed to set padding: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (EVP_EncryptUpdate(ctx, out_data, &tmp_len, in_data, in_len) <= 0) {
        fprintf(stderr, "Encryption failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *out_len = tmp_len;

    if (EVP_EncryptFinal_ex(ctx, out_data + tmp_len, &tmp_len) <= 0) {
        fprintf(stderr, "Final encryption step failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    *out_len += tmp_len;

out:
    if (!ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}

static void make_kn(unsigned char *k1, const unsigned char *l, int bl)
{
    int i;
    unsigned char c = l[0], carry = c >> 7, cnext;

    /* Shift block to left, including carry */
    for (i = 0; i < bl - 1; i++, c = cnext)
        k1[i] = (c << 1) | ((cnext = l[i + 1]) >> 7);

    /* If MSB set fixup with R */
    k1[i] = (c << 1) ^ ((0 - carry) & (bl == 16 ? 0x87 : 0x1b));
}

#define SM4_BLOCK_SIZE 16

int my_cmac() {
    int ret = 0;
    unsigned char key[32] = {0}; // SM4 key size is 16 bytes
    unsigned char data[] = "Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!"; // Example data to be processed
    size_t data_len = sizeof(data) - 1; // Exclude null terminator
    unsigned char mac[EVP_MAX_MD_SIZE];
    int mac_len = 0;
    int i = 0;
    unsigned char *p_last = NULL;

    unsigned char k1[16] = {0}, k2[16] = {0};
    unsigned char zeor_iv[16] = {0};
    unsigned char zeor_data[16] = {0};

    unsigned char L[16] = {0};
    unsigned char *out_data = NULL;
    unsigned int out_len = 0;

    // step 1: Encrypt the zero block to get L
    if (ecb_block_cbc(key, zeor_iv, zeor_data, sizeof(L), L, &mac_len) < 0) {
        fprintf(stderr, "Failed to encrypt zero block: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // step 2: Generate k1 and k2 from L
    make_kn(k1, L, SM4_BLOCK_SIZE);
    make_kn(k2, k1, SM4_BLOCK_SIZE);

    // step 3: Process the input data
    int blocks = (data_len + SM4_BLOCK_SIZE - 1) / SM4_BLOCK_SIZE;
    unsigned char *p = malloc(blocks * SM4_BLOCK_SIZE);
    if (!p) {
        fprintf(stderr, "Memory allocation failed: %s\n", strerror(errno));
        ret = -1;
        goto out;
    }

    if (data_len % SM4_BLOCK_SIZE == 0) {
        // If data length is a multiple of block size, the last block xor k1
        memcpy(p, data, data_len);
        p_last = p + (blocks - 1) * SM4_BLOCK_SIZE;
        for (i = 0; i < SM4_BLOCK_SIZE; i++) {
            p_last[i] ^= k1[i];
        }
    } else {
        // If not, pad the last block  and xor with k2
        memcpy(p, data, data_len);
        p_last = p + (blocks - 1) * SM4_BLOCK_SIZE;
        int last_block_size = data_len % SM4_BLOCK_SIZE;
        p_last[last_block_size] = 0x80; // Padding with 0x80
        for (i = last_block_size + 1; i < SM4_BLOCK_SIZE; i++) {
            p_last[i] = 0x00; // Padding with 0x00
        }
        for (i = 0; i < SM4_BLOCK_SIZE; i++) {
            p_last[i] ^= k2[i];
        }
    }

    // step 4: Encrypt the blocks
    memset(zeor_iv, 0, sizeof(zeor_iv)); // Initialize IV to zero
    out_data = malloc(blocks * SM4_BLOCK_SIZE);
    if (!out_data) {
        fprintf(stderr, "Memory allocation for output data failed: %s\n", strerror(errno));
        ret = -1;
        goto out;
    }
    if (ecb_block_cbc(key, zeor_iv, p, blocks * SM4_BLOCK_SIZE, out_data, &out_len) < 0) {
        fprintf(stderr, "Failed to encrypt data blocks: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // step 5: The last block of the output is the CMAC
    if (out_len < SM4_BLOCK_SIZE) {
        fprintf(stderr, "Output length is less than block size: %d\n", out_len);
        ret = -1;
        goto out;
    }
    memcpy(mac, out_data + (blocks - 1) * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);

    // print the resulting MAC
    printf("SM4 CMAC: ");
    for (i = 0; i < SM4_BLOCK_SIZE; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");

out:
    if (p) {
        free(p);
    }
    return ret;
}


int main(int argc, char *argv[]) {
    int ret = 0;
    old_call_cmac();
    // new_call_cmac();
    my_cmac();
    return ret;
}