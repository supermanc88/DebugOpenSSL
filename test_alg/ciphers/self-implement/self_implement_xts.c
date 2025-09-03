#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>


/**
 *
 * @param enc 0 for decrypt, 1 for encrypt
 * @param key input key, must be 16 bytes for SM4
 * @param iv initialization vector, not used in ECB mode
 * @param in input data, must be multiple of 16 bytes
 * @param inlen length of input data
 * @param out output buffer, must be at least inlen bytes
 * @param outlen length of output data
 * @return 0 on success, -1 on failure
 */
int block_cipher(int enc,
                 unsigned char *key, unsigned char *iv,
                 unsigned char *in, size_t inlen,
                 unsigned char *out, size_t *outlen) {
    int ret = 0;
    // use SM4 in ECB mode as the underlying block cipher
    const EVP_CIPHER *cipher = EVP_sm4_ecb();
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;
    unsigned char *out_ptr = NULL;
    if (inlen % 16 != 0) {
        fprintf(stderr, "Input length must be multiple of 16 bytes\n");
        ret = -1;
        goto out;
    }

    // malloc output buffer
    out_ptr = (unsigned char *)malloc(inlen);
    if (!out_ptr) {
        fprintf(stderr, "Failed to allocate memory for output buffer: %s\n", strerror(errno));
        ret = -1;
        goto out;
    }
    memset(out_ptr, 0, inlen);

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Initialize the encryption or decryption operation
    if (1 != EVP_CipherInit_ex(ctx, cipher, NULL, key, NULL, enc)) {
        fprintf(stderr, "EVP_CipherInit_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Provide the message to be encrypted or decrypted, and obtain the output
    if (1 != EVP_CipherUpdate(ctx, out_ptr, &len, in, inlen)) {
        fprintf(stderr, "EVP_CipherUpdate failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ciphertext_len = len;

    // Finalize the encryption or decryption
    if (1 != EVP_CipherFinal_ex(ctx, out_ptr + len, &len)) {
        fprintf(stderr, "EVP_CipherFinal_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ciphertext_len += len;
    *outlen = ciphertext_len;

    memcpy(out, out_ptr, ciphertext_len);
    free(out_ptr);
    out_ptr = NULL;

    ret = 0;

out:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (out_ptr) {
        free(out_ptr);
    }
    return ret;
}

int block_cipher_decrypt(
    unsigned char *key, unsigned char *iv,
    unsigned char *in, size_t inlen,
    unsigned char *out, size_t *outlen) {
    return block_cipher(0, key, iv, in, inlen, out, outlen);
}

int block_cipher_encrypt(
    unsigned char *key, unsigned char *iv,
    unsigned char *in, size_t inlen,
    unsigned char *out, size_t *outlen) {
    return block_cipher(1, key, iv, in, inlen, out, outlen);
}

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef u64 u64_a1;

#    define BSWAP8(x) ({ u64 ret_;                       \
asm ("rev %0,%1"                \
: "=r"(ret_) : "r"(x)); ret_;   })

#define MBEDTLS_IS_BIG_ENDIAN 0

static inline uint64_t mbedtls_get_unaligned_uint64(const void *p)
{
    uint64_t r;
    memcpy(&r, p, sizeof(r));
    return r;
}

static inline void mbedtls_put_unaligned_uint64(void *p, uint64_t x)
{
    memcpy(p, &x, sizeof(x));
}


#if defined(__clang__) && defined(__has_builtin)
#if __has_builtin(__builtin_bswap16) && !defined(MBEDTLS_BSWAP16)
#define MBEDTLS_BSWAP16 __builtin_bswap16
#endif /* __has_builtin(__builtin_bswap16) */
#if __has_builtin(__builtin_bswap32) && !defined(MBEDTLS_BSWAP32)
#define MBEDTLS_BSWAP32 __builtin_bswap32
#endif /* __has_builtin(__builtin_bswap32) */
#if __has_builtin(__builtin_bswap64) && !defined(MBEDTLS_BSWAP64)
#define MBEDTLS_BSWAP64 __builtin_bswap64
#endif /* __has_builtin(__builtin_bswap64) */
#endif /* defined(__clang__) && defined(__has_builtin) */

#if !defined(MBEDTLS_BSWAP16)
static inline uint16_t mbedtls_bswap16(uint16_t x)
{
    return
        (x & 0x00ff) << 8 |
        (x & 0xff00) >> 8;
}
#define MBEDTLS_BSWAP16 mbedtls_bswap16
#endif /* !defined(MBEDTLS_BSWAP16) */

#if !defined(MBEDTLS_BSWAP32)
static inline uint32_t mbedtls_bswap32(uint32_t x)
{
    return
        (x & 0x000000ff) << 24 |
        (x & 0x0000ff00) <<  8 |
        (x & 0x00ff0000) >>  8 |
        (x & 0xff000000) >> 24;
}
#define MBEDTLS_BSWAP32 mbedtls_bswap32
#endif /* !defined(MBEDTLS_BSWAP32) */

#if !defined(MBEDTLS_BSWAP64)
static inline uint64_t mbedtls_bswap64(uint64_t x)
{
    return
        (x & 0x00000000000000ffULL) << 56 |
        (x & 0x000000000000ff00ULL) << 40 |
        (x & 0x0000000000ff0000ULL) << 24 |
        (x & 0x00000000ff000000ULL) <<  8 |
        (x & 0x000000ff00000000ULL) >>  8 |
        (x & 0x0000ff0000000000ULL) >> 24 |
        (x & 0x00ff000000000000ULL) >> 40 |
        (x & 0xff00000000000000ULL) >> 56;
}
#define MBEDTLS_BSWAP64 mbedtls_bswap64
#endif /* !defined(MBEDTLS_BSWAP64) */




#define MBEDTLS_GET_UINT64_LE(data, offset)                                \
((MBEDTLS_IS_BIG_ENDIAN)                                               \
? MBEDTLS_BSWAP64(mbedtls_get_unaligned_uint64((data) + (offset))) \
: mbedtls_get_unaligned_uint64((data) + (offset))                  \
)

#define MBEDTLS_PUT_UINT64_LE(n, data, offset)                                   \
{                                                                            \
    if (MBEDTLS_IS_BIG_ENDIAN)                                               \
    {                                                                        \
        mbedtls_put_unaligned_uint64((data) + (offset), MBEDTLS_BSWAP64((uint64_t) (n))); \
    }                                                                        \
    else                                                                     \
    {                                                                        \
        mbedtls_put_unaligned_uint64((data) + (offset), (uint64_t) (n));     \
    }                                                                        \
}


static inline void mbedtls_gf128mul_x_ble(unsigned char r[16],
                                          const unsigned char x[16])
{
    uint64_t a, b, ra, rb;

    a = MBEDTLS_GET_UINT64_LE(x, 0);
    b = MBEDTLS_GET_UINT64_LE(x, 8);

    ra = (a << 1)  ^ 0x0087 >> (8 - ((b >> 63) << 3));
    rb = (a >> 63) | (b << 1);

    MBEDTLS_PUT_UINT64_LE(ra, r, 0);
    MBEDTLS_PUT_UINT64_LE(rb, r, 8);
}


int xts_encrypt(
    unsigned char *key1, unsigned char *key2,
    unsigned char *iv,
    unsigned char *in, size_t inlen,
    unsigned char *out, size_t *outlen) {
    int ret = 0;

    *outlen = inlen;
/**
    #define XTS_SET_KEY_FN(fn_set_enc_key, fn_set_dec_key,                         \
                           fn_block_enc, fn_block_dec,                             \
                           fn_stream, fn_stream_gb) {                              \
        size_t bytes = keylen / 2;                                                 \
                                                                                   \
        if (ctx->enc) {                                                            \
            fn_set_enc_key(key, &xctx->ks1.ks);                                    \
            xctx->xts.block1 = (block128_f)fn_block_enc;                           \
        } else {                                                                   \
            fn_set_dec_key(key, &xctx->ks1.ks);                                    \
            xctx->xts.block1 = (block128_f)fn_block_dec;                           \
        }                                                                          \
        fn_set_enc_key(key + bytes, &xctx->ks2.ks);                                \
        xctx->xts.block2 = (block128_f)fn_block_enc;                               \
        xctx->xts.key1 = &xctx->ks1;                                               \
        xctx->xts.key2 = &xctx->ks2;                                               \
        xctx->stream = fn_stream;                                                  \
        xctx->stream_gb = fn_stream_gb;                                            \
    }
*/
    // 上述代码中的 key1 和 key2 已经是轮密钥了

    union {
        u64 u[2];
        u32 d[4];
        u8 c[16];
    } tweak, scratch;
    unsigned int i;

    // 判断输入长度是否小于16字节
    if (inlen < 16) {
        fprintf(stderr, "Input length must be at least 16 bytes\n");
        ret = -1;
        goto out;
    }

    // 使用iv当成作初始tweak值
    memcpy(tweak.c, iv, 16);

    // 使用key2加密tweak值
    size_t tweak_len = 0;
    if (block_cipher_encrypt(key2, NULL, tweak.c, 16, tweak.c, &tweak_len) != 0) {
        fprintf(stderr, "Tweak encryption failed\n");
        ret = -1;
        goto out;
    }

    if (1) {
        // print tweak value
        printf("Tweak: ");
        for (i = 0; i < 16; i++) {
            printf("%02x", tweak.c[i]);
        }
        printf("\n");
    }

    if (0 && (inlen % 16)) {
        // 处理最后一块不足16字节的数据，则先处理到倒数第二块整块
        inlen -= 16;
    }

    while (inlen >= 16) {
        scratch.u[0] = ((u64_a1 *)in)[0] ^ tweak.u[0];
        scratch.u[1] = ((u64_a1 *)in)[1] ^ tweak.u[1];

        // 使用key1加密
        size_t block_len = 0;
        if (block_cipher_encrypt(key1, NULL, scratch.c, 16, scratch.c, &block_len) != 0) {
            fprintf(stderr, "Block encryption failed\n");
            ret = -1;
            goto out;
        }

        ((u64_a1 *)out)[0] = scratch.u[0] ^= tweak.u[0];
        ((u64_a1 *)out)[1] = scratch.u[1] ^= tweak.u[1];

        inlen -= 16;
        in += 16;
        out += 16;

        // 如果是最后一整块，直接算完返回
        if (inlen == 0) {
            return 0;
        }

        // GF(2^128)上的乘法
        if (0) {
            // unsigned int carry, res;
            //
            // res = 0x87 & (((int)tweak.d[3]) >> 31);
            // carry = (unsigned int)(tweak.u[0] >> 63);
            // tweak.u[0] = (tweak.u[0] << 1) ^ res;
            // tweak.u[1] = (tweak.u[1] << 1) | carry;
            mbedtls_gf128mul_x_ble(tweak.c, tweak.c);
        } else {
            u8 res;
            u64 hi, lo;
#ifdef BSWAP8
            hi = BSWAP8(tweak.u[0]);
            lo = BSWAP8(tweak.u[1]);
#else
            u8 *p = tweak.c;

            hi = (u64)GETU32(p) << 32 | GETU32(p + 4);
            lo = (u64)GETU32(p + 8) << 32 | GETU32(p + 12);
#endif
            res = (u8)lo & 1;
            tweak.u[0] = (lo >> 1) | (hi << 63);
            tweak.u[1] = hi >> 1;
            if (res)
                tweak.c[15] ^= 0xe1;
#ifdef BSWAP8
            hi = BSWAP8(tweak.u[0]);
            lo = BSWAP8(tweak.u[1]);
#else
            p = tweak.c;

            hi = (u64)GETU32(p) << 32 | GETU32(p + 4);
            lo = (u64)GETU32(p + 8) << 32 | GETU32(p + 12);
#endif
            tweak.u[0] = lo;
            tweak.u[1] = hi;
        }

    }

    // 处理最后一块不足16字节的数据
    {
        for (i = 0; i < inlen; ++i) {
            u8 c = in[i];
            out[i] = scratch.c[i];
            scratch.c[i] = c;
        }
        scratch.u[0] ^= tweak.u[0];
        scratch.u[1] ^= tweak.u[1];

        if (1) {
            // print scratch value
            printf("Scratch before final encrypt: ");
            for (i = 0; i < 16; i++) {
                printf("%02x", scratch.c[i]);
            }
            printf("\n");
        }

        // 使用key1加密
        size_t block_len = 0;
        if (block_cipher_encrypt(key1, NULL, scratch.c, 16, scratch.c, &block_len) != 0) {
            fprintf(stderr, "Block encryption failed\n");
            ret = -1;
            goto out;
        }
        scratch.u[0] ^= tweak.u[0];
        scratch.u[1] ^= tweak.u[1];
        memcpy(out - 16, scratch.c, 16);
    }

    ret = 0;

out:
    return ret;
}


int xts_decrypt(
    unsigned char *key1, unsigned char *key2,
    unsigned char *iv,
    unsigned char *in, size_t inlen,
    unsigned char *out, size_t *outlen) {
    int ret = 0;
    *outlen = inlen;

    union {
        u64 u[2];
        u32 d[4];
        u8 c[16];
    } tweak, scratch;
    unsigned int i;

    // 判断输入长度是否小于16字节
    if (inlen < 16) {
        fprintf(stderr, "Input length must be at least 16 bytes\n");
        ret = -1;
        goto out;
    }

    // 使用iv当成作初始tweak值
    memcpy(tweak.c, iv, 16);

    // 使用key2加密tweak值
    size_t tweak_len = 0;
    if (block_cipher_encrypt(key2, NULL, tweak.c, 16, tweak.c, &tweak_len) != 0) {
        fprintf(stderr, "Tweak encryption failed\n");
        ret = -1;
        goto out;
    }

    // 处理最后一块不足16字节的数据，则先处理到倒数第二块整块
    if (1 && (inlen % 16)) {
        inlen -= 16;
    }

    while (inlen >= 16) {
        scratch.u[0] = ((u64 *)in)[0] ^ tweak.u[0];
        scratch.u[1] = ((u64 *)in)[1] ^ tweak.u[1];

        // 使用key1加密
        size_t block_len = 0;
        if (block_cipher_decrypt(key1, NULL, scratch.c, 16, scratch.c, &block_len) != 0) {
            fprintf(stderr, "Block encryption failed\n");
            ret = -1;
            goto out;
        }

        ((u64 *)out)[0] = scratch.u[0] ^ tweak.u[0];
        ((u64 *)out)[1] = scratch.u[1] ^ tweak.u[1];

        inlen -= 16;
        in += 16;
        out += 16;

        // 如果是最后一整块，直接算完返回
        if (inlen == 0) {
            return 0;
        }

        // GF(2^128)上的乘法
        if (0) {
            // unsigned int carry, res;
            //
            // res = 0x87 & (((int)tweak.d[3]) >> 31);
            // carry = (unsigned int)(tweak.u[0] >> 63);
            // tweak.u[0] = (tweak.u[0] << 1) ^ res;
            // tweak.u[1] = (tweak.u[1] << 1) | carry;
            mbedtls_gf128mul_x_ble(tweak.c, tweak.c);
        } else {
            u8 res;
            u64 hi, lo;
#ifdef BSWAP8
            hi = BSWAP8(tweak.u[0]);
            lo = BSWAP8(tweak.u[1]);
#else
            u8 *p = tweak.c;

            hi = (u64)GETU32(p) << 32 | GETU32(p + 4);
            lo = (u64)GETU32(p + 8) << 32 | GETU32(p + 12);
#endif
            res = (u8)lo & 1;
            tweak.u[0] = (lo >> 1) | (hi << 63);
            tweak.u[1] = hi >> 1;
            if (res)
                tweak.c[15] ^= 0xe1;
#ifdef BSWAP8
            hi = BSWAP8(tweak.u[0]);
            lo = BSWAP8(tweak.u[1]);
#else
            p = tweak.c;

            hi = (u64)GETU32(p) << 32 | GETU32(p + 4);
            lo = (u64)GETU32(p + 8) << 32 | GETU32(p + 12);
#endif
            tweak.u[0] = lo;
            tweak.u[1] = hi;
        }
    }

    {
        // 处理最后一个整块和不足16字节的数据
        union {
            u64 u[2];
            u8 c[16];
        } tweak1;

        if (0) {
            // unsigned int carry, res;
            //
            // res = 0x87 & (((int)tweak.d[3]) >> 31);
            // carry = (unsigned int)(tweak.u[0] >> 63);
            // tweak1.u[0] = (tweak.u[0] << 1) ^ res;
            // tweak1.u[1] = (tweak.u[1] << 1) | carry;
            mbedtls_gf128mul_x_ble(tweak.c, tweak.c);
        } else {
            u8 res;
            u64 hi, lo;
#ifdef BSWAP8
            hi = BSWAP8(tweak.u[0]);
            lo = BSWAP8(tweak.u[1]);
#else
            u8 *p = tweak.c;

            hi = (u64)GETU32(p) << 32 | GETU32(p + 4);
            lo = (u64)GETU32(p + 8) << 32 | GETU32(p + 12);
#endif
            res = (u8)lo & 1;
            tweak1.u[0] = (lo >> 1) | (hi << 63);
            tweak1.u[1] = hi >> 1;
            if (res)
                tweak1.c[15] ^= 0xe1;
#ifdef BSWAP8
            hi = BSWAP8(tweak1.u[0]);
            lo = BSWAP8(tweak1.u[1]);
#else
            p = tweak1.c;

            hi = (u64)GETU32(p) << 32 | GETU32(p + 4);
            lo = (u64)GETU32(p + 8) << 32 | GETU32(p + 12);
#endif
            tweak1.u[0] = lo;
            tweak1.u[1] = hi;
        }

        scratch.u[0] = ((u64 *)in)[0] ^ tweak1.u[0];
        scratch.u[1] = ((u64 *)in)[1] ^ tweak1.u[1];

        // 使用key1解密
        size_t block_len = 0;
        if (block_cipher_decrypt(key1, NULL, scratch.c, 16, scratch.c, &block_len) != 0) {
            fprintf(stderr, "Block decryption failed\n");
            ret = -1;
            goto out;
        }
        scratch.u[0] ^= tweak1.u[0];
        scratch.u[1] ^= tweak1.u[1];

        for (i = 0; i < inlen; ++i) {
            u8 c = in[16 + i];
            out[16 + i] = scratch.c[i];
            scratch.c[i] = c;
        }
        scratch.u[0] ^= tweak.u[0];
        scratch.u[1] ^= tweak.u[1];
        // 使用key1解密
        block_len = 0;
        if (block_cipher(0, key1, NULL, scratch.c, 16, scratch.c, &block_len) != 0) {
            fprintf(stderr, "Block decryption failed\n");
            ret = -1;
            goto out;
        }
    }

    ((u64 *)out)[0] = scratch.u[0] ^ tweak.u[0];
    ((u64 *)out)[1] = scratch.u[1] ^ tweak.u[1];
    ret = 0;
out:
    return ret;
}


int openssl_xts_encrypt(unsigned char *key,
    unsigned char *iv,
    unsigned char *in, size_t inlen,
    unsigned char *out, size_t *outlen) {
    int ret = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;

    // use SM4 in XTS mode
    cipher = EVP_CIPHER_fetch(NULL, "SM4-XTS", NULL);
    if (!cipher) {
        fprintf(stderr, "Failed to get SM4-XTS cipher: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Initialize the encryption operation with XTS mode
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        fprintf(stderr, "Failed to initialize encryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // set no padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Provide the message to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, out, &len, in, inlen)) {
        fprintf(stderr, "Failed to encrypt data: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, out + len, &len)) {
        fprintf(stderr, "Failed to finalize encryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    ciphertext_len += len;
    *outlen = ciphertext_len;

    ret = 0;

out:
    if (cipher) {
        EVP_CIPHER_free(cipher);
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}


int openssl_xts_decrypt(unsigned char *key,
    unsigned char *iv,
    unsigned char *in, size_t inlen,
    unsigned char *out, size_t *outlen) {
    int ret = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int plaintext_len = 0;

    // use SM4 in XTS mode
    cipher = EVP_CIPHER_fetch(NULL, "SM4-XTS", NULL);
    if (!cipher) {
        fprintf(stderr, "Failed to get SM4-XTS cipher: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Failed to create cipher context: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // Initialize the decryption operation with XTS mode
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        fprintf(stderr, "Failed to initialize decryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    // set no padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Provide the message to be decrypted, and obtain the plaintext output
    if (1 != EVP_DecryptUpdate(ctx, out, &len, in, inlen)) {
        fprintf(stderr, "Failed to decrypt data: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    plaintext_len = len;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, out + len, &len)) {
        fprintf(stderr, "Failed to finalize decryption: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    plaintext_len += len;
    *outlen = plaintext_len;

    ret = 0;

out:
    if (cipher) {
        EVP_CIPHER_free(cipher);
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}


int main(int argc, char *argv[]) {
    int ret = 0;
    unsigned char key1[16] = {0};
    unsigned char key2[16] = {0};
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};
    unsigned char in[] = "This is a test message for XTS mode encryption!";
    size_t inlen = strlen((char *)in);
    unsigned char out[128] = {0};
    size_t outlen = 0;
    unsigned char dec[128] = {0};
    size_t declen = 0;

    // randomly generate keys and iv
    if (RAND_bytes(key1, sizeof(key1)) != 1) {
        fprintf(stderr, "RAND_bytes key1 failed\n");
        ret = -1;
        goto out;
    }
    if (RAND_bytes(key2, sizeof(key2)) != 1) {
        fprintf(stderr, "RAND_bytes key2 failed\n");
        ret = -1;
        goto out;
    }
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "RAND_bytes iv failed\n");
        ret = -1;
        goto out;
    }
    // print keys and iv in hex
    printf("Key1: ");
    for (size_t i = 0; i < sizeof(key1); i++) {
        printf("%02x", key1[i]);
    }
    printf("\n");
    printf("Key2: ");
    for (size_t i = 0; i < sizeof(key2); i++) {
        printf("%02x", key2[i]);
    }
    printf("\n");
    printf("IV: ");
    for (size_t i = 0; i < sizeof(iv); i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    memcpy(key, key1, sizeof(key1));
    memcpy(key + sizeof(key1), key2, sizeof(key2));

    // use self-implemented XTS encryption
    if (xts_encrypt(key1, key2, iv, in, inlen, out, &outlen) != 0) {
        fprintf(stderr, "xts_encrypt failed\n");
        ret = -1;
        goto out;
    }
    printf("Self-implemented XTS encryption successful, outlen=%zu\n", outlen);
    // print ciphertext in hex
    printf("Self-implemented Ciphertext: ");
    for (size_t i = 0; i < outlen; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");

    // print key and iv in hex
    printf("Key: ");
    for (size_t i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    printf("IV: ");
    for (size_t i = 0; i < sizeof(iv); i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");
    // use OpenSSL XTS decryption
    if (openssl_xts_decrypt(key, iv, out, outlen, dec, &declen) != 0) {
        fprintf(stderr, "openssl_xts_decrypt failed\n");
        ret = -1;
        goto out;
    }
    printf("OpenSSL XTS decryption successful, declen=%zu\n", declen);
    // print decrypted text
    printf("openssl Decrypted text: ");
    for (size_t i = 0; i < declen; i++) {
        printf("%c", dec[i]);
    }
    printf("\n");

    if (declen != inlen || memcmp(in, dec, inlen) != 0) {
        fprintf(stderr, "Decrypted data does not match original\n");
        ret = -1;
        goto out;
    }
    printf("Decrypted data matches original\n");

    printf("==================================\n");


    // print key and iv in hex
    printf("Key: ");
    for (size_t i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    printf("IV: ");
    for (size_t i = 0; i < sizeof(iv); i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");
    // use OpenSSL XTS encryption
    memset(out, 0, sizeof(out));
    outlen = 0;
    if (openssl_xts_encrypt(key, iv, in, inlen, out, &outlen) != 0) {
        fprintf(stderr, "openssl_xts_encrypt failed\n");
        ret = -1;
        goto out;
    }
    printf("OpenSSL XTS encryption successful, outlen=%zu\n", outlen);
    // print ciphertext in hex
    printf("openssl Ciphertext: ");
    for (size_t i = 0; i < outlen; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");

    // use self-implemented XTS decryption
    memset(dec, 0, sizeof(dec));
    declen = 0;
    if (xts_decrypt(key1, key2, iv, out, outlen, dec, &declen) != 0) {
        fprintf(stderr, "xts_decrypt failed\n");
        ret = -1;
        goto out;
    }
    printf("Self-implemented XTS decryption successful, declen=%zu\n", declen);
    // print decrypted text
    printf("Self-implemented Decrypted text: ");
    for (size_t i = 0; i < declen; i++) {
        printf("%c", dec[i]);
    }
    printf("\n");
    if (declen != inlen || memcmp(in, dec, inlen) != 0) {
        fprintf(stderr, "Decrypted data does not match original\n");
        ret = -1;
        goto out;
    }
    printf("Decrypted data matches original\n");

    ret = 0;

out:
    return ret;
}