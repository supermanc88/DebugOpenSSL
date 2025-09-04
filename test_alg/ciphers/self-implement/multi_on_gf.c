#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


const char *T0 = "27182818284590452353602874713526";
const char *T1 = "4e305030508b208a46a6c050e8e26a4c";

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;


int hex2bin(const char *hex, u8 *bin, size_t bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || bin_len < hex_len / 2) {
        return -1;
    }
    for (size_t i = 0; i < hex_len / 2; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }
    return 0;
}

#define BSWAP8(x) ({ u64 ret_;                       \
asm ("rev %0,%1"                \
: "=r"(ret_) : "r"(x)); ret_;   })

// 自实现的 GF(2^128) 乘以 x (即左移一位并模多项式 0x87)
// 小端语义下，最低字节在最低地址
// u[0] 低地址，u[1] 高地址
// 0x87 = 10000111b，对应多项式  x^7 + x^2 + x + 1
// 最高位溢出时，需对最低字节进行异或操作
static inline void gf_mulx_le_u64(uint64_t u[2]) {
    // 预取最高位（移位前）
    unsigned msb = (unsigned)((u[1] >> 63) & 1u);
    unsigned carry = (unsigned)((u[0] >> 63) & 1u);

    u[0] = (u[0] << 1);
    u[1] = (u[1] << 1) | carry;

    // 小端语义下，“最低字节”在整体的最低地址 => u[0] 的最低 8 位
    if (msb) u[0] ^= 0x87u;
}

// 国标的 GF(2^128) 乘以 x (即左移一位并模多项式 0xe1)
static inline void gf_mulx_gb_u64(uint64_t u[2]) {
    u8 res;
    u64 hi, lo;
    // printf("u[0] = %016llx, u[1] = %016llx\n", u[0], u[1]);

    hi = BSWAP8(u[0]);
    lo = BSWAP8(u[1]);

    // print hi, lo
    printf("hi = %016llx, lo = %016llx\n", hi, lo);

    res = (u8)lo & 1;
    u[0] = (lo >> 1) | (hi << 63);
    u[1] = hi >> 1;
    if (res)
        ((char *)(u[1]))[15] ^= 0xe1;
    hi = BSWAP8(u[0]);
    lo = BSWAP8(u[1]);
    u[0] = lo;
    u[1] = hi;
}



int main(int argc, char *argv[]) {
    int ret = 0;
    union {
        u64 u[2];
        u32 d[4];
        u8 c[16];
    } T0_bytes, T1_bytes;

    ret = hex2bin(T0, T0_bytes.c, 16);
    if (ret != 0) {
        fprintf(stderr, "hex2bin T0 failed\n");
        ret = -1;
        goto out;
    }

    ret = hex2bin(T1, T1_bytes.c, 16);
    if (ret != 0) {
        fprintf(stderr, "hex2bin T1 failed\n");
        ret = -1;
        goto out;
    }

    // print T0 and T1
    printf("T0 = ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", T0_bytes.c[i]);
    }
    printf("\n");
    printf("T1 = ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", T1_bytes.c[i]);
    }
    printf("\n");

    gf_mulx_le_u64(T0_bytes.u);
    gf_mulx_le_u64(T1_bytes.u);

    // print results
    printf("T0 * x mod p = ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", T0_bytes.c[i]);
    }
    printf("\n");

    // print results
    printf("T1 * x mod p = ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", T1_bytes.c[i]);
    }
    printf("\n");

out:
    return ret;
}