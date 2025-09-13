# OpenSSL Digest Algorithms (Message Digest / Hash Functions) Implementation Guide

## 项目概述

本项目实现了OpenSSL中主要的消息摘要（哈希）算法，涵盖了四大算法家族：SHA-2、SHA-3、BLAKE2和SM3。通过统一的EVP接口演示了现代密码学哈希函数的使用方法，适用于数据完整性验证、数字签名、密钥派生等应用场景。

## 支持的算法家族

### 1. SHA-2 算法家族 (Secure Hash Algorithm 2)
- **SHA-224**: 224位输出，基于SHA-256的截断版本
- **SHA-256**: 256位输出，广泛应用的标准算法
- **SHA-384**: 384位输出，基于SHA-512的截断版本  
- **SHA-512**: 512位输出，高安全性长哈希

### 2. SHA-3 算法家族 (Secure Hash Algorithm 3)
- **SHA3-224**: 224位输出，基于Keccak的标准化版本
- **SHA3-256**: 256位输出，SHA-3的主要变体
- **SHA3-384**: 384位输出，中等长度安全级别
- **SHA3-512**: 512位输出，最高安全级别
- **SHAKE128**: 可变长度输出，扩展输出函数
- **SHAKE256**: 可变长度输出，更高安全性

### 3. BLAKE2 算法家族 (高速哈希函数)
- **BLAKE2s-256**: 256位输出，优化32位平台
- **BLAKE2b-512**: 512位输出，优化64位平台

### 4. SM3 算法 (中国国家标准)
- **SM3**: 256位输出，中国密码标准算法

## 核心实现文件

### 1. SHA-2 实现 (`test_digest_sha2.c`)
```c
// 支持的算法列表
const char* algorithms[] = {"SHA224", "SHA256", "SHA384", "SHA512"};

// 核心调用函数
int call_digest_sha2(const char *algorithm_name, 
                     unsigned char *input, size_t input_len,
                     unsigned char *digest, unsigned int *digest_len)
```

**技术特点:**
- 使用 `EVP_get_digestbyname()` 动态获取算法
- 支持所有SHA-2变体的统一接口
- 完整的错误处理机制
- 内存安全的实现方式

### 2. SHA-3 实现 (`test_digest_sha3.c`)
```c
// 标准SHA-3算法
const char* algorithms[] = {"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};

// SHAKE扩展输出函数
const char* shake_algorithms[] = {"SHAKE128", "SHAKE256"};

// SHAKE截断输出实现
int call_digest_shake_truncate_length(const char *algorithm_name,
                                     unsigned char *input, size_t input_len,
                                     unsigned char *digest, unsigned int target_len)
```

**技术亮点:**
- 标准SHA-3和SHAKE函数的完整实现
- 支持SHAKE的可变长度输出
- 灵活的截断机制
- 基于Keccak海绵函数构造

### 3. BLAKE2 实现 (`test_digest_blake2.c`)
```c
// BLAKE2变体
const char* algorithms[] = {"BLAKE2s256", "BLAKE2b512"};

// 高性能哈希计算
int call_digest_blake2(const char *algorithm_name,
                      unsigned char *input, size_t input_len,
                      unsigned char *digest, unsigned int *digest_len)
```

**性能特征:**
- 高速并行化设计
- BLAKE2s: 针对32位平台优化
- BLAKE2b: 针对64位平台优化
- 优于SHA-2/SHA-3的性能表现

### 4. SM3 实现 (`test_digest_sm3.c`)
```c
// 直接算法引用
const EVP_MD *md = EVP_sm3();

// 国标实现
int call_digest_sm3(unsigned char *input, size_t input_len,
                   unsigned char *digest, unsigned int *digest_len)
```

**标准特性:**
- 符合GB/T 32905-2016国家标准
- 256位固定输出长度
- 专用于中国密码应用场景
- 直接EVP算法引用方式

## EVP接口统一模式

所有算法都遵循OpenSSL EVP框架的标准模式：

```c
// 1. 创建和初始化上下文
EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
if (!mdctx) handleErrors();

// 2. 初始化摘要操作
if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) handleErrors();

// 3. 更新输入数据
if (1 != EVP_DigestUpdate(mdctx, input, input_len)) handleErrors();

// 4. 完成计算并获取结果
if (1 != EVP_DigestFinal_ex(mdctx, digest, digest_len)) handleErrors();

// 5. 清理资源
EVP_MD_CTX_free(mdctx);
```

## 算法获取方式对比

### 通用名称获取方式
```c
const EVP_MD *md = EVP_get_digestbyname("SHA256");  // SHA-2, SHA-3, BLAKE2
```

### 直接函数获取方式  
```c
const EVP_MD *md = EVP_sm3();  // SM3专用
```

## 安全性分析

### 抗冲突强度对比
| 算法 | 输出长度 | 理论安全级别 | 抗原像攻击 | 抗第二原像攻击 |
|------|----------|-------------|------------|----------------|
| SHA-256 | 256位 | 128位 | 2^256 | 2^256 |
| SHA-512 | 512位 | 256位 | 2^512 | 2^512 |
| SHA3-256 | 256位 | 128位 | 2^256 | 2^256 |
| SHA3-512 | 512位 | 256位 | 2^512 | 2^512 |
| BLAKE2b-512 | 512位 | 256位 | 2^512 | 2^512 |
| SM3 | 256位 | 128位 | 2^256 | 2^256 |

### 性能特征对比
| 算法家族 | 相对性能 | 内存需求 | 硬件加速 | 并行化支持 |
|----------|----------|----------|----------|------------|
| SHA-2 | 基准 | 低 | 广泛支持 | 有限 |
| SHA-3 | 较慢 | 中等 | 部分支持 | 良好 |
| BLAKE2 | 最快 | 低 | 部分支持 | 优秀 |
| SM3 | 中等 | 低 | 有限支持 | 有限 |

## 应用场景指南

### 1. 通用应用推荐
- **文件校验**: SHA-256 (广泛兼容)
- **数字签名**: SHA-256/SHA-512 (标准要求)
- **区块链**: SHA-256 (Bitcoin标准)
- **高性能应用**: BLAKE2b-512 (最佳性能)

### 2. 合规性要求
- **FIPS 140-2**: SHA-2, SHA-3算法
- **国密标准**: SM3算法 (中国)
- **欧盟标准**: SHA-3, BLAKE2 (现代标准)

### 3. 安全等级选择
- **128位安全**: SHA-256, SHA3-256, SM3
- **256位安全**: SHA-512, SHA3-512, BLAKE2b-512
- **可变安全**: SHAKE128/256 (根据输出长度)

## 编译与运行

### 构建要求
```bash
# 确保OpenSSL支持所有算法
openssl version -a
openssl list -digest-algorithms
```

### 编译命令
```bash
# SHA-2测试
gcc -o test_digest_sha2 test_digest_sha2.c -lssl -lcrypto

# SHA-3测试  
gcc -o test_digest_sha3 test_digest_sha3.c -lssl -lcrypto

# BLAKE2测试
gcc -o test_digest_blake2 test_digest_blake2.c -lssl -lcrypto

# SM3测试
gcc -o test_digest_sm3 test_digest_sm3.c -lssl -lcrypto
```

### 运行示例
```bash
# 测试所有SHA-2算法
./test_digest_sha2

# 测试SHA-3和SHAKE
./test_digest_sha3

# 测试高性能BLAKE2
./test_digest_blake2

# 测试国密SM3
./test_digest_sm3
```

## 代码示例详解

### SHA-2 多算法测试
```c
int main(void) {
    const char* test_data = "Hello, OpenSSL Digest!";
    const char* algorithms[] = {"SHA224", "SHA256", "SHA384", "SHA512"};
    
    for (int i = 0; i < 4; i++) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len;
        
        if (call_digest_sha2(algorithms[i], 
                            (unsigned char*)test_data, strlen(test_data),
                            digest, &digest_len) == 1) {
            printf("%s: ", algorithms[i]);
            print_hex(digest, digest_len);
        }
    }
}
```

### SHAKE可变长度输出
```c
// SHAKE128生成不同长度的输出
unsigned char output_32[32], output_64[64];

call_digest_shake_truncate_length("SHAKE128", 
                                 (unsigned char*)"test", 4,
                                 output_32, 32);

call_digest_shake_truncate_length("SHAKE128",
                                 (unsigned char*)"test", 4,
                                 output_64, 64);
```

## 错误处理最佳实践

### 完整的错误检查流程
```c
int call_digest_secure(const char *algorithm_name, 
                      unsigned char *input, size_t input_len,
                      unsigned char *digest, unsigned int *digest_len) {
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    int result = 0;
    
    // 1. 算法有效性检查
    md = EVP_get_digestbyname(algorithm_name);
    if (!md) {
        fprintf(stderr, "未知的摘要算法: %s\n", algorithm_name);
        goto cleanup;
    }
    
    // 2. 上下文创建检查
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "无法创建摘要上下文\n");
        goto cleanup;
    }
    
    // 3. 每步操作的返回值检查
    if (1 != EVP_DigestInit_ex(mdctx, md, NULL) ||
        1 != EVP_DigestUpdate(mdctx, input, input_len) ||
        1 != EVP_DigestFinal_ex(mdctx, digest, digest_len)) {
        fprintf(stderr, "摘要计算失败\n");
        goto cleanup;
    }
    
    result = 1; // 成功
    
cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    return result;
}
```

## 性能优化建议

### 1. 批量处理优化
```c
// 对大数据使用分块更新
EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

while (data_remaining > 0) {
    size_t chunk_size = min(CHUNK_SIZE, data_remaining);
    EVP_DigestUpdate(mdctx, data_ptr, chunk_size);
    data_ptr += chunk_size;
    data_remaining -= chunk_size;
}

EVP_DigestFinal_ex(mdctx, digest, &digest_len);
```

### 2. 内存管理优化
```c
// 使用栈分配避免堆内存
unsigned char digest[EVP_MAX_MD_SIZE];  // 栈分配
unsigned int digest_len;

// 避免重复创建上下文
static EVP_MD_CTX *global_ctx = NULL;
if (!global_ctx) global_ctx = EVP_MD_CTX_new();
```

## 标准符合性声明

### 算法标准对照表
| 算法 | 标准文档 | RFC编号 | 标准化组织 |
|------|----------|---------|------------|
| SHA-256 | FIPS PUB 180-4 | RFC 6234 | NIST |
| SHA-512 | FIPS PUB 180-4 | RFC 6234 | NIST |
| SHA3-256 | FIPS PUB 202 | - | NIST |
| SHA3-512 | FIPS PUB 202 | - | NIST |
| BLAKE2b | RFC 7693 | RFC 7693 | IETF |
| SM3 | GB/T 32905-2016 | - | 国标委 |

### 认证和合规性
- **FIPS 140-2 Level 1**: SHA-2, SHA-3算法家族
- **国密认证**: SM3算法
- **欧盟eIDAS**: SHA-3, BLAKE2算法
- **Common Criteria**: EAL4+级别验证

## 常见问题解答

### Q: 如何选择合适的哈希算法？
A: 根据应用需求选择：
- 兼容性要求高: SHA-256
- 性能要求高: BLAKE2b-512
- 后量子安全: SHA-3算法家族
- 国内合规: SM3

### Q: SHAKE算法的输出长度如何确定？
A: SHAKE是扩展输出函数(XOF)，可以生成任意长度的输出：
- SHAKE128: 安全级别128位，推荐输出≥32字节
- SHAKE256: 安全级别256位，推荐输出≥64字节

### Q: OpenSSL版本兼容性如何？
A: 本项目支持：
- OpenSSL 3.0+: 全功能支持
- OpenSSL 1.1.1+: 部分支持(SM3需要特殊构建)
- OpenSSL 1.0.2及以下: 不推荐使用

### Q: 如何验证实现的正确性？
A: 使用标准测试向量：
```bash
# 使用OpenSSL命令行验证
echo -n "test" | openssl dgst -sha256
echo -n "test" | openssl dgst -sha3-256
echo -n "test" | openssl dgst -blake2b512
```

## 扩展阅读

### 相关资源
- [OpenSSL EVP文档](https://www.openssl.org/docs/man3.0/man7/evp.html)
- [NIST密码标准](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [国密算法标准](http://www.gmbz.org.cn/)
- [BLAKE2官方网站](https://www.blake2.net/)

### 学术论文
- SHA-3: "The Keccak SHA-3 Submission" by Bertoni et al.
- BLAKE2: "BLAKE2: Simpler, Smaller, Fast as MD5" by Aumasson et al.
- SM3: "The SM3 Hash Function" by Wang et al.

---

*本文档基于OpenSSL 3.5.2版本编写，涵盖了现代密码学哈希函数的理论基础和工程实践。*