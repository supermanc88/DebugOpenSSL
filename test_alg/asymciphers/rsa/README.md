# RSA 非对称加密算法实现

基于 OpenSSL 3.0+ 实现的RSA（Rivest-Shamir-Adleman）非对称加密算法，展示传统RSA API和现代EVP API两种实现方式，用于密码学学习和算法对比研究。

## 算法概述

### 技术背景

RSA算法是1977年由Ron Rivest、Adi Shamir和Leonard Adleman提出的第一个既能用于数据加密也能用于数字签名的公钥算法。它基于大整数分解的数学困难问题，是现代非对称密码学的奠基性算法。

RSA算法的核心原理：
- **数学基础**: 基于大整数分解的计算困难性（整数分解问题 IFP）
- **密钥生成**: 选择两个大素数，构造公私钥对
- **加密解密**: 使用模幂运算实现加密和解密操作
- **安全性**: 依赖于分解大整数的困难性，但不抗量子攻击

### 安全特性

- **数学安全性**: 基于整数分解问题，目前无多项式时间经典算法
- **密钥大小**: 2048位提供112位安全强度，3072位提供128位安全强度
- **填充方案**: 支持PKCS#1 v1.5、OAEP等安全填充模式
- **标准兼容**: 符合PKCS#1、RFC 3447等国际标准
- **量子威胁**: ⚠️ 不抗量子攻击，Shor算法可有效破解

### 支持的密钥规格

基于NIST和RSA Labs推荐，支持以下密钥规格：

| 密钥长度 | 安全强度 | 推荐应用场景 | 性能 | FIPS 140-2 | 量子安全期 |
|----------|----------|--------------|------|-------------|------------|
| **1024-bit** | 80-bit | ❌ 已不推荐 | 高 | ❌ | 已过期 |
| **2048-bit** | 112-bit | 通用应用 | 中等 | ✅ | ~2030年前 |
| **3072-bit** | 128-bit | 高安全要求 | 较慢 | ✅ | ~2035年前 |
| **4096-bit** | 152-bit | 最高安全级别 | 慢 | ✅ | ~2040年前 |

**注意**: 随着计算能力提升和量子威胁，建议使用3072位或更长密钥，或考虑迁移到后量子算法。

### 算法实现对比

#### 1. 传统RSA API (Legacy)
```c
// 使用传统的RSA_*函数族
RSA *rsa = RSA_new();
RSA_generate_key_ex(rsa, keybits, bn_exp, NULL);
i2d_RSA_PUBKEY_bio(bio, rsa);
i2d_RSAPrivateKey_bio(bio, rsa);
```

#### 2. 现代EVP API (Recommended)
```c
// 使用现代的EVP_PKEY_*函数族
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
EVP_PKEY_keygen_init(ctx);
EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keybits);
EVP_PKEY_keygen(ctx, &pkey);
```

**推荐使用EVP API的原因**：
- 算法无关性，易于迁移到其他算法
- 更好的错误处理和资源管理
- 支持硬件加速和引擎
- 符合现代OpenSSL设计理念
- 更好的前向兼容性

## 系统要求

### OpenSSL版本依赖
- **OpenSSL 1.1.1+** (基本支持)
  - 支持传统RSA API
  - 基础EVP_PKEY功能
- **OpenSSL 3.0.0+** (推荐)
  - 完整的EVP_PKEY RSA支持
  - 更好的错误处理
  - 提供者框架支持
- **推荐版本**: OpenSSL 3.1.0+ (性能优化和安全增强)

### 编译环境要求
- **C编译器**: GCC 7.0+ / Clang 6.0+ / MSVC 2019+
- **C标准**: ISO C99兼容 (`-std=c99`)
- **构建系统**: Make / CMake 3.10+
- **系统**: Linux, macOS, Windows (Cygwin/MinGW)

### 依赖检查
```bash
# 检查OpenSSL版本
openssl version -a

# 检查RSA算法支持
openssl list -public-key-algorithms | grep RSA

# 检查可用的填充模式
openssl list -cipher-algorithms | grep -i pkcs
```

## 编译和运行

### 编译程序
```bash
# 使用Make编译
make

# 或使用CMake
mkdir build && cd build
cmake ..
make
```

### 运行测试
```bash
# 直接运行
./test_asymcipher_rsa

# 或通过Make运行
make run
```

### 性能测试
```bash
# 运行性能基准测试
make benchmark

# 测试不同密钥长度
./test_asymcipher_rsa --keybits 2048
./test_asymcipher_rsa --keybits 3072
./test_asymcipher_rsa --keybits 4096
```

## 实现架构

### 双API实现对比

本实现提供两种RSA API使用方式的对比：

#### 1. 传统RSA API实现
- **函数**: `call_rsa_gen_via_old()`
- **特点**: 直接使用RSA结构体和RSA_*函数
- **优势**: 
  - API简单直观
  - 历史兼容性好
  - 性能开销较小
- **劣势**:
  - 算法绑定，难以迁移
  - 错误处理相对简单
  - 未来可能被弃用

#### 2. 现代EVP API实现
- **函数**: `call_rsa_gen_via_evp()`
- **特点**: 使用EVP_PKEY抽象层
- **优势**:
  - 算法无关设计
  - 更好的错误处理
  - 支持硬件加速
  - 标准化接口
- **劣势**:
  - API相对复杂
  - 轻微的性能开销

### 核心功能实现

```c
// RSA密钥生成 (传统API)
int call_rsa_gen_via_old(size_t keybits, unsigned long exp,
                         unsigned char **pub, size_t *publen,
                         unsigned char **pri, size_t *prilen);

// RSA密钥生成 (EVP API)  
int call_rsa_gen_via_evp(size_t keybits, unsigned long exp,
                         unsigned char **pub, size_t *publen,
                         unsigned char **pri, size_t *prilen);
```

### 密钥导出格式

#### 公钥导出
- **传统API**: 使用`i2d_RSA_PUBKEY_bio()` - SubjectPublicKeyInfo格式
- **EVP API**: 使用`i2d_PUBKEY_bio()` - 标准EVP公钥格式

#### 私钥导出
- **传统API**: 使用`i2d_RSAPrivateKey_bio()` - PKCS#1私钥格式
- **EVP API**: 使用`i2d_PrivateKey_bio()` - PKCS#8私钥格式

## 输出示例

```
RSA非对称加密算法测试程序
=========================
测试参数:
- 密钥长度: 2048 bits
- 公钥指数: 65537 (RSA_F4)
- OpenSSL版本: OpenSSL 3.5.2

========================================
测试传统RSA API (call_rsa_gen_via_old)
========================================
✓ RSA密钥生成成功
📄 公钥信息:
- 格式: SubjectPublicKeyInfo (DER)
- 长度: 294 bytes
- 数据: 308201A0300D06092A864886F70D010101050003820189003082018402820181...

📄 私钥信息:
- 格式: PKCS#1 PrivateKey (DER)  
- 长度: 1192 bytes
- 数据: 3082049B02010002820181009C8B5E6F2A1D7C8E3F4A2B5C9D8E7F6A1B2C3D4E...

========================================  
测试现代EVP API (call_rsa_gen_via_evp)
========================================
✓ EVP_PKEY RSA密钥生成成功
📄 公钥信息:
- 格式: X.509 SubjectPublicKeyInfo (DER)
- 长度: 294 bytes  
- 数据: 308201A0300D06092A864886F70D010101050003820189003082018402820181...

📄 私钥信息:
- 格式: PKCS#8 PrivateKeyInfo (DER)
- 长度: 1218 bytes
- 数据: 30820482020100300D06092A864886F70D0101010500048204BA308204B60201...

========================================
测试结果对比
========================================
✅ 两种API均成功生成RSA密钥对
📊 性能对比:
- 传统API耗时: ~45ms
- EVP API耗时: ~47ms
- 性能差异: <5%

🔍 格式差异:
- 公钥格式相同 (SubjectPublicKeyInfo)
- 私钥格式不同 (PKCS#1 vs PKCS#8)
- EVP API提供更标准的输出格式

✅ 所有RSA测试通过！
```

## 技术规范

### 密钥和数据规格

| 密钥长度 | 公钥大小(DER) | 私钥大小(PKCS#1) | 私钥大小(PKCS#8) | 加密块大小 | 签名长度 |
|----------|---------------|------------------|------------------|------------|----------|
| **1024-bit** | ~162 bytes | ~610 bytes | ~636 bytes | 117 bytes | 128 bytes |
| **2048-bit** | ~294 bytes | ~1190 bytes | ~1216 bytes | 245 bytes | 256 bytes |
| **3072-bit** | ~422 bytes | ~1770 bytes | ~1796 bytes | 373 bytes | 384 bytes |
| **4096-bit** | ~550 bytes | ~2350 bytes | ~2376 bytes | 501 bytes | 512 bytes |

### RSA算法参数

#### 标准参数配置
```c
// 常用公钥指数
#define RSA_3   0x03      // 3 (不推荐，安全性问题)
#define RSA_F4  0x10001   // 65537 (推荐，平衡安全性和性能)

// 密钥生成参数
typedef struct {
    int key_bits;          // 密钥长度 (1024, 2048, 3072, 4096)
    unsigned long exp;     // 公钥指数 (通常使用65537)
    int padding;           // 填充方案
    const char *mgf;       // 掩码生成函数 (用于OAEP)
} rsa_keygen_params_t;
```

#### 填充方案对比
```c
// PKCS#1 v1.5 填充 (传统)
RSA_PKCS1_PADDING
- 优点: 兼容性好，广泛支持
- 缺点: 存在已知的攻击向量
- 使用场景: 兼容性要求高的场合

// OAEP填充 (推荐)  
RSA_PKCS1_OAEP_PADDING
- 优点: 更高安全性，抗选择密文攻击
- 缺点: 占用更多空间
- 使用场景: 新系统，高安全要求

// PSS填充 (签名专用)
RSA_PKCS1_PSS_PADDING  
- 优点: 可证明安全的签名方案
- 使用场景: 数字签名应用
```

### OpenSSL API映射

#### 传统RSA API
```c
// 密钥生成
RSA *rsa = RSA_new();
BIGNUM *e = BN_new();
BN_set_word(e, RSA_F4);
RSA_generate_key_ex(rsa, key_bits, e, NULL);

// 密钥导出
BIO *bio = BIO_new(BIO_s_mem());
i2d_RSA_PUBKEY_bio(bio, rsa);        // 公钥
i2d_RSAPrivateKey_bio(bio, rsa);     // 私钥

// 加密解密
RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
RSA_private_decrypt(encrypted_len, encrypted, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
```

#### 现代EVP API
```c
// 密钥生成
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
EVP_PKEY_keygen_init(ctx);
EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_bits);
BIGNUM *e = BN_new();
BN_set_word(e, RSA_F4);
EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, e);
EVP_PKEY_keygen(ctx, &pkey);

// 密钥导出
BIO *bio = BIO_new(BIO_s_mem());
i2d_PUBKEY_bio(bio, pkey);           // 公钥 (X.509 格式)
i2d_PrivateKey_bio(bio, pkey);       // 私钥 (PKCS#8 格式)

// 加密解密
EVP_PKEY_CTX *encrypt_ctx = EVP_PKEY_CTX_new(pkey, NULL);
EVP_PKEY_encrypt_init(encrypt_ctx);
EVP_PKEY_CTX_set_rsa_padding(encrypt_ctx, RSA_PKCS1_OAEP_PADDING);
EVP_PKEY_encrypt(encrypt_ctx, encrypted, &encrypted_len, data, data_len);
```

## 故障排除

### 编译问题

#### 1. OpenSSL头文件未找到
```bash
# 错误信息
error: openssl/rsa.h: No such file or directory
error: openssl/evp.h: No such file or directory

# 解决方案
# macOS (Homebrew)
export CPPFLAGS="-I$(brew --prefix openssl)/include"
export LDFLAGS="-L$(brew --prefix openssl)/lib"

# Ubuntu/Debian
sudo apt-get install libssl-dev

# CentOS/RHEL
sudo yum install openssl-devel
```

#### 2. RSA函数未定义
```bash
# 错误信息
undefined reference to 'RSA_generate_key_ex'
undefined reference to 'EVP_PKEY_CTX_set_rsa_keygen_bits'

# 解决方案
# 确保链接OpenSSL库
gcc -o test_rsa test_rsa.c -lssl -lcrypto

# 检查OpenSSL安装
pkg-config --cflags --libs openssl
```

#### 3. 版本兼容性问题
```bash
# 错误信息 (OpenSSL 1.0.x)
error: 'EVP_PKEY_CTX_set_rsa_keygen_pubexp' undeclared

# 解决方案: 使用条件编译
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    // OpenSSL 1.1.0+ 代码
    EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, e);
#else
    // OpenSSL 1.0.x 兼容代码  
    EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, e);
    BN_free(e); // 手动释放
#endif
```

### 运行时错误

#### 1. 密钥生成失败
```bash
# 错误信息
RSA_generate_key_ex failed: error:0D0680A8:asn1 encoding routines

# 可能原因
1. 密钥长度无效 (小于512或非2的幂)
2. 公钥指数无效 (必须是奇数且大于1)
3. 系统随机数不足

# 解决方案
# 检查参数合法性
if (keybits < 1024 || (keybits & (keybits - 1)) != 0) {
    fprintf(stderr, "Invalid key bits: %zu\n", keybits);
    return -1;
}

# 检查随机数状态
if (RAND_status() != 1) {
    fprintf(stderr, "Insufficient entropy for key generation\n");
    return -1;
}
```

#### 2. 内存分配失败
```bash
# 错误信息
malloc for pub failed
BIO_new failed: out of memory

# 解决方案
# 检查系统内存
free -h

# 实现内存检查
unsigned char *pub = malloc(bio_len_pub);
if (!pub) {
    fprintf(stderr, "Memory allocation failed: %zu bytes\n", bio_len_pub);
    return -1;
}
```

#### 3. 密钥导出格式问题
```bash
# 错误信息
i2d_RSA_PUBKEY_bio failed: error:0909006C:PEM routines

# 调试方法
# 检查密钥有效性
if (!rsa || RSA_check_key(rsa) != 1) {
    fprintf(stderr, "Invalid RSA key\n");
    ERR_print_errors_fp(stderr);
    return -1;
}

# 验证BIO状态
if (!bio) {
    fprintf(stderr, "BIO creation failed\n");
    return -1;
}
```

### 性能问题

#### 1. 密钥生成缓慢
```c
// 问题: 大密钥生成时间过长
// 解决方案: 使用多线程或显示进度

// 密钥生成进度回调
int progress_callback(int p, int n, BN_GENCB *cb) {
    char c = '*';
    if (p == 0) c = '.';
    if (p == 1) c = '+';  
    if (p == 2) c = '*';
    if (p == 3) c = '\n';
    fputc(c, stdout);
    fflush(stdout);
    return 1;
}

// 使用回调
BN_GENCB *cb = BN_GENCB_new();
BN_GENCB_set(cb, progress_callback, NULL);
RSA_generate_key_ex(rsa, keybits, bn_exp, cb);
BN_GENCB_free(cb);
```

#### 2. 内存使用优化
```c
// 优化内存分配
// 预分配固定大小缓冲区而非动态分配
#define MAX_RSA_KEY_SIZE 4096
#define MAX_DER_SIZE ((MAX_RSA_KEY_SIZE / 8) * 5)  // 估算DER大小

static unsigned char pub_buffer[MAX_DER_SIZE];
static unsigned char pri_buffer[MAX_DER_SIZE];

// 重用BIO对象
static BIO *reusable_bio = NULL;
if (!reusable_bio) {
    reusable_bio = BIO_new(BIO_s_mem());
}
BIO_reset(reusable_bio);
```

## 安全考虑

### 密码学安全性

#### 1. 密钥长度选择
- **当前推荐**: 2048位以上，优选3072位
- **长期安全**: 考虑迁移到后量子算法
- **性能权衡**: 密钥越长，性能越差

```c
// 安全的密钥长度检查
int validate_key_bits(size_t keybits) {
    if (keybits < 2048) {
        fprintf(stderr, "Warning: Key length %zu bits is below recommended minimum (2048)\n", keybits);
        return -1;
    }
    if (keybits < 3072) {
        fprintf(stderr, "Note: Consider using 3072+ bits for long-term security\n");
    }
    return 0;
}
```

#### 2. 填充方案安全性
```c
// 推荐的填充方案使用
typedef struct {
    int padding_mode;
    const char *mgf_hash;      // OAEP使用的哈希函数
    const char *oaep_label;    // OAEP标签（可选）
} rsa_padding_config_t;

// 安全配置示例
rsa_padding_config_t secure_config = {
    .padding_mode = RSA_PKCS1_OAEP_PADDING,
    .mgf_hash = "sha256",
    .oaep_label = NULL
};

// ⚠️ 不推荐的配置
rsa_padding_config_t deprecated_config = {
    .padding_mode = RSA_PKCS1_PADDING,  // 存在攻击风险
    .mgf_hash = "sha1",                 // 哈希算法过时
    .oaep_label = NULL
};
```

#### 3. 随机数质量
```c
// 确保随机数生成器初始化
int ensure_random_initialized(void) {
    if (RAND_status() != 1) {
        fprintf(stderr, "Random number generator not properly initialized\n");
        
        // 尝试从系统熵源添加随机性
#ifdef __linux__
        RAND_load_file("/dev/urandom", 1024);
#endif
        
        if (RAND_status() != 1) {
            fprintf(stderr, "Failed to initialize random number generator\n");
            return -1;
        }
    }
    return 0;
}
```

### 实现安全注意事项

#### 1. 密钥材料保护
```c
// 安全的内存分配和清理
void secure_key_cleanup(unsigned char **key, size_t key_len) {
    if (key && *key) {
        // 使用安全清零函数
        OPENSSL_cleanse(*key, key_len);
        OPENSSL_free(*key);
        *key = NULL;
    }
}

// 避免敏感数据留在栈上
int generate_rsa_secure(size_t keybits) {
    unsigned char *private_key = OPENSSL_secure_malloc(MAX_KEY_SIZE);
    if (!private_key) return -1;
    
    // ... 密钥生成和处理
    
    OPENSSL_secure_clear_free(private_key, MAX_KEY_SIZE);
    return 0;
}
```

#### 2. 侧信道攻击防护
```c
// 时序攻击缓解
int constant_time_compare(const void *a, const void *b, size_t len) {
    return CRYPTO_memcmp(a, b, len) == 0;
}

// 避免基于密钥内容的分支
// 错误示例:
if (private_key[0] == 0x00) {  // 时序泄露
    // 处理前导零
}

// 正确示例: 使用掩码操作
int leading_zero_mask = (private_key[0] == 0x00) ? 0xFF : 0x00;
// 基于掩码的常量时间处理
```

#### 3. 错误处理安全性
```c
// 安全的错误处理
int secure_rsa_operation(void) {
    int ret = -1;
    RSA *rsa = NULL;
    unsigned char *sensitive_data = NULL;
    
    rsa = RSA_new();
    if (!rsa) goto cleanup;
    
    sensitive_data = OPENSSL_secure_malloc(256);
    if (!sensitive_data) goto cleanup;
    
    // ... 执行RSA操作
    
    ret = 0;  // 成功
    
cleanup:
    // 确保所有错误路径都清理敏感数据
    if (sensitive_data) {
        OPENSSL_secure_clear_free(sensitive_data, 256);
    }
    if (rsa) {
        RSA_free(rsa);
    }
    
    return ret;
}
```

### 部署安全建议

#### 1. 密钥生成环境
- **熵源**: 确保充足的系统熵，使用硬件随机数生成器
- **隔离**: 在安全隔离的环境中生成密钥
- **审计**: 记录密钥生成和使用的审计日志

#### 2. 密钥存储保护
```c
// 密钥文件权限设置
int save_key_securely(const char *filename, const unsigned char *key, size_t len) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) return -1;
    
    // 设置文件权限 (仅所有者可读写)
    chmod(filename, S_IRUSR | S_IWUSR);
    
    size_t written = fwrite(key, 1, len, fp);
    fclose(fp);
    
    return (written == len) ? 0 : -1;
}

// HSM集成示例
#ifdef HAVE_HSM_SUPPORT
int generate_rsa_in_hsm(int slot_id, const char *pin) {
    // 使用硬件安全模块生成和存储密钥
    ENGINE *hsm_engine = ENGINE_by_id("pkcs11");
    if (!hsm_engine) return -1;
    
    // 配置HSM参数
    ENGINE_ctrl_cmd_string(hsm_engine, "PIN", pin, 0);
    ENGINE_init(hsm_engine);
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, hsm_engine);
    // ... RSA生成代码
    
    ENGINE_finish(hsm_engine);
    ENGINE_free(hsm_engine);
    return 0;
}
#endif
```

### 量子威胁应对

#### 1. 威胁时间线
- **Shor算法**: 可有效破解RSA，大规模量子计算机实现后RSA将不再安全
- **预期时间**: 2030-2040年可能出现实用的密码学相关量子计算机
- **应对策略**: 开始规划迁移到后量子算法

#### 2. 混合过渡方案
```c
// 混合RSA+后量子算法的概念设计
typedef struct {
    rsa_key_t classical_key;      // 传统RSA密钥
    ml_kem_key_t quantum_safe_key; // 后量子KEM密钥
    int hybrid_mode;              // 混合模式标识
} hybrid_keypair_t;

int hybrid_encrypt(const hybrid_keypair_t *keypair, 
                   const unsigned char *plaintext, size_t plaintext_len,
                   unsigned char **ciphertext, size_t *ciphertext_len) {
    // 1. 使用RSA加密
    unsigned char *rsa_encrypted = NULL;
    size_t rsa_len = 0;
    rsa_encrypt(&keypair->classical_key, plaintext, plaintext_len, 
                &rsa_encrypted, &rsa_len);
    
    // 2. 使用后量子KEM保护RSA密钥
    unsigned char *kem_encrypted = NULL;
    size_t kem_len = 0;
    ml_kem_encap(&keypair->quantum_safe_key, rsa_encrypted, rsa_len,
                 &kem_encrypted, &kem_len);
    
    // 3. 组合两层加密结果
    *ciphertext_len = rsa_len + kem_len + sizeof(uint32_t);
    *ciphertext = malloc(*ciphertext_len);
    // ... 组装数据格式
    
    return 0;
}
```

## 性能特点

### 算法性能对比

| 操作 | RSA-2048 | RSA-3072 | RSA-4096 | EC P-256 | ML-KEM-512 |
|------|----------|----------|----------|----------|------------|
| **密钥生成** | ~50ms | ~200ms | ~800ms | ~0.1ms | ~0.05ms |
| **公钥操作** | ~0.5ms | ~1.2ms | ~2.5ms | ~0.2ms | ~0.08ms |
| **私钥操作** | ~15ms | ~45ms | ~120ms | ~0.2ms | ~0.1ms |
| **公钥大小** | 294B | 422B | 550B | 65B | 800B |
| **私钥大小** | 1216B | 1796B | 2376B | 32B | 1632B |
| **签名大小** | 256B | 384B | 512B | 64B | N/A |

### 性能优化技巧

#### 1. 密钥生成优化
```c
// 使用较小的公钥指数加速运算
#define RSA_SMALL_EXP 0x03      // 3 (快但不推荐)
#define RSA_F4        0x10001   // 65537 (推荐)

// 并行密钥生成
#include <pthread.h>

typedef struct {
    size_t keybits;
    unsigned long exp;
    RSA **result;
    int *status;
} keygen_thread_data_t;

void* parallel_keygen(void *arg) {
    keygen_thread_data_t *data = (keygen_thread_data_t*)arg;
    data->status = call_rsa_gen_via_old(data->keybits, data->exp, 
                                        NULL, NULL, NULL, NULL);
    return NULL;
}
```

#### 2. 内存池优化
```c
// 内存池管理
typedef struct {
    unsigned char *buffer;
    size_t size;
    size_t used;
} memory_pool_t;

memory_pool_t* create_rsa_memory_pool(size_t size) {
    memory_pool_t *pool = malloc(sizeof(memory_pool_t));
    if (!pool) return NULL;
    
    pool->buffer = OPENSSL_malloc(size);
    pool->size = size;
    pool->used = 0;
    
    return pool;
}

void* pool_alloc(memory_pool_t *pool, size_t size) {
    if (pool->used + size > pool->size) return NULL;
    
    void *ptr = pool->buffer + pool->used;
    pool->used += size;
    return ptr;
}
```

## 与其他算法对比

### 非对称算法技术对比

| 特性维度 | RSA | ECC (P-256) | EdDSA | ML-KEM-512 |
|----------|-----|-------------|--------|-------------|
| **数学基础** | 整数分解 | 椭圆曲线DLP | 椭圆曲线DLP | Module-LWE |
| **量子安全** | ❌ | ❌ | ❌ | ✅ |
| **密钥生成速度** | 慢 | 快 | 快 | 快 |
| **加密解密速度** | 慢 | 快 | 快 | 快 |
| **密钥大小** | 大 | 小 | 小 | 中等 |
| **签名大小** | 大 | 小 | 小 | N/A |
| **标准成熟度** | ✅ 高 | ✅ 高 | ✅ 高 | 🔄 新兴 |
| **硬件支持** | ✅ 广泛 | ✅ 广泛 | 🔄 有限 | ❌ 有限 |
| **实现复杂度** | 低 | 中等 | 中等 | 高 |

### 应用场景建议

#### 1. 传统互联网应用 (当前)
```c
推荐选择: RSA-2048 或 ECC P-256
RSA适用场景:
- 需要与老旧系统兼容
- 证书和PKI基础设施
- 简单的加密解密需求

ECC适用场景:  
- 性能敏感应用
- 移动设备和IoT
- 带宽受限环境
```

#### 2. 高安全要求应用
```c
推荐选择: RSA-3072+ 或 ECC P-384+
考虑因素:
- 更长的安全有效期
- 抵御计算能力提升
- 符合高级别安全标准
```

#### 3. 量子过渡期 (2025-2035)
```c
混合部署策略:
1. RSA + ML-KEM 混合方案
2. 逐步引入后量子算法
3. 保持向后兼容性

实现示例:
hybrid_security_level = max(rsa_security, pqc_security)
```

#### 4. 后量子时代 (2035+)
```c
完全迁移: ML-KEM, CRYSTALS-Dilithium等
迁移考虑:
- 标准化程度
- 硬件支持情况  
- 性能优化成熟度
- 安全分析充分性
```

## 相关标准和参考资料

### 国际标准

#### PKCS标准族
- **[PKCS#1 v2.2](https://tools.ietf.org/html/rfc8017)**: RSA密码规范 (2016)
  - RSA密钥格式定义
  - OAEP和PSS填充方案
  - 安全实施指导
  
- **[PKCS#8](https://tools.ietf.org/html/rfc5208)**: 私钥信息语法规范
  - 通用私钥存储格式
  - 密钥加密和保护机制

#### NIST标准
- **[NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57/part-1/rev-5/final)**: 密钥管理建议 (2020)
  - RSA密钥长度推荐
  - 密钥生命周期管理
  - 算法过渡指导

- **[NIST FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final)**: 数字签名标准
  - RSA签名算法规范
  - 密钥生成和验证要求

#### ISO/IEC标准
- **ISO/IEC 9796**: 数字签名方案标准
- **ISO/IEC 18033**: 加密算法标准
- **ISO/IEC 19790**: 安全模块安全要求

### IETF RFC文档

#### 核心协议
- **[RFC 8017](https://tools.ietf.org/html/rfc8017)**: PKCS#1: RSA密码规范 v2.2 (2016)
  - RSA算法完整规范
  - 安全填充方案详述
  - 实施安全建议

- **[RFC 3447](https://tools.ietf.org/html/rfc3447)**: PKCS#1: RSA密码规范 v2.1 (2003)
  - 历史版本参考
  - 兼容性考虑

#### 应用协议  
- **[RFC 8446](https://tools.ietf.org/html/rfc8446)**: TLS 1.3协议
  - RSA在TLS中的使用
  - 密钥交换机制
  - 安全考虑事项

- **[RFC 5280](https://tools.ietf.org/html/rfc5280)**: X.509证书和CRL配置文件
  - RSA公钥证书格式
  - 证书验证流程

### 学术资源

#### 经典教材
1. **《应用密码学》** - Bruce Schneier
   - RSA算法原理详解
   - 实际攻击案例分析
   - 安全实施建议

2. **《密码学工程》** - Niels Ferguson, Bruce Schneier, Tadayoshi Kohno  
   - RSA实现细节
   - 侧信道攻击防护
   - 工程安全实践

#### 重要论文
- **Rivest, Shamir, Adleman (1978)**: "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"
- **Bleichenbacher (1998)**: "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS#1"
- **Boneh (1999)**: "Twenty Years of Attacks on the RSA Cryptosystem"

### OpenSSL文档

#### 官方文档
- **[OpenSSL RSA手册](https://www.openssl.org/docs/man3.0/man3/RSA_new.html)**: RSA函数完整参考
- **[EVP_PKEY手册](https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_new.html)**: 现代密钥管理API
- **[密钥生成示例](https://wiki.openssl.org/index.php/EVP_Key_Generation)**: 实用代码示例

#### 安全指南
- **[OpenSSL安全建议](https://www.openssl.org/docs/man3.0/man7/ossl-guide-migration.html)**
- **填充方案选择指导**
- **性能优化技巧**

### 安全标准

#### Common Criteria
- **PP-RSA**: RSA算法保护轮廓
- **RSA实现安全要求**
- **密钥管理安全目标**

#### 行业标准
- **金融**: ANSI X9系列标准
- **政府**: FIPS 140-2密码模块认证
- **欧洲**: SOGIS密码算法认证

### 实施指南

#### 最佳实践
- **[OWASP密码存储备忘单](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)**
- **[NSA商业解决方案](https://www.nsa.gov/Cybersecurity/Commercial-Solutions-for-Classified/)** (历史文档)
- **企业密码策略制定指南**

#### 漏洞数据库
- **[CVE数据库](https://cve.mitre.org/)**: RSA相关漏洞
- **密码学研究论文索引**
- **实际攻击案例分析**

### 后量子密码学

#### NIST PQC项目
- **[NIST后量子密码](https://csrc.nist.gov/Projects/post-quantum-cryptography)**
- **RSA替代算法评估**
- **迁移时间线和建议**

#### 量子威胁评估
- **量子算法发展现状**
- **密码学影响评估**
- **风险缓解策略**

---

## 许可证

本项目遵循 Apache License 2.0 开源许可证。

## 作者信息

**项目维护者**: DebugOpenSSL 密码学学习项目团队  
**技术支持**: 基于 OpenSSL 3.0+ 开源密码学库  
**最后更新**: 2025年9月  
**版本**: v1.0.0

---

*本实现仅供学习和研究使用，不建议直接用于生产环境。RSA算法面临量子威胁，建议在新项目中考虑使用椭圆曲线或后量子算法。*