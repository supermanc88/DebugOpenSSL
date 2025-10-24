# DES 加密模式完整指南

本文档详细介绍 OpenSSL 中 DES (Data Encryption Standard) 及其变体的使用方法、差异对比和注意事项。

## ⚠️ 重要安全警告

**DES 已不再安全，不应在生产环境中使用！**

- **DES (56位密钥)** 在1990年代后期就已被证明可被暴力破解
- **3DES** 虽然更安全，但性能较差且也在逐步淘汰
- **推荐使用 AES** 作为替代方案

本文档仅用于：
- 教学和学习目的
- 维护遗留系统
- 理解加密算法演进历史

---

## 目录

- [DES 概述](#des-概述)
- [DES 基础模式](#des-基础模式)
  - [ECB 模式](#ecb-模式)
  - [CBC 模式](#cbc-模式)
  - [CFB 模式](#cfb-模式)
  - [CFB 变体 (CFB1, CFB8, CFB64)](#cfb-变体)
  - [OFB 模式](#ofb-模式)
- [DES 增强版本](#des-增强版本)
  - [DESX](#desx)
- [3DES (Triple DES)](#3des-triple-des)
  - [3DES 基本概念](#3des-基本概念)
  - [3DES 额外模式](#3des-额外模式)
- [模式对比](#模式对比)
- [DES vs AES](#des-vs-aes)
- [常见错误](#常见错误)
- [最佳实践](#最佳实践)

---

## DES 概述

### ⚠️ OpenSSL 3.x 重要说明

**在 OpenSSL 3.0 及更高版本中，DES 被归类为遗留算法**，需要显式加载 legacy provider 才能使用：

```c
#include <openssl/provider.h>

// 加载 legacy 和 default provider
OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");

if (!legacy || !deflt) {
    fprintf(stderr, "Failed to load providers\n");
    return -1;
}

// 现在可以使用 DES
const EVP_CIPHER *cipher = EVP_des_cbc();

// 使用完后卸载 providers
OSSL_PROVIDER_unload(legacy);
OSSL_PROVIDER_unload(deflt);
```

**环境变量设置**：

```bash
# 运行 DES 程序需要设置 OPENSSL_MODULES 指向 providers 目录
export OPENSSL_MODULES=/path/to/openssl/providers
```

这进一步证明了 DES 已经过时，连 OpenSSL 都将其标记为遗留算法。

### 算法特性

| 特性 | DES | 3DES | AES-128 (对比) |
|------|-----|------|---------------|
| 密钥长度 | 56 位 (8字节) | 168 位 (24字节) | 128 位 (16字节) |
| 块大小 | 64 位 (8字节) | 64 位 (8字节) | 128 位 (16字节) |
| 安全性 | ❌ 不安全 | ⚠️ 勉强 | ✅ 安全 |
| 性能 | 🐢 慢 | 🐢🐢🐢 很慢 | 🚀 快 |
| 推荐使用 | ❌ 否 | ❌ 否 | ✅ 是 |

### 密钥格式

DES 使用 8 字节密钥，但实际有效密钥长度只有 56 位：
- 每个字节的最低位用作奇偶校验位
- 实际加密强度：2^56 ≈ 7.2 × 10^16

```c
// DES 密钥示例 (8 字节 = 64 位，其中 56 位有效)
unsigned char des_key[8] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};
```

---

## DES 基础模式

### ECB 模式

**Electronic Codebook Mode** - 电子密码本模式

#### 特性

- 最简单的 DES 工作模式
- 每个 8 字节块独立加密
- **不使用 IV**
- **严重安全漏洞**：相同明文产生相同密文

#### 实现示例

```c
const EVP_CIPHER *cipher = EVP_des_ecb();
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// 初始化（无 IV）
EVP_EncryptInit_ex(ctx, cipher, NULL, des_key, NULL);

// 设置填充
EVP_CIPHER_CTX_set_padding(ctx, 1);  // PKCS7 填充

// 加密
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### 安全警告

❌ **永远不要在生产环境使用 ECB 模式**
- 相同的 8 字节明文块产生相同的密文块
- 容易泄露数据模式
- 著名的 "ECB 企鹅图" 展示了其缺陷

---

### CBC 模式

**Cipher Block Chaining Mode** - 密码块链接模式

#### 特性

- 每个明文块与前一个密文块 XOR 后再加密
- **需要 8 字节 IV**
- 加密必须顺序进行
- 解密可以并行
- 相对安全（配合 MAC 使用）

#### 实现示例

```c
unsigned char des_iv[8] = { /* 8字节随机IV */ };
const EVP_CIPHER *cipher = EVP_des_cbc();
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// 初始化（必须提供 IV）
EVP_EncryptInit_ex(ctx, cipher, NULL, des_key, des_iv);

// CBC 使用 PKCS7 填充
EVP_CIPHER_CTX_set_padding(ctx, 1);

// 加密
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);

// 解密时使用相同的 IV
EVP_DecryptInit_ex(ctx, cipher, NULL, des_key, des_iv);
EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len);
```

#### 注意事项

⚠️ **IV 必须随机且不可重用**
⚠️ **需要配合 MAC 防止篡改**
⚠️ **容易受到填充预言攻击**

---

### CFB 模式

**Cipher Feedback Mode** - 密码反馈模式

#### 特性

- 将块密码变为流密码
- **需要 8 字节 IV**
- 可以处理小于块大小的数据
- 不需要填充
- 错误会传播有限的块

#### 实现示例

```c
unsigned char des_iv[8] = { /* 8字节随机IV */ };
const EVP_CIPHER *cipher = EVP_des_cfb64();  // 64位反馈
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// 初始化
EVP_EncryptInit_ex(ctx, cipher, NULL, des_key, des_iv);

// CFB 不需要填充
EVP_CIPHER_CTX_set_padding(ctx, 0);

// 加密（可以处理任意长度）
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### 适用场景

✅ 流式数据加密
✅ 数据长度不是块大小倍数
⚠️ 仍需配合 MAC 使用

---

### CFB 变体

DES 的 CFB 模式支持不同的反馈位数，提供不同粒度的流密码操作。

#### CFB1 - 1位反馈模式

**特性**：
- 每次处理 1 位数据
- 最细粒度的 CFB 模式
- 适合比特流加密
- 性能最慢

```c
const EVP_CIPHER *cipher = EVP_des_cfb1();
EVP_EncryptInit_ex(ctx, cipher, NULL, des_key, des_iv);
EVP_CIPHER_CTX_set_padding(ctx, 0);  // 不需要填充
```

#### CFB8 - 8位反馈模式

**特性**：
- 每次处理 1 字节（8位）
- 字节流加密
- 常用于字符数据加密
- 性能居中

```c
const EVP_CIPHER *cipher = EVP_des_cfb8();
EVP_EncryptInit_ex(ctx, cipher, NULL, des_key, des_iv);
EVP_CIPHER_CTX_set_padding(ctx, 0);  // 不需要填充
```

#### CFB64 - 64位反馈模式（标准 CFB）

**特性**：
- 每次处理 8 字节（64位，一个 DES 块）
- 标准的 CFB 模式
- 性能最好
- 最常用的 CFB 变体

```c
const EVP_CIPHER *cipher = EVP_des_cfb64();
// 或者使用宏
const EVP_CIPHER *cipher = EVP_des_cfb();
EVP_EncryptInit_ex(ctx, cipher, NULL, des_key, des_iv);
EVP_CIPHER_CTX_set_padding(ctx, 0);  // 不需要填充
```

#### CFB 变体对比

| 变体 | 反馈位数 | 处理单位 | 性能 | 适用场景 |
|------|---------|---------|------|---------|
| CFB1 | 1 位 | 1 位 | 🐢 最慢 | 比特流 |
| CFB8 | 8 位 | 1 字节 | 🐢🐢 较慢 | 字符流 |
| CFB64 | 64 位 | 8 字节 | 🚀 最快 | 通用（推荐） |

---

### OFB 模式

**Output Feedback Mode** - 输出反馈模式

#### 特性

- 将块密码变为同步流密码
- **需要 8 字节 IV**
- 加密和解密操作相同
- 不需要填充
- 错误不会传播

#### 实现示例

```c
unsigned char des_iv[8] = { /* 8字节随机IV */ };
const EVP_CIPHER *cipher = EVP_des_ofb();
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// 初始化
EVP_EncryptInit_ex(ctx, cipher, NULL, des_key, des_iv);

// OFB 不需要填充
EVP_CIPHER_CTX_set_padding(ctx, 0);

// 加密和解密使用相同操作
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### 安全警告

❌ **IV 重用会导致灾难性失败**
- 两条消息使用相同 IV 可以通过 XOR 恢复明文
- 必须确保每次加密使用唯一 IV

---

## DES 增强版本

### DESX

**DESX (DES-X)** 是 DES 的增强版本，通过密钥白化技术提高安全性。

#### 概述

DESX 于 1984 年由 Ron Rivest 提出，通过在 DES 加密前后进行 XOR 操作来增强安全性。

**工作原理**：
```
密文 = (明文 ⊕ K1) DES(K2) (⊕ K3)
```

其中：
- K1: 8字节输入白化密钥
- K2: 8字节标准 DES 密钥
- K3: 8字节输出白化密钥

#### 密钥结构

```c
// DESX 使用 24 字节密钥
unsigned char desx_key[24] = {
    // K2: DES 密钥 (8字节)
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    // K1 + K3: 额外密钥材料 (16字节)
    0xf1, 0xe0, 0xd3, 0xc2, 0xb5, 0xa4, 0x97, 0x86,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};
```

#### 实现示例

```c
const EVP_CIPHER *cipher = EVP_desx_cbc();
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// 初始化（密钥长度为 24 字节）
EVP_EncryptInit_ex(ctx, cipher, NULL, desx_key, des_iv);
EVP_CIPHER_CTX_set_padding(ctx, 1);

// 加密
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### 安全性分析

| 特性 | DES | DESX | 3DES |
|------|-----|------|------|
| 有效密钥长度 | 56 位 | ~120 位 | 112-168 位 |
| 性能 | 🚀 快 | 🚀 快 | 🐢 慢（3倍） |
| 安全性 | ❌ 不安全 | ⚠️ 勉强 | ⚠️ 较好 |
| 标准化 | ✅ FIPS 46-3 | 🟡 非官方 | ✅ NIST SP 800-67 |

#### 优缺点

**优点** ✅：
- 比 DES 更安全（有效密钥长度增加）
- 性能接近 DES（比 3DES 快约 3 倍）
- 向后兼容 DES（可以设置 K1=K3=0）
- 实现简单

**缺点** ❌：
- 不是正式标准
- 仍然基于 DES（块大小仅 64 位）
- 密钥管理复杂
- 已被证明存在相关密钥攻击

#### 适用场景

⚠️ **不推荐用于新系统**

仅适用于：
- 需要兼容遗留 DES 系统但需要增强安全性
- 无法升级到 3DES 或 AES 的场景
- 性能敏感但 DES 不够安全的过渡方案

**更好的选择**：直接使用 AES-128

---

## 3DES (Triple DES)

### 3DES 基本概念

3DES 通过三次应用 DES 算法来增强安全性：
1. **加密** 使用密钥 K1
2. **解密** 使用密钥 K2
3. **加密** 使用密钥 K3

### 密钥选项

| 选项 | 密钥配置 | 有效强度 | 描述 |
|------|---------|---------|------|
| 3DES-EDE3 | K1 ≠ K2 ≠ K3 | 168 位 | 三个独立密钥（推荐） |
| 3DES-EDE2 | K1 ≠ K2, K3=K1 | 112 位 | 两个独立密钥 |
| 3DES-EDE  | K1 = K2 = K3 | 56 位 | 等同于 DES（不推荐） |

### 实现示例

```c
// 3DES 密钥 (24 字节 = 192 位)
unsigned char des3_key[24] = {
    // K1 (8字节)
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    // K2 (8字节)
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    // K3 (8字节)
    0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67
};

unsigned char des_iv[8] = { /* 8字节随机IV */ };

// 3DES-CBC 模式
const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// 初始化
EVP_EncryptInit_ex(ctx, cipher, NULL, des3_key, des_iv);
EVP_CIPHER_CTX_set_padding(ctx, 1);

// 加密
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

### 3DES 变体

OpenSSL 支持的 3DES 算法：

```c
// 3-key 3DES (EDE3) - 168 位密钥（推荐）
EVP_des_ede3_cbc()      // 3DES-EDE3-CBC
EVP_des_ede3_ecb()      // 3DES-EDE3-ECB（不推荐）
EVP_des_ede3_cfb64()    // 3DES-EDE3-CFB64
EVP_des_ede3_cfb8()     // 3DES-EDE3-CFB8
EVP_des_ede3_cfb1()     // 3DES-EDE3-CFB1
EVP_des_ede3_ofb()      // 3DES-EDE3-OFB
EVP_des_ede3_wrap()     // 3DES-EDE3 Key Wrapping (RFC 3217)
EVP_des_ede3()          // 3DES-EDE3 (等同于 EDE3-ECB)

// 2-key 3DES (EDE) - 128 位密钥
EVP_des_ede_cbc()       // 2-key 3DES-CBC
EVP_des_ede_ecb()       // 2-key 3DES-ECB（不推荐）
EVP_des_ede_cfb64()     // 2-key 3DES-CFB64
EVP_des_ede_ofb()       // 2-key 3DES-OFB
EVP_des_ede()           // 2-key 3DES (等同于 EDE-ECB)
```

#### 3-key vs 2-key 3DES

| 特性 | 2-key 3DES (EDE) | 3-key 3DES (EDE3) |
|------|------------------|-------------------|
| 密钥长度 | 128 位 (16 字节) | 192 位 (24 字节) |
| 有效强度 | 112 位 | 168 位 |
| 加密过程 | E(K1) → D(K2) → E(K1) | E(K1) → D(K2) → E(K3) |
| 安全性 | 🟡 中等 | ✅ 较高 |
| 推荐使用 | ⚠️ 仅遗留系统 | ✅ 如必须用 3DES |

**注意**：即使是 3-key 3DES 也正在被淘汰，建议迁移到 AES。

### 3DES 额外模式

除了 CBC 模式，3DES 还支持其他工作模式：

#### 3DES-ECB 模式

```c
const EVP_CIPHER *cipher = EVP_des_ede3_ecb();
EVP_EncryptInit_ex(ctx, cipher, NULL, des3_key, NULL);  // 无 IV
EVP_CIPHER_CTX_set_padding(ctx, 1);
```

❌ **警告**：与 DES-ECB 相同的安全问题，不要使用！

#### 3DES-OFB 模式

```c
unsigned char des_iv[8] = { /* 8字节随机IV */ };
const EVP_CIPHER *cipher = EVP_des_ede3_ofb();
EVP_EncryptInit_ex(ctx, cipher, NULL, des3_key, des_iv);
EVP_CIPHER_CTX_set_padding(ctx, 0);  // 不需要填充
```

**特点**：
- 流密码模式
- 错误不传播
- IV 重用会导致灾难性失败

#### 3DES-CFB 模式变体

3DES 也支持不同的 CFB 反馈位数：

```c
// CFB64 (标准)
const EVP_CIPHER *cipher = EVP_des_ede3_cfb64();

// CFB8 (字节流)
const EVP_CIPHER *cipher = EVP_des_ede3_cfb8();

// CFB1 (比特流)
const EVP_CIPHER *cipher = EVP_des_ede3_cfb1();

EVP_EncryptInit_ex(ctx, cipher, NULL, des3_key, des_iv);
EVP_CIPHER_CTX_set_padding(ctx, 0);  // 不需要填充
```

#### 3DES 模式对比

| 模式 | 需要IV | 需要填充 | 性能 | 安全性 | 推荐使用 |
|------|-------|---------|------|--------|---------|
| ECB | ❌ | ✅ | 快 | ❌ 差 | ❌ 否 |
| CBC | ✅ | ✅ | 中 | ✅ 好 | ✅ 是 |
| CFB64 | ✅ | ❌ | 中 | ✅ 好 | ✅ 是 |
| CFB8 | ✅ | ❌ | 慢 | ✅ 好 | 🟡 可选 |
| CFB1 | ✅ | ❌ | 很慢 | ✅ 好 | 🟡 特殊场景 |
| OFB | ✅ | ❌ | 中 | ✅ 好 | ✅ 是 |

### 3DES 模式选择建议

```
需要 3DES 加密？
├─ 需要认证？
│  └─ 使用 3DES-CBC + HMAC（没有 AEAD 模式）
├─ 块加密？
│  └─ 使用 3DES-CBC
├─ 流式数据？
│  ├─ 字节流 → 使用 3DES-CFB8
│  └─ 块流 → 使用 3DES-CFB64 或 3DES-OFB
├─ 密钥包裹？
│  └─ 使用 3DES-WRAP (RFC 3217)
└─ 永远不要使用 3DES-ECB
```

### 3DES Key Wrapping 模式

3DES Key Wrapping (`EVP_des_ede3_wrap()`) 是一种特殊的密钥包裹算法，用于安全地传输或存储其他密钥。

#### 特点

```c
const EVP_CIPHER *cipher = EVP_des_ede3_wrap();

// 要包裹的密钥（必须是 8 字节的倍数）
unsigned char key_to_wrap[16] = { /* AES-128 密钥 */ };
unsigned char wrapped_key[32];  // 输出会比输入长

// Key Encryption Key (KEK) - 用于包裹的密钥
unsigned char kek[24] = { /* 24字节 3DES 密钥 */ };

// 包裹密钥
EVP_EncryptInit_ex(ctx, cipher, NULL, kek, NULL);  // 不需要 IV
EVP_EncryptUpdate(ctx, wrapped_key, &len, key_to_wrap, 16);
EVP_EncryptFinal_ex(ctx, wrapped_key + len, &final_len);

// 包裹后长度 = 原长度 + 8 字节（完整性校验值 + padding）
```

**关键特性**：
- ✅ 提供**机密性**保护（加密）
- ✅ 提供**完整性**保护（自动添加 ICV）
- ✅ 符合 RFC 3217 标准
- ⚠️ 输入必须是 8 字节的倍数
- ⚠️ 任何篡改都会导致解包裹失败

**使用场景**：
- 密钥分发系统
- 密钥备份和恢复
- PKI 系统中的密钥传输
- HSM (硬件安全模块) 密钥导入/导出

**注意**：虽然提供完整性保护，但 3DES 本身已不够安全，推荐使用 **AES Key Wrap (RFC 3394)**。

### 性能考虑

⚠️ **3DES 比 DES 慢约 3 倍**
⚠️ **3DES 比 AES-128 慢约 10 倍**

---

## 模式对比

### 安全特性

| 模式 | 需要IV | IV重用后果 | 需要填充 | 并行加密 | 并行解密 |
|------|-------|-----------|---------|---------|---------|
| ECB | ❌ | N/A | ✅ | ✅ | ✅ |
| CBC | ✅ | 信息泄露 | ✅ | ❌ | ✅ |
| CFB | ✅ | 灾难性 | ❌ | ❌ | 🟡 |
| OFB | ✅ | 灾难性 | ❌ | ❌ | ❌ |

### 使用场景

| 场景 | 推荐模式 | 说明 |
|------|---------|------|
| 新项目 | ❌ 不使用 DES | 使用 AES-GCM |
| 遗留系统 | CBC + HMAC | 如果必须使用 DES |
| 文件加密 | CBC + HMAC | 配合认证 |
| 流式数据 | CFB/OFB + HMAC | 配合认证 |

---

## DES vs AES

### 为什么应该使用 AES？

| 特性 | DES | 3DES | AES-128 |
|------|-----|------|---------|
| 密钥长度 | 56 位 | 168 位 | 128 位 |
| 块大小 | 64 位 | 64 位 | 128 位 |
| 轮数 | 16 | 48 | 10 |
| 已知攻击 | ✅ 多种 | 🟡 少量 | ❌ 很少 |
| 硬件加速 | 🟡 有限 | 🟡 有限 | ✅ AES-NI |
| 标准化 | ⚠️ 已废弃 | ⚠️ 逐步淘汰 | ✅ 现行标准 |

### 迁移建议

```c
// ❌ 旧代码 (DES)
EVP_CIPHER *cipher = EVP_des_cbc();
unsigned char key[8] = { /* 8字节密钥 */ };
unsigned char iv[8] = { /* 8字节IV */ };

// ✅ 新代码 (AES)
EVP_CIPHER *cipher = EVP_aes_128_cbc();
unsigned char key[16] = { /* 16字节密钥 */ };
unsigned char iv[16] = { /* 16字节IV */ };

// 更好的选择：使用 AES-GCM (认证加密)
EVP_CIPHER *cipher = EVP_aes_128_gcm();
```

---

## 常见错误

### 1. 使用 DES 进行新开发

```c
// ❌ 错误：使用 DES 开发新系统
EVP_CIPHER *cipher = EVP_des_cbc();

// ✅ 正确：使用 AES
EVP_CIPHER *cipher = EVP_aes_256_gcm();
```

**原因**：DES 的 56 位密钥可以在几小时内被暴力破解。

### 2. 重用 IV

```c
// ❌ 错误：固定的 IV
unsigned char iv[8] = {0, 0, 0, 0, 0, 0, 0, 0};
for (int i = 0; i < 100; i++) {
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);  // 重用 IV
}

// ✅ 正确：每次生成新 IV
for (int i = 0; i < 100; i++) {
    unsigned char iv[8];
    RAND_bytes(iv, sizeof(iv));
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
}
```

### 3. 使用 ECB 模式

```c
// ❌ 错误：使用 ECB
EVP_CIPHER *cipher = EVP_des_ecb();

// ✅ 正确：使用 CBC 或其他模式
EVP_CIPHER *cipher = EVP_des_cbc();
// 更好：使用 AES-GCM
EVP_CIPHER *cipher = EVP_aes_256_gcm();
```

### 4. 忘记认证

```c
// ❌ 错误：仅加密，无认证
EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv);
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

// ✅ 正确：加密 + HMAC
// 或者直接使用 AES-GCM
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce);
```

### 5. 弱密钥检测

DES 有一些已知的弱密钥和半弱密钥：

```c
// DES 弱密钥示例（不要使用）
unsigned char weak_keys[][8] = {
    {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},  // 全0奇偶
    {0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE},  // 全1奇偶
    {0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1},  // 半弱密钥
    // ... 共有 16 个弱密钥和半弱密钥
};

// ✅ 使用随机生成的密钥
unsigned char key[8];
RAND_bytes(key, sizeof(key));
```

---

## 最佳实践

### 1. 不要使用 DES

```
第一条规则：不要使用 DES
第二条规则：真的不要使用 DES
第三条规则：如果必须使用，至少用 3DES，并计划尽快迁移
```

### 2. 如果被迫使用 DES

```c
// 最低安全要求
void secure_des_encrypt(
    const unsigned char *plaintext, size_t plaintext_len,
    unsigned char *ciphertext, size_t *ciphertext_len,
    const unsigned char *key, unsigned char *iv
) {
    // 1. 使用 CBC 模式（不要用 ECB）
    const EVP_CIPHER *cipher = EVP_des_cbc();
    
    // 2. 生成随机 IV
    RAND_bytes(iv, 8);
    
    // 3. 加密
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    int final_len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
    *ciphertext_len = len + final_len;
    EVP_CIPHER_CTX_free(ctx);
    
    // 4. 计算 HMAC（必须！）
    // hmac_sha256(key_mac, ciphertext, *ciphertext_len, tag);
    
    // 5. 输出格式：[IV][密文][HMAC]
}
```

### 3. 密钥管理

```c
// ✅ 使用 PBKDF2 从密码派生密钥
unsigned char salt[16];
RAND_bytes(salt, sizeof(salt));

unsigned char key[8];  // DES 密钥
PKCS5_PBKDF2_HMAC(
    password, password_len,
    salt, sizeof(salt),
    100000,  // 迭代次数
    EVP_sha256(),
    sizeof(key), key
);
```

### 4. 迁移路径

```c
// 阶段1：立即停止使用 DES-ECB
// 阶段2：DES → 3DES (短期)
// 阶段3：3DES → AES (中期)
// 阶段4：AES-CBC → AES-GCM (长期)

// 最终目标
const EVP_CIPHER *cipher = EVP_aes_256_gcm();
```

---

## 示例代码库

本目录包含以下示例：

### 基础 DES 模式
- `ecb_des.c` - DES-ECB 模式（教学用，不安全）
- `cbc_des.c` - DES-CBC 模式（推荐）
- `cfb_des.c` - DES-CFB64 模式
- `ofb_des.c` - DES-OFB 模式

### DES 扩展模式
- `cfb_variants_des.c` - DES-CFB 变体（CFB1, CFB8, CFB64）
- `desx_cbc.c` - DESX-CBC 增强 DES

### 3-key 3DES 模式（推荐）
- `des3_ede3.c` - **3DES-EDE3 全模式测试**（ECB, CBC, OFB, CFB1/8/64）
- `des3_wrap.c` - 3DES Key Wrapping (RFC 3217)

### 2-key 3DES 模式
- `des_ede_2key.c` - 2-key 3DES 模式测试（ECB, CBC, OFB, CFB64）

### 编译和运行

```bash
# 编译所有 DES 测试
cd build
cmake ..
cmake --build . --target test_des_cbc
cmake --build . --target test_des3_wrap
# ... 或直接 cmake --build . 编译所有

# 设置环境变量（macOS）
export DYLD_LIBRARY_PATH=/path/to/openssl-3.5.2:$DYLD_LIBRARY_PATH
export OPENSSL_MODULES=/path/to/openssl-3.5.2/providers

# 如果使用 no-module 重新编译的 OpenSSL，则无需环境变量
# 详见 STATIC_LINKING.md

# Linux 使用 LD_LIBRARY_PATH
# export LD_LIBRARY_PATH=/path/to/openssl-3.5.2:$LD_LIBRARY_PATH

# 运行测试
./ciphers/test_des_cbc
./ciphers/test_des3_cbc
./ciphers/test_des3_wrap
./ciphers/test_des_ede_2key
```

**注意**：所有 DES 相关算法在 OpenSSL 3.x 中需要加载 legacy 提供者。代码中已包含：
```c
OSSL_PROVIDER_load(NULL, "legacy");
OSSL_PROVIDER_load(NULL, "default");
```

---

## 安全审计清单

在使用 DES 前，确认以下事项：

- [ ] 确认确实需要使用 DES（通常答案是"不需要"）
- [ ] 制定了迁移到 AES 的计划
- [ ] 没有使用 ECB 模式
- [ ] 每次加密都生成新的随机 IV
- [ ] 实现了认证（HMAC 或使用 AEAD）
- [ ] 密钥使用 CSPRNG 生成
- [ ] 密钥安全存储
- [ ] 考虑了弱密钥问题
- [ ] 定期轮换密钥
- [ ] 记录了安全风险和限制

---

## 参考资源

### 标准文档

- FIPS 46-3: DES (已废弃)
- FIPS 197: AES (现行标准)
- NIST SP 800-67: 3DES 使用建议
- NIST SP 800-131A: 过渡建议

### 安全公告

- **2005**: NIST 建议停止使用 DES
- **2017**: NIST 宣布 3DES 将在 2023 年后逐步淘汰
- **2023**: 禁止在新系统中使用 3DES

---

## 总结

### 快速决策

```
需要加密吗？
├─ 新项目
│  └─ 使用 AES-256-GCM（不要用 DES）
├─ 维护遗留系统
│  ├─ 可以升级？
│  │  └─ 迁移到 AES
│  └─ 不能升级？
│     └─ 使用 3DES-CBC + HMAC（临时方案）
└─ 学习目的
   └─ 可以研究 DES，但不要在生产中使用
```

### 关键要点

1. **DES 已过时**：不要在任何新项目中使用
2. **3DES 正在淘汰**：仅作为过渡方案
3. **AES 是标准**：所有新开发应使用 AES
4. **IV 不可重用**：每次加密必须使用新的随机 IV
5. **必须认证**：加密不等于认证，需要 MAC 或 AEAD
6. **避免 ECB**：永远不要使用 ECB 模式

---

*最后更新：2025-10-24*
*安全警告：DES 仅用于教学和遗留系统维护*
