# AES 加密模式完整指南

本文档详细介绍 OpenSSL 中 AES 各种加密模式的使用方法、差异对比和常见陷阱。

## 目录

- [AES 模式概览](#aes-模式概览)
- [基础模式](#基础模式)
  - [ECB 模式](#ecb-模式)
  - [CBC 模式](#cbc-模式)
  - [CFB 模式](#cfb-模式)
  - [OFB 模式](#ofb-模式)
  - [CTR 模式](#ctr-模式)
- [认证加密模式 (AEAD)](#认证加密模式-aead)
  - [GCM 模式](#gcm-模式)
  - [CCM 模式](#ccm-模式)
- [专用模式](#专用模式)
  - [XTS 模式](#xts-模式)
- [模式对比表](#模式对比表)
- [常见错误与陷阱](#常见错误与陷阱)
- [最佳实践](#最佳实践)

---

## AES 模式概览

AES (Advanced Encryption Standard) 是一种对称加密算法，支持多种工作模式。每种模式有不同的特性和适用场景。

### 支持的密钥长度

| 密钥长度 | 位数 | 字节数 | 安全级别 |
|---------|------|--------|---------|
| AES-128 | 128 bit | 16 bytes | 标准安全 |
| AES-192 | 192 bit | 24 bytes | 高安全 |
| AES-256 | 256 bit | 32 bytes | 最高安全 |

**注意**：某些模式（如 XTS）不支持所有密钥长度。

---

## 基础模式

### ECB 模式

**Electronic Codebook Mode** - 电子密码本模式

#### 特性

- **最简单的加密模式**
- 每个明文块独立加密
- 相同的明文块生成相同的密文块
- **不使用 IV**
- **不推荐用于实际应用**（存在严重安全问题）

#### 实现要点

```c
EVP_CIPHER *cipher = EVP_aes_128_ecb();  // 或 192/256
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// 初始化 - 注意：IV 参数为 NULL
EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);

// ECB 模式需要禁用填充或使用 PKCS7 填充
EVP_CIPHER_CTX_set_padding(ctx, 1);  // 1=启用PKCS7, 0=禁用

// 加密
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### 常见陷阱

❌ **严重安全问题**：相同明文产生相同密文，容易暴露数据模式
❌ **不适合加密大于一个块的数据**
❌ **禁止用于生产环境**

#### 适用场景

- ❌ **几乎不应该使用**
- 仅用于教学演示
- 加密随机数据（如密钥材料）

---

### CBC 模式

**Cipher Block Chaining Mode** - 密码块链接模式

#### 特性

- 每个明文块与前一个密文块 XOR 后再加密
- **需要 IV**（初始化向量）
- 加密必须顺序进行
- 解密可以并行
- IV 必须随机且不可预测

#### 实现要点

```c
unsigned char iv[16] = { /* 16字节随机IV */ };
EVP_CIPHER *cipher = EVP_aes_128_cbc();

// 初始化 - 必须提供 IV
EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

// CBC 默认使用 PKCS7 填充
EVP_CIPHER_CTX_set_padding(ctx, 1);  // 通常保持默认

// 加密
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### 常见陷阱

❌ **IV 重用**：使用相同的 IV 加密多条消息会泄露信息
❌ **IV 可预测**：IV 必须随机生成，不能使用递增计数器
⚠️ **填充预言攻击**：需要配合 MAC 使用以防止填充预言攻击
⚠️ **顺序依赖**：加密无法并行化

#### 适用场景

✅ 加密大块数据（配合 MAC）
✅ 文件加密
✅ TLS/SSL（历史上，现在推荐 GCM）

---

### CFB 模式

**Cipher Feedback Mode** - 密码反馈模式

#### 特性

- 将块密码变为流密码
- **需要 IV**
- 加密和解密都使用加密操作
- 可以处理小于块大小的数据
- 错误会传播有限的块

#### 实现要点

```c
unsigned char iv[16] = { /* 16字节随机IV */ };
EVP_CIPHER *cipher = EVP_aes_128_cfb128();  // 128位反馈

// 初始化
EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

// CFB 模式不需要填充
EVP_CIPHER_CTX_set_padding(ctx, 0);

// 加密 - 可以处理任意长度
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### 常见陷阱

❌ **IV 重用**：严重安全问题
⚠️ **无认证**：需要单独的 MAC
⚠️ **位翻转攻击**：攻击者可以翻转密文位来修改明文

#### 适用场景

✅ 流式数据加密
✅ 数据长度不是块大小倍数的场景
✅ 需要自同步的场景

---

### OFB 模式

**Output Feedback Mode** - 输出反馈模式

#### 特性

- 将块密码变为同步流密码
- **需要 IV**
- 加密和解密操作相同
- 不需要填充
- 错误不会传播

#### 实现要点

```c
unsigned char iv[16] = { /* 16字节随机IV */ };
EVP_CIPHER *cipher = EVP_aes_128_ofb();

// 初始化
EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

// OFB 模式不需要填充
EVP_CIPHER_CTX_set_padding(ctx, 0);

// 加密和解密使用相同的操作
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### 常见陷阱

❌ **IV 重用导致灾难性失败**：两条消息 XOR 可恢复明文
❌ **无认证**：容易受到位翻转攻击
⚠️ **密钥流重用**：必须确保 IV 唯一

#### 适用场景

✅ 需要错误不传播的场景
✅ 流式数据加密
❌ 通常不如 CTR 模式

---

### CTR 模式

**Counter Mode** - 计数器模式

#### 特性

- 将块密码变为流密码
- **需要 IV/Nonce + 计数器**
- 加密和解密操作相同
- 可以并行化
- 可以随机访问

#### 实现要点

```c
unsigned char iv[16] = { /* Nonce + Counter */ };
EVP_CIPHER *cipher = EVP_aes_128_ctr();

// 初始化
EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

// CTR 模式不需要填充
EVP_CIPHER_CTX_set_padding(ctx, 0);

// 加密和解密使用相同的操作
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### 常见陷阱

❌ **计数器/Nonce 重用**：与 OFB 相同的灾难性问题
❌ **无认证**：需要配合 MAC 使用
⚠️ **计数器溢出**：需要确保计数器不会循环

#### 适用场景

✅ 高性能加密（可并行）
✅ 磁盘加密
✅ 网络协议（配合 MAC）
✅ 随机访问需求

---

## 认证加密模式 (AEAD)

AEAD (Authenticated Encryption with Associated Data) 模式同时提供加密和认证。

### GCM 模式

**Galois/Counter Mode** - 伽罗瓦计数器模式

#### 特性

- **AEAD 模式**：同时提供加密和认证
- 基于 CTR 模式
- 生成认证标签
- 支持附加认证数据 (AAD)
- 可并行化
- **推荐用于现代应用**

#### 实现要点

**加密流程**：

```c
unsigned char nonce[12] = { /* 12字节随机nonce */ };
unsigned char aad[20] = { /* 附加认证数据 */ };
unsigned char tag[16];  // 认证标签

EVP_CIPHER *cipher = EVP_aes_128_gcm();
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// 1. 初始化（cipher参数必须提供）
EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);

// 2. 设置IV长度（通常12字节）
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);

// 3. 设置密钥和nonce
EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

// 注意：GCM 是流密码模式，不需要填充
// 可以省略此调用，或显式禁用（推荐）
EVP_CIPHER_CTX_set_padding(ctx, 0);

// 4. 设置AAD（可选）
int len;
EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad));

// 5. 加密明文
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

// 6. 完成加密
int final_len;
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);

// 7. 获取认证标签
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
```

**解密流程**：

```c
// 1. 初始化
EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);

// 2. 设置IV长度
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);

// 3. 设置预期的认证标签
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, expected_tag);

// 4. 设置密钥和nonce
EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);

// 注意：GCM 不需要填充，禁用填充（推荐）
EVP_CIPHER_CTX_set_padding(ctx, 0);

// 5. 设置AAD（必须与加密时相同）
EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof(aad));

// 6. 解密密文
EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

// 7. 完成解密并验证标签
if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) <= 0) {
    // 标签验证失败！
    // 必须丢弃所有解密数据
}
```

#### 常见陷阱

❌ **Nonce 重用**：同一个密钥使用相同 nonce 会完全破坏安全性
❌ **忘记设置标签长度**：虽然默认是16字节，但最好显式设置
❌ **AAD 不匹配**：解密时 AAD 必须与加密时完全相同
❌ **标签验证失败后使用数据**：必须在验证成功后才能使用解密数据
⚠️ **不需要设置明文长度**：这是与 CCM 的关键区别

#### 与 CCM 对比

| 特性 | GCM | CCM |
|------|-----|-----|
| 预先设置数据长度 | ❌ 不需要 | ✅ 必须 |
| 并行化 | ✅ 支持 | ❌ 不支持 |
| 性能 | 🚀 更快 | 🐢 较慢 |
| 专利 | ✅ 无专利 | ✅ 无专利 |
| 标准化 | ✅ 广泛 | ✅ 广泛 |

#### 适用场景

✅ **推荐用于所有需要加密+认证的场景**
✅ TLS 1.3
✅ IPsec
✅ 网络协议
✅ 文件加密（需要认证）

---

### CCM 模式

**Counter with CBC-MAC Mode** - 计数器模式配合 CBC-MAC

#### 特性

- **AEAD 模式**：同时提供加密和认证
- 基于 CTR + CBC-MAC
- 生成认证标签
- 支持 AAD
- **必须预先知道明文长度**
- **只能调用一次 EVP_EncryptUpdate 加密数据**（不支持分步加密）
- 不可并行化

#### 实现要点

**加密流程**：

```c
unsigned char nonce[12] = { /* 7-13字节nonce */ };
unsigned char aad[20] = { /* 附加认证数据 */ };
unsigned char tag[16];  // 认证标签

EVP_CIPHER *cipher = EVP_aes_128_ccm();
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// 1. 初始化
EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);

// 2. 设置IV长度（CCM支持7-13字节）
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);

// 3. 设置标签长度（4-16字节，必须是偶数）
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL);

// 4. 设置密钥和nonce（cipher参数设为NULL）
EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

// 注意：CCM 是流密码模式，不需要填充
// 可以调用 EVP_CIPHER_CTX_set_padding(ctx, 0)，但这是可选的
// CCM 模式本身不使用填充机制

// 5. ⚠️ 关键步骤：设置明文长度（CCM特有）
int len;
EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len);

// 6. 设置AAD
EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad));

// 7. 加密明文（⚠️ CCM 只能调用一次！）
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
// ❌ 不能再次调用 EVP_EncryptUpdate 加密更多数据！

// 8. 完成加密
int final_len;
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);

// 9. 获取认证标签
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
```

**解密流程**：

```c
// 1. 初始化
EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);

// 2. 设置IV长度
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);

// 3. 设置预期的认证标签
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, expected_tag);

// 4. 设置密钥和nonce
EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);

// 注意：CCM 是流密码模式，不需要填充（可选调用）

// 5. ⚠️ 关键步骤：设置密文长度（CCM特有）
int len;
EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len);

// 6. 设置AAD
EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof(aad));

// 7. 解密密文（⚠️ CCM 只能调用一次！）
EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
// ❌ 不能再次调用 EVP_DecryptUpdate 解密更多数据！

// 8. 完成解密并验证标签
int final_len;
if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) <= 0) {
    // 标签验证失败！
}
```

#### 常见陷阱

❌ **忘记设置明文/密文长度**：这是 CCM 最常见的错误，会导致加密失败
❌ **明文长度设置错误**：必须精确匹配实际数据长度
❌ **多次调用 EVP_EncryptUpdate 加密数据**：CCM 只能调用一次 Update 来加密，不支持分步加密
❌ **Nonce 重用**：与 GCM 相同的严重问题
⚠️ **第二次 `EVP_EncryptInit_ex` 必须使用 NULL cipher**
⚠️ **填充设置**：CCM 是流密码模式，不使用填充机制（调用 `set_padding` 是允许的但没有效果）

#### 与 GCM 对比

**为什么 CCM 需要预先设置长度？**

CCM 基于 CBC-MAC，需要预先知道消息长度来计算认证标签。GCM 基于 Galois 域乘法，可以增量更新认证标签。

**为什么 CCM 不支持分步加密？**

CCM 的工作流程是先计算整个消息的 CBC-MAC（认证），然后再使用 CTR 模式加密。这要求在加密前必须拥有完整的数据，因此不能像 GCM 那样支持流式/分步处理。

| 特性 | GCM | CCM |
|------|-----|-----|
| 预先设置数据长度 | ❌ 不需要 | ✅ 必须 |
| 分步加密（多次Update） | ✅ 支持 | ❌ 不支持 |
| 并行化 | ✅ 支持 | ❌ 不支持 |
| 性能 | 🚀 更快 | 🐢 较慢 |
| 专利 | ✅ 无专利 | ✅ 无专利 |
| 标准化 | ✅ 广泛 | ✅ 广泛 |

#### 适用场景

✅ 资源受限设备（代码体积小）
✅ IEEE 802.15.4（ZigBee）
✅ Bluetooth Low Energy
⚠️ 如果无特殊限制，推荐使用 GCM

---

## 专用模式

### XTS 模式

**XEX-based Tweaked-codebook mode with ciphertext Stealing** - 基于 XEX 的可调密码本模式

#### 特性

- **专为磁盘/存储加密设计**
- **需要双倍长度密钥**（一个用于加密，一个用于tweak）
- 使用 tweak 值（通常是扇区号）
- 不提供认证
- 不需要填充
- 仅支持 AES-128 和 AES-256

#### 实现要点

```c
// XTS 需要双倍长度的密钥
unsigned char xts_key[32] = {
    // 前16字节：加密密钥
    0x00, 0x01, ..., 0x0f,
    // 后16字节：tweak密钥
    0x10, 0x11, ..., 0x1f
};

unsigned char tweak[16] = { /* 通常是扇区号 */ };

EVP_CIPHER *cipher = EVP_aes_128_xts();  // 或 aes_256_xts
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// 初始化（密钥长度是普通AES的两倍）
EVP_EncryptInit_ex(ctx, cipher, NULL, xts_key, tweak);

// 注意：XTS 不使用填充，必须显式禁用
// 明文长度必须至少16字节（一个AES块）
EVP_CIPHER_CTX_set_padding(ctx, 0);

// 加密（数据长度必须至少16字节）
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### 常见陷阱

❌ **使用标准长度密钥**：必须使用双倍长度（32字节用于128位，64字节用于256位）
❌ **不支持 AES-192**：XTS 只支持 128 和 256 位
❌ **两个子密钥相同**：两部分密钥不能相同（OpenSSL 会检测并报错）
❌ **数据长度小于16字节**：XTS 要求数据至少一个完整块（16字节）
❌ **多次 EVP_EncryptUpdate 分步加密**：XTS 不支持分步加密，必须一次性处理整个数据单元（详见"常见错误与陷阱"章节）
❌ **忘记禁用填充**：必须调用 `EVP_CIPHER_CTX_set_padding(ctx, 0)`，否则可能导致错误
⚠️ **误用于网络传输**：XTS 不提供认证，不适合网络协议
⚠️ **明文长度不是块大小倍数**：虽然 XTS 支持 Ciphertext Stealing，但需要至少16字节

#### 密钥长度对照

| AES 强度 | 单密钥长度 | XTS 总密钥长度 |
|---------|-----------|---------------|
| 128-bit | 16 bytes | 32 bytes |
| 256-bit | 32 bytes | 64 bytes |

#### 适用场景

✅ **磁盘全盘加密**（dm-crypt, BitLocker）
✅ 文件系统加密
✅ SSD/存储设备加密
❌ 网络传输加密（使用 GCM）
❌ 需要认证的场景（使用 GCM/CCM）

---

## 模式对比表

### 安全特性对比

| 模式 | 需要IV | IV重用后果 | 提供认证 | 并行加密 | 并行解密 | 填充需求 | 分步加密 |
|------|-------|-----------|---------|---------|---------|---------|---------|
| ECB | ❌ | N/A | ❌ | ✅ | ✅ | ✅ | ✅ |
| CBC | ✅ | 信息泄露 | ❌ | ❌ | ✅ | ✅ | ✅ |
| CFB | ✅ | 灾难性 | ❌ | ❌ | 🟡 | ❌ | ✅ |
| OFB | ✅ | 灾难性 | ❌ | ❌ | ❌ | ❌ | ✅ |
| CTR | ✅ | 灾难性 | ❌ | ✅ | ✅ | ❌ | ✅ |
| GCM | ✅ | 灾难性 | ✅ | ✅ | ✅ | ❌ | ✅ |
| CCM | ✅ | 灾难性 | ✅ | ❌ | ❌ | ❌ | ❌ |
| XTS | ✅ | 信息泄露 | ❌ | 🟡 | 🟡 | ❌ | ❌ |

**图例**：
- ✅ = 是/支持
- ❌ = 否/不支持
- 🟡 = 部分支持
- 灾难性 = 完全破坏安全性
- 信息泄露 = 泄露部分信息
- **分步加密** = 是否支持多次调用 EVP_EncryptUpdate 加密不同数据块

### 性能对比

| 模式 | 加密速度 | 解密速度 | 内存使用 | CPU指令优化 |
|------|---------|---------|---------|-----------|
| ECB | 🚀🚀🚀 | 🚀🚀🚀 | 最低 | ✅ AES-NI |
| CBC | 🚀 | 🚀🚀🚀 | 低 | ✅ AES-NI |
| CFB | 🚀🚀 | 🚀🚀 | 低 | ✅ AES-NI |
| OFB | 🚀🚀 | 🚀🚀 | 低 | ✅ AES-NI |
| CTR | 🚀🚀🚀 | 🚀🚀🚀 | 低 | ✅ AES-NI |
| GCM | 🚀🚀🚀 | 🚀🚀🚀 | 中 | ✅ AES-NI + PCLMULQDQ |
| CCM | 🚀 | 🚀 | 中 | ✅ AES-NI |
| XTS | 🚀🚀 | 🚀🚀 | 低 | ✅ AES-NI |

### 使用场景推荐

| 场景 | 推荐模式 | 备选模式 | 不推荐 |
|------|---------|---------|--------|
| 网络传输 | **GCM** | CCM | ECB, CBC, CTR |
| 文件加密（需认证） | **GCM** | CCM | CBC+HMAC |
| 磁盘加密 | **XTS** | - | CBC, GCM |
| 流式数据 | **CTR+HMAC** | GCM | CBC |
| 嵌入式设备 | **CCM** | GCM | - |
| API 令牌 | **GCM** | - | CBC |
| 数据库加密 | **GCM** | - | ECB, CBC |

---

## 常见错误与陷阱

### 1. IV/Nonce 管理错误

#### ❌ 错误：重用 IV/Nonce

```c
// 错误！永远不要这样做
unsigned char iv[16] = {0};  // 固定的IV
for (int i = 0; i < 100; i++) {
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);  // 重用相同IV
    EVP_EncryptUpdate(ctx, ...);
}
```

**后果**：
- CTR/GCM/CCM：完全破坏安全性，可恢复明文
- CBC：泄露相同前缀信息
- OFB：两条消息 XOR 可得明文

#### ✅ 正确：每次生成新的 IV

```c
// 正确做法
for (int i = 0; i < 100; i++) {
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));  // 每次生成新的随机IV
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    // 保存 IV 与密文一起传输
}
```

### 2. GCM/CCM 特有错误

#### ❌ 错误：CCM 忘记设置长度

```c
// 错误！CCM 加密缺少关键步骤
EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
// ❌ 缺少这一步！
// EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len);
EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
```

**症状**：加密返回错误，或产生错误的密文

#### ✅ 正确：CCM 必须设置长度

```c
// 正确做法
EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL);
EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

// ✅ CCM 特有：必须预先设置明文长度
int len;
EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len);

EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
```

#### ❌ 错误：CCM 多次调用 EVP_EncryptUpdate 加密数据

```c
// 错误！CCM 不支持分步加密
EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL);
EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

// 设置总明文长度
int len;
EVP_EncryptUpdate(ctx, NULL, &len, NULL, 64);  // 总共64字节

// 设置AAD
EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

// ❌ 错误！尝试分两次加密
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, 32);
EVP_EncryptUpdate(ctx, ciphertext + len, &len, plaintext + 32, 32);  // 会失败！
```

**为什么 CCM 不支持分步加密？**

CCM（Counter with CBC-MAC）模式的工作原理决定了它的限制：

1. **CBC-MAC 计算**：CCM 首先使用 CBC-MAC 计算整个消息的认证标签
2. **一次性处理**：CBC-MAC 需要在加密之前完成，因此必须一次性提供所有数据
3. **预知长度**：正因为这个原因，CCM 才需要预先设置明文长度

**技术原因**：
- CCM 内部先计算整个消息的 CBC-MAC（认证）
- 然后使用 CTR 模式加密数据和标签（加密）
- 这两步都需要完整的数据才能正确完成

#### ✅ 正确：CCM 一次性加密所有数据

```c
// 正确做法
EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL);
EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

// 设置明文总长度
int len;
EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len);

// 设置AAD
EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

// ✅ 一次性加密所有数据
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

// 完成加密
int final_len;
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### ❌ 错误：解密前使用数据

```c
// 错误！在验证标签前就使用数据
EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
process_data(plaintext);  // ❌ 标签还未验证！

if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) <= 0) {
    printf("Tag verification failed\n");
    // 但数据已经被使用了！
}
```

#### ✅ 正确：验证后才使用

```c
// 正确做法
EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

// ✅ 先验证标签
if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) <= 0) {
    // 验证失败，丢弃所有数据
    memset(plaintext, 0, len);
    return ERROR;
}

// ✅ 验证成功后才使用数据
process_data(plaintext);
```

### 3. XTS 特有错误

#### ❌ 错误：使用单倍长度密钥

```c
// 错误！XTS 需要双倍长度密钥
unsigned char key[16] = { /* 16 bytes */ };
EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key, tweak);
// 错误：应该提供 32 字节密钥
```

#### ✅ 正确：使用双倍长度密钥

```c
// 正确做法
unsigned char xts_key[32] = {
    // 前16字节：加密密钥
    0x00, 0x01, 0x02, ..., 0x0f,
    // 后16字节：tweak密钥
    0x10, 0x11, 0x12, ..., 0x1f
};
EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, xts_key, tweak);
```

#### ❌ 错误：两个子密钥相同

```c
// 错误！两个子密钥不能相同
unsigned char xts_key[32];
memcpy(xts_key, key, 16);
memcpy(xts_key + 16, key, 16);  // ❌ 复制相同的密钥
// OpenSSL 会检测到并返回错误
```

#### ❌ 错误：尝试分步加密（多次 EVP_EncryptUpdate）

```c
// 错误！XTS 不支持分步加密
unsigned char plaintext[64] = { /* 数据 */ };
int len;

// 第一次 Update
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, 32);

// ❌ 第二次 Update 会产生错误的结果！
EVP_EncryptUpdate(ctx, ciphertext + len, &len, plaintext + 32, 32);
// 密文与一次性加密所有64字节的结果不同！
```

**为什么 XTS 不支持分步加密？**

XTS 是专为磁盘扇区加密设计的，具有以下特性：

1. **数据单元边界**：XTS 使用 tweak 值（通常是扇区号）标识每个数据单元
2. **整体处理**：每个数据单元必须作为一个整体处理，内部使用块索引计算
3. **Ciphertext Stealing**：处理非块对齐数据时需要知道完整数据单元大小

**技术原因**：
- XTS 对每个 16 字节块使用 tweak + 块索引进行 XOR 运算
- 多次 `EVP_EncryptUpdate` 会导致内部块计数器状态不一致
- 第二次调用时无法正确计算 tweak 的多项式迭代

#### ✅ 正确：一次性加密整个数据单元

```c
// 正确做法：一次性处理整个数据单元
unsigned char plaintext[64] = { /* 数据 */ };
int len, final_len;

// ✅ 一次 Update 处理所有数据
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

**如果需要加密大量数据怎么办？**

按固定大小的数据单元（扇区）分块处理，每个扇区使用不同的 tweak：

```c
#define SECTOR_SIZE 512  // 或 4096

for (int sector = 0; sector < num_sectors; sector++) {
    // 为每个扇区设置不同的 tweak（通常是扇区号）
    unsigned char tweak[16];
    memset(tweak, 0, 16);
    memcpy(tweak, &sector, sizeof(sector));
    
    // 重新初始化上下文
    EVP_EncryptInit_ex(ctx, cipher, NULL, xts_key, tweak);
    
    // ✅ 一次性加密整个扇区
    int len, final_len;
    EVP_EncryptUpdate(ctx, 
                      ciphertext + sector * SECTOR_SIZE,
                      &len,
                      plaintext + sector * SECTOR_SIZE,
                      SECTOR_SIZE);
    EVP_EncryptFinal_ex(ctx, ciphertext + sector * SECTOR_SIZE + len, &final_len);
}
```

**与其他模式对比**：

| 模式 | 支持分步加密 | 原因 |
|------|--------------|------|
| ECB, CBC, CFB, OFB | ✅ 支持 | 块间独立或链式结构，可流式处理 |
| CTR, GCM | ✅ 支持 | 流密码模式，可增量处理 |
| **CCM** | ❌ **不支持** | **CBC-MAC 需要完整数据，先认证后加密** |
| **XTS** | ❌ **不支持** | **需知道完整数据单元边界和大小** |

### 4. 填充错误

#### ❌ 错误：流密码模式使用填充

```c
// 错误！CTR/GCM/CCM/OFB/CFB 不应该使用填充
EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
EVP_CIPHER_CTX_set_padding(ctx, 1);  // ❌ CTR不需要填充
```

#### ✅ 正确：根据模式设置填充

```c
// 块密码模式（ECB, CBC）：使用填充（如果需要）
EVP_CIPHER_CTX_set_padding(ctx, 1);  // 启用 PKCS7 填充

// 流密码模式（CTR, OFB, CFB）：禁用填充
EVP_CIPHER_CTX_set_padding(ctx, 0);

// 认证加密模式（GCM, CCM）：不使用填充（流密码模式）
// 可以调用 EVP_CIPHER_CTX_set_padding(ctx, 0)，但这是可选的
// 因为这些模式本身不使用填充机制

// XTS：必须禁用填充
EVP_CIPHER_CTX_set_padding(ctx, 0);  // 必须调用
```

**填充规则总结**：
- **块密码模式（ECB, CBC）**：明文不是16字节倍数时需要填充
- **流密码模式（CTR, OFB, CFB, GCM, CCM）**：不需要填充，可处理任意长度
- **XTS**：不使用填充，但要求数据至少16字节

### 5. 初始化顺序错误

#### ❌ 错误：GCM 初始化顺序混乱

```c
// 错误！顺序不对
EVP_EncryptInit_ex(ctx, cipher, NULL, key, nonce);  // ❌ 太早设置密钥
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
```

#### ✅ 正确：严格遵守初始化顺序

```c
// GCM 正确顺序
EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);     // 1. 设置算法
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL); // 2. 设置IV长度
EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);       // 3. 设置密钥和nonce

// CCM 正确顺序
EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);     // 1. 设置算法
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL); // 2. 设置IV长度
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL);   // 3. 设置标签长度
EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);       // 4. 设置密钥和nonce
EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len); // 5. 设置数据长度（CCM特有）
```

### 6. 内存管理错误

#### ❌ 错误：缓冲区大小不足

```c
// 错误！没有考虑填充
unsigned char ciphertext[PLAINTEXT_SIZE];  // ❌ 可能不够
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, PLAINTEXT_SIZE);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
// 可能缓冲区溢出！
```

#### ✅ 正确：预留足够空间

```c
// 正确做法：预留一个额外的块
unsigned char ciphertext[PLAINTEXT_SIZE + EVP_CIPHER_block_size(cipher)];
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, PLAINTEXT_SIZE);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
```

#### ❌ 错误：忘记释放上下文

```c
// 错误！内存泄漏
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
// ... 使用 ctx ...
return;  // ❌ 忘记释放
```

#### ✅ 正确：总是释放资源

```c
// 正确做法
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
if (!ctx) return ERROR;

// ... 使用 ctx ...

EVP_CIPHER_CTX_free(ctx);  // ✅ 总是释放
```

---

## 最佳实践

### 1. 模式选择指南

#### 需要加密 + 认证？

→ **使用 GCM**（首选）或 CCM（资源受限）

```c
// 推荐：GCM 用于大多数场景
EVP_CIPHER *cipher = EVP_aes_256_gcm();
```

#### 仅需要加密（已有 MAC）？

→ **使用 CTR**（可并行）或 CBC（传统）

```c
// 如果已有单独的MAC，使用CTR
EVP_CIPHER *cipher = EVP_aes_256_ctr();
// 然后计算 HMAC
```

#### 磁盘/存储加密？

→ **使用 XTS**

```c
// XTS 专为磁盘设计
EVP_CIPHER *cipher = EVP_aes_256_xts();
```

#### 绝不使用的模式

- ❌ **ECB**：除非你真的知道自己在做什么（通常你不知道）

### 2. 密钥管理

#### ✅ 使用强随机密钥

```c
unsigned char key[32];
if (RAND_bytes(key, sizeof(key)) != 1) {
    // 错误处理
}
```

#### ✅ 安全存储密钥

```c
// 使用密钥派生函数（KDF）
PKCS5_PBKDF2_HMAC(password, password_len,
                  salt, salt_len,
                  iterations,
                  EVP_sha256(),
                  sizeof(key), key);
```

#### ✅ 定期轮换密钥

- 设置密钥过期策略
- 使用密钥版本管理
- 实现密钥轮换机制

### 3. IV/Nonce 管理

#### ✅ 每次加密生成新的随机 IV

```c
unsigned char iv[16];
RAND_bytes(iv, sizeof(iv));
```

#### ✅ IV 可以公开传输

```c
// IV不是秘密，可以与密文一起发送
// 格式：[IV][密文][标签]
```

#### ✅ GCM nonce 管理

```c
// 方案1：随机nonce（推荐用于小数据量）
unsigned char nonce[12];
RAND_bytes(nonce, 12);

// 方案2：计数器nonce（高性能场景）
uint64_t counter = get_next_counter();
memcpy(nonce, &counter, 8);
RAND_bytes(nonce + 8, 4);  // 随机化剩余部分
```

### 4. 错误处理

#### ✅ 检查所有返回值

```c
if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
    ERR_print_errors_fp(stderr);
    return ERROR;
}

if (EVP_EncryptUpdate(ctx, out, &len, in, in_len) != 1) {
    ERR_print_errors_fp(stderr);
    return ERROR;
}

if (EVP_EncryptFinal_ex(ctx, out + len, &final_len) != 1) {
    ERR_print_errors_fp(stderr);
    return ERROR;
}
```

#### ✅ 清理敏感数据

```c
// 使用后清零敏感数据
OPENSSL_cleanse(key, sizeof(key));
OPENSSL_cleanse(plaintext, plaintext_len);
```

### 5. 性能优化

#### ✅ 重用 EVP_CIPHER_CTX

```c
// 创建一次，多次使用
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

for (int i = 0; i < 1000; i++) {
    // 重新初始化（比创建新上下文快）
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ...);
    EVP_EncryptFinal_ex(ctx, ...);
}

EVP_CIPHER_CTX_free(ctx);
```

#### ✅ 利用硬件加速

```c
// OpenSSL 自动使用 AES-NI 指令（如果可用）
// 确保编译时启用硬件优化
// ./config enable-aes-ni
```

#### ✅ 选择合适的模式

- 需要并行：CTR, GCM
- 需要低延迟：CTR, GCM
- 资源受限：CCM

### 6. 安全审计清单

在部署加密代码前，检查以下项目：

- [ ] 使用了认证加密（GCM/CCM）或加密+MAC
- [ ] IV/Nonce 每次都是唯一的
- [ ] 没有使用 ECB 模式
- [ ] 密钥长度至少 128 位（推荐 256 位）
- [ ] 正确处理了所有错误返回值
- [ ] 验证标签失败时丢弃所有数据
- [ ] 敏感数据使用后被清零
- [ ] 密钥使用 CSPRNG 生成
- [ ] 密钥安全存储（不在代码中硬编码）
- [ ] 实现了密钥轮换机制
- [ ] 所有 EVP_CIPHER_CTX 都被正确释放
- [ ] 缓冲区大小足够（考虑填充）
- [ ] AAD 在加密和解密时保持一致
- [ ] XTS 使用了不同的两个子密钥

---

## 模式特性速查表

### 一句话总结

| 模式 | 一句话描述 |
|------|----------|
| ECB | 最简单但最不安全，永远不要使用 |
| CBC | 传统的块密码模式，需要配合MAC |
| CFB | 流密码模式，适合流式数据 |
| OFB | 同步流密码，错误不传播 |
| CTR | 可并行的流密码，高性能 |
| GCM | 现代认证加密，首选模式 |
| CCM | 认证加密，适合嵌入式 |
| XTS | 磁盘加密专用模式 |

### 核心差异

```
认证能力：
  ECB, CBC, CFB, OFB, CTR: ❌ 无认证
  GCM, CCM: ✅ 内置认证
  XTS: ❌ 无认证

并行能力：
  ECB, CTR, GCM: ✅ 可并行
  CBC, CCM: ❌ 不可并行
  CFB, OFB, XTS: 🟡 部分

IV重用后果：
  ECB: N/A（无IV）
  CBC, XTS: 信息泄露
  CTR, GCM, CCM, OFB, CFB: 灾难性

特殊要求：
  CCM: 必须预先设置数据长度
  XTS: 必须使用双倍长度密钥
  GCM: 建议12字节nonce
  其他: 标准16字节IV
```

---

## 示例代码库

本目录包含以下示例：

- `ecb_aes.c` - ECB 模式示例（教学用）
- `cbc_aes.c` - CBC 模式示例
- `cfb_aes.c` - CFB 模式示例
- `ofb_aes.c` - OFB 模式示例
- `ctr_aes.c` - CTR 模式示例
- `gcm_aes.c` - GCM 模式示例（推荐）
- `ccm_aes.c` - CCM 模式示例
- `xts_aes.c` - XTS 模式示例

每个示例都展示了完整的加密和解密流程。

---

## 参考资源

### OpenSSL 文档

- [EVP Symmetric Encryption and Decryption](https://www.openssl.org/docs/man3.0/man7/evp.html)
- [EVP_EncryptInit_ex](https://www.openssl.org/docs/man3.0/man3/EVP_EncryptInit_ex.html)

### 标准文档

- NIST SP 800-38A: ECB, CBC, CFB, OFB, CTR
- NIST SP 800-38D: GCM
- NIST SP 800-38C: CCM
- IEEE 1619-2007: XTS

### 安全建议

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Cryptography Coding Rules](https://github.com/veorq/cryptocoding)

---

## 总结

### 快速决策树

```
需要加密吗？
├─ 是
│  ├─ 需要认证吗？
│  │  ├─ 是 → 使用 GCM（或 CCM for 嵌入式）
│  │  └─ 否 → 场景是什么？
│  │     ├─ 磁盘加密 → 使用 XTS
│  │     ├─ 网络传输 → 使用 CTR + HMAC（或直接用GCM）
│  │     └─ 其他 → 使用 CTR 或 CBC（配合MAC）
│  └─ 传统兼容 → CBC + HMAC
└─ 否 → 考虑其他方案

永远避免：ECB（除非你完全理解风险且有充分理由）
```

### 最后的建议

1. **默认选择**：AES-256-GCM
2. **磁盘加密**：AES-256-XTS
3. **嵌入式系统**：AES-128-CCM
4. **传统系统**：AES-256-CBC + HMAC-SHA256

**记住**：
- 总是使用认证加密或加密+MAC
- 永远不要重用 IV/Nonce
- 验证所有返回值
- 清理敏感数据
- 定期更新密钥

---

*最后更新：2025-10-24*
