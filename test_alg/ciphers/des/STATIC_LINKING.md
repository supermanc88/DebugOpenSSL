# DES Legacy Provider 静态链接指南

## 问题背景

在 OpenSSL 3.x 中，DES/3DES/DESX 等算法被移到了 **legacy provider** 中。默认情况下，需要：
1. 动态加载 `legacy.dylib`（或 `legacy.so`）
2. 设置环境变量 `OPENSSL_MODULES` 指向 providers 目录

## 方法对比

### 方法 1：动态加载（当前方法）✅ 可行

```c
#include <openssl/provider.h>

// 需要运行时加载
OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");

// 使用 DES
const EVP_CIPHER *cipher = EVP_des_cbc();

// 清理
OSSL_PROVIDER_unload(legacy);
OSSL_PROVIDER_unload(deflt);
```

**编译**：
```bash
gcc -o test test.c -I/path/to/openssl-3.5.2/include \
    /path/to/openssl-3.5.2/libcrypto.a \
    /path/to/openssl-3.5.2/libssl.a
```

**运行**：
```bash
export OPENSSL_MODULES=/path/to/openssl-3.5.2/providers
./test
```

**优点**：
- ✅ 简单，无需特殊编译
- ✅ 与当前所有 DES 测试代码兼容

**缺点**：
- ❌ 需要设置环境变量
- ❌ 需要 legacy.dylib 文件存在

---

### 方法 2：静态链接 liblegacy.a ❌ **不可行**

```bash
# 尝试静态链接
gcc -o test test.c \
    /path/to/openssl-3.5.2/libcrypto.a \
    /path/to/openssl-3.5.2/libssl.a \
    /path/to/openssl-3.5.2/providers/liblegacy.a
```

**问题**：
```
Undefined symbols: "_OSSL_provider_init"
```

**原因**：
- `liblegacy.a` 只包含算法实现（DES/MD4/MD5 等）
- **不包含** provider 初始化函数 `OSSL_provider_init`
- 初始化函数只在 `legacy.dylib` 中导出

**为什么会这样？**

查看 OpenSSL 源码 `providers/legacyprov.c:32-34`：
```c
#ifdef STATIC_LEGACY
OSSL_provider_init_fn ossl_legacy_provider_init;
# define OSSL_provider_init ossl_legacy_provider_init
#endif
```

这意味着：
- 默认编译的 OpenSSL **不支持**静态链接 legacy provider
- 需要用 `STATIC_LEGACY` 宏重新编译整个 OpenSSL 才行

---

### 方法 3：重新编译 OpenSSL 内置 legacy provider ✅ **推荐用于学习**

#### 步骤 1：配置 OpenSSL（关键：使用 no-module）

```bash
cd openssl-3.5.2
./Configure darwin64-arm64-cc -g -O0 no-module
```

**关键选项说明**：
- `no-module`: **最重要**！禁用动态模块，使 legacy provider 编译为内置
- `-g`: 生成调试信息（便于学习源码）
- `-O0`: 关闭优化（便于调试）

**错误示例**（不要这样做）：
```bash
# ❌ 错误：仅添加 -DSTATIC_LEGACY 不够
./Configure darwin64-arm64-cc -g -O0 -DSTATIC_LEGACY  # 会链接失败！
```

#### 步骤 2：编译

```bash
make clean
make -j8
```

**编译结果**：
- ✅ `libcrypto.a` (约 19MB) - 包含内置的 legacy provider
- ✅ `libssl.a` (约 5MB)
- ❌ **不生成** `providers/legacy.dylib`（预期行为）
- ✅ 符号 `ossl_legacy_provider_init` 存在于 `libcrypto.a` 中

**验证编译结果**：
```bash
# 检查符号是否存在
nm libcrypto.a | grep ossl_legacy_provider_init
# 应该输出: 0000000000000000 T _ossl_legacy_provider_init

# 确认不生成动态库
ls providers/legacy.dylib
# 应该报错: No such file or directory （这是正确的！）
```

#### 步骤 3：使用静态内置的 legacy（代码无需修改！）

```c
#include <openssl/evp.h>
#include <openssl/provider.h>

int main() {
    // 代码完全不需要修改！OpenSSL 会自动识别内置的 legacy provider
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    
    // 使用 DES
    const EVP_CIPHER *cipher = EVP_des_cbc();
    
    // ... 加密解密操作 ...
    
    // 清理
    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(deflt);
    
    return 0;
}
```

**编译和运行**：
```bash
# 编译（使用静态库）
gcc -o test test.c -I openssl-3.5.2/include \
    openssl-3.5.2/libcrypto.a \
    openssl-3.5.2/libssl.a

# 运行（无需任何环境变量！）
./test  ✅
```

#### 技术原理

在 `providers/build.info` 中（第 136-147 行）：
```makefile
IF[{- $disabled{module} -}]
    # Become built in
    $LEGACYGOAL=../libcrypto
    SOURCE[$LEGACYGOAL]=$LIBLEGACY
    DEFINE[$LEGACYGOAL]=STATIC_LEGACY
```

当使用 `no-module` 配置时：
1. OpenSSL 自动将 `liblegacy.a` 链接进 `libcrypto.a`
2. 自动定义 `STATIC_LEGACY` 宏
3. 导出 `ossl_legacy_provider_init` 符号
4. 不生成 `legacy.dylib` 动态模块

在 `providers/legacyprov.c:32-34` 中：
```c
#ifdef STATIC_LEGACY
OSSL_provider_init_fn ossl_legacy_provider_init;
# define OSSL_provider_init ossl_legacy_provider_init
#endif
```

这使得 legacy provider 可以被作为内置 provider 直接加载。

**优点**：
- ✅ 完全静态，不需要环境变量
- ✅ 不需要 legacy.dylib 文件
- ✅ 代码无需任何修改
- ✅ 简化部署和使用
- ✅ 便于调试和学习（debug 版本）

**缺点**：
- ⚠️ 需要重新编译 OpenSSL（耗时约 5-10 分钟）
- ⚠️ libcrypto.a 体积较大（19MB vs 原来的约 15MB）
- ⚠️ 包含不安全算法（仅适合学习，不建议生产使用）

---

## 推荐方案

### ✅ 推荐：使用方法 3（静态内置）- 最佳学习体验

如果你是为了学习密码学和 OpenSSL 源码，强烈推荐使用方法 3：

```bash
# 一次性重新编译 OpenSSL
cd openssl-3.5.2
./Configure darwin64-arm64-cc -g -O0 no-module
make clean
make -j8

# 之后所有 DES 测试程序都可以直接运行，无需环境变量
./build/ciphers/test_des_cbc  ✅
./build/ciphers/test_des3_variants  ✅
./build/ciphers/test_desx_cbc  ✅
```

**优势**：
- 🚀 简化使用：完全不需要设置环境变量
- 🔧 便于调试：Debug 版本，可以单步调试 OpenSSL 源码
- 📦 便于部署：所有依赖都静态编译在一起
- 📚 适合学习：可以深入研究 provider 架构

### 🟡 备选：使用方法 1（动态加载）- 快速开始

如果你：
- 已有编译好的 OpenSSL，不想重新编译
- 只是快速测试 DES 算法
- 临时性使用

可以使用方法 1：

```bash
# 一次性设置（添加到 ~/.zshrc）
export OPENSSL_MODULES=/path/to/openssl-3.5.2/providers
export DYLD_LIBRARY_PATH=/path/to/openssl-3.5.2:$DYLD_LIBRARY_PATH

# 或者每次运行时临时设置
OPENSSL_MODULES=openssl-3.5.2/providers \
DYLD_LIBRARY_PATH=openssl-3.5.2:$DYLD_LIBRARY_PATH \
./build/ciphers/test_des_cbc
```

### 对于生产环境：不要使用 DES！⚠️

```c
// ❌ 不要用 DES（无论静态还是动态）
const EVP_CIPHER *cipher = EVP_des_cbc();

// ✅ 使用 AES-GCM
const EVP_CIPHER *cipher = EVP_aes_256_gcm();
```

**原因**：
- DES 已被废弃（NIST 2005）
- 3DES 正在淘汰（NIST 2023 后禁止新系统使用）
- AES 更快、更安全、是现行标准
- 本项目的 DES 实现仅用于学习密码学原理

---

## CMakeLists.txt 配置

### 方法 3 配置（静态内置 - 推荐）

使用 `no-module` 重新编译 OpenSSL 后：

```cmake
cmake_minimum_required(VERSION 3.5)
project(test_cipher_des)
set(CMAKE_C_STANDARD 11)

# DES CBC 测试
add_executable(test_des_cbc cbc_des.c)
target_link_libraries(test_des_cbc
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)
```

**运行方式**（无需环境变量）：
```bash
# 编译
cmake --build build --target test_des_cbc

# 直接运行
./build/ciphers/test_des_cbc  ✅
```

### 方法 1 配置（动态加载）

使用默认编译的 OpenSSL：

```cmake
cmake_minimum_required(VERSION 3.5)
project(test_cipher_des)
set(CMAKE_C_STANDARD 11)

# DES CBC 测试
add_executable(test_des_cbc cbc_des.c)
target_link_libraries(test_des_cbc
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)
```

**运行方式**（需要环境变量）：
```bash
# 编译
cmake --build build --target test_des_cbc

# 运行（需要环境变量）
OPENSSL_MODULES=openssl-3.5.2/providers \
DYLD_LIBRARY_PATH=openssl-3.5.2:$DYLD_LIBRARY_PATH \
./build/ciphers/test_des_cbc
```

**两种方法的 CMakeLists.txt 完全相同！区别只在于 OpenSSL 的编译方式。**

---

## 常见问题

### Q1: 为什么不能静态链接 liblegacy.a？

**A**: 因为 OpenSSL **默认编译**时没有启用 `STATIC_LEGACY` 宏，导致：
- `liblegacy.a` 中没有 `OSSL_provider_init` 初始化函数
- 只有算法实现代码（DES/MD4/RC4 等）
- 初始化函数只在 `legacy.dylib` 中

**解决方案**：使用 `no-module` 重新编译 OpenSSL，它会：
- 自动定义 `STATIC_LEGACY` 宏
- 将 legacy provider 编译进 `libcrypto.a`
- 导出 `ossl_legacy_provider_init` 符号
- 不生成 `legacy.dylib`

### Q2: 使用 no-module 和 -DSTATIC_LEGACY 有什么区别？

**A**: 
- ❌ **错误方式**：`./Configure ... -DSTATIC_LEGACY`
  - 只定义了宏，但构建系统不知道要内置 legacy provider
  - 会导致链接错误：`Undefined symbols: "_ossl_legacy_provider_init"`
  
- ✅ **正确方式**：`./Configure ... no-module`
  - 告诉构建系统禁用模块，内置所有 provider
  - 构建系统自动定义 `STATIC_LEGACY` 并正确配置链接
  - 一切都自动处理好

**技术原理**：`no-module` 会触发 `providers/build.info` 中的条件编译：
```makefile
IF[{- $disabled{module} -}]  # no-module 会设置这个
    $LEGACYGOAL=../libcrypto
    DEFINE[$LEGACYGOAL]=STATIC_LEGACY  # 自动定义
```

### Q3: AES 为什么不需要加载 provider？

**A**: 因为 AES 在 **default provider** 中：
- default provider 是**内置**的（编译进 libcrypto.a）
- 不需要外部动态库
- 自动可用

DES 在 **legacy provider** 中：
- legacy provider 是**独立**的
- 需要外部动态库 `legacy.dylib`
- 需要手动加载

### Q4: 使用 no-module 后，我的代码需要修改吗？

**A**: **完全不需要修改！** 这是最大的优点。

原有代码：
```c
OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
const EVP_CIPHER *cipher = EVP_des_cbc();
```

这段代码在两种情况下都能正常工作：
- ✅ 默认编译：从 `legacy.dylib` 动态加载
- ✅ no-module 编译：从 `libcrypto.a` 加载内置版本

OpenSSL 会自动识别并处理，无需任何代码修改！

### Q5: no-module 会影响其他算法吗？

**A**: 不会，反而更简单：

```c
// AES (在 default provider 中)
const EVP_CIPHER *aes = EVP_aes_256_gcm();  // ✅ 正常工作

// RSA (在 default provider 中) 
EVP_PKEY *rsa = EVP_PKEY_new();  // ✅ 正常工作

// DES (在 legacy provider 中)
OSSL_PROVIDER_load(NULL, "legacy");
const EVP_CIPHER *des = EVP_des_cbc();  // ✅ 正常工作，且无需环境变量
```

所有算法都能正常使用，且 DES 不再需要环境变量。

---

## 总结

### 三种方法最终对比

| 特性 | 方法 1<br>动态加载 | 方法 2<br>静态链接 liblegacy.a | 方法 3<br>no-module 重编译 |
|------|----------|----------------------|-------------------|
| 需要重新编译 OpenSSL | ❌ | ❌ | ✅ (5-10分钟) |
| 需要环境变量 | ✅ 需要 | ❌ | ❌ |
| 代码需要修改 | ❌ | ✅ 需要 | ❌ |
| 是否可行 | ✅ | ❌ 不可行 | ✅ |
| 适用场景 | 快速测试 | - | 学习研究 |
| 推荐度 | 🟡 | ❌ | ✅ |

### 快速决策指南

```
你的情况是？
├─ 只是临时测试 DES
│  └─ 使用方法 1（动态加载）
│     export OPENSSL_MODULES=...
│
├─ 学习密码学和 OpenSSL 源码
│  └─ 使用方法 3（no-module 重编译）✅ 推荐
│     ./Configure ... no-module
│     make -j8
│
└─ 生产环境
   └─ 不要使用 DES！改用 AES-GCM ⚠️
```

### 最佳实践总结

**对于本项目（学习密码学）**：

1. ✅ **一次性操作**：使用 `no-module` 重新编译 OpenSSL
   ```bash
   cd openssl-3.5.2
   ./Configure darwin64-arm64-cc -g -O0 no-module
   make clean && make -j8
   ```

2. ✅ **之后使用**：所有 DES 测试都能直接运行
   ```bash
   ./build/ciphers/test_des_cbc  # 无需环境变量 ✅
   ./build/ciphers/test_des3_variants  # 无需环境变量 ✅
   ```

3. ✅ **代码不变**：所有现有代码无需任何修改

4. ✅ **便于调试**：Debug 版本，可以单步跟踪 OpenSSL 源码

### 问题答案

> provider 能静态链接进去吗？

**答案**：✅ **能！使用 `no-module` 配置重新编译 OpenSSL**

**关键要点**：
- ✅ 使用 `./Configure ... no-module`（不是 `-DSTATIC_LEGACY`）
- ✅ Legacy provider 会自动内置到 `libcrypto.a`
- ✅ 代码完全不需要修改
- ✅ 运行时无需环境变量
- ✅ 适合学习和调试

**不推荐方式**：
- ❌ 直接链接 `liblegacy.a`（会链接失败）
- ❌ 只加 `-DSTATIC_LEGACY` 参数（会链接失败）
- ❌ 手动编译 `legacyprov.c`（太复杂）

### 为什么 AES 可以用静态库但 DES 需要动态 provider？

```
OpenSSL 3.x 架构：

libcrypto.a (静态库)
├── default provider (内置) ✅
│   ├── AES
│   ├── SHA256
│   ├── RSA
│   └── ...
│
├── base provider (内置) ✅
│   └── 基础算法
│
└── provider 加载机制 🔄

legacy.dylib (动态库)
└── legacy provider (外部) ❌
    ├── DES
    ├── 3DES
    ├── MD4
    └── ...
```

**设计目的**：
- 把不安全的算法（DES/MD4/RC4）隔离到独立的 provider
- 鼓励用户迁移到现代算法（AES/SHA256）
- 减小 libcrypto 的体积（可选）

**使用 no-module 后的架构**：
```
libcrypto.a (静态库 - 使用 no-module 编译)
├── default provider (内置) ✅
│   ├── AES
│   ├── SHA256
│   ├── RSA
│   └── ...
│
├── legacy provider (内置) ✅  ← 现在也内置了！
│   ├── DES
│   ├── 3DES
│   ├── MD4
│   └── ...
│
└── base provider (内置) ✅
```

所有 provider 都在 `libcrypto.a` 中，无需外部动态库！

---

## 实测结果

### 编译信息
- OpenSSL 版本：3.5.2
- 配置命令：`./Configure darwin64-arm64-cc -g -O0 no-module`
- 编译时间：约 5-8 分钟（8 核并行）
- libcrypto.a 大小：19MB（包含 legacy provider）
- libssl.a 大小：5.1MB

### 测试结果
所有 8 个 DES 测试程序，**无需任何环境变量**，全部通过：

```bash
✅ test_des_ecb          - DES-ECB 模式
✅ test_des_cbc          - DES-CBC 模式
✅ test_des_cfb          - DES-CFB64 模式
✅ test_des_ofb          - DES-OFB 模式
✅ test_des3_cbc         - 3DES-CBC 模式
✅ test_des_cfb_variants - DES-CFB1/8/64 变体
✅ test_desx_cbc         - DESX-CBC 增强 DES
✅ test_des3_variants    - 3DES ECB/OFB/CFB 变体
```

运行命令示例：
```bash
# 完全无需环境变量
./build/ciphers/test_des_cbc
./build/ciphers/test_des3_variants
./build/ciphers/test_desx_cbc
```

### 符号验证
```bash
$ nm libcrypto.a | grep ossl_legacy_provider_init
0000000000000000 T _ossl_legacy_provider_init  ✅

$ ls providers/legacy.dylib
ls: providers/legacy.dylib: No such file or directory  ✅ (预期结果)
```

---

*最后更新：2025-10-24*  
*基于 OpenSSL 3.5.2 实测验证*
