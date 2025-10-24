# OpenSSL 3.5.2 静态编译 Legacy Provider 指南

## 编译日期
2025-10-24

## 编译配置

### 配置命令
```bash
cd openssl-3.5.2
./Configure darwin64-arm64-cc -g -O0 no-module
```

### 关键选项说明
- `darwin64-arm64-cc`: macOS ARM64 架构
- `-g`: 生成调试信息
- `-O0`: 关闭优化（便于调试）
- `no-module`: **关键**！禁用动态模块，使 legacy provider 编译为内置

### 编译命令
```bash
make clean
make -j8
```

## 编译结果

### 生成的文件
```
libcrypto.a     19MB    包含 legacy provider（内置）
libssl.a        5.1MB   SSL/TLS 库
```

### Legacy Provider 状态
- ✅ **已内置到 libcrypto.a**
- ✅ 符号 `ossl_legacy_provider_init` 存在于 libcrypto.a
- ✅ 不需要 `legacy.dylib` 动态库
- ✅ 不需要设置 `OPENSSL_MODULES` 环境变量

### 验证方法
```bash
# 检查符号
nm libcrypto.a | grep ossl_legacy_provider_init
# 输出：
# 0000000000000000 T _ossl_legacy_provider_init

# 检查是否存在动态库
ls providers/legacy.dylib
# 应该不存在（因为 no-module）
```

## 使用方法

### CMakeLists.txt 配置
```cmake
# 直接链接静态库
add_executable(test_des_cbc cbc_des.c)
target_link_libraries(test_des_cbc
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)
```

### C 代码
```c
#include <openssl/evp.h>
#include <openssl/provider.h>

int main() {
    // 加载 legacy provider（现在是内置的）
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

### 编译和运行
```bash
# 编译
cmake --build build --target test_des_cbc

# 运行（不需要任何环境变量！）
./build/ciphers/test_des_cbc
```

## 技术原理

### no-module 的作用

在 OpenSSL 的 `providers/build.info` 中：

```makefile
IF[{- $disabled{module} -}]
    # Become built in
    $LEGACYGOAL=../libcrypto
    SOURCE[$LEGACYGOAL]=$LIBLEGACY
    DEFINE[$LEGACYGOAL]=STATIC_LEGACY
```

当使用 `no-module` 时：
1. Legacy provider 不会编译成独立的 `legacy.dylib`
2. 而是将 `liblegacy.a` 的内容链接到 `libcrypto.a`
3. 同时定义 `STATIC_LEGACY` 宏
4. 这会导出 `ossl_legacy_provider_init` 符号

### 代码中的处理

在 `providers/legacyprov.c:32-34`：
```c
#ifdef STATIC_LEGACY
OSSL_provider_init_fn ossl_legacy_provider_init;
# define OSSL_provider_init ossl_legacy_provider_init
#endif
```

这使得 legacy provider 可以被静态链接并直接调用。

## 与之前的对比

### 之前（动态模式）
```bash
# 编译
gcc -o test test.c libcrypto.a libssl.a

# 运行（需要环境变量）
export OPENSSL_MODULES=/path/to/providers
export DYLD_LIBRARY_PATH=/path/to/openssl
./test
```

### 现在（静态内置）
```bash
# 编译
gcc -o test test.c libcrypto.a libssl.a

# 运行（无需环境变量）
./test
```

## 测试结果

所有 DES 测试程序都能正常运行：

```
✅ test_des_ecb          - DES-ECB 模式
✅ test_des_cbc          - DES-CBC 模式
✅ test_des_cfb          - DES-CFB64 模式
✅ test_des_ofb          - DES-OFB 模式
✅ test_des3_cbc         - 3DES-CBC 模式
✅ test_des_cfb_variants - DES-CFB1/8/64 变体
✅ test_desx_cbc         - DESX-CBC 增强 DES
✅ test_des3_variants    - 3DES ECB/OFB/CFB 变体
```

全部无需设置任何环境变量！

## 优点和缺点

### 优点
- ✅ 完全静态链接，无运行时依赖
- ✅ 不需要设置环境变量
- ✅ 不需要分发 legacy.dylib
- ✅ 简化部署
- ✅ 便于调试（debug 版本）

### 缺点
- ⚠️ libcrypto.a 体积增大（19MB）
- ⚠️ 包含了不安全的算法（DES/MD4/RC4 等）
- ⚠️ 仅适用于学习和测试，不推荐生产环境

## 注意事项

1. **仅用于学习**：DES 已被废弃，不应在生产环境使用
2. **调试版本**：使用 `-g -O0` 编译，适合学习源码
3. **架构特定**：此编译针对 macOS ARM64，其他平台需调整
4. **OpenSSL 版本**：基于 OpenSSL 3.5.2

## 相关文档
- `STATIC_LINKING.md` - 详细的静态链接技术说明
- `README.md` - DES 算法使用指南
- `../aes/README.md` - AES 算法使用指南（推荐使用）

---

*编译完成时间：2025-10-24 21:05*
*适用于学习和测试，不建议生产使用*
