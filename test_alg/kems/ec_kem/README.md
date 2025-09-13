# EC KEM 椭圆曲线密钥封装机制测试程序

这是一个用于测试基于椭圆曲线的密钥封装机制 (EC KEM) 的测试程序，使用 OpenSSL 3.0+ 的椭圆曲线密码学 API 实现。

## 算法简介

EC KEM 是基于椭圆曲线离散对数困难问题的密钥封装机制，结合了椭圆曲线 Diffie-Hellman (ECDH) 密钥协商和 HKDF 密钥派生函数。它提供了高效的密钥封装和解封装操作。

### 支持的椭圆曲线

- **prime256v1 (P-256)**: NIST P-256 椭圆曲线，256位安全强度
- **secp384r1 (P-384)**: NIST P-384 椭圆曲线，384位安全强度
- **secp521r1 (P-521)**: NIST P-521 椭圆曲线，521位安全强度

## 系统要求

### OpenSSL 版本
- **OpenSSL 3.0.0** 或更高版本
- 支持标准椭圆曲线和 HKDF

### 编译环境
- GCC 或 Clang 编译器
- 支持 C11 标准
- Make 构建工具

## 编译和运行

### 编译程序
```bash
make
```

### 运行完整测试
```bash
make run
```

### 运行特定椭圆曲线测试
```bash
make test-p256    # 测试 P-256 (prime256v1)
make test-p384    # 测试 P-384 (secp384r1)  
make test-p521    # 测试 P-521 (secp521r1)
```

### 检查算法支持
```bash
make check-support
```

### 清理编译文件
```bash
make clean
```

## 程序功能

### 核心功能
1. **椭圆曲线支持检测**: 检查当前 OpenSSL 支持的椭圆曲线
2. **密钥对生成**: 生成椭圆曲线公私钥对
3. **密钥封装**: 使用接收方公钥生成临时密钥对和共享密钥
4. **密钥解封装**: 使用接收方私钥和临时公钥恢复共享密钥
5. **一致性验证**: 验证封装和解封装得到的共享密钥是否一致

### 实现原理
```
封装过程:
1. 生成临时椭圆曲线密钥对 (ephemeral_private, ephemeral_public)
2. 使用临时私钥和接收方公钥执行 ECDH → ecdh_shared_secret
3. 使用 HKDF-SHA256 派生最终共享密钥
4. 输出: (ephemeral_public, shared_secret)

解封装过程:
1. 使用接收方私钥和临时公钥执行 ECDH → ecdh_shared_secret
2. 使用相同的 HKDF-SHA256 派生最终共享密钥
3. 输出: shared_secret (与封装时生成的相同)
```

### 测试流程
```
1. 生成接收方密钥对 (recipient_public, recipient_private)
2. 密钥封装: recipient_public → (ephemeral_public, shared_secret1)
3. 密钥解封装: (recipient_private, ephemeral_public) → shared_secret2
4. 验证 shared_secret1 == shared_secret2
```

## 输出示例

```
EC KEM (Elliptic Curve Key Encapsulation Mechanism) 测试程序
使用 OpenSSL 3.0+ 的椭圆曲线密钥封装算法
============================================
OpenSSL 版本: OpenSSL 3.5.2 5 Aug 2025
✓ prime256v1 curve supported
✓ secp384r1 curve supported
✓ secp521r1 curve supported
✓ EC KEM support confirmed! (3 curves available)

========================================
开始测试 EC KEM prime256v1 完整流程
========================================

=== 测试 EC KEM 密钥生成 (prime256v1) ===
密钥生成成功！

=== 测试 EC KEM 密钥封装 (prime256v1) ===
ECDH共享密钥长度: 32 bytes
密钥封装成功！
临时公钥长度: 65 bytes
最终共享密钥长度: 32 bytes
临时公钥: 04a1b2c3d4e5f6...
共享密钥: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

=== 测试 EC KEM 密钥解封装 (prime256v1) ===
ECDH共享密钥长度: 32 bytes
密钥解封装成功！
最终共享密钥长度: 32 bytes
共享密钥: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

=== 验证共享密钥一致性 ===
✓ 共享密钥一致性验证成功！
椭圆曲线: prime256v1
共享密钥长度: 32 bytes
临时公钥长度: 65 bytes

prime256v1 EC KEM 测试完成 - 成功!

============================================
测试总结:
成功: 3/3
✓ 所有EC KEM算法测试通过!

支持的椭圆曲线:
  - prime256v1 (NIST P-256): 256-bit 椭圆曲线
  - secp384r1 (NIST P-384):  384-bit 椭圆曲线
  - secp521r1 (NIST P-521):  521-bit 椭圆曲线

KEM 实现特点:
  - 基于 ECDH 密钥协商
  - 使用 HKDF-SHA256 密钥派生
  - 256-bit 共享密钥输出
  - 符合现代密码学最佳实践
```

## 技术详情

### 密钥和数据大小
- **P-256 (prime256v1)**: 公钥 65字节, 私钥 32字节, 共享密钥 32字节
- **P-384 (secp384r1)**: 公钥 97字节, 私钥 48字节, 共享密钥 32字节
- **P-521 (secp521r1)**: 公钥 133字节, 私钥 66字节, 共享密钥 32字节

### 密码学组件
- **椭圆曲线**: NIST 标准曲线 (P-256, P-384, P-521)
- **密钥协商**: ECDH (Elliptic Curve Diffie-Hellman)
- **密钥派生**: HKDF-SHA256 (HMAC-based Key Derivation Function)
- **信息字符串**: "EC-KEM-ENCAP"

### OpenSSL API 使用
- `EVP_PKEY_keygen()` - 椭圆曲线密钥对生成
- `EVP_PKEY_derive()` - ECDH 密钥协商
- `EVP_KDF_derive()` - HKDF 密钥派生
- `EVP_PKEY_fromdata()` - 从原始数据重建公钥

## 故障排除

### 常见问题

1. **编译失败**
   ```
   错误: openssl/evp.h: No such file or directory
   ```
   **解决方案**: 确保 OpenSSL 3.0+ 已正确安装，头文件路径正确。

2. **运行时错误**
   ```
   错误: 当前OpenSSL版本不支持必要的EC算法
   ```
   **解决方案**: 升级到 OpenSSL 3.0.0+ 并确保椭圆曲线支持已启用。

3. **密钥导出失败**
   ```
   错误: 获取临时公钥长度失败
   ```
   **解决方案**: 检查椭圆曲线名称是否正确，使用 `EVP_PKEY_get_octet_string_param` 而不是 `EVP_PKEY_get_raw_public_key`。

4. **ECDH 失败**
   ```
   错误: ECDH密钥协商失败
   ```
   **解决方案**: 确保两个密钥使用相同的椭圆曲线，密钥有效且格式正确。

### 调试模式
编译调试版本以获得更详细的错误信息：
```bash
make debug
```

## 安全注意事项

1. **测试目的**: 本程序仅用于测试和学习，不适用于生产环境
2. **随机性**: 使用系统随机数生成器，确保临时密钥的随机性
3. **内存安全**: 敏感数据使用后会被安全清除
4. **曲线选择**: 建议使用 P-256 或更高强度的曲线
5. **量子威胁**: 椭圆曲线算法不抗量子攻击，考虑使用后量子算法

## 文件结构

```
ec_kem/
├── ec_kem.c          # 主程序源代码
├── Makefile          # 构建配置
├── README.md         # 本文档
├── CMakeLists.txt    # CMake 构建配置
└── test_ec_kem       # 编译后的可执行文件
```

## 性能特点

- **高效性**: 椭圆曲线操作比 RSA 更高效
- **安全性**: 基于椭圆曲线离散对数困难问题
- **标准化**: 使用 NIST 标准椭圆曲线
- **兼容性**: 与现有椭圆曲线基础设施兼容

## 与其他KEM的对比

| 特性 | EC KEM | ML-KEM | RSA-KEM |
|------|--------|---------|---------|
| 安全基础 | 椭圆曲线DLP | 格理论 | 整数分解 |
| 量子安全 | ❌ | ✅ | ❌ |
| 效率 | 高 | 中等 | 低 |
| 密钥大小 | 小 | 中等 | 大 |
| 标准化 | NIST/ANSI | NIST PQC | PKCS#1 |

## 相关标准

- **NIST SP 800-56A**: ECC 密钥建立推荐实践
- **ANSI X9.62**: 椭圆曲线数字签名算法
- **ANSI X9.63**: 椭圆曲线密钥协商和密钥传输协议
- **RFC 5869**: HMAC 密钥派生函数 (HKDF)
- **RFC 6090**: 椭圆曲线密码学基础算法

## 许可证

本程序遵循与 OpenSSL 相同的许可证条款。

## 参考资料

- [NIST SP 800-56A Rev. 3 - Elliptic Curve Cryptography](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final)
- [OpenSSL 3.0+ Documentation](https://www.openssl.org/docs/)
- [RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function](https://tools.ietf.org/html/rfc5869)
- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)