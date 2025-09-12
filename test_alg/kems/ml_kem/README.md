# ML-KEM 密钥封装机制测试程序

这是一个用于测试 OpenSSL 3.5+ 中 ML-KEM (Module Lattice Key Encapsulation Mechanism) 后量子密钥封装算法的测试程序。

## 算法简介

ML-KEM 是 NIST 后量子密码标准化项目选定的密钥封装机制标准，基于格理论的数学困难问题。它提供了抵御经典和量子计算机攻击的安全性。

### 支持的算法变种

- **ML-KEM-512**: 128位安全强度，密钥封装机制
- **ML-KEM-768**: 192位安全强度，密钥封装机制  
- **ML-KEM-1024**: 256位安全强度，密钥封装机制

## 系统要求

### OpenSSL 版本
- **OpenSSL 3.5.0** 或更高版本
- 必须启用后量子密码学支持

### 编译环境
- GCC 或 Clang 编译器
- 支持 C99 标准
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

### 运行特定算法测试
```bash
make test-512    # 测试 ML-KEM-512
make test-768    # 测试 ML-KEM-768  
make test-1024   # 测试 ML-KEM-1024
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
1. **算法支持检测**: 检查当前 OpenSSL 是否支持 ML-KEM 算法
2. **密钥对生成**: 生成 ML-KEM 公私钥对
3. **密钥封装**: 使用公钥生成共享密钥和密文
4. **密钥解封装**: 使用私钥从密文中恢复共享密钥
5. **一致性验证**: 验证封装和解封装得到的共享密钥是否一致

### 测试流程
```
1. 生成密钥对 (公钥, 私钥)
2. 使用公钥进行密钥封装 → (密文, 共享密钥1)
3. 使用私钥对密文进行解封装 → 共享密钥2
4. 验证 共享密钥1 == 共享密钥2
```

## 输出示例

```
ML-KEM (Module Lattice Key Encapsulation Mechanism) 测试程序
使用 OpenSSL 3.5+ 的后量子密钥封装算法
==============================================
OpenSSL 版本: OpenSSL 3.5.0 
✓ 当前OpenSSL版本支持ML-KEM算法

========================================
开始测试 ML-KEM-512 完整流程
========================================

=== 测试 ML-KEM 密钥生成 (ML-KEM-512) ===
密钥生成成功！

=== 测试 ML-KEM 密钥封装 (ML-KEM-512) ===
密文长度: 768 bytes
共享密钥长度: 32 bytes
密钥封装成功！
密文: c1a2b3c4d5e6f708...
共享密钥: 1234567890abcdef...

=== 测试 ML-KEM 密钥解封装 (ML-KEM-512) ===
共享密钥长度: 32 bytes
密钥解封装成功！
共享密钥: 1234567890abcdef...

=== 验证共享密钥一致性 ===
✓ 共享密钥一致性验证成功！
共享密钥长度: 32 bytes

ML-KEM-512 测试完成 - 成功!

==============================================
测试总结:
成功: 3/3
✓ 所有ML-KEM算法测试通过!
```

## 技术详情

### 密钥大小
- **ML-KEM-512**: 公钥 800字节, 私钥 1632字节, 密文 768字节, 共享密钥 32字节
- **ML-KEM-768**: 公钥 1184字节, 私钥 2400字节, 密文 1088字节, 共享密钥 32字节
- **ML-KEM-1024**: 公钥 1568字节, 私钥 3168字节, 密文 1568字节, 共享密钥 32字节

### OpenSSL API 使用
- `EVP_PKEY_keygen()` - 密钥对生成
- `EVP_PKEY_encapsulate()` - 密钥封装
- `EVP_PKEY_decapsulate()` - 密钥解封装

## 故障排除

### 常见问题

1. **编译失败**
   ```
   错误: openssl/evp.h: No such file or directory
   ```
   **解决方案**: 确保 OpenSSL 3.5+ 已正确安装，头文件路径正确。

2. **运行时错误**
   ```
   错误: 当前OpenSSL版本不支持ML-KEM算法
   ```
   **解决方案**: 升级到 OpenSSL 3.5.0+ 并确保启用了后量子密码支持。

3. **链接错误**
   ```
   undefined reference to EVP_PKEY_encapsulate
   ```
   **解决方案**: 确保链接了正确版本的 libcrypto 库。

### 调试模式
编译调试版本以获得更详细的错误信息：
```bash
make debug
```

## 安全注意事项

1. **测试目的**: 本程序仅用于测试和学习，不适用于生产环境
2. **随机性**: 使用系统随机数生成器，确保真随机性
3. **内存安全**: 敏感数据使用后会被安全清除
4. **量子安全性**: ML-KEM 提供量子计算机抵抗性

## 文件结构

```
ml_kem/
├── ml_kem.c          # 主程序源代码
├── Makefile          # 构建配置
├── README.md         # 本文档
└── test_ml_kem       # 编译后的可执行文件
```

## 相关标准

- **FIPS 203**: ML-KEM 标准规范
- **NIST PQC**: NIST 后量子密码标准化项目
- **RFC**: 相关 Internet 标准草案

## 许可证

本程序遵循与 OpenSSL 相同的许可证条款。

## 参考资料

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [OpenSSL 3.5+ Documentation](https://www.openssl.org/docs/)
- [FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)