# 单向认证 vs 双向认证 - 快速对比

## 📊 核心对比表

| 特性 | 单向认证（One-way TLS） | 双向认证（Mutual TLS/mTLS） |
|------|------------------------|----------------------------|
| **客户端需要证书** | ❌ 不需要 | ✅ 需要 |
| **服务端需要证书** | ✅ 需要 | ✅ 需要 |
| **客户端验证服务端** | ✅ 验证 | ✅ 验证 |
| **服务端验证客户端** | ❌ 不验证 | ✅ 验证 |
| **安全性** | 中等 | 高 |
| **配置复杂度** | 低 | 中等 |
| **证书管理** | 简单（只管理服务端） | 复杂（管理双方） |
| **性能开销** | 低 | 稍高（多一次验证） |
| **适用场景** | 公开服务 | 内部系统、高安全场景 |

## 🔐 认证模式详解

### 单向认证（常见）
```
客户端 ──→ 服务端
  ↓          ↓
验证服务端   不验证客户端
  ✅         ❌

身份验证方式：
- 客户端：TLS 证书验证服务端身份
- 服务端：用户名/密码、Token、API Key 等其他方式
```

**典型场景：**
- 🌐 HTTPS 网站（你访问淘宝）
- 📱 移动应用连接后端 API
- 🔌 公开的 REST API

### 双向认证（高安全）
```
客户端 ⇄ 服务端
  ↓        ↓
验证服务端 验证客户端
  ✅       ✅

身份验证方式：
- 客户端：TLS 证书验证服务端身份
- 服务端：TLS 证书验证客户端身份
```

**典型场景：**
- 🏢 微服务之间通信（Service Mesh）
- 🔒 企业内部系统对接
- 💰 金融、支付系统
- 🤖 IoT 设备认证

## 📝 代码对比

### 服务端配置

#### 单向认证（默认）
```c
void configure_server_context(SSL_CTX *ctx) {
    // 只需加载服务端证书和私钥
    SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM);
    
    // 不设置验证模式 → 默认不验证客户端
}
```

#### 双向认证
```c
void configure_server_context(SSL_CTX *ctx) {
    // 1. 加载服务端证书和私钥
    SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM);
    
    // 2. 加载 CA 证书（用于验证客户端证书）⭐
    SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL);
    
    // 3. 要求并验证客户端证书 ⭐
    SSL_CTX_set_verify(ctx, 
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);
}
```

### 客户端配置

#### 单向认证（默认）
```c
void configure_client_context(SSL_CTX *ctx) {
    // 可选：加载 CA 证书验证服务端
    SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    // 不需要提供客户端证书
}
```

#### 双向认证
```c
void configure_client_context(SSL_CTX *ctx) {
    // 1. 加载客户端证书和私钥 ⭐
    SSL_CTX_use_certificate_file(ctx, "client-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "client-key.pem", SSL_FILETYPE_PEM);
    
    // 2. 加载 CA 证书验证服务端
    SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}
```

## 🔧 验证模式标志

### SSL_CTX_set_verify() 第二个参数

| 标志 | 值 | 客户端 | 服务端 | 说明 |
|------|---|--------|--------|------|
| `SSL_VERIFY_NONE` | 0x00 | ⚠️ 不安全 | ❌ 不推荐 | 完全不验证对方证书 |
| `SSL_VERIFY_PEER` | 0x01 | ✅ 推荐 | ✅ 双向认证 | 验证对方证书 |
| `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` | 0x02 | ❌ 无效 | ✅ 与 PEER 一起用 | 对方必须提供证书，否则握手失败 |
| `SSL_VERIFY_CLIENT_ONCE` | 0x04 | ❌ 无效 | ✅ 性能优化 | 只在初次握手时验证，重协商时不验证 |

### 常用组合

```c
// 客户端：验证服务端（推荐）
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

// 客户端：不验证服务端（不安全，仅测试）
SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

// 服务端：要求客户端提供证书（双向认证）
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

// 服务端：可选的客户端证书
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  // 不加 FAIL_IF_NO_PEER_CERT
```

## 📜 证书需求对比

### 单向认证

**服务端：**
- ✅ server-cert.pem（服务端证书）
- ✅ server-key.pem（服务端私钥）

**客户端：**
- ⚠️ ca-cert.pem（CA 证书，用于验证服务端，可选）

**总计：** 2-3 个文件

### 双向认证

**服务端：**
- ✅ server-cert.pem（服务端证书）
- ✅ server-key.pem（服务端私钥）
- ✅ ca-cert.pem（CA 证书，用于验证客户端）

**客户端：**
- ✅ client-cert.pem（客户端证书）⭐
- ✅ client-key.pem（客户端私钥）⭐
- ✅ ca-cert.pem（CA 证书，用于验证服务端）

**总计：** 6 个文件（共享 CA 证书）

## 🚀 快速切换方法

### 从单向认证切换到双向认证

1. **生成客户端证书**
   ```bash
   bash gen_mtls_certs.sh
   ```

2. **修改服务端代码**（`test_tls.c` 第 147 行）
   ```c
   // 取消注释这两行
   SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL);
   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
   ```

3. **修改客户端代码**（`test_tls.c` 第 320 行）
   ```c
   // 在 configure_client_context() 开头添加
   SSL_CTX_use_certificate_file(ctx, "client-cert.pem", SSL_FILETYPE_PEM);
   SSL_CTX_use_PrivateKey_file(ctx, "client-key.pem", SSL_FILETYPE_PEM);
   ```

4. **重新编译**
   ```bash
   gcc -o test_tls test_tls.c -I../openssl-3.5.2/include -L../openssl-3.5.2 -lssl -lcrypto
   ```

## 🎯 使用建议

### 什么时候用单向认证？

✅ **适用场景：**
- Web 应用、网站（HTTPS）
- 移动应用的后端 API
- 公开的 REST API
- 大量不可控的客户端

✅ **优势：**
- 配置简单
- 用户体验好（无需管理证书）
- 适合大规模部署

❌ **劣势：**
- 无法在 TLS 层面识别客户端身份
- 依赖其他认证方式（密码、Token）

### 什么时候用双向认证？

✅ **适用场景：**
- 微服务之间通信（Kubernetes Service Mesh）
- 企业内部系统对接
- IoT 设备与云端通信
- 金融、支付、医疗等高安全场景
- B2B API（企业对企业）

✅ **优势：**
- 安全性最高
- 在 TLS 层面完成认证
- 无需额外的认证机制
- 防止未授权访问

❌ **劣势：**
- 证书管理复杂
- 需要 PKI 基础设施
- 客户端配置复杂
- 证书过期、吊销处理麻烦

## 🔄 混合模式

### 可选的客户端证书

```c
// 服务端：请求但不强制要求客户端证书
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  // 不加 FAIL_IF_NO_PEER_CERT

// 握手后检查
X509 *client_cert = SSL_get_peer_certificate(ssl);
if (client_cert) {
    // 客户端提供了证书 → 高权限
    printf("已认证客户端\n");
    X509_free(client_cert);
} else {
    // 客户端未提供证书 → 基本权限
    printf("匿名客户端\n");
}
```

### 基于路径的不同要求

```c
// 公开接口：单向认证
if (path starts with "/api/public") {
    // 任何客户端都可以访问
}

// 管理接口：双向认证
if (path starts with "/api/admin") {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        return 403;  // Forbidden
    }
    X509_free(cert);
}
```

## 📚 相关命令

### 测试单向认证
```bash
# 客户端不提供证书
openssl s_client -connect localhost:4433 -CAfile ca-cert.pem
```

### 测试双向认证
```bash
# 客户端提供证书（应该成功）
openssl s_client -connect localhost:4433 \
  -cert client-cert.pem \
  -key client-key.pem \
  -CAfile ca-cert.pem

# 客户端不提供证书（应该失败）
openssl s_client -connect localhost:4433 -CAfile ca-cert.pem
```

## 🎓 学习路径

1. ✅ **理解单向认证**：运行默认的 test_tls
2. ✅ **生成双向认证证书**：运行 `gen_mtls_certs.sh`
3. ✅ **修改代码启用双向认证**：按上述步骤修改
4. ✅ **测试双向认证**：用 OpenSSL 命令行工具
5. ✅ **实现可选证书**：混合模式
6. ✅ **实现证书验证回调**：自定义验证逻辑

---

**总结：**
- 大多数情况用**单向认证** → 简单、够用
- 高安全场景用**双向认证** → 最安全、最可靠
- 根据实际需求选择，不要过度设计 🎯
