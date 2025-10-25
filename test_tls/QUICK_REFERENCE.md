# OpenSSL TLS 教程总结

## 🎯 你已经学到了什么

### 1. TLS 核心概念
- ✅ TLS 是什么：传输层安全协议，提供加密、完整性、认证
- ✅ TLS 握手流程：ClientHello → ServerHello → 密钥交换 → 加密通信
- ✅ 证书的作用：验证服务端身份，提供公钥用于密钥交换
- ✅ 对称 vs 非对称加密：握手用非对称，数据传输用对称

### 2. OpenSSL API 核心组件
- ✅ **SSL_CTX**：SSL 上下文，存储全局配置（证书、密钥、加密套件）
- ✅ **SSL**：SSL 连接对象，代表一个具体的 TLS 连接
- ✅ **SSL_METHOD**：选择协议方法（`TLS_client_method()` / `TLS_server_method()`）

### 3. 客户端实现步骤（7步）
```c
1. 创建 SSL_CTX        → SSL_CTX_new(TLS_client_method())
2. 配置验证（可选）    → SSL_CTX_load_verify_locations()
3. 创建 TCP socket     → socket() + connect()
4. 创建 SSL 对象       → SSL_new(ctx)
5. 绑定 SSL 到 socket  → SSL_set_fd(ssl, sockfd)
6. TLS 握手            → SSL_connect(ssl)  ⭐ 关键步骤
7. 加密通信            → SSL_write() / SSL_read()
```

### 4. 服务端实现步骤（8步）
```c
1. 创建 SSL_CTX        → SSL_CTX_new(TLS_server_method())
2. 加载证书            → SSL_CTX_use_certificate_file()  ⚠️ 必须
3. 加载私钥            → SSL_CTX_use_PrivateKey_file()   ⚠️ 必须
4. 创建监听 socket     → socket() + bind() + listen()
5. 接受客户端连接      → accept()
6. 创建 SSL 对象       → SSL_new(ctx)
7. 绑定 SSL 到 socket  → SSL_set_fd(ssl, client_fd)
8. TLS 握手            → SSL_accept(ssl)  ⭐ 关键步骤
9. 加密通信            → SSL_read() / SSL_write()
```

### 5. 关键 API 函数

| 函数 | 作用 | 客户端 | 服务端 |
|------|------|--------|--------|
| `SSL_CTX_new()` | 创建 SSL 上下文 | ✅ | ✅ |
| `SSL_CTX_use_certificate_file()` | 加载证书 | ❌ | ✅ 必须 |
| `SSL_CTX_use_PrivateKey_file()` | 加载私钥 | ❌ | ✅ 必须 |
| `SSL_CTX_load_verify_locations()` | 加载 CA 证书 | ✅ 推荐 | ❌ |
| `SSL_new()` | 创建 SSL 对象 | ✅ | ✅ |
| `SSL_set_fd()` | 绑定 socket | ✅ | ✅ |
| `SSL_connect()` | 客户端握手 | ✅ | ❌ |
| `SSL_accept()` | 服务端握手 | ❌ | ✅ |
| `SSL_write()` | 发送加密数据 | ✅ | ✅ |
| `SSL_read()` | 接收加密数据 | ✅ | ✅ |
| `SSL_shutdown()` | 关闭连接 | ✅ | ✅ |
| `SSL_free()` | 释放 SSL 对象 | ✅ | ✅ |
| `SSL_CTX_free()` | 释放 SSL_CTX | ✅ | ✅ |

## 📂 项目文件说明

```
test_tls/
├── test_tls.c          # 完整的客户端+服务端实现（500+ 行）
├── README.md           # 详细教程（你现在看的）
├── run_server.sh       # 启动服务端的脚本
├── run_client.sh       # 启动客户端的脚本
├── demo.sh             # 自动演示脚本
├── server-cert.pem     # 服务端证书（自动生成）
├── server-key.pem      # 服务端私钥（自动生成）
└── ca-cert.pem         # CA 证书（客户端信任列表）
```

## 🚀 快速开始

### 最简单的方式：运行演示脚本
```bash
bash demo.sh
```
这会自动：
1. 生成自签名证书
2. 启动服务端（后台）
3. 启动客户端连接服务端
4. 展示完整的 TLS 通信过程
5. 清理并退出

### 手动运行（两个终端）
```bash
# 终端 1：启动服务端
bash run_server.sh

# 终端 2：启动客户端
bash run_client.sh
```

## 🔍 代码核心部分解析

### 客户端握手核心代码
```c
// 1. 创建配置
SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

// 2. 创建 SSL 对象并绑定到 socket
SSL *ssl = SSL_new(ctx);
SSL_set_fd(ssl, sockfd);

// 3. 执行 TLS 握手（这一步完成了整个握手流程）
if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
}

// 4. 握手成功，可以安全通信了
printf("使用的加密套件：%s\n", SSL_get_cipher(ssl));
SSL_write(ssl, "Hello", 5);
```

**`SSL_connect()` 内部做了什么？**
1. 发送 ClientHello（包含支持的加密算法）
2. 接收 ServerHello + 证书
3. 验证服务端证书（如果配置了 CA）
4. 密钥交换（生成共享密钥）
5. 计算会话密钥
6. 发送 Finished 消息
7. 等待服务端 Finished 消息
8. 握手完成 ✅

### 服务端握手核心代码
```c
// 1. 创建配置
SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

// 2. 加载证书和私钥（服务端必须！）
SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM);
SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM);

// 3. 接受客户端 TCP 连接
int client_fd = accept(server_fd, NULL, NULL);

// 4. 创建 SSL 对象并绑定到客户端 socket
SSL *ssl = SSL_new(ctx);
SSL_set_fd(ssl, client_fd);

// 5. 执行 TLS 握手（这一步完成了整个握手流程）
if (SSL_accept(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
}

// 6. 握手成功，可以安全通信了
SSL_read(ssl, buffer, sizeof(buffer));
SSL_write(ssl, "World", 5);
```

**`SSL_accept()` 内部做了什么？**
1. 接收 ClientHello
2. 发送 ServerHello + 证书 + 私钥签名
3. 接收客户端的密钥交换消息
4. 计算会话密钥
5. 接收客户端 Finished 消息
6. 发送 Finished 消息
7. 握手完成 ✅

## ⚠️ 常见错误和解决方法

### 错误 1: 握手失败（Handshake Failure）
**症状：** `SSL_connect()` 或 `SSL_accept()` 返回 <= 0

**可能原因：**
1. 服务端没有加载证书/私钥
2. 证书与私钥不匹配
3. 客户端不信任服务端证书

**解决方法：**
```bash
# 查看详细错误
ERR_print_errors_fp(stderr);

# 重新生成证书
openssl req -new -x509 -key server-key.pem -out server-cert.pem -days 365
```

### 错误 2: 证书验证失败（Certificate Verify Failed）
**症状：** 客户端报错 "certificate verify failed"

**原因：** 客户端不信任服务端的自签名证书

**解决方法：**
```c
// 方法 1: 加载 CA 证书（推荐）
SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL);

// 方法 2: 关闭验证（仅用于测试！不安全）
SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
```

### 错误 3: 连接被拒绝（Connection Refused）
**症状：** `connect()` 失败

**原因：** 服务端未启动或端口不对

**解决方法：**
```bash
# 检查服务端是否在运行
ps aux | grep test_tls

# 检查端口是否被监听
lsof -i :4433
netstat -an | grep 4433
```

### 错误 4: SSL_read 返回 0
**这不是错误！** 这表示对方正常关闭了连接（调用了 `SSL_shutdown()`）

```c
int bytes = SSL_read(ssl, buffer, size);
if (bytes > 0) {
    // 正常接收数据
} else if (bytes == 0) {
    printf("连接已正常关闭\n");
} else {
    // 实际错误
    ERR_print_errors_fp(stderr);
}
```

## 💡 进阶话题

### 1. 证书验证回调
```c
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    // 自定义证书验证逻辑
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    // ... 检查证书 ...
    return 1; // 1 = 接受，0 = 拒绝
}

SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
```

### 2. 会话恢复（Session Resumption）
```c
// 保存会话
SSL_SESSION *session = SSL_get1_session(ssl);

// 下次连接时恢复
SSL_set_session(new_ssl, session);
```

### 3. SNI（Server Name Indication）
```c
// 客户端设置 SNI
SSL_set_tlsext_host_name(ssl, "example.com");

// 服务端处理 SNI
SSL_CTX_set_tlsext_servername_callback(ctx, sni_callback);
```

### 4. ALPN（Application-Layer Protocol Negotiation）
```c
// 客户端设置支持的协议
unsigned char alpn[] = "\x08http/1.1\x02h2";
SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));

// 服务端选择协议
SSL_CTX_set_alpn_select_cb(ctx, alpn_select_callback, NULL);
```

## 📊 性能优化建议

1. **重用 SSL_CTX**：多个连接共享一个 SSL_CTX
2. **会话恢复**：减少握手开销
3. **证书缓存**：避免重复加载证书
4. **线程池**：服务端使用线程池处理多个客户端
5. **非阻塞 IO**：结合 select/poll/epoll 提高并发性能

## 🔐 安全最佳实践

1. ✅ **使用 TLS 1.2+**：禁用 TLS 1.0/1.1
   ```c
   SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
   ```

2. ✅ **强加密套件**：只使用强加密算法
   ```c
   SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5");
   ```

3. ✅ **验证证书**：客户端必须验证服务端证书
   ```c
   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   ```

4. ✅ **保护私钥**：私钥文件权限设置为 600
   ```bash
   chmod 600 server-key.pem
   ```

5. ✅ **定期更新证书**：证书有效期不要太长（推荐 90 天）

## 📚 下一步学习

1. **阅读源码**：理解 `test_tls.c` 的每一行代码
2. **修改代码**：尝试添加新功能
3. **抓包分析**：用 Wireshark 观察 TLS 握手
4. **实现 HTTPS**：在 TLS 基础上实现 HTTP
5. **学习 TLS 1.3**：了解最新的 TLS 版本改进

## 🎓 学习检查清单

完成以下任务，确保你真正理解了 TLS：

- [ ] 能够解释 TLS 握手的每一步
- [ ] 能够独立编写客户端代码
- [ ] 能够独立编写服务端代码
- [ ] 理解 SSL_CTX 和 SSL 的区别
- [ ] 知道什么时候用 `SSL_connect()` 和 `SSL_accept()`
- [ ] 能够生成自签名证书
- [ ] 能够配置证书验证
- [ ] 能够处理 SSL 错误
- [ ] 能够用 Wireshark 分析 TLS 握手
- [ ] 能够解释对称加密和非对称加密的区别

---

**恭喜你！🎉**

你已经掌握了 OpenSSL TLS 编程的基础知识。继续实践和探索，你会成为 TLS 专家的！

**有问题？**
- 查看 README.md 的详细教程
- 阅读 OpenSSL 官方文档：https://www.openssl.org/docs/
- 参考示例代码：test_tls.c
