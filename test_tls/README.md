# OpenSSL TLS 编程教程

> 从零开始学习 OpenSSL TLS 编程，包含完整的客户端和服务端实现。

## 📚 文档导航

- **📖 本文档（README.md）** - 完整教程，适合系统学习
- **⚡ [QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - API 速查表，快速查找函数用法
- **🔐 [ONE_WAY_VS_MUTUAL_TLS.md](ONE_WAY_VS_MUTUAL_TLS.md)** - 单向/双向认证对比
- **📑 [INDEX.md](INDEX.md)** - 完整文件索引和学习路径

---

## 📚 快速导航

### 🚀 快速开始（2分钟）
```bash
# 1. 编译
gcc -o test_tls test_tls.c -I../openssl-3.5.2/include -L../openssl-3.5.2 -lssl -lcrypto

# 2. 运行演示
bash demo.sh
```

### 📖 学习路径
- **新手**：先阅读 [TLS 基础概念](#1-tls-基础概念) 和 [快速开始](#7-编译和运行)
- **进阶**：学习 [客户端实现](#4-客户端实现步骤) 和 [服务端实现](#5-服务端实现步骤)
- **高级**：了解 [单向认证 vs 双向认证](#9-单向认证-vs-双向认证)

### 📋 文件说明
| 文件 | 说明 |
|------|------|
| `test_tls.c` | 完整的客户端+服务端实现 |
| `run_server.sh` / `run_client.sh` | 快速启动脚本 |
| `demo.sh` | 自动演示脚本 |
| `gen_mtls_certs.sh` | 生成双向认证证书 |

---

## 目录
1. [TLS 基础概念](#1-tls-基础概念)
2. [TLS 握手流程](#2-tls-握手流程)
3. [OpenSSL TLS API 核心组件](#3-openssl-tls-api-核心组件)
4. [客户端实现步骤](#4-客户端实现步骤)
5. [服务端实现步骤](#5-服务端实现步骤)
6. [完整示例说明](#6-完整示例说明)
7. [编译和运行](#7-编译和运行)
8. [常见问题](#8-常见问题)
9. [单向认证 vs 双向认证](#9-单向认证-vs-双向认证)
10. [常见问题（扩展）](#10-常见问题扩展)

---

## 1. TLS 基础概念

### 什么是 TLS？
**TLS (Transport Layer Security)** 是一种加密协议，用于在网络通信中提供：
- **机密性 (Confidentiality)**：数据加密，防止窃听
- **完整性 (Integrity)**：防止数据被篡改
- **认证 (Authentication)**：验证通信对方的身份

### TLS vs SSL
- **SSL (Secure Sockets Layer)**：旧协议，已被废弃
- **TLS**：SSL 的继任者，更安全
- OpenSSL 库同时支持两者（但建议只使用 TLS 1.2+）

### TLS 版本
- **TLS 1.0/1.1**：已废弃，不安全
- **TLS 1.2**：当前广泛使用
- **TLS 1.3**：最新版本，更快更安全（OpenSSL 1.1.1+）

---

## 2. TLS 握手流程

TLS 握手是建立安全连接的过程，让我们用通俗的方式理解：

### TLS 1.2 握手流程（简化版）

```
客户端                                服务端
  |                                     |
  |------ ① ClientHello -------------->|  (客户端发送：支持的加密算法、随机数)
  |                                     |
  |<----- ② ServerHello ---------------|  (服务端选择：加密算法、发送证书、随机数)
  |       ServerCertificate             |
  |       ServerHelloDone               |
  |                                     |
  |------ ③ ClientKeyExchange -------->|  (客户端发送：预主密钥，用服务端公钥加密)
  |       ChangeCipherSpec              |
  |       Finished                      |
  |                                     |
  |<----- ④ ChangeCipherSpec ----------|  (服务端确认：开始加密通信)
  |       Finished                      |
  |                                     |
  |====== 加密通信开始 =================|
  |                                     |
  |<===== ⑤ 应用数据交换 =============>|  (SSL_read/SSL_write)
  |                                     |
```

### 握手步骤详解

#### ① ClientHello - 客户端打招呼
客户端说："你好！我支持这些加密算法，这是我的随机数，咱们开始吧！"
- 发送支持的 TLS 版本
- 发送支持的加密套件列表
- 发送客户端随机数（Client Random）

#### ② ServerHello - 服务端响应
服务端说："好的！我选择用这个加密算法，这是我的证书（证明我是真的），这是我的随机数。"
- 选择 TLS 版本和加密套件
- 发送服务端证书（包含公钥）
- 发送服务端随机数（Server Random）

#### ③ 密钥交换
客户端：
1. 验证服务端证书是否可信
2. 生成预主密钥（Pre-Master Secret）
3. 用服务端公钥加密预主密钥
4. 发送给服务端

#### ④ 密钥计算
双方使用三个随机数（Client Random + Server Random + Pre-Master Secret）计算出**会话密钥**：
- 加密密钥
- MAC 密钥
- 初始化向量（IV）

#### ⑤ 开始加密通信
握手完成，双方使用会话密钥进行对称加密通信

---

## 3. OpenSSL TLS API 核心组件

### 3.1 核心数据结构

#### **SSL_CTX** - SSL 上下文（配置模板）
```c
SSL_CTX *ctx;
```
**作用**：存储 SSL/TLS 的全局配置
- **类比**：就像一个"配置模板"或"工厂"
- **配置内容**：
  - 证书和私钥
  - 支持的 TLS 版本
  - 加密套件
  - 验证模式

**为什么需要它？**
- 可以创建多个 SSL 连接共享同一个配置
- 避免重复设置，提高效率

#### **SSL** - SSL 连接对象
```c
SSL *ssl;
```
**作用**：代表一个具体的 SSL/TLS 连接
- **类比**：就像一个"电话通话"
- **每个连接独立**：可以同时有多个 SSL 对象（多个客户端连接）
- **关联 socket**：通过 `SSL_set_fd()` 绑定到 TCP socket

### 3.2 核心 API 函数

#### 初始化相关

```c
// 创建 SSL 上下文
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
  参数：method - TLS_client_method() 或 TLS_server_method()
  返回：SSL_CTX 指针，失败返回 NULL

// 创建 SSL 连接对象
SSL *SSL_new(SSL_CTX *ctx);
  参数：ctx - SSL 上下文
  返回：SSL 指针，失败返回 NULL
```

#### 证书和密钥相关

```c
// 加载服务端证书（服务端必须）
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
  参数：
    ctx - SSL 上下文
    file - 证书文件路径（通常是 .pem 或 .crt）
    type - SSL_FILETYPE_PEM 或 SSL_FILETYPE_ASN1
  返回：1 成功，0 失败

// 加载服务端私钥（服务端必须）
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
  参数：同上
  返回：1 成功，0 失败

// 加载 CA 证书（客户端验证服务端证书时用）
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, 
                                   const char *CAfile,
                                   const char *CApath);
  参数：
    CAfile - CA 证书文件路径
    CApath - CA 证书目录路径
  返回：1 成功，0 失败
```

#### 连接相关

```c
// 将 SSL 对象绑定到 socket
int SSL_set_fd(SSL *ssl, int fd);
  参数：
    ssl - SSL 对象
    fd - socket 文件描述符
  返回：1 成功，0 失败

// 客户端发起 TLS 握手
int SSL_connect(SSL *ssl);
  作用：客户端主动连接服务端，完成 TLS 握手
  返回：1 成功，<= 0 失败

// 服务端接受 TLS 握手
int SSL_accept(SSL *ssl);
  作用：服务端等待客户端握手请求并响应
  返回：1 成功，<= 0 失败
```

#### 数据传输相关

```c
// 读取加密数据
int SSL_read(SSL *ssl, void *buf, int num);
  参数：
    ssl - SSL 对象
    buf - 接收缓冲区
    num - 缓冲区大小
  返回：读取的字节数，<= 0 表示错误或连接关闭

// 发送加密数据
int SSL_write(SSL *ssl, const void *buf, int num);
  参数：
    ssl - SSL 对象
    buf - 要发送的数据
    num - 数据长度
  返回：实际发送的字节数，<= 0 表示错误
```

#### 清理相关

```c
// 关闭 SSL 连接
int SSL_shutdown(SSL *ssl);
  返回：1 双向关闭完成，0 需要再次调用，< 0 错误

// 释放 SSL 对象
void SSL_free(SSL *ssl);

// 释放 SSL 上下文
void SSL_CTX_free(SSL_CTX *ctx);
```

#### 错误处理

```c
// 获取错误码
int SSL_get_error(SSL *ssl, int ret);
  参数：
    ssl - SSL 对象
    ret - SSL_read/SSL_write 的返回值
  返回：错误类型（SSL_ERROR_NONE, SSL_ERROR_WANT_READ 等）

// 打印错误信息
void ERR_print_errors_fp(FILE *fp);
  参数：fp - 输出文件指针（通常是 stderr）
```

---

## 4. 客户端实现步骤

### 步骤概览

```
1. 初始化 OpenSSL
2. 创建 SSL_CTX（使用 TLS_client_method）
3. 配置 SSL_CTX（可选：加载 CA 证书）
4. 创建 TCP socket 并连接服务器
5. 创建 SSL 对象
6. 将 SSL 绑定到 socket
7. 执行 TLS 握手（SSL_connect）
8. 加密通信（SSL_read/SSL_write）
9. 关闭连接
10. 清理资源
```

### 详细步骤

#### 步骤 1: 初始化 OpenSSL
```c
// 在 OpenSSL 3.0+ 中，不需要显式初始化
// OpenSSL 1.1.0+ 也会自动初始化
// 如果使用旧版本，需要：
SSL_library_init();
SSL_load_error_strings();
OpenSSL_add_all_algorithms();
```

#### 步骤 2: 创建 SSL_CTX
```c
const SSL_METHOD *method = TLS_client_method();
SSL_CTX *ctx = SSL_CTX_new(method);
if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(1);
}
```

**为什么用 `TLS_client_method()`？**
- 自动选择客户端支持的最高 TLS 版本
- 比指定 `TLSv1_2_client_method()` 更灵活

#### 步骤 3: 配置 SSL_CTX（可选）
```c
// 如果要验证服务端证书（推荐）
SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL);

// 设置验证模式
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
```

**什么是证书验证？**
- **SSL_VERIFY_NONE**：不验证（不安全，容易被中间人攻击）
- **SSL_VERIFY_PEER**：验证对方证书（推荐）

#### 步骤 4: 创建 socket 并连接
```c
int sockfd = socket(AF_INET, SOCK_STREAM, 0);

struct sockaddr_in server_addr;
server_addr.sin_family = AF_INET;
server_addr.sin_port = htons(4433);
inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
    perror("connect");
    exit(1);
}
```

#### 步骤 5-6: 创建 SSL 并绑定 socket
```c
SSL *ssl = SSL_new(ctx);
SSL_set_fd(ssl, sockfd);
```

#### 步骤 7: TLS 握手
```c
if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
}

printf("TLS 握手成功！使用的加密套件：%s\n", SSL_get_cipher(ssl));
```

#### 步骤 8: 加密通信
```c
// 发送数据
const char *msg = "Hello, TLS Server!";
SSL_write(ssl, msg, strlen(msg));

// 接收数据
char buffer[1024] = {0};
int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
printf("收到服务端响应：%s\n", buffer);
```

#### 步骤 9-10: 清理
```c
SSL_shutdown(ssl);
SSL_free(ssl);
close(sockfd);
SSL_CTX_free(ctx);
```

---

## 5. 服务端实现步骤

### 步骤概览

```
1. 初始化 OpenSSL
2. 创建 SSL_CTX（使用 TLS_server_method）
3. 加载证书和私钥（必须）
4. 创建 TCP socket 并监听
5. 进入循环：
   a. accept 客户端连接
   b. 创建 SSL 对象
   c. 将 SSL 绑定到客户端 socket
   d. 执行 TLS 握手（SSL_accept）
   e. 加密通信（SSL_read/SSL_write）
   f. 关闭 SSL 连接
6. 清理资源
```

### 详细步骤

#### 步骤 2: 创建服务端 SSL_CTX
```c
const SSL_METHOD *method = TLS_server_method();
SSL_CTX *ctx = SSL_CTX_new(method);
```

#### 步骤 3: 加载证书和私钥（必须！）
```c
// 加载服务端证书
if (SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
}

// 加载服务端私钥
if (SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
}

// 验证私钥与证书是否匹配
if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr, "私钥与证书不匹配\n");
    exit(1);
}
```

**为什么服务端必须有证书？**
- 客户端需要验证服务端身份
- 证书包含服务端公钥，用于密钥交换

#### 步骤 4: 创建监听 socket
```c
int server_fd = socket(AF_INET, SOCK_STREAM, 0);

struct sockaddr_in addr;
addr.sin_family = AF_INET;
addr.sin_port = htons(4433);
addr.sin_addr.s_addr = INADDR_ANY;

bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
listen(server_fd, 5);

printf("服务端监听在端口 4433...\n");
```

#### 步骤 5: 接受客户端连接
```c
while (1) {
    // 5a. 接受 TCP 连接
    int client_fd = accept(server_fd, NULL, NULL);
    
    // 5b-c. 创建 SSL 并绑定
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    
    // 5d. TLS 握手
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        // 5e. 通信
        char buffer[1024] = {0};
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        printf("收到客户端消息：%s\n", buffer);
        
        const char *reply = "Hello, TLS Client!";
        SSL_write(ssl, reply, strlen(reply));
    }
    
    // 5f. 关闭
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
}
```

---

## 6. 完整示例说明

`test_tls.c` 实现了一个完整的客户端-服务端示例：

### 运行模式
```bash
# 服务端模式
./test_tls server

# 客户端模式
./test_tls client
```

### 功能特性
1. **自动生成自签名证书**（用于测试）
2. **客户端和服务端代码在同一文件**
3. **完整的错误处理**
4. **支持多次通信**

### 证书生成
程序会自动调用 OpenSSL 命令生成：
- `server-key.pem`：服务端私钥
- `server-cert.pem`：服务端证书
- `ca-cert.pem`：CA 证书（客户端信任列表）

---

## 7. 编译和运行

### 编译
```bash
cd /Users/chengheming/Source/Personal/DebugOpenSSL/test_tls

# macOS/Linux
gcc -o test_tls test_tls.c \
    -I../openssl-3.5.2/include \
    -L../openssl-3.5.2 \
    -lssl -lcrypto

# 或使用 CMake（如果你配置了 CMakeLists.txt）
mkdir build && cd build
cmake ..
make
```

### 运行

#### 方法 1: 使用提供的脚本（推荐）

**步骤 1: 启动服务端**
```bash
# 在终端 1 中运行
bash run_server.sh
```

**步骤 2: 启动客户端（打开新终端）**
```bash
# 在终端 2 中运行
bash run_client.sh
```

#### 方法 2: 手动设置环境变量

**步骤 1: 启动服务端**
```bash
# macOS
export DYLD_LIBRARY_PATH=../openssl-3.5.2:$DYLD_LIBRARY_PATH
./test_tls server

# Linux
export LD_LIBRARY_PATH=../openssl-3.5.2:$LD_LIBRARY_PATH
./test_tls server
```

**步骤 2: 启动客户端（新终端）**
```bash
# macOS
export DYLD_LIBRARY_PATH=../openssl-3.5.2:$DYLD_LIBRARY_PATH
./test_tls client

# Linux
export LD_LIBRARY_PATH=../openssl-3.5.2:$LD_LIBRARY_PATH
./test_tls client
```

#### 预期输出

**服务端首次启动时：**
```
[服务端] 正在生成自签名证书...
[服务端] 证书生成完成
[服务端] SSL_CTX 创建成功
[服务端] 证书和私钥加载成功
[服务端] 服务端监听在 127.0.0.1:4433
[服务端] 等待客户端连接...
```

**客户端连接时：**
```
[客户端] SSL_CTX 创建成功
[客户端] 已加载 CA 证书，将验证服务端证书
[客户端] 已连接到服务端 127.0.0.1:4433
[客户端] 开始 TLS 握手...
[客户端] TLS 握手成功！
[客户端] 使用的加密套件：TLS_AES_256_GCM_SHA384
[客户端] TLS 版本：TLSv1.3
[客户端] 发送消息：Hello from TLS client!
[客户端] 收到服务端响应：Hello from TLS server! Message received: Hello from TLS client!
[客户端] 连接已关闭
```

**服务端接受连接时：**
```
[服务端] 接受客户端连接，fd=4
[服务端] 等待 TLS 握手...
[服务端] TLS 握手成功！
[服务端] 使用的加密套件：TLS_AES_256_GCM_SHA384
[服务端] TLS 版本：TLSv1.3
[服务端] 收到客户端消息：Hello from TLS client!
[服务端] 发送响应给客户端
[服务端] 客户端连接已关闭
[服务端] 等待客户端连接...
```

#### 使用 OpenSSL 命令行工具测试

你也可以使用 OpenSSL 自带的工具测试：

**用 `openssl s_client` 作为客户端：**
```bash
# 启动服务端后，在另一个终端运行
../openssl-3.5.2/apps/openssl s_client -connect 127.0.0.1:4433 -CAfile ca-cert.pem
```

**用 `openssl s_server` 作为服务端：**
```bash
# 先生成证书，然后运行服务端
../openssl-3.5.2/apps/openssl s_server -accept 4433 -cert server-cert.pem -key server-key.pem

# 在另一个终端运行客户端
./test_tls client
```

---

## 8. 常见问题

### Q1: 为什么握手失败？
**可能原因：**
1. 证书不存在或路径错误
   - 检查 `server-cert.pem` 和 `server-key.pem` 是否存在
2. 证书与私钥不匹配
   - 重新生成证书
3. 客户端不信任服务端证书
   - 客户端需要加载 CA 证书

**解决方法：**
```bash
# 查看详细错误
ERR_print_errors_fp(stderr);
```

### Q2: SSL_read 返回 0 是什么意思？
**表示连接已正常关闭**
- 对方调用了 `SSL_shutdown()`
- 这是正常的结束流程

### Q3: SSL_connect 卡住不动？
**可能原因：**
1. 服务端未调用 `SSL_accept()`
2. 防火墙阻止连接
3. 服务端未启动

### Q4: 如何查看 TLS 版本和加密套件？
```c
printf("TLS 版本：%s\n", SSL_get_version(ssl));
printf("加密套件：%s\n", SSL_get_cipher(ssl));
```

### Q5: 自签名证书安全吗？
**仅用于测试！**
- 生产环境必须使用 CA 签发的证书
- 自签名证书容易被中间人攻击

### Q6: 如何限制 TLS 版本？
```c
// 只允许 TLS 1.2 和 1.3
SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
```

### Q7: 多线程如何处理？
```c
// 服务端为每个客户端创建线程
pthread_t thread;
pthread_create(&thread, NULL, handle_client, (void*)ssl);
pthread_detach(thread);
```

---

## 附录：术语表

| 术语 | 英文 | 解释 |
|------|------|------|
| TLS | Transport Layer Security | 传输层安全协议 |
| SSL | Secure Sockets Layer | TLS 的前身（已废弃） |
| 握手 | Handshake | 建立安全连接的协商过程 |
| 证书 | Certificate | 包含公钥的数字文件，用于身份验证 |
| CA | Certificate Authority | 证书颁发机构 |
| 私钥 | Private Key | 密钥对的私有部分，必须保密 |
| 公钥 | Public Key | 密钥对的公开部分，可以公开 |
| 加密套件 | Cipher Suite | 一组加密算法的组合 |
| 对称加密 | Symmetric Encryption | 使用相同密钥加密和解密 |
| 非对称加密 | Asymmetric Encryption | 使用不同密钥（公钥/私钥）加密和解密 |

---

## 附录：代码流程图解

### 客户端完整流程

```
开始
  │
  ├─→ 1. 创建 SSL_CTX (TLS_client_method)
  │      └─ SSL_CTX_new()
  │
  ├─→ 2. 配置 SSL_CTX
  │      ├─ SSL_CTX_load_verify_locations() [可选：加载 CA 证书]
  │      └─ SSL_CTX_set_verify() [设置验证模式]
  │
  ├─→ 3. 创建 TCP socket
  │      ├─ socket()
  │      └─ connect() [连接到服务端 IP:端口]
  │
  ├─→ 4. 创建 SSL 对象
  │      └─ SSL_new(ctx)
  │
  ├─→ 5. 绑定 SSL 到 socket
  │      └─ SSL_set_fd(ssl, sockfd)
  │
  ├─→ 6. TLS 握手 ⭐
  │      └─ SSL_connect(ssl)
  │           ├─ 发送 ClientHello
  │           ├─ 接收 ServerHello + 证书
  │           ├─ 验证服务端证书
  │           ├─ 密钥交换
  │           └─ 计算会话密钥
  │
  ├─→ 7. 加密通信 🔐
  │      ├─ SSL_write(ssl, data, len) [发送加密数据]
  │      └─ SSL_read(ssl, buffer, size) [接收加密数据]
  │
  ├─→ 8. 关闭连接
  │      ├─ SSL_shutdown(ssl) [关闭 SSL 连接]
  │      └─ close(sockfd) [关闭 TCP socket]
  │
  └─→ 9. 清理资源
         ├─ SSL_free(ssl)
         └─ SSL_CTX_free(ctx)
结束
```

### 服务端完整流程

```
开始
  │
  ├─→ 1. 创建 SSL_CTX (TLS_server_method)
  │      └─ SSL_CTX_new()
  │
  ├─→ 2. 配置 SSL_CTX ⚠️ 必须！
  │      ├─ SSL_CTX_use_certificate_file() [加载证书]
  │      ├─ SSL_CTX_use_PrivateKey_file() [加载私钥]
  │      └─ SSL_CTX_check_private_key() [验证匹配]
  │
  ├─→ 3. 创建监听 socket
  │      ├─ socket()
  │      ├─ bind() [绑定 IP:端口]
  │      └─ listen() [开始监听]
  │
  ├─→ 4. 主循环：接受客户端
  │      │
  │      ├─→ accept() [等待客户端连接]
  │      │     └─ 返回客户端 socket fd
  │      │
  │      ├─→ 创建 SSL 对象
  │      │     └─ SSL_new(ctx)
  │      │
  │      ├─→ 绑定 SSL 到客户端 socket
  │      │     └─ SSL_set_fd(ssl, client_fd)
  │      │
  │      ├─→ TLS 握手 ⭐
  │      │     └─ SSL_accept(ssl)
  │      │          ├─ 接收 ClientHello
  │      │          ├─ 发送 ServerHello + 证书
  │      │          ├─ 接收客户端密钥交换
  │      │          └─ 计算会话密钥
  │      │
  │      ├─→ 加密通信 🔐
  │      │     ├─ SSL_read(ssl, buffer, size)
  │      │     └─ SSL_write(ssl, data, len)
  │      │
  │      ├─→ 关闭客户端连接
  │      │     ├─ SSL_shutdown(ssl)
  │      │     ├─ SSL_free(ssl)
  │      │     └─ close(client_fd)
  │      │
  │      └─→ 回到 accept() [等待下一个客户端]
  │
  └─→ 清理（程序退出时）
         ├─ close(server_fd)
         └─ SSL_CTX_free(ctx)
结束
```

### TLS 握手详细流程（TLS 1.3）

```
客户端                                         服务端
  │                                              │
  │───────── ① ClientHello ────────────────────→│
  │   包含：                                      │
  │   - 支持的 TLS 版本 (TLS 1.3)                │
  │   - 随机数 (Client Random)                   │
  │   - 支持的加密套件列表                       │
  │   - 支持的扩展                               │
  │   - 密钥共享 (Key Share)                     │
  │                                              │
  │←──────── ② ServerHello + ... ───────────────│
  │   包含：                                      │
  │   - 选择的 TLS 版本                          │
  │   - 随机数 (Server Random)                   │
  │   - 选择的加密套件                           │
  │   - 密钥共享 (Key Share)                     │
  │   ───────────────────────────────────────   │
  │   [加密握手消息] Encrypted Extensions        │
  │   [加密握手消息] Certificate (服务端证书)    │
  │   [加密握手消息] Certificate Verify (签名)   │
  │   [加密握手消息] Finished (握手完成)         │
  │                                              │
  ├─→ [客户端验证服务端证书]                     │
  ├─→ [双方计算会话密钥]                         │
  │                                              │
  │───────── ③ [加密握手消息] ──────────────────→│
  │   包含：                                      │
  │   - Finished (握手完成)                      │
  │                                              │
  │═══════════ 握手完成，开始加密通信 ═══════════│
  │                                              │
  │←═════════ ④ 应用数据 (加密) ════════════════→│
  │                                              │
```

**TLS 1.3 相比 TLS 1.2 的改进：**
- ✅ 更少的往返次数（1-RTT vs 2-RTT）
- ✅ 更强的安全性（移除弱加密算法）
- ✅ 前向保密（Perfect Forward Secrecy）
- ✅ 0-RTT 恢复会话（可选）

### 密钥计算过程

```
客户端和服务端都有：
  ├─ Client Random (ClientHello 中)
  ├─ Server Random (ServerHello 中)
  └─ 共享密钥 (通过 ECDHE 或 DHE 密钥交换)

↓ 使用密钥派生函数 (KDF)

会话密钥：
  ├─ 客户端写密钥 (Client Write Key) - 客户端加密用
  ├─ 服务端写密钥 (Server Write Key) - 服务端加密用
  ├─ 客户端 MAC 密钥 (Client MAC Key) - 验证完整性
  ├─ 服务端 MAC 密钥 (Server MAC Key) - 验证完整性
  └─ 初始化向量 (IV)

↓

对称加密通信 (AES-GCM, ChaCha20-Poly1305 等)
```

### 证书验证流程

```
客户端接收到服务端证书后：
  │
  ├─→ 1. 检查证书有效期
  │      ├─ Not Before (开始时间)
  │      └─ Not After (结束时间)
  │
  ├─→ 2. 检查证书用途
  │      └─ 是否允许用于 TLS 服务端认证
  │
  ├─→ 3. 检查主机名
  │      └─ 证书的 CN 或 SAN 是否匹配服务端域名
  │
  ├─→ 4. 验证证书链 ⭐
  │      ├─ 服务端证书
  │      ├─ 中间 CA 证书 (可能有多个)
  │      └─ 根 CA 证书 (必须在客户端信任列表中)
  │
  ├─→ 5. 验证签名
  │      └─ 用上级 CA 的公钥验证证书签名
  │
  ├─→ 6. 检查吊销状态 (可选)
  │      ├─ CRL (证书吊销列表)
  │      └─ OCSP (在线证书状态协议)
  │
  └─→ ✅ 验证通过 / ❌ 验证失败
```

---

## 附录：OpenSSL 命令行工具使用

### 生成证书和密钥

```bash
# 1. 生成 RSA 私钥
openssl genpkey -algorithm RSA -out server-key.pem -pkeyopt rsa_keygen_bits:2048

# 2. 生成自签名证书（用于测试）
openssl req -new -x509 -key server-key.pem -out server-cert.pem -days 365 \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/CN=localhost"

# 3. 查看证书内容
openssl x509 -in server-cert.pem -text -noout

# 4. 验证私钥和证书是否匹配
openssl x509 -noout -modulus -in server-cert.pem | openssl md5
openssl rsa -noout -modulus -in server-key.pem | openssl md5
# 两个 MD5 值应该相同
```

### 使用 OpenSSL 命令行测试 TLS

```bash
# 启动测试服务端
openssl s_server -accept 4433 -cert server-cert.pem -key server-key.pem -www

# 连接到服务端（测试客户端）
openssl s_client -connect localhost:4433 -CAfile ca-cert.pem

# 查看服务端支持的加密套件
openssl s_server -accept 4433 -cert server-cert.pem -key server-key.pem -cipher

# 测试特定的 TLS 版本
openssl s_client -connect localhost:4433 -tls1_3
openssl s_client -connect localhost:4433 -tls1_2

# 显示详细的 TLS 握手信息
openssl s_client -connect localhost:4433 -state -debug
```

### 调试 TLS 连接

```bash
# 抓取网络包查看 TLS 握手
tcpdump -i lo0 -nn -X port 4433

# 使用 Wireshark 查看（推荐）
# 1. 启动 Wireshark
# 2. 过滤器输入：tcp.port == 4433
# 3. 可以看到完整的 TLS 握手过程
```

---

**学习建议：**
1. ✅ 先运行示例代码，观察输出
2. ✅ 修改代码，尝试不同的配置
3. ✅ 使用 Wireshark 抓包观察 TLS 握手过程
4. ✅ 阅读 OpenSSL 官方文档：https://www.openssl.org/docs/
5. ✅ 尝试实现更多功能：
   - 证书验证回调
   - 会话恢复
   - 多线程服务端
   - SNI (Server Name Indication)
   - ALPN (Application-Layer Protocol Negotiation)
   - **双向认证（Mutual TLS）** ⭐

---

## 9. 单向认证 vs 双向认证

### 9.1 什么是单向认证？

**单向认证（Single-way Authentication）** 是最常见的 TLS 模式：
- ✅ **客户端验证服务端**：确保连接的是正确的服务端
- ❌ **服务端不验证客户端**：任何客户端都可以连接

**使用场景：**
- 网页浏览（HTTPS）
- 大多数公开的 API 服务
- 移动应用连接后端服务器

**示例：**
```
你 (客户端)  →  淘宝服务器 (服务端)
检查淘宝证书 ✅   不检查你的身份 ❌
```

### 9.2 什么是双向认证？

**双向认证（Mutual TLS/mTLS）** 更加安全：
- ✅ **客户端验证服务端**：确保连接的是正确的服务端
- ✅ **服务端验证客户端**：只允许持有有效证书的客户端连接

**使用场景：**
- 企业内部系统通信
- 微服务之间的安全通信
- 金融系统、支付系统
- IoT 设备认证
- API 的高安全级别访问控制

**示例：**
```
银行客户端 (客户端)  ⇄  银行服务器 (服务端)
检查服务器证书 ✅        检查客户端证书 ✅
```

### 9.3 单向认证 vs 双向认证对比

| 特性 | 单向认证 | 双向认证 |
|------|---------|---------|
| **客户端需要证书** | ❌ 不需要 | ✅ 需要 |
| **服务端需要证书** | ✅ 需要 | ✅ 需要 |
| **客户端验证服务端** | ✅ 验证 | ✅ 验证 |
| **服务端验证客户端** | ❌ 不验证 | ✅ 验证 |
| **安全性** | 中等 | 高 |
| **配置复杂度** | 低 | 中等 |
| **性能开销** | 低 | 稍高（多一次证书验证） |
| **使用场景** | 公开服务 | 内部系统、高安全场景 |

### 9.4 为什么大多数情况用单向认证？

1. **客户端身份验证的其他方式**
   - 用户名/密码
   - OAuth Token
   - API Key
   - Session Cookie

2. **证书管理的复杂性**
   - 为每个客户端颁发证书很麻烦
   - 证书过期、吊销管理困难
   - 客户端设备丢失需要撤销证书

3. **用户体验**
   - 普通用户不懂如何管理证书
   - 移动设备上证书管理不方便

### 9.5 实现双向认证

#### 服务端配置（验证客户端证书）

```c
void configure_server_context(SSL_CTX *ctx) {
    // 1. 加载服务端证书和私钥（必须）
    SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM);

    // 2. 加载客户端 CA 证书（用于验证客户端证书）
    SSL_CTX_load_verify_locations(ctx, "client-ca.pem", NULL);

    // 3. 设置验证模式 ⭐
    // SSL_VERIFY_PEER: 要求对方提供证书
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT: 如果对方不提供证书，握手失败
    SSL_CTX_set_verify(ctx, 
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 
                       NULL);
}
```

**验证模式标志说明：**

| 标志 | 含义 | 服务端 | 客户端 |
|------|------|--------|--------|
| `SSL_VERIFY_NONE` | 不验证对方 | ❌ 不推荐 | ⚠️ 不安全 |
| `SSL_VERIFY_PEER` | 验证对方证书 | ✅ 双向认证 | ✅ 推荐 |
| `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` | 对方必须提供证书 | ✅ 与 PEER 一起用 | ❌ 无效 |
| `SSL_VERIFY_CLIENT_ONCE` | 只在初次握手时验证 | ✅ 性能优化 | ❌ 无效 |

#### 客户端配置（提供客户端证书）

```c
void configure_client_context_with_cert(SSL_CTX *ctx) {
    // 1. 加载客户端证书（双向认证时需要）
    if (SSL_CTX_use_certificate_file(ctx, "client-cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // 2. 加载客户端私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, "client-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // 3. 加载服务端 CA 证书（验证服务端）
    SSL_CTX_load_verify_locations(ctx, "server-ca.pem", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}
```

### 9.6 双向认证完整流程

```
客户端                                         服务端
  │                                              │
  │───────── ① ClientHello ────────────────────→│
  │   + 客户端支持的加密套件                      │
  │                                              │
  │←──────── ② ServerHello ────────────────────│
  │   + 服务端证书                               │
  │   + 证书请求 (Certificate Request) ⭐        │
  │                                              │
  ├─→ [验证服务端证书]                           │
  │                                              │
  │───────── ③ 客户端证书 ─────────────────────→│
  │   + Certificate (客户端证书) ⭐               │
  │   + Certificate Verify (证书签名)            │
  │   + Finished                                 │
  │                                              │
  │                                              ├─→ [验证客户端证书] ⭐
  │                                              │
  │←──────── ④ Finished ───────────────────────│
  │                                              │
  │═══════════ 握手完成，开始加密通信 ═══════════│
```

**关键区别：**
- 单向认证：服务端不发送 `Certificate Request`
- 双向认证：服务端要求客户端提供证书，客户端在握手时发送证书

### 9.7 生成双向认证所需的证书

```bash
# ========== 生成 CA（证书颁发机构）==========

# 1. 生成 CA 私钥
openssl genpkey -algorithm RSA -out ca-key.pem -pkeyopt rsa_keygen_bits:2048

# 2. 生成 CA 证书（自签名）
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=MyCA/CN=My Root CA"

# ========== 生成服务端证书 ==========

# 3. 生成服务端私钥
openssl genpkey -algorithm RSA -out server-key.pem -pkeyopt rsa_keygen_bits:2048

# 4. 生成服务端证书签名请求（CSR）
openssl req -new -key server-key.pem -out server.csr \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/CN=localhost"

# 5. 用 CA 签名服务端证书
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365

# ========== 生成客户端证书 ==========

# 6. 生成客户端私钥
openssl genpkey -algorithm RSA -out client-key.pem -pkeyopt rsa_keygen_bits:2048

# 7. 生成客户端证书签名请求（CSR）
openssl req -new -key client-key.pem -out client.csr \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/CN=client1"

# 8. 用 CA 签名客户端证书
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out client-cert.pem -days 365

# ========== 验证证书 ==========

# 验证服务端证书
openssl verify -CAfile ca-cert.pem server-cert.pem

# 验证客户端证书
openssl verify -CAfile ca-cert.pem client-cert.pem
```

### 9.8 双向认证示例代码

#### 修改后的服务端（启用客户端验证）

在 `configure_server_context()` 中取消注释双向认证代码：

```c
void configure_server_context(SSL_CTX *ctx) {
    // ... 加载服务端证书和私钥 ...

    // 启用双向认证
    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL)) {
        handle_errors("无法加载客户端 CA 证书");
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    printf("[服务端] 已启用客户端证书验证（双向认证）\n");
}
```

#### 修改后的客户端（提供客户端证书）

```c
void configure_client_context(SSL_CTX *ctx) {
    // 加载客户端证书
    if (SSL_CTX_use_certificate_file(ctx, "client-cert.pem", SSL_FILETYPE_PEM) <= 0) {
        handle_errors("无法加载客户端证书");
    }

    // 加载客户端私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, "client-key.pem", SSL_FILETYPE_PEM) <= 0) {
        handle_errors("无法加载客户端私钥");
    }

    // 验证服务端
    SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}
```

### 9.9 验证证书的回调函数（高级）

如果需要自定义验证逻辑（例如检查证书的特定字段）：

```c
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    // preverify_ok: OpenSSL 内置验证结果（1=通过，0=失败）
    // ctx: 证书存储上下文，包含证书链信息

    // 获取当前正在验证的证书
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    
    // 获取证书的主题（Subject）
    char subject[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    
    printf("验证证书：%s\n", subject);
    
    if (!preverify_ok) {
        // OpenSSL 内置验证失败
        int err = X509_STORE_CTX_get_error(ctx);
        printf("证书验证失败：%s\n", X509_verify_cert_error_string(err));
        return 0; // 拒绝
    }

    // 可以添加自定义验证逻辑
    // 例如：检查证书的 CN、检查证书扩展字段等
    
    // 获取证书的 CN（Common Name）
    X509_NAME *name = X509_get_subject_name(cert);
    int pos = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (pos >= 0) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, pos);
        ASN1_STRING *cn_asn1 = X509_NAME_ENTRY_get_data(entry);
        char *cn = (char *)ASN1_STRING_get0_data(cn_asn1);
        printf("证书 CN：%s\n", cn);
        
        // 例如：只允许特定的客户端
        if (strcmp(cn, "client1") != 0 && strcmp(cn, "client2") != 0) {
            printf("不允许的客户端：%s\n", cn);
            return 0; // 拒绝
        }
    }

    return 1; // 接受
}

// 设置回调
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
```

### 9.10 双向认证常见问题

#### Q1: 双向认证性能影响大吗？
**答：影响很小**
- 额外的证书验证只在握手时进行
- 会话建立后，通信性能完全相同
- 可以使用会话恢复减少握手次数

#### Q2: 如何管理大量客户端证书？
**方案：**
1. **证书吊销列表（CRL）**：维护已撤销的证书列表
2. **OCSP（在线证书状态协议）**：实时查询证书状态
3. **短期证书**：证书有效期设置为几天，减少吊销需求
4. **自动化工具**：使用 cert-manager、CFSSL 等工具

#### Q3: 客户端证书丢失怎么办？
**处理步骤：**
1. 将丢失的证书加入 CRL（吊销）
2. 为该客户端颁发新证书
3. 配置服务端定期检查 CRL

#### Q4: 可以只在特定接口要求双向认证吗？
**答：可以**
```c
// 在接受连接后，动态设置验证模式
SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

// 或者检查是否提供了证书
X509 *client_cert = SSL_get_peer_certificate(ssl);
if (client_cert) {
    // 客户端提供了证书
    X509_free(client_cert);
} else {
    // 客户端未提供证书
    // 可以根据访问的 URL 决定是否允许
}
```

### 9.11 双向认证 vs 其他认证方式

| 认证方式 | 安全性 | 复杂度 | 使用场景 |
|---------|--------|--------|---------|
| **单向 TLS + 密码** | 中 | 低 | Web 应用、普通 API |
| **单向 TLS + Token** | 中 | 低 | RESTful API、移动应用 |
| **双向 TLS** | 高 | 中 | 微服务、企业内部系统 |
| **双向 TLS + 其他** | 很高 | 高 | 金融系统、军事系统 |

### 9.12 实战建议

**什么时候用单向认证？**
- ✅ 面向公众的 Web 服务
- ✅ 移动应用的后端 API
- ✅ 用户通过账号密码登录的系统

**什么时候用双向认证？**
- ✅ 微服务之间的通信（Service Mesh）
- ✅ 企业内部系统对接
- ✅ IoT 设备与服务器通信
- ✅ 高安全要求的场景（金融、支付）
- ✅ 需要证书级别的访问控制

**组合使用：**
```
┌─────────────────────────────────────────┐
│  外部用户 → 边缘服务（单向 TLS）        │
│     ↓                                    │
│  边缘服务 ⇄ 内部服务（双向 TLS）        │
│     ↓            ↓                       │
│  数据库     消息队列（双向 TLS）        │
└─────────────────────────────────────────┘
```

---

## 10. 常见问题（扩展）

### Q8: 为什么服务端默认不验证客户端？

**答：这是 TLS 设计的默认行为，原因如下：**

1. **大多数场景不需要**
   - 网页浏览（HTTPS）：服务器不需要知道你是谁
   - 公开 API：任何人都可以访问
   - 移动应用：通过 Token 等其他方式认证

2. **客户端身份验证有其他方式**
   - 用户名 + 密码
   - OAuth 2.0 / JWT Token
   - API Key
   - Session Cookie

3. **证书管理成本高**
   - 为每个用户颁发证书很麻烦
   - 用户不懂如何管理证书
   - 移动设备上证书管理不方便

4. **灵活性**
   - 可以根据需要选择性启用
   - 不同的 API 端点可以有不同的要求

**什么时候需要服务端验证客户端？**
- ✅ 微服务之间的通信（Service Mesh）
- ✅ 企业内部系统
- ✅ 高安全要求的场景（金融、支付）
- ✅ IoT 设备认证

### Q9: 如何在现有代码中启用双向认证？

**步骤：**

1. **生成客户端证书**（见第 9.7 节）

2. **修改服务端代码**
   在 `test_tls.c` 的 `configure_server_context()` 函数中，取消注释双向认证代码：
   ```c
   // 取消这段代码的注释
   SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL);
   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
   ```

3. **修改客户端代码**
   添加客户端证书加载：
   ```c
   // 在 configure_client_context() 中添加
   SSL_CTX_use_certificate_file(ctx, "client-cert.pem", SSL_FILETYPE_PEM);
   SSL_CTX_use_PrivateKey_file(ctx, "client-key.pem", SSL_FILETYPE_PEM);
   ```

4. **重新编译运行**
   ```bash
   gcc -o test_tls test_tls.c -I../openssl-3.5.2/include -L../openssl-3.5.2 -lssl -lcrypto
   ```

### Q10: 单向认证和双向认证可以共存吗？

**答：可以！有几种方式：**

**方式 1：可选的客户端证书**
```c
// 服务端：请求但不强制要求客户端证书
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  // 不加 FAIL_IF_NO_PEER_CERT

// 在握手后检查
X509 *client_cert = SSL_get_peer_certificate(ssl);
if (client_cert) {
    printf("客户端提供了证书\n");
    // 给予更高权限
    X509_free(client_cert);
} else {
    printf("客户端未提供证书\n");
    // 给予基本权限
}
```

**方式 2：基于路径的不同要求**
```c
// 普通 API：不要求证书
if (strncmp(path, "/api/public", 11) == 0) {
    // 任何客户端都可以访问
}

// 管理 API：要求证书
if (strncmp(path, "/api/admin", 10) == 0) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        // 拒绝访问
        return 403;
    }
    X509_free(cert);
}
```

**方式 3：多个服务端端口**
```
端口 4433：单向认证（公开服务）
端口 4434：双向认证（管理接口）
```

### Q11: 如何调试证书验证问题？

**工具和方法：**

```bash
# 1. 查看证书内容
openssl x509 -in server-cert.pem -text -noout

# 2. 验证证书链
openssl verify -CAfile ca-cert.pem server-cert.pem

# 3. 检查证书和私钥是否匹配
openssl x509 -noout -modulus -in server-cert.pem | openssl md5
openssl rsa -noout -modulus -in server-key.pem | openssl md5
# 两个 MD5 值应该相同

# 4. 使用 s_client 测试（显示详细握手）
openssl s_client -connect localhost:4433 -CAfile ca-cert.pem -state -debug

# 5. 测试双向认证
openssl s_client -connect localhost:4433 \
  -cert client-cert.pem \
  -key client-key.pem \
  -CAfile ca-cert.pem
```

**代码中启用详细日志：**
```c
// 打印所有 OpenSSL 错误
ERR_print_errors_fp(stderr);

// 在验证回调中打印详细信息
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    char subject[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, 256);
    
    printf("验证证书：%s\n", subject);
    printf("验证深度：%d\n", X509_STORE_CTX_get_error_depth(ctx));
    
    if (!preverify_ok) {
        printf("验证失败：%s\n", 
               X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }
    
    return preverify_ok;
}
```

---

## 附录：双向认证完整示例

这里提供一个完整的双向认证示例脚本：

### 生成所有证书
```bash
#!/bin/bash
# gen_mtls_certs.sh - 生成双向认证所需的所有证书

echo "========== 1. 生成 CA =========="
openssl genpkey -algorithm RSA -out ca-key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=MyCA/CN=Root CA"

echo "========== 2. 生成服务端证书 =========="
openssl genpkey -algorithm RSA -out server-key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key server-key.pem -out server.csr \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/CN=localhost"
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365

echo "========== 3. 生成客户端证书 =========="
openssl genpkey -algorithm RSA -out client-key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key client-key.pem -out client.csr \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/CN=client1"
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out client-cert.pem -days 365

echo "========== 4. 验证证书 =========="
openssl verify -CAfile ca-cert.pem server-cert.pem
openssl verify -CAfile ca-cert.pem client-cert.pem

echo "========== 完成 =========="
echo "生成的文件："
ls -lh ca-*.pem server-*.pem client-*.pem
```

### 测试双向认证
```bash
# 终端 1：启动要求客户端证书的服务端
# （修改 test_tls.c 启用双向认证后）
./test_tls server

# 终端 2：客户端提供证书连接
openssl s_client -connect localhost:4433 \
  -cert client-cert.pem \
  -key client-key.pem \
  -CAfile ca-cert.pem

# 测试：客户端不提供证书（应该失败）
openssl s_client -connect localhost:4433 -CAfile ca-cert.pem
# 预期：握手失败，服务端拒绝连接
```

---
   - 证书验证回调
   - 会话恢复
   - 多线程服务端
   - SNI (Server Name Indication)
   - ALPN (Application-Layer Protocol Negotiation)

---

## 参考资源

- [OpenSSL 官方文档](https://www.openssl.org/docs/)
- [OpenSSL Wiki - Simple TLS Server](https://wiki.openssl.org/index.php/Simple_TLS_Server)
- [RFC 8446 - TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 5246 - TLS 1.2](https://datatracker.ietf.org/doc/html/rfc5246)

