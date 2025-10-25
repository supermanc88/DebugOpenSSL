# OpenSSL TLS 教程 - 文件索引

## 📚 核心文档

### 📖 [README.md](README.md) - 完整教程（推荐从这里开始）
**45KB | 1500+ 行**

包含内容：
- ✅ TLS 基础概念
- ✅ 握手流程详解
- ✅ OpenSSL API 完整说明
- ✅ 客户端实现步骤（10步详解）
- ✅ 服务端实现步骤（10步详解）
- ✅ 完整的流程图
- ✅ 单向认证 vs 双向认证
- ✅ 常见问题解答
- ✅ 术语表

**适合：** 从零开始学习 TLS

---

### ⚡ [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - 快速参考（速查表）
**10KB | 330 行**

包含内容：
- ✅ 核心概念总结
- ✅ API 函数速查表
- ✅ 客户端/服务端步骤清单
- ✅ 常见错误解决
- ✅ 性能优化建议
- ✅ 安全最佳实践
- ✅ 学习检查清单

**适合：** 快速查找 API 用法、复习要点

---

### 🔐 [ONE_WAY_VS_MUTUAL_TLS.md](ONE_WAY_VS_MUTUAL_TLS.md) - 认证模式对比
**8KB | 280 行**

包含内容：
- ✅ 单向认证 vs 双向认证详细对比
- ✅ 代码示例对比
- ✅ 使用场景分析
- ✅ 验证模式标志说明
- ✅ 证书需求对比
- ✅ 混合模式实现

**适合：** 理解不同认证模式、选择合适的方案

---

## 💻 代码和脚本

### 📝 [test_tls.c](test_tls.c) - 完整实现
**12KB | 450+ 行**

功能：
- ✅ 完整的 TLS 客户端实现
- ✅ 完整的 TLS 服务端实现
- ✅ 自动生成自签名证书
- ✅ 详细的代码注释
- ✅ 完整的错误处理
- ✅ 支持单向认证（默认）
- ✅ 支持双向认证（可选启用）

---

### 🚀 快速启动脚本

#### [demo.sh](demo.sh) - 自动演示
```bash
bash demo.sh
```
自动启动服务端（后台）→ 运行客户端 → 展示通信过程 → 清理

#### [run_server.sh](run_server.sh) - 启动服务端
```bash
bash run_server.sh
```

#### [run_client.sh](run_client.sh) - 启动客户端
```bash
bash run_client.sh
```

---

### 🔧 [gen_mtls_certs.sh](gen_mtls_certs.sh) - 生成双向认证证书
```bash
bash gen_mtls_certs.sh
```

生成内容：
- CA 证书和私钥
- 服务端证书和私钥
- 客户端证书和私钥
- 自动验证所有证书

---

## 🎯 学习路径

### 新手（第一次学习 TLS）
```
1. 阅读 README.md 的基础部分
   - TLS 基础概念
   - 握手流程
   
2. 运行演示
   bash demo.sh
   
3. 阅读代码
   查看 test_tls.c
   
4. 手动运行
   bash run_server.sh  # 终端1
   bash run_client.sh  # 终端2
```

### 进阶（已有基础知识）
```
1. 阅读 QUICK_REFERENCE.md
   快速回顾核心 API
   
2. 研究 test_tls.c 实现
   理解每个步骤
   
3. 修改代码实验
   - 修改端口
   - 修改消息内容
   - 添加多次通信
```

### 高级（深入理解）
```
1. 阅读 ONE_WAY_VS_MUTUAL_TLS.md
   理解不同认证模式
   
2. 启用双向认证
   bash gen_mtls_certs.sh
   修改 test_tls.c
   
3. 实现高级特性
   - 证书验证回调
   - 会话恢复
   - 多线程服务端
```

---

## 📋 快速开始（2分钟）

```bash
# 1. 编译
cd /Users/chengheming/Source/Personal/DebugOpenSSL/test_tls
gcc -o test_tls test_tls.c \
  -I../openssl-3.5.2/include \
  -L../openssl-3.5.2 \
  -lssl -lcrypto

# 2. 运行演示
bash demo.sh
```

---

## 📊 文件大小和用途

| 文件 | 大小 | 类型 | 用途 |
|------|------|------|------|
| `README.md` | 45KB | 📖 教程 | 完整学习教程 |
| `QUICK_REFERENCE.md` | 10KB | ⚡ 速查 | API 速查表 |
| `ONE_WAY_VS_MUTUAL_TLS.md` | 8KB | 🔐 对比 | 认证模式对比 |
| `test_tls.c` | 12KB | 💻 代码 | 完整实现 |
| `demo.sh` | 1.4KB | 🚀 脚本 | 自动演示 |
| `run_server.sh` | 114B | 🚀 脚本 | 启动服务端 |
| `run_client.sh` | 114B | 🚀 脚本 | 启动客户端 |
| `gen_mtls_certs.sh` | 4.4KB | 🔧 工具 | 生成证书 |
| `CMakeLists.txt` | 304B | 🔨 构建 | CMake 配置 |

---

## 🎓 推荐阅读顺序

### 方案 A：系统学习（推荐新手）
```
README.md (完整阅读)
  ↓
运行 demo.sh (实践)
  ↓
研究 test_tls.c (代码)
  ↓
QUICK_REFERENCE.md (复习)
  ↓
ONE_WAY_VS_MUTUAL_TLS.md (进阶)
```

### 方案 B：快速上手（有经验的开发者）
```
QUICK_REFERENCE.md (快速浏览)
  ↓
运行 demo.sh (验证环境)
  ↓
test_tls.c (研究代码)
  ↓
README.md (查阅细节)
```

### 方案 C：针对性学习（解决特定问题）
```
遇到问题
  ↓
README.md 常见问题部分
  ↓
QUICK_REFERENCE.md 查找 API
  ↓
test_tls.c 参考实现
```

---

## 🔍 快速查找

### 如何...？
- **实现客户端** → README.md 第4节 | test_tls.c 第 300-430 行
- **实现服务端** → README.md 第5节 | test_tls.c 第 100-250 行
- **验证证书** → README.md 第8节 Q1 | ONE_WAY_VS_MUTUAL_TLS.md
- **启用双向认证** → ONE_WAY_VS_MUTUAL_TLS.md | test_tls.c 第 147 行
- **生成证书** → README.md 附录 | gen_mtls_certs.sh
- **调试错误** → README.md 第8节 | QUICK_REFERENCE.md 常见错误部分

### API 查找
- **SSL_CTX 相关** → QUICK_REFERENCE.md API 速查表
- **SSL 相关** → README.md 第3节
- **证书相关** → README.md 第5节 + ONE_WAY_VS_MUTUAL_TLS.md

---

## 🛠️ 构建选项

### 使用 GCC
```bash
gcc -o test_tls test_tls.c \
  -I../openssl-3.5.2/include \
  -L../openssl-3.5.2 \
  -lssl -lcrypto \
  -Wl,-rpath,../openssl-3.5.2  # macOS
  # -Wl,-rpath=../openssl-3.5.2  # Linux
```

### 使用 CMake
```bash
mkdir build && cd build
cmake ..
make
```

---

## 📝 临时文件说明

运行程序后会生成以下临时文件（已添加到 `.gitignore`）：
- `test_tls` - 编译后的可执行文件
- `*.pem` - 自动生成的证书和密钥
- `*.log` - 日志文件

清理：
```bash
rm -f test_tls *.pem *.csr *.srl *.log
```

---

## 🎯 核心要点

1. **SSL_CTX** vs **SSL**
   - SSL_CTX = 配置模板（全局）
   - SSL = 具体连接（每个客户端一个）

2. **客户端** vs **服务端**
   - 客户端：`SSL_connect()`
   - 服务端：`SSL_accept()` + 必须有证书

3. **单向认证** vs **双向认证**
   - 单向：只验证服务端（常见）
   - 双向：互相验证（高安全）

---

**祝学习顺利！** 🎓

有问题请参考 README.md 的常见问题部分，或查看 QUICK_REFERENCE.md 的 API 说明。
