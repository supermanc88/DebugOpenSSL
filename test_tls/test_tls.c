/**
 * OpenSSL TLS 客户端-服务端完整示例
 * 
 * 功能：
 * 1. 实现 TLS 客户端和服务端
 * 2. 自动生成自签名证书（用于测试）
 * 3. 演示完整的 TLS 握手和通信流程
 * 
 * 编译：
 *   gcc -o test_tls test_tls.c -I../openssl-3.5.2/include -L../openssl-3.5.2 -lssl -lcrypto
 * 
 * 运行：
 *   ./test_tls server   # 启动服务端
 *   ./test_tls client   # 启动客户端（另一个终端）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// 配置参数
#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 4433
#define BUFFER_SIZE 1024

// 证书文件路径
#define SERVER_CERT_FILE "server-cert.pem"
#define SERVER_KEY_FILE  "server-key.pem"
#define CA_CERT_FILE     "ca-cert.pem"

// 前向声明
void run_server(void);
void run_client(void);
void generate_self_signed_cert(void);
void handle_errors(const char *msg);

/**
 * 主函数
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("用法：\n");
        printf("  %s server   # 启动服务端\n", argv[0]);
        printf("  %s client   # 启动客户端\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "server") == 0) {
        run_server();
    } else if (strcmp(argv[1], "client") == 0) {
        run_client();
    } else {
        fprintf(stderr, "未知参数：%s\n", argv[1]);
        return 1;
    }

    return 0;
}

/**
 * 生成自签名证书（用于测试）
 * 
 * 在生产环境中，应该使用由 CA 签发的证书
 */
void generate_self_signed_cert(void) {
    printf("[服务端] 正在生成自签名证书...\n");

    // 生成私钥
    system("openssl genpkey -algorithm RSA -out " SERVER_KEY_FILE " -pkeyopt rsa_keygen_bits:2048 2>/dev/null");

    // 生成自签名证书（有效期 365 天）
    system("openssl req -new -x509 -key " SERVER_KEY_FILE " -out " SERVER_CERT_FILE " -days 365 "
           "-subj \"/C=CN/ST=Beijing/L=Beijing/O=TestOrg/CN=localhost\" 2>/dev/null");

    // 复制证书作为 CA 证书（客户端信任列表）
    system("cp " SERVER_CERT_FILE " " CA_CERT_FILE);

    printf("[服务端] 证书生成完成\n");
}

/**
 * 错误处理函数
 */
void handle_errors(const char *msg) {
    fprintf(stderr, "[错误] %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/**
 * ==============================================
 * 服务端实现
 * ==============================================
 */

/**
 * 创建服务端 SSL 上下文
 */
SSL_CTX *create_server_context(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // 步骤 1: 选择服务端方法
    // TLS_server_method() 支持 TLS 1.0 到 TLS 1.3
    method = TLS_server_method();

    // 步骤 2: 创建 SSL_CTX
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        handle_errors("无法创建 SSL_CTX");
    }

    printf("[服务端] SSL_CTX 创建成功\n");
    return ctx;
}

/**
 * 配置服务端上下文（加载证书和私钥）
 */
void configure_server_context(SSL_CTX *ctx) {
    // 步骤 1: 加载服务端证书
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        handle_errors("无法加载服务端证书");
    }

    // 步骤 2: 加载服务端私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        handle_errors("无法加载服务端私钥");
    }

    // 步骤 3: 验证私钥与证书是否匹配
    if (!SSL_CTX_check_private_key(ctx)) {
        handle_errors("私钥与证书不匹配");
    }

    printf("[服务端] 证书和私钥加载成功\n");

    // ========== 双向认证（可选）==========
    // 如果需要服务端验证客户端证书，取消下面代码的注释
    
    /*
    // 步骤 4: 加载客户端 CA 证书（用于验证客户端证书）
    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL)) {
        handle_errors("无法加载客户端 CA 证书");
    }

    // 步骤 5: 设置验证模式
    // SSL_VERIFY_PEER: 要求客户端提供证书
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT: 如果客户端不提供证书，则握手失败
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    
    printf("[服务端] 已启用客户端证书验证（双向认证）\n");
    */
    
    // 默认：不验证客户端证书（单向认证）
    printf("[服务端] 未启用客户端证书验证（单向认证）\n");
}

/**
 * 创建监听 socket
 */
int create_server_socket(void) {
    int server_fd;
    struct sockaddr_in addr;
    int opt = 1;

    // 步骤 1: 创建 socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // 步骤 2: 设置 socket 选项（允许端口重用）
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // 步骤 3: 绑定地址和端口
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // 步骤 4: 开始监听
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("[服务端] 服务端监听在 %s:%d\n", SERVER_ADDR, SERVER_PORT);
    return server_fd;
}

/**
 * 处理客户端连接
 */
void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes;

    // 步骤 1: 执行 TLS 握手（服务端接受）
    printf("[服务端] 等待 TLS 握手...\n");
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }

    printf("[服务端] TLS 握手成功！\n");
    printf("[服务端] 使用的加密套件：%s\n", SSL_get_cipher(ssl));
    printf("[服务端] TLS 版本：%s\n", SSL_get_version(ssl));

    // 步骤 2: 读取客户端消息
    memset(buffer, 0, sizeof(buffer));
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[服务端] 收到客户端消息：%s\n", buffer);

        // 步骤 3: 发送响应
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), 
                 "Hello from TLS server! Message received: %s", buffer);
        
        SSL_write(ssl, response, strlen(response));
        printf("[服务端] 发送响应给客户端\n");
    } else if (bytes == 0) {
        printf("[服务端] 客户端已关闭连接\n");
    } else {
        ERR_print_errors_fp(stderr);
    }
}

/**
 * 运行服务端
 */
void run_server(void) {
    SSL_CTX *ctx;
    int server_fd, client_fd;

    // 步骤 1: 检查证书是否存在，不存在则生成
    if (access(SERVER_CERT_FILE, F_OK) != 0 || access(SERVER_KEY_FILE, F_OK) != 0) {
        generate_self_signed_cert();
    }

    // 步骤 2: 创建并配置 SSL 上下文
    ctx = create_server_context();
    configure_server_context(ctx);

    // 步骤 3: 创建监听 socket
    server_fd = create_server_socket();

    // 步骤 4: 主循环 - 接受客户端连接
    printf("[服务端] 等待客户端连接...\n");
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        SSL *ssl;

        // 4a. 接受 TCP 连接
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        printf("[服务端] 接受客户端连接，fd=%d\n", client_fd);

        // 4b. 创建 SSL 对象
        ssl = SSL_new(ctx);
        if (!ssl) {
            handle_errors("无法创建 SSL 对象");
        }

        // 4c. 将 SSL 绑定到客户端 socket
        SSL_set_fd(ssl, client_fd);

        // 4d. 处理客户端
        handle_client(ssl);

        // 4e. 清理
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        printf("[服务端] 客户端连接已关闭\n");
        printf("[服务端] 等待客户端连接...\n");
    }

    // 步骤 5: 清理（实际上这里不会执行到）
    close(server_fd);
    SSL_CTX_free(ctx);
}

/**
 * ==============================================
 * 客户端实现
 * ==============================================
 */

/**
 * 创建客户端 SSL 上下文
 */
SSL_CTX *create_client_context(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // 步骤 1: 选择客户端方法
    // TLS_client_method() 支持 TLS 1.0 到 TLS 1.3
    method = TLS_client_method();

    // 步骤 2: 创建 SSL_CTX
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        handle_errors("无法创建 SSL_CTX");
    }

    printf("[客户端] SSL_CTX 创建成功\n");
    return ctx;
}

/**
 * 配置客户端上下文（可选：加载 CA 证书进行验证）
 */
void configure_client_context(SSL_CTX *ctx) {
    // 选项 1: 验证服务端证书（推荐）
    // 需要提供 CA 证书或信任的证书列表
    if (access(CA_CERT_FILE, F_OK) == 0) {
        if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL)) {
            handle_errors("无法加载 CA 证书");
        }
        // 设置验证模式：验证对方证书
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        printf("[客户端] 已加载 CA 证书，将验证服务端证书\n");
    } else {
        // 选项 2: 不验证服务端证书（不安全，仅用于测试）
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        printf("[客户端] 警告：未加载 CA 证书，不验证服务端证书\n");
    }
}

/**
 * 创建连接到服务端的 socket
 */
int create_client_socket(void) {
    int sockfd;
    struct sockaddr_in server_addr;

    // 步骤 1: 创建 socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // 步骤 2: 设置服务端地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    
    if (inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    // 步骤 3: 连接服务端
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    printf("[客户端] 已连接到服务端 %s:%d\n", SERVER_ADDR, SERVER_PORT);
    return sockfd;
}

/**
 * 运行客户端
 */
void run_client(void) {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    char buffer[BUFFER_SIZE];
    const char *message = "Hello from TLS client!";

    // 步骤 1: 创建并配置 SSL 上下文
    ctx = create_client_context();
    configure_client_context(ctx);

    // 步骤 2: 创建 TCP 连接
    sockfd = create_client_socket();

    // 步骤 3: 创建 SSL 对象
    ssl = SSL_new(ctx);
    if (!ssl) {
        handle_errors("无法创建 SSL 对象");
    }

    // 步骤 4: 将 SSL 绑定到 socket
    SSL_set_fd(ssl, sockfd);

    // 步骤 5: 执行 TLS 握手（客户端主动连接）
    printf("[客户端] 开始 TLS 握手...\n");
    if (SSL_connect(ssl) <= 0) {
        handle_errors("TLS 握手失败");
    }

    printf("[客户端] TLS 握手成功！\n");
    printf("[客户端] 使用的加密套件：%s\n", SSL_get_cipher(ssl));
    printf("[客户端] TLS 版本：%s\n", SSL_get_version(ssl));

    // 步骤 6: 发送消息
    printf("[客户端] 发送消息：%s\n", message);
    int bytes = SSL_write(ssl, message, strlen(message));
    if (bytes <= 0) {
        handle_errors("发送消息失败");
    }

    // 步骤 7: 接收响应
    memset(buffer, 0, sizeof(buffer));
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[客户端] 收到服务端响应：%s\n", buffer);
    } else if (bytes == 0) {
        printf("[客户端] 服务端关闭了连接\n");
    } else {
        ERR_print_errors_fp(stderr);
    }

    // 步骤 8: 清理资源
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    printf("[客户端] 连接已关闭\n");
}
