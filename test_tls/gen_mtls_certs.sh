#!/bin/bash
# gen_mtls_certs.sh - 生成双向认证（Mutual TLS）所需的所有证书

set -e  # 遇到错误立即退出

echo "========================================"
echo "生成双向认证（mTLS）证书"
echo "========================================"
echo ""

# 清理旧文件
rm -f ca-*.pem server-*.pem client-*.pem *.csr *.srl

echo "步骤 1/4: 生成 CA（证书颁发机构）"
echo "------------------------------------"

# 生成 CA 私钥
openssl genpkey -algorithm RSA -out ca-key.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null
echo "✅ CA 私钥: ca-key.pem"

# 生成 CA 自签名证书
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=MyCA/CN=Root CA" 2>/dev/null
echo "✅ CA 证书: ca-cert.pem"
echo ""

echo "步骤 2/4: 生成服务端证书"
echo "------------------------------------"

# 生成服务端私钥
openssl genpkey -algorithm RSA -out server-key.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null
echo "✅ 服务端私钥: server-key.pem"

# 生成服务端证书签名请求（CSR）
openssl req -new -key server-key.pem -out server.csr \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/CN=localhost" 2>/dev/null
echo "✅ 服务端 CSR: server.csr"

# 用 CA 签名服务端证书
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365 2>/dev/null
echo "✅ 服务端证书: server-cert.pem"
echo ""

echo "步骤 3/4: 生成客户端证书"
echo "------------------------------------"

# 生成客户端私钥
openssl genpkey -algorithm RSA -out client-key.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null
echo "✅ 客户端私钥: client-key.pem"

# 生成客户端证书签名请求（CSR）
openssl req -new -key client-key.pem -out client.csr \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/CN=client1" 2>/dev/null
echo "✅ 客户端 CSR: client.csr"

# 用 CA 签名客户端证书
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out client-cert.pem -days 365 2>/dev/null
echo "✅ 客户端证书: client-cert.pem"
echo ""

echo "步骤 4/4: 验证证书"
echo "------------------------------------"

# 验证服务端证书
if openssl verify -CAfile ca-cert.pem server-cert.pem > /dev/null 2>&1; then
    echo "✅ 服务端证书验证通过"
else
    echo "❌ 服务端证书验证失败"
    exit 1
fi

# 验证客户端证书
if openssl verify -CAfile ca-cert.pem client-cert.pem > /dev/null 2>&1; then
    echo "✅ 客户端证书验证通过"
else
    echo "❌ 客户端证书验证失败"
    exit 1
fi
echo ""

echo "========================================"
echo "证书生成完成！"
echo "========================================"
echo ""

echo "生成的文件列表："
echo "------------------------------------"
ls -lh ca-*.pem server-*.pem client-*.pem | awk '{printf "%-25s %8s  %s\n", $9, $5, $6" "$7" "$8}'
echo ""

echo "证书用途："
echo "------------------------------------"
echo "ca-cert.pem       - CA 证书（双方信任的根证书）"
echo "ca-key.pem        - CA 私钥（签发证书用，妥善保管）"
echo "server-cert.pem   - 服务端证书"
echo "server-key.pem    - 服务端私钥"
echo "client-cert.pem   - 客户端证书"
echo "client-key.pem    - 客户端私钥"
echo ""

echo "查看证书内容："
echo "------------------------------------"
echo "# 查看 CA 证书"
echo "openssl x509 -in ca-cert.pem -text -noout"
echo ""
echo "# 查看服务端证书"
echo "openssl x509 -in server-cert.pem -text -noout"
echo ""
echo "# 查看客户端证书"
echo "openssl x509 -in client-cert.pem -text -noout"
echo ""

echo "测试双向认证："
echo "------------------------------------"
echo "1. 修改 test_tls.c，在 configure_server_context() 中启用双向认证"
echo "2. 修改 test_tls.c，在 configure_client_context() 中加载客户端证书"
echo "3. 重新编译：gcc -o test_tls test_tls.c -I../openssl-3.5.2/include -L../openssl-3.5.2 -lssl -lcrypto"
echo "4. 运行服务端：./test_tls server"
echo "5. 运行客户端：./test_tls client"
echo ""

echo "使用 OpenSSL 命令行测试："
echo "------------------------------------"
echo "# 客户端提供证书（应该成功）"
echo "openssl s_client -connect localhost:4433 -cert client-cert.pem -key client-key.pem -CAfile ca-cert.pem"
echo ""
echo "# 客户端不提供证书（应该失败）"
echo "openssl s_client -connect localhost:4433 -CAfile ca-cert.pem"
echo ""
