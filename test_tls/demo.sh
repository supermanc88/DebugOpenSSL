#!/bin/bash
# TLS 演示脚本 - 在一个终端中演示完整流程

echo "========================================"
echo "OpenSSL TLS 演示"
echo "========================================"
echo ""

cd "$(dirname "$0")"
export DYLD_LIBRARY_PATH="../openssl-3.5.2:$DYLD_LIBRARY_PATH"
export LD_LIBRARY_PATH="../openssl-3.5.2:$LD_LIBRARY_PATH"

# 清理旧的证书
rm -f server-cert.pem server-key.pem ca-cert.pem

echo "步骤 1: 启动服务端（后台运行）"
./test_tls server > server.log 2>&1 &
SERVER_PID=$!
echo "服务端 PID: $SERVER_PID"
echo ""

# 等待服务端启动
sleep 2

echo "服务端输出："
cat server.log
echo ""

echo "========================================"
echo "步骤 2: 启动客户端连接服务端"
echo "========================================"
echo ""

./test_tls client

echo ""
echo "========================================"
echo "完整的服务端日志："
echo "========================================"
cat server.log
echo ""

echo "========================================"
echo "清理: 停止服务端"
echo "========================================"
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null

echo "演示完成！"
echo ""
echo "提示："
echo "  - 查看 server-cert.pem: 服务端证书"
echo "  - 查看 server-key.pem: 服务端私钥"
echo "  - 查看 ca-cert.pem: CA 证书（客户端信任列表）"
echo "  - 查看 server.log: 服务端日志"
