# EC KEM (Elliptic Curve Key Encapsulation Mechanism) 测试程序
# 需要 OpenSSL 3.0+ 支持椭圆曲线密码学

# 编译器和标志
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -g
INCLUDES = -I../../../openssl-3.5.2/include
LDFLAGS = -L../../../openssl-3.5.2 -lcrypto -lssl

# 目标文件
TARGET = test_ec_kem
SOURCE = ec_kem.c
OBJECT = $(SOURCE:.c=.o)

# 默认目标
all: $(TARGET)

# 编译目标
$(TARGET): $(OBJECT)
	@echo "链接 $(TARGET)..."
	$(CC) $(CFLAGS) $(OBJECT) $(LDFLAGS) -o $(TARGET)
	@echo "编译完成！"

# 编译源文件
%.o: %.c
	@echo "编译 $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 运行测试
run: $(TARGET)
	@echo "运行 EC KEM 测试..."
	@echo "=================================="
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET)

# 运行特定椭圆曲线测试
test-p256: $(TARGET)
	@echo "测试 P-256 (prime256v1)..."
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) | grep -A25 "prime256v1"

test-p384: $(TARGET)
	@echo "测试 P-384 (secp384r1)..."
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) | grep -A25 "secp384r1"

test-p521: $(TARGET)
	@echo "测试 P-521 (secp521r1)..."
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) | grep -A25 "secp521r1"

# 检查椭圆曲线支持
check-support: $(TARGET)
	@echo "检查 EC KEM 椭圆曲线支持..."
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) | grep -E "(支持|不支持|curve|版本|available)"

# 显示支持的椭圆曲线
list-curves: $(TARGET)
	@echo "显示支持的椭圆曲线..."
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) | grep -A10 "支持的椭圆曲线"

# 测试密钥大小
test-key-sizes: $(TARGET)
	@echo "测试不同椭圆曲线的密钥大小..."
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) | grep -E "(密钥长度|公钥长度|私钥长度)"

# 性能测试模式 - 运行多次取平均值
benchmark: $(TARGET)
	@echo "运行 EC KEM 性能测试..."
	@echo "每个椭圆曲线运行 5 次取平均时间..."
	@for i in 1 2 3 4 5; do \
		echo "第 $$i 次测试:"; \
		time LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) > /dev/null; \
	done

# 验证测试 - 确保所有测试都通过
verify: $(TARGET)
	@echo "运行验证测试..."
	@if LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) | grep -q "成功: 3/3"; then \
		echo "✅ 所有测试验证通过！"; \
		exit 0; \
	else \
		echo "❌ 测试验证失败！"; \
		exit 1; \
	fi

# 调试模式编译
debug: CFLAGS += -DDEBUG -O0 -ggdb3
debug: clean $(TARGET)

# 性能测试模式
release: CFLAGS += -DNDEBUG -O3 -march=native
release: clean $(TARGET)

# 安全编译模式 - 添加额外的安全检查
secure: CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC
secure: LDFLAGS += -Wl,-z,relro -Wl,-z,now
secure: clean $(TARGET)

# 静态分析
analyze: $(SOURCE)
	@echo "运行静态分析..."
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=all --std=c11 $(INCLUDES) $(SOURCE); \
	else \
		echo "cppcheck 未安装，跳过静态分析"; \
	fi

# 内存检查 (需要 valgrind)
memcheck: $(TARGET)
	@echo "运行内存泄漏检查..."
	@if command -v valgrind >/dev/null 2>&1; then \
		LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET); \
	else \
		echo "valgrind 未安装，跳过内存检查"; \
	fi

# 清理编译文件
clean:
	@echo "清理编译文件..."
	rm -f $(OBJECT) $(TARGET)
	@echo "清理完成！"

# 完全清理（包括依赖）
distclean: clean
	@echo "完全清理完成！"

# 安装到系统（可选）
install: $(TARGET)
	@echo "安装 $(TARGET) 到 /usr/local/bin..."
	@if [ -w /usr/local/bin ]; then \
		cp $(TARGET) /usr/local/bin/; \
		echo "安装完成！"; \
	else \
		echo "需要 sudo 权限安装到 /usr/local/bin"; \
		sudo cp $(TARGET) /usr/local/bin/; \
	fi

# 卸载
uninstall:
	@echo "从 /usr/local/bin 卸载 $(TARGET)..."
	@if [ -f /usr/local/bin/$(TARGET) ]; then \
		rm -f /usr/local/bin/$(TARGET); \
		echo "卸载完成！"; \
	else \
		echo "$(TARGET) 未安装到系统"; \
	fi

# 显示帮助信息
help:
	@echo "EC KEM 测试程序 Makefile"
	@echo "=========================="
	@echo "可用目标："
	@echo "  all           - 编译程序 (默认)"
	@echo "  run           - 运行完整测试套件"
	@echo "  test-p256     - 仅测试 P-256 椭圆曲线"
	@echo "  test-p384     - 仅测试 P-384 椭圆曲线"
	@echo "  test-p521     - 仅测试 P-521 椭圆曲线"
	@echo "  check-support - 检查椭圆曲线支持状态"
	@echo "  list-curves   - 显示支持的椭圆曲线"
	@echo "  test-key-sizes- 测试不同曲线的密钥大小"
	@echo "  benchmark     - 性能基准测试"
	@echo "  verify        - 验证所有测试通过"
	@echo "  debug         - 编译调试版本"
	@echo "  release       - 编译优化版本"
	@echo "  secure        - 编译安全加固版本"
	@echo "  analyze       - 静态代码分析"
	@echo "  memcheck      - 内存泄漏检查"
	@echo "  clean         - 清理编译文件"
	@echo "  distclean     - 完全清理"
	@echo "  install       - 安装到系统"
	@echo "  uninstall     - 从系统卸载"
	@echo "  help          - 显示此帮助信息"
	@echo ""
	@echo "需求："
	@echo "  - OpenSSL 3.0.0 或更高版本"
	@echo "  - 支持椭圆曲线密码学的 OpenSSL 构建"
	@echo "  - GCC 或 Clang 编译器"
	@echo ""
	@echo "椭圆曲线："
	@echo "  - prime256v1 (P-256): NIST P-256，256位安全强度"
	@echo "  - secp384r1 (P-384):  NIST P-384，384位安全强度"
	@echo "  - secp521r1 (P-521):  NIST P-521，521位安全强度"
	@echo ""
	@echo "示例用法："
	@echo "  make              # 编译程序"
	@echo "  make run          # 运行所有测试"
	@echo "  make test-p256    # 仅测试 P-256"
	@echo "  make verify       # 验证测试通过"
	@echo "  make benchmark    # 性能测试"

# 显示版本信息
version:
	@echo "EC KEM 测试程序版本信息"
	@echo "======================"
	@echo "程序版本: 1.0.0"
	@echo "支持的椭圆曲线: P-256, P-384, P-521"
	@echo "OpenSSL 最低版本要求: 3.0.0"
	@if LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) 2>/dev/null | head -3; then :; else echo "程序未编译或运行失败"; fi

# 创建发布包
package: clean
	@echo "创建发布包..."
	@mkdir -p ec_kem-release
	@cp ec_kem.c Makefile README.md CMakeLists.txt ec_kem-release/
	@tar -czf ec_kem-v1.0.0.tar.gz ec_kem-release/
	@rm -rf ec_kem-release/
	@echo "发布包已创建: ec_kem-v1.0.0.tar.gz"

# 声明伪目标
.PHONY: all run test-p256 test-p384 test-p521 check-support list-curves test-key-sizes benchmark verify debug release secure analyze memcheck clean distclean install uninstall help version package

# 确保在并行构建时正确处理依赖
$(TARGET): | check-openssl

# 检查 OpenSSL 版本
check-openssl:
	@echo "检查 OpenSSL 版本..."
	@if [ ! -f "../../../openssl-3.5.2/include/openssl/evp.h" ]; then \
		echo "❌ 未找到 OpenSSL 头文件，请确保 OpenSSL 3.0+ 已正确安装"; \
		exit 1; \
	fi
	@if [ ! -f "../../../openssl-3.5.2/libcrypto.so" ] && [ ! -f "../../../openssl-3.5.2/libcrypto.a" ] && [ ! -f "../../../openssl-3.5.2/libcrypto.dylib" ]; then \
		echo "❌ 未找到 OpenSSL 库文件，请确保 OpenSSL 3.0+ 已正确编译"; \
		exit 1; \
	fi
	@echo "✅ OpenSSL 环境检查通过"