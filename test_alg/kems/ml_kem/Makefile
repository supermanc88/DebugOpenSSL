# ML-KEM (Module Lattice Key Encapsulation Mechanism) 测试程序
# 需要 OpenSSL 3.5+ 支持后量子密码学

# 编译器和标志
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g
INCLUDES = -I../../../openssl-3.5.2/include
LDFLAGS = -L../../../openssl-3.5.2 -lcrypto -lssl

# 目标文件
TARGET = test_ml_kem
SOURCE = ml_kem.c
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
	@echo "运行 ML-KEM 测试..."
	@echo "=================================="
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET)

# 运行特定算法测试
test-512: $(TARGET)
	@echo "测试 ML-KEM-512..."
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) | grep -A20 "ML-KEM-512"

test-768: $(TARGET)
	@echo "测试 ML-KEM-768..."
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) | grep -A20 "ML-KEM-768"

test-1024: $(TARGET)
	@echo "测试 ML-KEM-1024..."
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) | grep -A20 "ML-KEM-1024"

# 检查算法支持
check-support: $(TARGET)
	@echo "检查 ML-KEM 算法支持..."
	LD_LIBRARY_PATH=../../../openssl-3.5.2:$$LD_LIBRARY_PATH ./$(TARGET) | grep -E "(支持|不支持|算法|版本)"

# 调试模式编译
debug: CFLAGS += -DDEBUG -O0
debug: clean $(TARGET)

# 性能测试模式
release: CFLAGS += -DNDEBUG -O3
release: clean $(TARGET)

# 清理编译文件
clean:
	@echo "清理编译文件..."
	rm -f $(OBJECT) $(TARGET)
	@echo "清理完成！"

# 完全清理（包括依赖）
distclean: clean
	@echo "完全清理完成！"

# 显示帮助信息
help:
	@echo "ML-KEM 测试程序 Makefile"
	@echo "========================"
	@echo "可用目标："
	@echo "  all           - 编译程序 (默认)"
	@echo "  run           - 运行完整测试套件"
	@echo "  test-512      - 仅测试 ML-KEM-512"
	@echo "  test-768      - 仅测试 ML-KEM-768"
	@echo "  test-1024     - 仅测试 ML-KEM-1024"
	@echo "  check-support - 检查算法支持状态"
	@echo "  debug         - 编译调试版本"
	@echo "  release       - 编译优化版本"
	@echo "  clean         - 清理编译文件"
	@echo "  distclean     - 完全清理"
	@echo "  help          - 显示此帮助信息"
	@echo ""
	@echo "需求："
	@echo "  - OpenSSL 3.5.0 或更高版本"
	@echo "  - 支持后量子密码学的 OpenSSL 构建"
	@echo ""
	@echo "示例用法："
	@echo "  make          # 编译程序"
	@echo "  make run      # 运行所有测试"
	@echo "  make test-512 # 仅测试 ML-KEM-512"

# 声明伪目标
.PHONY: all run test-512 test-768 test-1024 check-support debug release clean distclean help

# 确保在并行构建时正确处理依赖
$(TARGET): | check_openssl

# 检查 OpenSSL 安装
check_openssl:
	@if [ ! -f "../../../openssl-3.5.2/libcrypto.dylib" ] && [ ! -f "../../../openssl-3.5.2/libcrypto.so" ]; then \
		echo "错误: 找不到 OpenSSL 库文件"; \
		echo "请确保 OpenSSL 3.5.2 已正确编译和安装"; \
		exit 1; \
	fi