本项目旨在学习密码学相关知识,主要包括以下内容：
1. 如何调用openssl
2. openssl源码分析
3. 常用算法实现逻辑
4. 自己实现常用算法



编译debug版本openssl (静态内置 legacy provider)

./Configure darwin64-arm64-cc -g -O0 no-module
make clean
make -j8

关键说明：
- no-module: 使 legacy provider 编译为内置（不生成 legacy.dylib）
- 编译后 DES/3DES/DESX 等算法直接内置在 libcrypto.a 中
- 运行 DES 测试程序无需设置 OPENSSL_MODULES 环境变量
- 详细说明见 BUILD_NOTES.md

可以直接使用clion打开此项目
