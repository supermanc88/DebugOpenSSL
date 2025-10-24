cmake_minimum_required(VERSION 3.5)

project(test_cipher_des)
set(CMAKE_C_STANDARD 11)

# DES ECB 模式测试
add_executable(test_des_ecb ecb_des.c)
target_link_libraries(test_des_ecb
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# DES CBC 模式测试
add_executable(test_des_cbc cbc_des.c)
target_link_libraries(test_des_cbc
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# DES CFB 模式测试
add_executable(test_des_cfb cfb_des.c)
target_link_libraries(test_des_cfb
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# DES OFB 模式测试
add_executable(test_des_ofb ofb_des.c)
target_link_libraries(test_des_ofb
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# 3DES-EDE3 全模式测试（ECB, CBC, OFB, CFB1/8/64）
add_executable(test_des3_ede3 des3_ede3.c)
target_link_libraries(test_des3_ede3
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# DES CFB 变体测试（CFB1, CFB8, CFB64）
add_executable(test_des_cfb_variants cfb_variants_des.c)
target_link_libraries(test_des_cfb_variants
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# DESX CBC 模式测试
add_executable(test_desx_cbc desx_cbc.c)
target_link_libraries(test_desx_cbc
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# 2-key 3DES (DES-EDE) 模式测试
add_executable(test_des_ede_2key des_ede_2key.c)
target_link_libraries(test_des_ede_2key
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# 3DES Key Wrapping 测试
add_executable(test_des3_wrap des3_wrap.c)
target_link_libraries(test_des3_wrap
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)
