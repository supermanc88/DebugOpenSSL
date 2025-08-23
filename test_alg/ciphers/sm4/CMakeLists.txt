cmake_minimum_required(VERSION 3.5)

project(test_xts_sm4 C)
set(CMAKE_C_STANDARD 11)

add_executable(test_xts_sm4
        xts_sm4.c)


target_link_libraries(test_xts_sm4
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)