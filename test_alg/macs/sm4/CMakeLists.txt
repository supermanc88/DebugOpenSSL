cmake_minimum_required(VERSION 3.5)
project(test_mac_sm4 C)
set(CMAKE_C_STANDARD 11)

message(STATUS "OpenSSL root directory: ${OPENSSL_ROOT_DIR}")

add_executable(test_mac_sm4
        mac_sm4.c)

target_link_libraries(test_mac_sm4
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)