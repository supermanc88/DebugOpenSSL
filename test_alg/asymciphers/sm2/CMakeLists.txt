cmake_minimum_required(VERSION 3.5)

project(test_asymcipher_sm2 C)
set(CMAKE_C_STANDARD 11)

add_executable(test_asymcipher_sm2
asymcipher_sm2.c)
target_link_libraries(test_asymcipher_sm2
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)