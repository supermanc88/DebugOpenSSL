cmake_minimum_required(VERSION 3.5)

project(test_asymcipher_rsa C)
set(CMAKE_C_STANDARD 11)

add_executable(test_asymcipher_rsa
asymcipher_rsa.c)
target_link_libraries(test_asymcipher_rsa
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)