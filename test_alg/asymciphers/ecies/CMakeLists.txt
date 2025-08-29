cmake_minimum_required(VERSION 3.5)

project(test_asymcipher_ecies C)
set(CMAKE_C_STANDARD 11)

add_executable(test_asymcipher_prime256v1
            asymcipher_prime256v1.c)
target_link_libraries(test_asymcipher_prime256v1
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)