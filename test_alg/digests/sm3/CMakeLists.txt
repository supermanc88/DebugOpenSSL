cmake_minimum_required(VERSION 3.5)

project(test_digest_sm3 C)
set(CMAKE_C_STANDARD 11)


add_executable(test_digest_sm3 test_digest_sm3.c)
target_link_libraries(test_digest_sm3
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)