cmake_minimum_required(VERSION 3.5)
project(test_dsa_sig C)
set(CMAKE_C_STANDARD 11)

add_executable(test_dsa_sig dsa_sig.c)
target_link_libraries(test_dsa_sig
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)