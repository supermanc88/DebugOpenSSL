cmake_minimum_required(VERSION 3.5)
project(test_ec_kem C)
set(CMAKE_C_STANDARD 11)

add_executable(test_ec_kem ec_kem.c)
target_link_libraries(test_ec_kem
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)