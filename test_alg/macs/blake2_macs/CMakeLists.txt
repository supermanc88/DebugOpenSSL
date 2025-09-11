cmake_minimum_required(VERSION 3.5)
project(test_blake2_macs C)
set(CMAKE_C_STANDARD 11)

add_executable(test_blake2_macs
        blake2_macs.c)
target_link_libraries(test_blake2_macs
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)