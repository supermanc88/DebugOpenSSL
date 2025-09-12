cmake_minimum_required(VERSION 3.5)
project(test_ml_kem C)
set(CMAKE_C_STANDARD 11)

add_executable(test_ml_kem ml_kem.c)
target_link_libraries(test_ml_kem
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)