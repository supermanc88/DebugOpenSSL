set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT_DIR}/build/test_tls)

cmake_minimum_required(VERSION 3.10)

project(test_tls C)
set(CMAKE_C_STANDARD 11)

add_executable(test_tls
    test_tls.c)
target_link_libraries(test_tls
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)