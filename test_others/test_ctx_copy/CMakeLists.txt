set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT_DIR}/build/test_ctx_copy)

cmake_minimum_required(VERSION 3.5)

project(test_ctx_copy C)
set(CMAKE_C_STANDARD 11)

add_executable(test_ctx_copy
ctx_copy.c)
target_link_libraries(test_ctx_copy
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)
