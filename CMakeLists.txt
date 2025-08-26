cmake_minimum_required(VERSION 3.5)
project(DebugOpenSSL C)

set(CMAKE_C_STANDARD 11)

set(PROJECT_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(OPENSSL_DIR_NAME "openssl-3.5.2")
set(OPENSSL_ROOT_DIR "${PROJECT_ROOT_DIR}/${OPENSSL_DIR_NAME}")

include_directories(${OPENSSL_ROOT_DIR}/include)

add_executable(DebugOpenSSL main.c)

add_subdirectory(test_alg/asymciphers)
add_subdirectory(test_alg/ciphers)
add_subdirectory(test_alg/macs)