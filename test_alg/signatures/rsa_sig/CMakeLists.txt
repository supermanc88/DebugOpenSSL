cmake_minimum_required(VERSION 3.5)
project(test_rsa_sig C)
set(CMAKE_CXX_STANDARD 11)

add_executable(test_rsa_sig rsa_sig.c)
target_link_libraries(test_rsa_sig 
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)