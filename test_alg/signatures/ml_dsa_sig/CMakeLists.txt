cmake_minimum_required(VERSION 3.5)
project(test_ml_dsa_sig C)
set(CMAKE_C_STANDARD 11)

add_executable(test_ml_dsa_sig
        ml_dsa_sig.c)
target_link_libraries(test_ml_dsa_sig
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)