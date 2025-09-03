cmake_minimum_required(VERSION 3.5)

project(test_self_implement C)
set(CMAKE_C_STANDARD 11)

add_executable(test_self_implement_xts
        self_implement_xts.c)
target_link_libraries(test_self_implement_xts
${OPENSSL_ROOT_DIR}/libcrypto.a
${OPENSSL_ROOT_DIR}/libssl.a)

add_executable(test_multi_on_gf
    multi_on_gf.c)