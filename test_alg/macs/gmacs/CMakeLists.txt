cmake_minimum_required(VERSION 3.5)
project(test_gmacs C)
set(CMAKE_C_STANDARD 11)

add_executable(test_gmac_all
        gmac_all.c)
target_link_libraries(test_gmac_all
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)