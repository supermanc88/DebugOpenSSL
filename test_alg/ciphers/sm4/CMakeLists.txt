cmake_minimum_required(VERSION 3.5)

project(test_cipher_sm4 C)
set(CMAKE_C_STANDARD 11)

# xts mode
add_executable(test_xts_sm4
        xts_sm4.c)
target_link_libraries(test_xts_sm4
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)


# gcm mode
add_executable(test_gcm_sm4
        gcm_sm4.c)
target_link_libraries(test_gcm_sm4
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# ccm mode
add_executable(test_ccm_sm4
        ccm_sm4.c)
target_link_libraries(test_ccm_sm4
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)