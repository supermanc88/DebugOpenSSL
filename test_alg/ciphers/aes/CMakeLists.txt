cmake_minimum_required(VERSION 3.5)

project(test_cipher_aes)
set(CMAKE_C_STANDARD 11)

add_executable(test_ecb_aes
        ecb_aes.c)
target_link_libraries(test_ecb_aes
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

add_executable(test_cbc_aes
        cbc_aes.c)
target_link_libraries(test_cbc_aes
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

add_executable(test_cfb_aes
        cfb_aes.c)
target_link_libraries(test_cfb_aes
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

add_executable(test_ofb_aes
        ofb_aes.c)
target_link_libraries(test_ofb_aes
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

add_executable(test_ctr_aes
        ctr_aes.c)
target_link_libraries(test_ctr_aes
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

add_executable(test_ccm_aes
        ccm_aes.c)
target_link_libraries(test_ccm_aes
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

add_executable(test_gcm_aes
        gcm_aes.c)
target_link_libraries(test_gcm_aes
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

add_executable(test_xts_aes
        xts_aes.c)
target_link_libraries(test_xts_aes
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)