cmake_minimum_required(VERSION 3.5)
project(test_hmacs C)
set(CMAKE_C_STANDARD 11)


# hmac with sm3
add_executable(test_hmac_sm3
            hmac_sm3.c)
target_link_libraries(test_hmac_sm3
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# hmac with sha1
add_executable(test_hmac_sha1
            hmac_sha1.c)
target_link_libraries(test_hmac_sha1
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# hmac with sha256
add_executable(test_hmac_sha256
            hmac_sha256.c)
target_link_libraries(test_hmac_sha256
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# hmac with sha224
add_executable(test_hmac_sha224
            hmac_sha224.c)
target_link_libraries(test_hmac_sha224
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# hmac with sha384
add_executable(test_hmac_sha384
            hmac_sha384.c)
target_link_libraries(test_hmac_sha384
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# hmac with sha512
add_executable(test_hmac_sha512
            hmac_sha512.c)
target_link_libraries(test_hmac_sha512
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# hmac with sha3-224
add_executable(test_hmac_sha3_224
            hmac_sha3_224.c)
target_link_libraries(test_hmac_sha3_224
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# hmac with sha3-256
add_executable(test_hmac_sha3_256
            hmac_sha3_256.c)
target_link_libraries(test_hmac_sha3_256
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# hmac with sha3-384
add_executable(test_hmac_sha3_384
            hmac_sha3_384.c)
target_link_libraries(test_hmac_sha3_384
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# hmac with sha3-512
add_executable(test_hmac_sha3_512
            hmac_sha3_512.c)
target_link_libraries(test_hmac_sha3_512
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)