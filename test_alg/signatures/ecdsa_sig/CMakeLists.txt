cmake_minimum_required(VERSION 3.5)
project(test_ecdsa_sig C)
set(CMAKE_C_STANDARD 11)

# ecdsa with prime256v1
add_executable(test_ecdsa_prime256v1
            ecdsa_prime256v1.c)
target_link_libraries(test_ecdsa_prime256v1
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)

# ecdsa with other curves
add_executable(test_ecdsa_other_curves
            ecdsa_other_curves.c)
target_link_libraries(test_ecdsa_other_curves
        ${OPENSSL_ROOT_DIR}/libcrypto.a
        ${OPENSSL_ROOT_DIR}/libssl.a)