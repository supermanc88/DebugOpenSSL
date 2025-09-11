# binary output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT_DIR}/build/signatures)

add_subdirectory(dsa_sig)
add_subdirectory(ecdsa_sig)
add_subdirectory(rsa_sig)