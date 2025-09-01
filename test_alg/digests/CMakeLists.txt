# binary output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT_DIR}/build/digests)

add_subdirectory(blake2)
add_subdirectory(sha2)
add_subdirectory(sha3)
add_subdirectory(sm3)