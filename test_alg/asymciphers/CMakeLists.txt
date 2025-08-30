set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT_DIR}/build/asymciphers)

add_subdirectory(ecies)
add_subdirectory(rsa)
add_subdirectory(sm2)