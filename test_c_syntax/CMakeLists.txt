cmake_minimum_required(VERSION 3.10)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT_DIR}/build/c_syntax)

project(test_c_syntax C)
set(CMAKE_C_STANDARD 11)

add_executable(test_const
    test_const.c)
