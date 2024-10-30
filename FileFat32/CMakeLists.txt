cmake_minimum_required(VERSION 3.5.0)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set(CMAKE_C_COMPILER "gcc")

project(FileFAT32 VERSION 0.1.0 LANGUAGES C)

set(SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")

# Add the executable
add_executable(${PROJECT_NAME} "${SOURCE_DIR}/main.c")