cmake_minimum_required(VERSION 3.5.0)
project(DNS_proxy VERSION 0.1.0 LANGUAGES C)

set(EXECUTABLE_OUTPUT_PATH "bin")

add_executable(DNS_proxy main.c)