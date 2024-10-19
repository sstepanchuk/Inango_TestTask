cmake_minimum_required(VERSION 3.5.0)

find_package(Threads REQUIRED)
add_library(thpool SHARED thpool.c)

target_link_libraries(thpool PRIVATE Threads::Threads)
target_include_directories(thpool PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})