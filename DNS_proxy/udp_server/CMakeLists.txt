cmake_minimum_required(VERSION 3.5.0)

add_library(udp_server SHARED udp_server.c)
target_link_libraries(udp_server PRIVATE thpool)

target_include_directories(udp_server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})