cmake_minimum_required(VERSION 3.5.0)
project(udp_server VERSION 0.1.0 LANGUAGES C)

add_library(${PROJECT_NAME} SHARED udp_server.c)
target_link_libraries(${PROJECT_NAME} PRIVATE dns_packet)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})