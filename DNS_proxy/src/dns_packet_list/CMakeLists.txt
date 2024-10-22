cmake_minimum_required(VERSION 3.5.0)
project(dns_packet_list VERSION 0.1.0 LANGUAGES C)

find_package(Threads REQUIRED)

add_library(${PROJECT_NAME} SHARED dns_packet_list.c)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads dns_packet)