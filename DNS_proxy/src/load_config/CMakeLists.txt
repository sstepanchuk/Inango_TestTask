cmake_minimum_required(VERSION 3.5.0)
project(load_config VERSION 0.1.0 LANGUAGES C)

add_library(${PROJECT_NAME} SHARED load_config.c)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE inih dns_packet)