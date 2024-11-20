cmake_minimum_required(VERSION 3.5.0)
project(trafic_stats VERSION 0.1.0 LANGUAGES C)

add_library(${PROJECT_NAME} SHARED trafic_stats.c)

target_link_libraries(${PROJECT_NAME} PRIVATE dns_packet_list thpool)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})