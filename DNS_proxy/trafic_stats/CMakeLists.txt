cmake_minimum_required(VERSION 3.5.0)

add_library(trafic_stats SHARED trafic_stats.c)

target_include_directories(trafic_stats PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})