cmake_minimum_required(VERSION 3.5.0)
project(inih VERSION 0.1.0 LANGUAGES C)

add_library(${PROJECT_NAME} SHARED inih.c)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})