cmake_minimum_required(VERSION 3.5.0)
project(utils VERSION 0.1.0 LANGUAGES C)

add_library(${PROJECT_NAME} SHARED strrchrn.c remove_elements.c uthash.h)

target_include_directories(${PROJECT_NAME} PUBLIC .)