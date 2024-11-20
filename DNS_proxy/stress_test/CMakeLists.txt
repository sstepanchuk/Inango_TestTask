cmake_minimum_required(VERSION 3.5.0)
find_package(Threads REQUIRED)

project(stress_test VERSION 0.1.0 LANGUAGES C)

add_executable(${PROJECT_NAME} main.c)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC pthread dns_packet)