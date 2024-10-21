cmake_minimum_required(VERSION 3.5.0)
find_package(Check 0.15.2 REQUIRED)
find_package(Threads REQUIRED)

include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

project(tests VERSION 0.1.0 LANGUAGES C)

#libraries
set(LIBS 
  dns_packet
)

file(GLOB_RECURSE TEST_SOURCES "*.c")
add_executable(${PROJECT_NAME} ${TEST_SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

find_program(DEBIAN "dpkg")
if(DEBIAN)
    target_link_libraries(${PROJECT_NAME} ${LIBS} check m rt pthread subunit)
else()
    target_link_libraries(${PROJECT_NAME} ${LIBS} check)
endif()

add_test(NAME ALL_TESTS COMMAND ${PROJECT_NAME} WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
