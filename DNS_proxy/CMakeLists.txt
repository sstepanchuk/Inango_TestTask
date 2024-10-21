cmake_minimum_required(VERSION 3.5.0)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
enable_testing()

project(DNS_proxy VERSION 0.1.0 LANGUAGES C)

set(SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")

#libraries
set(LIBS 
  udp_server
  thpool
  dns_packet
  trafic_stats
)

# Add subdirectories for the libraries
foreach (lib IN LISTS LIBS)
  add_subdirectory("${SOURCE_DIR}/${lib}")
endforeach()
add_subdirectory(tests)

# Add the executable
add_executable(${PROJECT_NAME} "${SOURCE_DIR}/main.c")

# Link the libraries
target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBS})