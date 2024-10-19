cmake_minimum_required(VERSION 3.5.0)
project(DNS_proxy VERSION 0.1.0 LANGUAGES C)

set(EXECUTABLE_OUTPUT_PATH "bin")

# Add subdirectories for the libraries
add_subdirectory(thpool)
add_subdirectory(udp_server)
add_subdirectory(dns_packet)
add_subdirectory(trafic_stats)

# Add the executable
add_executable(DNS_proxy main.c)

# Link the libraries
target_link_libraries(DNS_proxy PRIVATE udp_server thpool dns_packet trafic_stats)