cmake_minimum_required(VERSION 3.5.0)

add_library(dns_packet SHARED dns_packet.c)

target_include_directories(dns_packet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})