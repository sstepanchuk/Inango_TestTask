#ifndef SOCKADDR_UTILS_H
#define SOCKADDR_UTILS_H

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Function to convert address family to a human-readable string
const char *family_to_string(int family);

// Function to print sockaddr_in details
void print_sockaddr_in(struct sockaddr_in *addr);

#endif // SOCKADDR_UTILS_H
