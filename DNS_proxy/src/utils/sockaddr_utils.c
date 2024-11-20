#include "sockaddr_utils.h"

const char *family_to_string(int family) {
  switch (family) {
  case AF_INET:
    return "AF_INET (IPv4)";
  case AF_INET6:
    return "AF_INET6 (IPv6)";
  case AF_UNIX:
    return "AF_UNIX (Unix Domain)";
  default:
    return "Unknown Family";
  }
}

void print_sockaddr_in(struct sockaddr_in *addr) {
  // Print the address family as a string
  printf("Address Family: %s\n", family_to_string(addr->sin_family));

  // Print the port number in host byte order (use ntohs to convert to host byte
  // order)
  printf("Port: %d\n", ntohs(addr->sin_port));

  // Print the IP address (use inet_ntoa to convert from network byte order to a
  // string)
  char ip_str[INET_ADDRSTRLEN]; // Buffer to hold the IP address as a string
  inet_ntop(AF_INET, &(addr->sin_addr), ip_str, INET_ADDRSTRLEN);
  printf("IP Address: %s\n", ip_str);
}
