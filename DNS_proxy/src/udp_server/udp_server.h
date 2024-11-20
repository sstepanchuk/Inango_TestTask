#ifndef UDP_SERVER_H
#define UDP_SERVER_H

#include "dns_defs.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>

#define SERVER_BUFFER_SIZE MAX_DNS_PACKET_SIZE

typedef struct {
  struct sockaddr_in client_addr;
  unsigned char *buffer;
  int packet_size;
  socklen_t addr_len;
} Request;

typedef struct {
  int port;
  int sockfd;
} UdpServer;

// Оголошення типу для обробника запитів
typedef void (*RequestResolveHandler)(UdpServer *server, Request request,
                                      void *context);

// Функції для створення і знищення сервера
UdpServer *udp_server_create(int port, int socket_buffer_size,
                             int sock_type_flags);
void udp_server_destroy(UdpServer *server);

// Функція для запуску сервера
void udp_server_listen(UdpServer *server, RequestResolveHandler handler,
                       void *context);

#endif
