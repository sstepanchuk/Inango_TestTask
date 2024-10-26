#include "udp_server.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Функція для створення нового UDP сервера
UdpServer *udp_server_create(int port, int socket_buffer_size,
                             int sock_type_flags) {
  UdpServer *server = malloc(sizeof(UdpServer));
  server->port = port;
  // server->buffer_size = buffer_size;

  // Створення UDP-сокета
  if ((server->sockfd = socket(AF_INET, SOCK_DGRAM | sock_type_flags, 0)) < 0) {
    perror("Can't create socket");
    free(server);
    return NULL;
  }

  // Налаштування серверної адреси
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(port);

  if (setsockopt(server->sockfd, SOL_SOCKET, SO_RCVBUF, &socket_buffer_size,
                 sizeof(socket_buffer_size)) < 0) {
    perror("Can't change socket buffer size");
    close(server->sockfd);
    free(server);
    return NULL;
  }

  // Прив'язка сокета до адреси
  if (bind(server->sockfd, (const struct sockaddr *)&server_addr,
           sizeof(server_addr)) < 0) {
    perror("Can't bind socket");
    close(server->sockfd);
    free(server);
    return NULL;
  }

  return server;
}

// Функція для знищення UDP сервера
void udp_server_destroy(UdpServer *server) {
  close(server->sockfd);
  free(server);
}

// Функція для запуску сервера
void udp_server_listen(UdpServer *server, RequestResolveHandler handler,
                       void *context) // Можна тільки в одному потоці
{
  Request request;
  request.addr_len = sizeof(request.client_addr);

  request.packet_size =
      recvfrom(server->sockfd, request.buffer, (size_t)SERVER_BUFFER_SIZE, 0,
               (struct sockaddr *)&request.client_addr, &request.addr_len);

  if (request.packet_size > 0) {
    handler(server, request, context);
  } else if (errno != EAGAIN && errno != EWOULDBLOCK)
    perror("Помилка recvfrom");
}
