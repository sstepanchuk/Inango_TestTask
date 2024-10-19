#include "udp_server.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Функція для створення нового UDP сервера
UdpServer *udp_server_create(int port, int buffer_size, int sock_type_flags) {
  UdpServer *server = malloc(sizeof(UdpServer));
  server->port = port;
  server->buffer_size = buffer_size;

  // Створення UDP-сокета
  if ((server->sockfd = socket(AF_INET, SOCK_DGRAM | sock_type_flags, 0)) < 0) {
    perror("Не вдалося створити сокет");
    free(server);
    return NULL;
  }

  // Налаштування серверної адреси
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(port);

  // Прив'язка сокета до адреси
  if (bind(server->sockfd, (const struct sockaddr *)&server_addr,
           sizeof(server_addr)) < 0) {
    perror("Не вдалося прив'язати сокет");
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

void _udp_server_request_handler(ServerRequestInfo *info) {
  info->request_handler(info->server, info->request, info->validation_context);
  free(info->request.buffer); // Звільняємо буфер у разі помилки
  free(info);
}

// Функція для запуску сервера
void udp_server_listen(UdpServer *server, RequestHandler handler,
                       RequestValidatorHandler validation_handler,
                       threadpool pool) // Можна тільки в одному потоці
{
  // Основний цикл сервера
  static ServerRequestInfo *rinfo = NULL;
  static Request *request;
  static socklen_t addr_len;

  if (rinfo == NULL) {
    rinfo = malloc(sizeof(ServerRequestInfo));
    request = &rinfo->request;

    rinfo->server = server;
    rinfo->request_handler = handler;
    request->buffer = malloc(server->buffer_size); // Виділяємо буфер динамічно
    addr_len = sizeof(request->client_addr);
  }

  request->packet_size =
      recvfrom(server->sockfd, request->buffer, server->buffer_size, 0,
               (struct sockaddr *)&request->client_addr, &addr_len);

  if (request->packet_size > 0) {
    if (validation_handler == NULL ||
        (rinfo->validation_context = validation_handler(server, *request))) {
      thpool_add_work(pool, (void (*)(void *)) & _udp_server_request_handler,
                      (void *)rinfo);
      rinfo = NULL;
    }
  } else if (errno == EAGAIN || errno == EWOULDBLOCK)
    perror("Помилка recvfrom");
}
