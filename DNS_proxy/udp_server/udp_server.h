#ifndef UDP_SERVER_H
#define UDP_SERVER_H

#include <arpa/inet.h>
#include <pthread.h>
#include "thpool.h"

typedef struct {
    struct sockaddr_in client_addr;
    char* buffer;  // Динамічний розмір буфера
    int packet_size;
    socklen_t addr_len;
} Request;

typedef struct {
    int port;
    int buffer_size;
    int sockfd;
    void* context;
} UdpServer;

// Оголошення типу для обробника запитів
typedef void (*RequestHandler)(UdpServer *server, Request request);

typedef struct {
    UdpServer *server;
    Request request;
    RequestHandler request_handler;
} ServerRequestInfo;

// Функції для створення і знищення сервера
UdpServer* udp_server_create(int port, int buffer_size, int sock_type_flags);
void udp_server_destroy(UdpServer* server);

// Функція для запуску сервера
void udp_server_listen(UdpServer *server, RequestHandler handler, threadpool pool);

#endif
