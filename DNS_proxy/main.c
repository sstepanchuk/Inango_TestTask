#include "thpool.h"
#include "udp_server.h"
#include <stdio.h>

// Кастомний обробник запитів
void custom_request_handler(UdpServer *server, Request request)
{
    printf("Обробка запиту від клієнта: %s\n", request.buffer);
    // Тут можна реалізувати специфічну логіку обробки запиту
}

int main()
{
    // Налаштування серверів (порт, розмір буфера, кількість потоків, розмір черги)
    int buffer_size = 512;
    int thread_pool_size = 8;

    threadpool pool = thpool_init(thread_pool_size);
    UdpServer *server = udp_server_create(8080, buffer_size, 0);
    if (!server)
        fprintf(stderr, "Не вдалося створити сервер на порту %d\n", 8080);

    while(1) {
        udp_server_listen(server, custom_request_handler, pool);
    }

    // Не забудьте звільнити ресурси
    thpool_destroy(pool);
    udp_server_destroy(server);

    return 0;
}
