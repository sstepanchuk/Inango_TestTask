#include "main.h"

// Кастомний обробник запитів
void custom_request_handler(UdpServer *server, Request request,
                            DnsPacket *packet) {
  print_dns_packet(packet);
  free_dns_packet(packet);
}

// Кастомний валідатор запитів
void *custom_request_validator(UdpServer *server, Request request) {
  return parse_dns_packet(request.buffer, request.packet_size);
}

int main() {
  // Налаштування серверів (порт, розмір буфера, кількість потоків)
  int port = 8080;
  int buffer_size = MAX_DNS_PACKET_SIZE;
  int thread_pool_size = 8;

  threadpool pool = thpool_init(thread_pool_size);
  UdpServer *server = udp_server_create(port, buffer_size, 0);
  if (!server)
    fprintf(stderr, "Не вдалося створити сервер на порту %d\n", port);

  while (1) {
    udp_server_listen(server, (RequestHandler)custom_request_handler,
                      custom_request_validator, pool);
  }

  thpool_destroy(pool);
  udp_server_destroy(server);

  return 0;
}
