#include "main.h"

// TrafficStats *gstats;

// Кастомний обробник запитів
void custom_request_handler(UdpServer *server, Request request,
                            DnsPacket *packet) {
  // pthread_mutex_lock(&gstats->lock);
  // gstats->total_rx_bytes += request.packet_size;
  // pthread_mutex_unlock(&gstats->lock);
  print_dns_packet(packet);
  free_dns_packet(packet);
}

// Кастомний валідатор запитів
void *custom_request_validator(UdpServer *server, Request request) {
  return parse_dns_packet(request.buffer, request.packet_size);
  // return (void *)1;
}

// Кастомний обробник запитів
/*void speedtester(void *arg) {
  while (1) {
    sleep(INTERVAL);
    calculate_and_print_traffic_speed(gstats);
  }
}*/

int main() {
  // Налаштування серверів (порт, розмір буфера, кількість потоків)
  int port = 8080;
  int buffer_size = MAX_DNS_PACKET_SIZE;
  int thread_pool_size = 8;

  threadpool pool = thpool_init(thread_pool_size);
  UdpServer *server = udp_server_create(port, buffer_size, 0);
  // TrafficStats stats;
  // memset(&stats, 0, sizeof(TrafficStats));
  // stats.start_time = time(NULL);
  // pthread_mutex_init(&stats.lock, NULL);

  // gstats = &stats;

  if (!server)
    fprintf(stderr, "Не вдалося створити сервер на порту %d\n", port);

  // thpool_add_work(pool, speedtester, 0);

  while (1) {
    udp_server_listen(server, (RequestHandler)custom_request_handler,
                      custom_request_validator, pool);
  }

  thpool_destroy(pool);
  udp_server_destroy(server);
  // pthread_mutex_destroy(&stats.lock);
  return 0;
}
