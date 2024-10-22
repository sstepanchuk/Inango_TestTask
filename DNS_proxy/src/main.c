#include "main.h"

Config cfg;
TrafficStats *gstats;
unsigned short cached_dns_id = 0;
// Кастомний обробник запитів
void custom_request_handler(UdpServer *server, Request request,
                            DnsPacket *packet) {

  if (packet->header.qr) {
    int result = add_dns_packet((struct DnsPacketHashEntry){
        0, packet, request.client_addr, request.addr_len, time(NULL)});

    pthread_mutex_lock(&cached_dns_mutex);
    printf("New packet with incorrect id: %hu should be: %hu\n", result,
           cached_dns_id++);
    pthread_mutex_unlock(&cached_dns_mutex);

    // ssize_t sent_bytes =
    //    sendto(server->sockfd, message, strlen(message), 0,
    //           (const struct sockaddr *)&server_addr, sizeof(server_addr));
  }

  // pthread_mutex_lock(&gstats->lock);
  // gstats->total_rx_bytes += request.packet_size;
  // pthread_mutex_unlock(&gstats->lock);
  // print_dns_packet(packet);
  // free_dns_packet(packet);
}

// Кастомний валідатор запитів
void *custom_request_validator(UdpServer *server, Request request) {
  return parse_dns_packet(request.buffer, request.packet_size);
  // return (void *)1;
}

// Кастомний обробник запитів
void speedtester(void *arg) {
  while (1) {
    sleep(INTERVAL);
    calculate_and_print_traffic_speed(gstats);
  }
}

int main() {
  // Parse config

  if (!load_config(&cfg)) {
    printf("Can't read config file '%s'\n", default_config_file);
    return 1;
  }

  // Налаштування серверів (порт, розмір буфера, кількість потоків)
  int port = 8080;
  int buffer_size = MAX_DNS_PACKET_SIZE;
  int thread_pool_size = 8;

  threadpool pool = thpool_init(thread_pool_size);
  UdpServer *server = udp_server_create(port, buffer_size, 1024 * 1024, 0);
  TrafficStats stats;
  memset(&stats, 0, sizeof(TrafficStats));
  stats.start_time = time(NULL);
  pthread_mutex_init(&stats.lock, NULL);
  pthread_mutex_init(&cached_dns_mutex, NULL);

  gstats = &stats;

  if (!server)
    fprintf(stderr, "Не вдалося створити сервер на порту %d\n", port);

  // thpool_add_work(pool, speedtester, 0);

  ServerRequestInfo *info = NULL;
  while (1) {
    udp_server_listen(server, (RequestHandler)custom_request_handler,
                      custom_request_validator, pool, &info);
  }

  thpool_destroy(pool);
  udp_server_destroy(server);
  pthread_mutex_destroy(&stats.lock);
  free_dns_packet_list();
  pthread_mutex_destroy(&cached_dns_mutex);
  return 0;
}
