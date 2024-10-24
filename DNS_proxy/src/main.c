#include "main.h"

void dns_server_response_handler(DNSRequestContext *context) {
  DnsPacket *packet = context->packet;

  free_dns_packet(packet);
  free(context);
}

void proxy_incomming_request_handler(DNSRequestContext *context) {
  static unsigned short cached_dns_id = 0;

  DnsPacket *packet = context->packet;

  int result = add_dns_packet((struct DnsPacketHashEntry){
      0, packet, context->client_addr, context->addr_len, time(NULL)});

  pthread_mutex_lock(&cached_dns_mutex);
  printf("New incomming packet with incorrect id: %hu should be: %hu\n", result,
         cached_dns_id++);
  pthread_mutex_unlock(&cached_dns_mutex);

  free(context);
}

void request_handler(UdpServer *server, Request request,
                     ServerContext *servercontext) {
  DnsPacket *packet = parse_dns_packet(request.buffer, request.packet_size);
  if (packet == NULL)
    return;

  if (packet->header.qr &&
      request.client_addr.sin_addr.s_addr !=
          servercontext->cfg.upstreamdns_ipaddress.sin_addr.s_addr) {
    free_dns_packet(packet);
    return;
  }

  DNSRequestContext *request_context = malloc(sizeof(DNSRequestContext));
  request_context->server = servercontext;
  request_context->packet = packet;
  request_context->client_addr = request.client_addr;
  request_context->addr_len = request.addr_len;

  if (packet->header.qr)
    thpool_add_work(servercontext->response_thpool,
                    (void (*)(void *))dns_server_response_handler,
                    (void *)request_context);
  else
    thpool_add_work(servercontext->requests_thpool,
                    (void (*)(void *))proxy_incomming_request_handler,
                    (void *)request_context);
}
// Кастомний обробник запитів
// void speedtester(void *arg) {
//  while (1) {
//    sleep(INTERVAL);
//    calculate_and_print_traffic_speed(gstats);
//  }
//}

void free_proxy(ServerContext *servercontext) {
  thpool_destroy(servercontext->requests_thpool);
  thpool_destroy(servercontext->response_thpool);
  udp_server_destroy(servercontext->server);
  pthread_mutex_destroy(&servercontext->gstats.lock);
  free_dns_packet_list();
  pthread_mutex_destroy(&cached_dns_mutex);
}

int main() {
  // Parse config
  ServerContext server_context;

  if (!load_config(&server_context.cfg)) {
    printf("Can't read config file '%s'\n", default_config_file);
    return 1;
  }

  server_context.requests_thpool = thpool_init(MAX_THREADS / 2);
  server_context.response_thpool = thpool_init(MAX_THREADS / 2);
  server_context.server = udp_server_create(SERVER_PORT, 1024 * 1024, 0);
  pthread_mutex_init(&cached_dns_mutex, NULL);

  if (!server_context.server) {
    fprintf(stderr, "Не вдалося створити сервер на порту %d\n", SERVER_PORT);
    free_proxy(&server_context);
    return 1;
  }

  while (1) {
    udp_server_listen(server_context.server,
                      (RequestResolveHandler)request_handler, &server_context);
  }

  free_proxy(&server_context);
  return 0;
}
