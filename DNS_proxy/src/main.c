#include "main.h"

void dns_server_response_handler(DNSRequestContext *context) {
  DnsPacket *packet = context->packet;
  struct DnsPacketHashEntry out_entry;

  if (get_dns_packet(packet->header.id, &out_entry)) {

    unsigned char buffer[512];
    packet->header.id = out_entry.value->header.id;

    int size = serialize_dns_packet(packet, buffer);
    if (sendto(context->server->server->sockfd, buffer, size, 0,
               (struct sockaddr *)&out_entry.client_addr,
               out_entry.addr_len) < 0)
      perror("Sendto failed");
    else
      printf("Successfully return proxied\n");

    free_dns_packet(out_entry.value);
  }

  free_dns_packet(packet);
  free(context);
}

BlacklistItem *is_domain_blocked(char *domain, BlacklistItem **blacklist) {
  BlacklistItem *entry;

  while (domain != 0 && *domain != '\0') {
    HASH_FIND_STR(*blacklist, domain, entry);
    if (entry)
      return entry;
    domain = strchr(domain, '.');
    if (domain)
      ++domain;
  }
  return NULL;
}

unsigned char clean_packet(DnsPacket *packet, DNSRequestContext *context) {
  BlacklistItem **blacklist = &context->server->cfg.blacklisted_domains_hashmap;
  BlacklistItem *entry;

  unsigned short *blocked_query_ids =
      malloc(packet->header.q_count * sizeof(int));
  unsigned short blocked_query_count = 0;

  for (unsigned short i = 0; i < packet->header.q_count; i++)
    if ((packet->queries[i].ques.qtype == DNS_TYPE_A ||
         packet->queries[i].ques.qtype == DNS_TYPE_AAAA) &&
        (entry = is_domain_blocked(packet->queries[i].name, blacklist))) {

      blocked_query_ids[blocked_query_count++] = i;
    }

  if (blocked_query_count > 0) {
    DnsPacket *blocked_response = create_empty_dns_packet_copy(packet);
    blocked_response->header.qr = 1;
    blocked_response->queries = malloc(sizeof(DnsQuery) * blocked_query_count);
    if (context->server->cfg.blacklisted_response == 0)
      blocked_response->answers =
          malloc(sizeof(DnsAnswer) * blocked_query_count);
    else
      blocked_response->header.rcode =
          context->server->cfg.blacklisted_response;

    unsigned short query_id;

    for (unsigned short i = 0; i < blocked_query_count; i++) {
      query_id = blocked_query_ids[i];
      blocked_response->queries[i] = packet->queries[query_id];
      ++blocked_response->header.q_count;

      if (context->server->cfg.blacklisted_response == DNS_RCODE_NOERROR) {
        unsigned char str_size = strlen(packet->queries[query_id].name) + 1;
        blocked_response->answers[i].class =
            packet->queries[query_id].ques.qclass;
        blocked_response->answers[i].type =
            packet->queries[query_id].ques.qtype;
        blocked_response->answers[i].ttl = 3600;
        blocked_response->answers[i].name = malloc(str_size);
        strncpy(blocked_response->answers[i].name,
                packet->queries[query_id].name, str_size);
        ++blocked_response->header.ans_count;
      }
    }

    remove_elements(packet->queries, sizeof(DnsQuery), blocked_query_ids,
                    blocked_query_count, &packet->header.q_count);

    unsigned char buffer[512];
    int size = serialize_dns_packet(blocked_response, buffer);
    if (sendto(context->server->server->sockfd, buffer, size, 0,
               (struct sockaddr *)&context->client_addr, context->addr_len) < 0)
      perror("Sendto block failed");
    else
      for (unsigned short i = 0; i < blocked_response->header.q_count; i++)
        printf("Domain blocked: %s\n", blocked_response->queries[i].name);

    free_dns_packet(blocked_response);
  }

  free(blocked_query_ids);
}

void proxy_incomming_request_handler(DNSRequestContext *context) {
  static unsigned short cached_dns_id = 0;

  DnsPacket *packet = context->packet;

  // Check is in black list
  clean_packet(packet, context);

  if (packet->header.q_count > 0) {

    unsigned short packet_id_temp = packet->header.id;
    packet->header.id = add_dns_packet((struct DnsPacketHashEntry){
        0, packet, context->client_addr, context->addr_len, time(NULL)});

    unsigned char buffer[512];
    int size = serialize_dns_packet(packet, buffer);
    packet->header.id = packet_id_temp;

    if (sendto(context->server->server->sockfd, buffer, size, 0,
               (struct sockaddr *)&context->server->cfg.upstreamdns_ipaddress,
               sizeof(struct sockaddr_in)) < 0)
      perror("Sendto failed");
    else
      printf("Successfully proxied\n");

    /*pthread_mutex_lock(&cached_dns_mutex);
    printf("New incomming packet with incorrect id: %hu should be: %hu\n",
           result, cached_dns_id++);
    pthread_mutex_unlock(&cached_dns_mutex);*/
  } else
    free_dns_packet(packet);

  free(context);
}

void request_handler(UdpServer *server, Request request,
                     ServerContext *servercontext) {
  DnsPacket *packet = parse_dns_packet(request.buffer, request.packet_size);
  if (packet == NULL)
    return;

  /* unsigned char buffer[MAX_DNS_PACKET_SIZE];

   int size = serialize_dns_packet(packet, buffer);
   printf("In size: %d / Out size: %d", request.packet_size, size);

   if (sendto(server->sockfd, buffer, size, 0,
              (struct sockaddr *)&request.client_addr, request.addr_len) < 0)
     perror("Sendto failed");
   else
     printf("Successfully return proxied");

   free_dns_packet(packet);*/

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
  if (servercontext->server)
    udp_server_destroy(servercontext->server);
  pthread_mutex_destroy(&servercontext->gstats.lock);
  free_dns_packet_list();
  pthread_mutex_destroy(&cached_dns_mutex);
  free_config(&servercontext->cfg);
}

int main() {
  // Parse config
  ServerContext server_context;

  if (!load_config(&server_context.cfg)) {
    fprintf(stderr, "Can't read config file '%s' or blacklist file\n",
            default_config_file);
    return 1;
  }
  fflush(stdout);
  server_context.requests_thpool = thpool_init(MAX_THREADS / 2);
  server_context.response_thpool = thpool_init(MAX_THREADS / 2);
  server_context.server =
      udp_server_create(server_context.cfg.server_port, 1024 * 1024, 0);
  pthread_mutex_init(&cached_dns_mutex, NULL);

  if (!server_context.server) {
    fprintf(stderr, "Can't create server on 0.0.0.0:%hu\n",
            server_context.cfg.server_port);
    free_proxy(&server_context);
    return 1;
  } else
    printf("Started server on 0.0.0.0:%hu\n", server_context.cfg.server_port);

  while (1) {
    udp_server_listen(server_context.server,
                      (RequestResolveHandler)request_handler, &server_context);
  }

  free_proxy(&server_context);
  return 0;
}
