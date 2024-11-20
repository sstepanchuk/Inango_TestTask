#include "main.h"

#if ENABLE_STATS

void speedtester(ServerContext *servercontext) {
  clock_gettime(CLOCK_MONOTONIC, &servercontext->gstats.prev_time);
  while (1) {
    sleep(INTERVAL);
    calculate_and_print_traffic_speed(&servercontext->gstats,
                                      servercontext->requests_thpool,
                                      servercontext->response_thpool);
  }
}
#endif

void dns_server_response_handler(DNSRequestContext *context) {
  DnsPacket *packet =
      parse_dns_packet(context->request.buffer, context->request.packet_size);

  if (packet) {
    struct DnsPacketHashEntry out_entry;

    if (get_dns_packet(packet->header.id, &out_entry)) {
      unsigned char buffer[512];
      packet->header.id = out_entry.value->header.id;

      int size = serialize_dns_packet(packet, buffer);

      if (size > 0) {
        if (sendto(context->server->server->sockfd, buffer, size, 0,
                   (struct sockaddr *)&out_entry.client_addr,
                   out_entry.addr_len) < 0) {
          print_sockaddr_in(&out_entry.client_addr);
          perror("Sendto failed");
        } else {
#if ENABLE_STATS
          pthread_mutex_lock(&context->server->gstats.lock);
          context->server->gstats.total_tx_bytes += size;
          pthread_mutex_unlock(&context->server->gstats.lock);
#else
          printf("Successfully return proxied\n");
#endif
        }
      } else {
        printf("Serialization message from upstream failed\n");
        print_dns_packet(packet);
      }

      free_dns_packet(out_entry.value);
    }

    free_dns_packet(packet);
  }
  free(context->request.buffer);
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

    unsigned short query_id, qtype, str_size, addr_size;

    for (unsigned short i = 0; i < blocked_query_count; i++) {
      query_id = blocked_query_ids[i];
      blocked_response->queries[i] = packet->queries[query_id];
      ++blocked_response->header.q_count;

      if (context->server->cfg.blacklisted_response == DNS_RCODE_NOERROR) {
        str_size = strlen(packet->queries[query_id].name) + 1;
        qtype = packet->queries[query_id].ques.qtype;

        blocked_response->answers[i].class =
            packet->queries[query_id].ques.qclass;
        blocked_response->answers[i].type =
            packet->queries[query_id].ques.qtype;
        blocked_response->answers[i].ttl = 3600;
        blocked_response->answers[i].name = malloc(str_size);
        strncpy(blocked_response->answers[i].name,
                packet->queries[query_id].name, str_size);
        qtype = packet->queries[query_id].ques.qtype;
        addr_size = qtype == DNS_TYPE_A ? sizeof(struct in_addr)
                                        : sizeof(struct in6_addr);
        blocked_response->answers[i].data = malloc(addr_size);
        blocked_response->answers[i].data_len = addr_size;
        memcpy(blocked_response->answers[i].data,
               qtype == DNS_TYPE_A
                   ? (void *)context->server->cfg.blacklisted_ip_response
                   : (void *)context->server->cfg.blacklisted_ipv6_response,
               addr_size);
        ++blocked_response->header.ans_count;
      }
    }

    remove_elements(packet->queries, sizeof(DnsQuery), blocked_query_ids,
                    blocked_query_count, &packet->header.q_count);

    unsigned char buffer[512];
    int size = serialize_dns_packet(blocked_response, buffer);
    if (size > 0) {
      if (sendto(context->server->server->sockfd, buffer, size, 0,
                 (struct sockaddr *)&context->request.client_addr,
                 context->request.addr_len) < 0) {
        print_sockaddr_in(&context->request.client_addr);
        perror("Sendto block failed");
      } else {
#if ENABLE_STATS
        pthread_mutex_lock(&context->server->gstats.lock);
        context->server->gstats.total_tx_bytes += size;
        pthread_mutex_unlock(&context->server->gstats.lock);
#else
        for (unsigned short i = 0; i < blocked_response->header.q_count; i++)
          printf("Domain blocked: %s\n", blocked_response->queries[i].name);
#endif
      }
    } else {
      printf("Serialization block message failed\n");
      print_dns_packet(blocked_response);
    }

    free_dns_packet(blocked_response);
  }

  free(blocked_query_ids);
}

void proxy_incomming_request_handler(DNSRequestContext *context) {
  DnsPacket *packet =
      parse_dns_packet(context->request.buffer, context->request.packet_size);

  if (packet) {
#if ENABLE_STATS
    pthread_mutex_lock(&context->server->gstats.lock);
    context->server->gstats.total_packets += 1;
    pthread_mutex_unlock(&context->server->gstats.lock);
#endif

    // Check is in black list
    clean_packet(packet, context);

    if (packet->header.q_count > 0) {
      unsigned short packet_id_temp = packet->header.id;
      packet->header.id = add_dns_packet(
          (struct DnsPacketHashEntry){0, packet, context->request.client_addr,
                                      context->request.addr_len, time(NULL)});

      unsigned char buffer[512];
      int size = serialize_dns_packet(packet, buffer);
      if (size > 0) {
        packet->header.id = packet_id_temp;

        if (sendto(
                context->server->server->sockfd, buffer, size, 0,
                (struct sockaddr *)&context->server->cfg.upstreamdns_ipaddress,
                sizeof(struct sockaddr_in)) < 0) {
          print_sockaddr_in(&context->request.client_addr);
          perror("Sendto upstream failed");
        } else {
#if ENABLE_STATS
          pthread_mutex_lock(&context->server->gstats.lock);
          context->server->gstats.total_tx_bytes += size;
          pthread_mutex_unlock(&context->server->gstats.lock);
#else
          printf("Successfully proxied\n");
#endif
        }
      } else {
        full_remove_dns_packet(packet->header.id);

        packet->header.id = packet_id_temp;

        printf("Serialization message to upstream failed\n");
        print_dns_packet(packet);
        free_dns_packet(packet);
      }
    } else
      free_dns_packet(packet);
  }

  free(context->request.buffer);
  free(context);
}

void request_handler(UdpServer *server, Request request,
                     ServerContext *servercontext) {
#if ENABLE_STATS
  pthread_mutex_lock(&servercontext->gstats.lock);
  servercontext->gstats.total_rx_bytes += request.packet_size;
  pthread_mutex_unlock(&servercontext->gstats.lock);
#endif
  DnsHeader header;

  if (parse_dns_header(request.buffer, request.packet_size, &header) > 0) {
    free(request.buffer);
    return;
  }

  if (header.qr &&
      request.client_addr.sin_addr.s_addr !=
          servercontext->cfg.upstreamdns_ipaddress.sin_addr.s_addr) {
    free(request.buffer);
    return;
  }

  DNSRequestContext *request_context = malloc(sizeof(DNSRequestContext));
  request_context->server = servercontext;
  request_context->request = request;

  if (header.qr)
    thpool_add_work(servercontext->response_thpool,
                    (void (*)(void *))dns_server_response_handler,
                    (void *)request_context);
  else
    thpool_add_work(servercontext->requests_thpool,
                    (void (*)(void *))proxy_incomming_request_handler,
                    (void *)request_context);
}

void free_proxy(ServerContext *servercontext) {
  thpool_destroy(servercontext->requests_thpool);
  thpool_destroy(servercontext->response_thpool);
  if (servercontext->server)
    udp_server_destroy(servercontext->server);
#if ENABLE_STATS
  pthread_mutex_destroy(&servercontext->gstats.lock);
#endif
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
      udp_server_create(server_context.cfg.server_port, 1024 * 1024 * 1024, 0);
  pthread_mutex_init(&cached_dns_mutex, NULL);

#if ENABLE_STATS
  pthread_mutex_init(&server_context.gstats.lock, NULL);
  thpool_add_work(server_context.response_thpool, (void (*)(void *))speedtester,
                  (void *)&server_context);
#endif

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
