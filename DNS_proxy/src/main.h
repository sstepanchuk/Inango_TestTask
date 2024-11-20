#ifndef MAIN_H
#define MAIN_H

#define MAX_THREADS 8
#define DNS_PACKET_PRINT_ERRORS
#define ENABLE_STATS 1

#include "dns_packet.h"
#include "dns_packet_list.h"
#include "thpool.h"
#include "udp_server.h"
#include "load_config.h"
#include "remove_elements.h"
#include "sockaddr_utils.h"

#if ENABLE_STATS
#include "trafic_stats.h"
#endif

typedef struct {
  UdpServer *server;
  Config cfg;
#if ENABLE_STATS
  TrafficStats gstats;
#endif
  threadpool requests_thpool;
  threadpool response_thpool;
} ServerContext;

typedef struct {
  ServerContext *server;
  Request request;
} DNSRequestContext;

#endif