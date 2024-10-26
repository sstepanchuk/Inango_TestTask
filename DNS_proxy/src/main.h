#ifndef MAIN_H
#define MAIN_H

#include "dns_packet.h"
#include "dns_packet_list.h"
#include "thpool.h"
#include "trafic_stats.h"
#include "udp_server.h"
#include "load_config.h"
#include "remove_elements.h"

#define MAX_THREADS 8
#define MAX_THREADS 8

typedef struct {
  UdpServer *server;
  Config cfg;
  TrafficStats gstats;
  threadpool requests_thpool;
  threadpool response_thpool;
} ServerContext;

typedef struct {
  ServerContext *server;
  DnsPacket *packet;
  struct sockaddr_in client_addr;
  socklen_t addr_len;
} DNSRequestContext;

#endif