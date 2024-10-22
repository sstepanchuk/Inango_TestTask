#ifndef H_LOAD_CONFIG
#define H_LOAD_CONFIG

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "inih.h"
#include "dns_packet.h"

typedef struct {
  struct sockaddr_in upstreamdns_ipaddress;
  unsigned char blacklisted_response;
  struct sockaddr_in blacklisted_ipaddress_response;
} Config;

extern const char *default_config_file;

unsigned char load_config(Config *config_out);

#endif