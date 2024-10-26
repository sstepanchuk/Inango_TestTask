#ifndef H_LOAD_CONFIG
#define H_LOAD_CONFIG

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include "inih.h"
#include "dns_packet.h"
#include "uthash.h"

typedef struct {
  char key[MAX_DOMAIN_LENGTH];
  UT_hash_handle hh;
} BlacklistItem;

typedef struct {
  unsigned short server_port;
  struct sockaddr_in upstreamdns_ipaddress;
  unsigned char blacklisted_response;
  struct in_addr *blacklisted_ip_response;
  struct in6_addr *blacklisted_ipv6_response;
  char blacklist_file[255];
  BlacklistItem *blacklisted_domains_hashmap;
} Config;

extern const char *default_config_file;

unsigned char load_config(Config *config_out);

// FREE
void free_config(Config *config_out);

#endif