#ifndef H_DNS_PACKET_LIST
#define H_DNS_PACKET_LIST

#include "dns_packet.h"
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>

struct DnsPacketHashEntry {
  unsigned short key;
  DnsPacket *value;
  struct sockaddr_in client_addr;
  socklen_t addr_len;
  time_t create_time;
  UT_hash_handle hh;
};

extern struct DnsPacketHashEntry *cached_dns_packets;
extern pthread_mutex_t cached_dns_mutex;
extern unsigned short next_dns_package_id;

unsigned short add_dns_packet(struct DnsPacketHashEntry hentry);

unsigned char get_dns_packet(unsigned short key,
                             struct DnsPacketHashEntry *out_entry);
void full_remove_dns_packet(unsigned short key);
void free_dns_packet_list();

#endif