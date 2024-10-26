#include "dns_packet_list.h"

struct DnsPacketHashEntry *cached_dns_packets = NULL;
pthread_mutex_t cached_dns_mutex;
unsigned short next_dns_package_id = 0;

unsigned short add_dns_packet(struct DnsPacketHashEntry hentry) {
  struct DnsPacketHashEntry *entry;
  pthread_mutex_lock(&cached_dns_mutex);
  HASH_FIND(hh, cached_dns_packets, &next_dns_package_id,
            sizeof(next_dns_package_id), entry);

  if (entry == NULL) {
    entry =
        (struct DnsPacketHashEntry *)malloc(sizeof(struct DnsPacketHashEntry));
    memcpy(entry, &hentry, sizeof(struct DnsPacketHashEntry));
    entry->key = next_dns_package_id;
    HASH_ADD(hh, cached_dns_packets, key, sizeof(next_dns_package_id), entry);
  } else {
    free_dns_packet(entry->value);
    entry->value = hentry.value;
    entry->addr_len = hentry.addr_len;
    entry->client_addr = hentry.client_addr;
    entry->create_time = hentry.create_time;
  }
  unsigned short result = next_dns_package_id;
  ++next_dns_package_id;
  pthread_mutex_unlock(&cached_dns_mutex);
  return result;
}

unsigned char get_dns_packet(unsigned short key,
                             struct DnsPacketHashEntry *out_entry) {
  struct DnsPacketHashEntry *entry;
  pthread_mutex_lock(&cached_dns_mutex);
  HASH_FIND(hh, cached_dns_packets, &key, sizeof(key), entry);

  if (entry != NULL) {
    HASH_DEL(cached_dns_packets, entry);
    *out_entry = *entry;
    free(entry);
    pthread_mutex_unlock(&cached_dns_mutex);
    return 1; // Return the pointer to DnsPacket if found
  }
  pthread_mutex_unlock(&cached_dns_mutex);
  return 0; // Return NULL if not found
}

void free_dns_packet_list() {
  pthread_mutex_lock(&cached_dns_mutex);
  struct DnsPacketHashEntry *tmp, *p;
  HASH_ITER(hh, cached_dns_packets, p, tmp) {
    HASH_DEL(cached_dns_packets, p);
    free_dns_packet(p->value);
    free(p);
  }
  pthread_mutex_unlock(&cached_dns_mutex);
}