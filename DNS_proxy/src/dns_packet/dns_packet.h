#ifndef DNS_PACKET_H
#define DNS_PACKET_H

// Максимальний розмір DNS пакета (без EDNS)
#define MAX_DNS_PACKET_SIZE 512

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_defs.h"
#include "dns_validation.h"

// FREE
void free_dns_records(DnsAnswer *records, unsigned short count);
void free_dns_packet(DnsPacket *dns_packet);

// PARSE
int parse_dns_header(const unsigned char *packet, int packet_size,
                     DnsHeader *header_out);

int parse_domain_name(const unsigned char *packet, int packet_size, int pos,
                      char **name);

int parse_dns_queries(const unsigned char *packet, DnsQuery **_queries,
                      int packet_size, int *pos, unsigned short count);

int parse_dns_answers(const unsigned char *packet, DnsAnswer **_answers,
                      int packet_size, int *pos, unsigned short count);

DnsPacket *parse_dns_packet(const unsigned char *packet, int packet_size);

// PRINT
void print_dns_packet(DnsPacket *dns_packet);

#endif