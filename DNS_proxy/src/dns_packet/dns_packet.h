#ifndef DNS_PACKET_H
#define DNS_PACKET_H

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_defs.h"
#include "dns_validation.h"

// FREE
void free_dns_records(DnsAnswer *records, unsigned short count);
void free_dns_packet(DnsPacket *dns_packet);

// SERIALIZE
int serialize_domain_name(const char *name, unsigned char *packet, int pos);
int serialize_dns_header(const DnsHeader *header, unsigned char *packet,
                         int pos);
int serialize_dns_queries(const DnsQuery *queries, unsigned short count,
                          unsigned char *packet, int pos);
int serialize_dns_answers(const DnsAnswer *answers, unsigned short count,
                          unsigned char *packet, int pos);
int serialize_dns_packet(const DnsPacket *dns_packet, unsigned char *packet);

// PARSE
unsigned char parse_dns_rcode(const char *rcode_str, unsigned char *rcode_out);
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