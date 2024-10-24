#ifndef DNS_VALIDATION_H
#define DNS_VALIDATION_H

#include "dns_defs.h"

// VALIDATE
int validate_dns_header(const DnsHeader *dns_header, int packet_size);
int validate_type(const unsigned short type);
int validate_qtype(const unsigned short qtype);
int validate_class(const unsigned short class);
int validate_qclass(const unsigned short qclass);
int validate_label(const unsigned char *packet_with_pos,
                   const int label_length);

#endif