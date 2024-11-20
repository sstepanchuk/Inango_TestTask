#ifndef DNS_VALIDATION_H
#define DNS_VALIDATION_H

#include "dns_defs.h"

// VALIDATE
unsigned char validate_dns_header(const DnsHeader *dns_header, int packet_size);
unsigned char validate_type(const unsigned short type);
unsigned char validate_qtype(const unsigned short qtype);
unsigned char validate_class(const unsigned short class);
unsigned char validate_qclass(const unsigned short qclass);
unsigned char validate_label(const unsigned char *packet_with_pos,
                             const int label_length);

#endif