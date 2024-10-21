#ifndef DNS_VALIDATION_H
#define DNS_VALIDATION_H

#include "dns_defs.h"

// VALIDATE
int validate_dns_header(DnsHeader *dns_header, int packet_size);
int validate_type(unsigned short type);
int validate_qtype(unsigned short qtype);
int validate_class(unsigned short class);
int validate_qclass(unsigned short qclass);
int is_valid_label(const unsigned char *packet_with_pos, int label_length);

#endif