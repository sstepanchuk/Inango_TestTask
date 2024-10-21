#ifndef T_DNS_PACKET_MAIN_H
#define T_DNS_PACKET_MAIN_H

#include "dns_packet.h"
#include <check.h>
#include <stdint.h>
#include <stdlib.h>

// cases
TCase *test__parse_domain_name(void);

// suite
Suite *dns_packet_suite(void);

#endif