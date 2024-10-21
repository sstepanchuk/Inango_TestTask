
#include "./main.h"

Suite *dns_packet_suite(void) {
  Suite *s;
  TCase *tc_core;

  s = suite_create("dns_packet");
  suite_add_tcase(s, test__parse_domain_name());
  return s;
}